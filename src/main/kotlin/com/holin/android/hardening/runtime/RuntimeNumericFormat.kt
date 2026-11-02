package com.holin.android.hardening.runtime

import org.objectweb.asm.Opcodes
import org.objectweb.asm.Type
import org.objectweb.asm.tree.AbstractInsnNode
import org.objectweb.asm.tree.FieldInsnNode
import org.objectweb.asm.tree.IntInsnNode
import org.objectweb.asm.tree.InvokeDynamicInsnNode
import org.objectweb.asm.tree.LdcInsnNode
import org.objectweb.asm.tree.MethodInsnNode
import org.objectweb.asm.tree.MethodNode
import org.objectweb.asm.tree.TypeInsnNode
import org.objectweb.asm.tree.analysis.Frame
import org.objectweb.asm.tree.analysis.SourceValue

/** Proves numeric ID formatting without treating arbitrary Object formatting as a safe sink. */
internal object RuntimeNumericFormat {
    fun accepts(call: MethodInsnNode): Boolean = call.opcode == Opcodes.INVOKESTATIC &&
        call.owner == "java/lang/String" && call.name == "format" && call.desc in setOf(
            "(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;",
            "(Ljava/util/Locale;Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;",
        )

    fun proves(
        call: MethodInsnNode,
        method: MethodNode,
        frames: Array<out Frame<SourceValue>?>,
        referenced: Set<String>,
        names: (List<SourceValue>) -> Set<String>,
    ): Boolean {
        val frame = frames[method.instructions.indexOf(call)] ?: return false
        val argumentCount = Type.getArgumentTypes(call.desc).size
        val start = frame.stackSize - argumentCount
        val format = frame.getStack(start + argumentCount - 2).insns.singleOrNull() as? LdcInsnNode ?: return false
        val pattern = format.cst as? String ?: return false
        val conversions = conversions(pattern) ?: return false
        val argumentArray = frame.getStack(frame.stackSize - 1)
        val root = argumentArray.insns.singleOrNull() as? TypeInsnNode ?: return false
        if (root.opcode != Opcodes.ANEWARRAY || root.desc != "java/lang/Object") return false
        val allocationIndex = method.instructions.indexOf(root)
        if (allocationIndex < 0) return false
        val allocation = frames[allocationIndex] ?: return false
        val length = integer(allocation.getStack(allocation.stackSize - 1)) ?: return false
        if (length < 0 || conversions.keys.any { it !in 0 until length }) return false
        val writes = linkedMapOf<Int, MutableList<SourceValue>>()
        fun references(value: SourceValue) = value.insns.any { it === root }
        method.instructions.forEachIndexed { index, instruction ->
            val before = frames[index] ?: return@forEachIndexed
            fun top(distance: Int) = before.getStack(before.stackSize - distance)
            when (instruction) {
                is MethodInsnNode -> {
                    val count = Type.getArgumentTypes(instruction.desc).size + if (instruction.opcode == Opcodes.INVOKESTATIC) 0 else 1
                    for (distance in 1..count) if (references(top(distance))) {
                        if (instruction !== call || distance != 1 || top(distance).insns.size != 1) return false
                    }
                }
                is InvokeDynamicInsnNode -> {
                    for (distance in 1..Type.getArgumentTypes(instruction.desc).size) if (references(top(distance))) return false
                }
                is FieldInsnNode -> if (instruction.opcode in setOf(Opcodes.PUTFIELD, Opcodes.PUTSTATIC) && references(top(1))) return false
            }
            when (instruction.opcode) {
                Opcodes.AASTORE -> {
                    if (references(top(1))) return false
                    if (references(top(3))) {
                        if (top(3).insns.size != 1) return false
                        val slot = integer(top(2)) ?: return false
                        if (slot !in 0 until length) return false
                        writes.getOrPut(slot) { arrayListOf() }.add(top(1))
                    }
                }
                Opcodes.IASTORE, Opcodes.LASTORE, Opcodes.FASTORE, Opcodes.DASTORE,
                Opcodes.BASTORE, Opcodes.CASTORE, Opcodes.SASTORE -> if (references(top(3))) return false
                Opcodes.ARETURN, Opcodes.ATHROW, Opcodes.CHECKCAST -> if (references(top(1))) return false
            }
        }
        val covered = linkedSetOf<String>()
        writes.forEach { (slot, values) ->
            values.forEach { value ->
                val selected = names(listOf(value))
                if (selected.isNotEmpty()) {
                    val uses = conversions[slot] ?: return false
                    if (uses.any { it !in "doxX" } || !boxedInteger(value)) return false
                    covered.addAll(selected)
                }
            }
        }
        return covered.containsAll(referenced)
    }

    private fun boxedInteger(value: SourceValue): Boolean = value.insns.isNotEmpty() && value.insns.all {
        it is MethodInsnNode && it.opcode == Opcodes.INVOKESTATIC && it.owner == "java/lang/Integer" &&
            it.name == "valueOf" && it.desc == "(I)Ljava/lang/Integer;"
    }

    private fun integer(value: SourceValue): Int? {
        val instruction = value.insns.singleOrNull() ?: return null
        return when {
            instruction.opcode in Opcodes.ICONST_M1..Opcodes.ICONST_5 -> instruction.opcode - Opcodes.ICONST_0
            instruction is IntInsnNode && instruction.opcode in setOf(Opcodes.BIPUSH, Opcodes.SIPUSH) -> instruction.operand
            instruction is LdcInsnNode -> instruction.cst as? Int
            else -> null
        }
    }

    private val token = Regex("%(?:(\\d+)\\$)?([-#+ 0,(<]*)(\\d+)?(?:\\.(\\d+))?([tT])?([a-zA-Z%])")

    private fun conversions(pattern: String): Map<Int, List<Char>>? {
        val result = linkedMapOf<Int, MutableList<Char>>()
        var cursor = 0
        var ordinary = 0
        var previous = -1
        while (true) {
            val percent = pattern.indexOf('%', cursor)
            if (percent < 0) break
            val match = token.find(pattern, percent) ?: return null
            if (match.range.first != percent) return null
            cursor = match.range.last + 1
            val conversion = match.groupValues[6].single()
            val date = match.groupValues[5].isNotEmpty()
            if (date) {
                if (conversion !in "HIklMSLNpzZsQBbhAaCYyjmdeRTrDFc") return null
            } else if (conversion !in "bBhHsScCdoxXeEfgGaA%n") return null
            if (!date && conversion in "%n") continue
            val explicit = match.groupValues[1]
            val reuse = '<' in match.groupValues[2]
            if (explicit.isNotEmpty() && reuse) return null
            val index = when {
                reuse -> previous
                explicit.isNotEmpty() -> (explicit.toIntOrNull() ?: return null) - 1
                else -> ordinary++
            }
            if (index < 0) return null
            previous = index
            result.getOrPut(index) { arrayListOf() }.add(if (date) 't' else conversion)
        }
        return result
    }
}
