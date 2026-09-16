package com.holin.android.hardening.dex

import com.android.tools.smali.dexlib2.Opcode
import com.android.tools.smali.dexlib2.builder.MutableMethodImplementation
import com.android.tools.smali.dexlib2.builder.instruction.BuilderInstruction30t
import com.android.tools.smali.dexlib2.iface.MethodImplementation
import com.android.tools.smali.dexlib2.iface.instruction.Instruction
import com.android.tools.smali.dexlib2.iface.instruction.OffsetInstruction
import com.android.tools.smali.dexlib2.iface.instruction.PayloadInstruction
import com.android.tools.smali.dexlib2.immutable.ImmutableMethodImplementation
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.charset.StandardCharsets
import java.security.MessageDigest

internal const val MAX_REACHABLE_RELAY_PAIRS_PER_METHOD = 256

internal class ReachableRelaySplitter {
    fun split(
        implementation: MethodImplementation,
        salt: ByteArray,
        methodId: String,
        maximumPairs: Int = MAX_REACHABLE_RELAY_PAIRS_PER_METHOD,
    ): ReachableRelaySplit? {
        require(maximumPairs in 0..MAX_REACHABLE_RELAY_PAIRS_PER_METHOD) {
            "reachable relay pair limit is outside the DEX-safety cap"
        }
        val unchanged = requireNotNull(ImmutableMethodImplementation.of(implementation))
        val instructions = unchanged.instructions.toList()
        val originalEndAddress = instructions.sumOf(Instruction::getCodeUnits)
        if (
            instructions.size < 2 ||
            implementation.tryBlocks.any() ||
            instructions.any(::isSwitchOrPayload) ||
            implementation.debugItems.any { it.codeAddress >= originalEndAddress } ||
            !isTerminal(instructions.last())
        ) {
            return ReachableRelaySplit(unchanged, 0)
        }

        if (maximumPairs == 0) return ReachableRelaySplit(unchanged, 0)
        val safeBoundaries = safeBoundaries(instructions)
        if (safeBoundaries.isEmpty()) return ReachableRelaySplit(unchanged, 0)
        val boundaries = chooseBoundaries(instructions.size, safeBoundaries, salt, methodId, maximumPairs)
        if (boundaries.isEmpty()) return ReachableRelaySplit(unchanged, 0)

        val mutable = MutableMethodImplementation(unchanged)
        val continuations = boundaries.associateWith(mutable::newLabelForIndex)
        val physicalOrder = boundaries.sortedWith(
            compareBy<Int> { boundary -> saltedKey(salt, methodId, boundary, RELAY_ORDER_SUFFIX) }
                .thenBy { it },
        )
        val relays = physicalOrder.associateWith { boundary ->
            val relay = mutable.newLabelForIndex(mutable.instructions.size)
            mutable.addInstruction(
                mutable.instructions.size,
                BuilderInstruction30t(Opcode.GOTO_32, continuations.getValue(boundary)),
            )
            relay
        }
        boundaries.sortedDescending().forEach { boundary ->
            mutable.addInstruction(boundary, BuilderInstruction30t(Opcode.GOTO_32, relays.getValue(boundary)))
        }

        val split = requireNotNull(ImmutableMethodImplementation.of(mutable))
        val sourceIndexes = boundaries.mapTo(hashSetOf()) { boundary ->
            boundary + boundaries.count { it < boundary }
        }
        val firstRelayIndex = instructions.size + boundaries.size
        val relayIndexes = (firstRelayIndex until firstRelayIndex + boundaries.size).toSet()
        val retainedOpcodes = split.instructions.mapIndexedNotNull { index, instruction ->
            instruction.opcode.takeIf { index !in sourceIndexes && index !in relayIndexes }
        }
        return if (retainedOpcodes == instructions.map(Instruction::getOpcode)) {
            ReachableRelaySplit(split, boundaries.size)
        } else {
            null
        }
    }

    private fun safeBoundaries(instructions: List<Instruction>): Set<Int> {
        val addresses = IntArray(instructions.size)
        var address = 0
        instructions.forEachIndexed { index, instruction ->
            addresses[index] = address
            address += instruction.codeUnits
        }
        val targetedAddresses = instructions.mapIndexedNotNullTo(hashSetOf()) { index, instruction ->
            (instruction as? OffsetInstruction)?.let { addresses[index] + it.codeOffset }
        }
        val instructionIndexByAddress = addresses.withIndex().associate { it.value to it.index }
        val reachableIndexes = reachableInstructionIndexes(instructions, addresses, instructionIndexByAddress)
        return (1 until instructions.size).filterTo(linkedSetOf()) { boundary ->
            val previousIndex = (boundary - 1 downTo 0).firstOrNull { index ->
                instructions[index].opcode != Opcode.NOP
            } ?: return@filterTo false
            val previous = instructions[previousIndex]
            val next = instructions[boundary]
            previousIndex in reachableIndexes &&
                previous !is OffsetInstruction &&
                previous !is PayloadInstruction &&
                !isTerminal(previous) &&
                (previousIndex + 1..boundary).none { addresses[it] in targetedAddresses } &&
                next.opcode != Opcode.NOP &&
                next.opcode != Opcode.MOVE_EXCEPTION &&
                !(next.opcode in MOVE_RESULT_OPCODES && previous.opcode.setsResult())
        }
    }

    private fun reachableInstructionIndexes(
        instructions: List<Instruction>,
        addresses: IntArray,
        instructionIndexByAddress: Map<Int, Int>,
    ): Set<Int> {
        val reachable = linkedSetOf<Int>()
        val pending = ArrayDeque<Int>()
        pending += 0
        while (pending.isNotEmpty()) {
            val index = pending.removeFirst()
            if (index !in instructions.indices || !reachable.add(index)) continue
            val instruction = instructions[index]
            val branchTarget = (instruction as? OffsetInstruction)?.let { offset ->
                instructionIndexByAddress[addresses[index] + offset.codeOffset]
            }
            when {
                instruction.opcode in GOTO_OPCODES -> branchTarget?.let(pending::addLast)
                instruction.opcode.name.startsWith("IF_") -> {
                    branchTarget?.let(pending::addLast)
                    if (index + 1 < instructions.size) pending += index + 1
                }
                isTerminal(instruction) -> Unit
                index + 1 < instructions.size -> pending += index + 1
            }
        }
        return reachable
    }

    private fun chooseBoundaries(
        instructionCount: Int,
        safeBoundaries: Set<Int>,
        salt: ByteArray,
        methodId: String,
        maximumPairs: Int,
    ): Set<Int> {
        if (instructionCount < SHINGLE_WIDTH) {
            val candidates = safeBoundaries.sorted()
            return candidates.getOrNull(saltedIndex(salt, methodId, instructionCount, candidates.size))
                ?.let(::setOf)
                .orEmpty()
        }
        val selected = linkedSetOf<Int>()
        for (windowStart in 0..instructionCount - SHINGLE_WIDTH) {
            if (selected.size == maximumPairs) break
            val windowBoundaries = (windowStart + 1)..(windowStart + SHINGLE_WIDTH - 1)
            if (windowBoundaries.any(selected::contains)) continue
            val candidates = windowBoundaries.filter(safeBoundaries::contains)
            if (candidates.isEmpty()) continue
            selected += candidates[saltedIndex(salt, methodId, windowStart, candidates.size)]
        }
        return selected
    }

    private fun saltedIndex(
        salt: ByteArray,
        methodId: String,
        logicalBoundary: Int,
        size: Int,
    ): Int {
        if (size <= 1) return 0
        val digest = saltedDigest(salt, methodId, logicalBoundary, BOUNDARY_SUFFIX)
        val value = ByteBuffer.wrap(digest, 0, Int.SIZE_BYTES).order(ByteOrder.BIG_ENDIAN).int and Int.MAX_VALUE
        return value % size
    }

    private fun saltedKey(
        salt: ByteArray,
        methodId: String,
        logicalBoundary: Int,
        suffix: String,
    ): String = saltedDigest(salt, methodId, logicalBoundary, suffix)
        .joinToString("") { byte -> "%02x".format(byte.toInt() and 0xff) }

    private fun saltedDigest(
        salt: ByteArray,
        methodId: String,
        logicalBoundary: Int,
        suffix: String,
    ): ByteArray = MessageDigest.getInstance("SHA-256").apply {
        update(DOMAIN)
        updateInt(salt.size)
        update(salt)
        val method = methodId.toByteArray(StandardCharsets.UTF_8)
        updateInt(method.size)
        update(method)
        updateInt(logicalBoundary)
        update(suffix.toByteArray(StandardCharsets.UTF_8))
    }.digest()

    private fun MessageDigest.updateInt(value: Int) {
        update(ByteBuffer.allocate(Int.SIZE_BYTES).order(ByteOrder.BIG_ENDIAN).putInt(value).array())
    }

    private fun isTerminal(instruction: Instruction): Boolean = instruction.opcode in TERMINAL_OPCODES

    private fun isSwitchOrPayload(instruction: Instruction): Boolean =
        instruction is PayloadInstruction ||
            instruction.opcode == Opcode.PACKED_SWITCH ||
            instruction.opcode == Opcode.SPARSE_SWITCH ||
            instruction.opcode == Opcode.FILL_ARRAY_DATA

    private companion object {
        const val SHINGLE_WIDTH = 5
        const val BOUNDARY_SUFFIX = "\u0000boundary"
        const val RELAY_ORDER_SUFFIX = "\u0000relay-order"
        val DOMAIN = "com.holin.android.hardening/1.3.0/reachable-relay/v1\u0000".toByteArray(StandardCharsets.UTF_8)
        val MOVE_RESULT_OPCODES = setOf(
            Opcode.MOVE_RESULT,
            Opcode.MOVE_RESULT_WIDE,
            Opcode.MOVE_RESULT_OBJECT,
        )
        val TERMINAL_OPCODES = setOf(
            Opcode.GOTO,
            Opcode.GOTO_16,
            Opcode.GOTO_32,
            Opcode.RETURN_VOID,
            Opcode.RETURN,
            Opcode.RETURN_WIDE,
            Opcode.RETURN_OBJECT,
            Opcode.THROW,
        )
        val GOTO_OPCODES = setOf(Opcode.GOTO, Opcode.GOTO_16, Opcode.GOTO_32)
    }
}

internal data class ReachableRelaySplit(
    val implementation: ImmutableMethodImplementation,
    val pairCount: Int,
)
