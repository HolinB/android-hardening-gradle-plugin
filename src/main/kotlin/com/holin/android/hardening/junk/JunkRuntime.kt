package com.holin.android.hardening.junk

import org.objectweb.asm.ClassReader
import org.objectweb.asm.ClassWriter
import org.objectweb.asm.Label
import org.objectweb.asm.Opcodes.*
import org.objectweb.asm.tree.ClassNode
import org.objectweb.asm.tree.MethodInsnNode

internal data class JunkMethod(val owner: String, val name: String) {
    fun toMap(): Map<String, String> = linkedMapOf("owner" to owner, "name" to name)
}

internal data class JunkCallGroup(val name: String, val targets: List<JunkMethod>)

/** A bounded, acyclic call tree. Infrastructure is separate from configured payload counts. */
internal data class JunkRuntime(val entryClass: String, val groups: List<JunkCallGroup>) {
    fun toMap(): Map<String, Any> = linkedMapOf(
        "entryClass" to entryClass,
        "entryMethod" to "run",
        "groups" to groups.map { linkedMapOf("name" to it.name, "targets" to it.targets.map(JunkMethod::toMap)) },
    )

    fun validate(classes: List<JunkClass>) {
        val payload = classes.flatMap { item -> item.methods.map { JunkMethod(item.name, it) } }.toSet()
        val support = groups.map { it.name }.toSet()
        require(groups.isNotEmpty() && support.size == groups.size && groups.last().name == entryClass &&
            support.intersect(classes.map { it.name }.toSet()).isEmpty()) { "invalid junkCode runtime classes" }
        val available = payload.toMutableSet()
        val consumed = mutableSetOf<JunkMethod>()
        groups.forEach { group ->
            require(group.targets.isNotEmpty() && group.targets.size <= MAX_TARGETS) { "invalid junkCode call group size" }
            group.targets.forEach { target ->
                require(target in available && consumed.add(target)) { "invalid, repeated or cyclic junkCode call target" }
            }
            available.add(JunkMethod(group.name, "compute"))
        }
        require(consumed == available - JunkMethod(entryClass, "compute")) { "junkCode runtime does not cover every generated method" }
    }

    companion object {
        const val MAX_TARGETS = 2048

        fun create(classes: List<JunkClass>, name: (String) -> String): JunkRuntime? {
            var targets = classes.flatMap { item -> item.methods.map { JunkMethod(item.name, it) } }
            if (targets.isEmpty()) return null
            val groups = mutableListOf<JunkCallGroup>()
            var level = 0
            while (targets.size > MAX_TARGETS) {
                targets = targets.chunked(MAX_TARGETS).mapIndexed { index, batch ->
                    val group = JunkCallGroup(name("batch/$level/$index"), batch)
                    groups.add(group)
                    JunkMethod(group.name, "compute")
                }
                level++
            }
            val entry = name("entry")
            groups.add(JunkCallGroup(entry, targets))
            return JunkRuntime(entry, groups).also { it.validate(classes) }
        }

        fun decode(data: Map<*, *>): JunkRuntime {
            require(data["entryMethod"] == "run") { "unsupported junkCode runtime entry" }
            return JunkRuntime(data["entryClass"] as String, (data["groups"] as List<*>).map { value ->
                val group = value as Map<*, *>
                JunkCallGroup(group["name"] as String, (group["targets"] as List<*>).map { target ->
                    val method = target as Map<*, *>
                    JunkMethod(method["owner"] as String, method["name"] as String)
                })
            })
        }
    }
}

internal object JunkRuntimeBytecode {
    fun generate(runtime: JunkRuntime, group: JunkCallGroup, initialValue: Int): ByteArray {
        val owner = group.name.replace('.', '/')
        val entry = group.name == runtime.entryClass
        val parent = if (entry) "android/app/Application" else "java/lang/Object"
        val writer = ClassWriter(ClassWriter.COMPUTE_FRAMES or ClassWriter.COMPUTE_MAXS)
        writer.visit(V1_8, ACC_PUBLIC or ACC_FINAL or ACC_SUPER, owner, null, parent, null)
        writer.visitMethod(ACC_PUBLIC, "<init>", "()V", null, null).apply {
            visitCode(); visitVarInsn(ALOAD, 0); visitMethodInsn(INVOKESPECIAL, parent, "<init>", "()V", false)
            if (entry) visitMethodInsn(INVOKESTATIC, owner, "run", "()V", false)
            visitInsn(RETURN); visitMaxs(0, 0); visitEnd()
        }
        writer.visitMethod(ACC_PUBLIC or ACC_STATIC, "compute", "(I)I", null, null).apply {
            visitCode(); visitVarInsn(ILOAD, 0)
            group.targets.forEach { visitMethodInsn(INVOKESTATIC, it.owner.replace('.', '/'), it.name, "(I)I", false) }
            visitInsn(IRETURN); visitMaxs(0, 0); visitEnd()
        }
        if (entry) {
            writer.visitField(ACC_PRIVATE or ACC_STATIC or ACC_VOLATILE, "executed", "Z", null, null).visitEnd()
            writer.visitField(ACC_PRIVATE or ACC_STATIC or ACC_VOLATILE, "result", "I", null, null).visitEnd()
            writer.visitMethod(ACC_PUBLIC or ACC_STATIC or ACC_SYNCHRONIZED, "run", "()V", null, null).apply {
                visitCode()
                val done = Label()
                visitFieldInsn(GETSTATIC, owner, "executed", "Z"); visitJumpInsn(IFNE, done)
                visitLdcInsn(initialValue); visitMethodInsn(INVOKESTATIC, owner, "compute", "(I)I", false)
                visitFieldInsn(PUTSTATIC, owner, "result", "I")
                visitInsn(ICONST_1); visitFieldInsn(PUTSTATIC, owner, "executed", "Z")
                visitLabel(done); visitInsn(RETURN); visitMaxs(0, 0); visitEnd()
            }
        }
        writer.visitEnd()
        return writer.toByteArray()
    }
}

internal data class JunkApplicationInjection(val bytes: ByteArray, val calls: Int)

/** Insert a stack-neutral call only after a constructor completes successfully. */
internal object JunkApplicationBootstrap {
    fun install(bytes: ByteArray, entryClass: String): JunkApplicationInjection {
        val node = ClassNode().also { ClassReader(bytes).accept(it, 0) }
        require(node.access and (ACC_INTERFACE or ACC_ABSTRACT) == 0) { "junkCode requires a concrete Application class" }
        val owner = entryClass.replace('.', '/')
        val inserted = node.methods.filter { it.name == "<init>" }.flatMap { method ->
            require(method.instructions.toArray().none { it is MethodInsnNode && it.owner == owner && it.name == "run" }) {
                "junkCode Application call is already present"
            }
            method.instructions.toArray().filter { it.opcode == RETURN }.map { instruction ->
                val call = MethodInsnNode(INVOKESTATIC, owner, "run", "()V", false)
                method.instructions.insertBefore(instruction, call)
                method to call
            }
        }
        require(inserted.isNotEmpty()) { "junkCode Application has no successful constructor return" }
        val result = ClassWriter(0).also(node::accept).toByteArray()
        inserted.forEach { (method, call) -> method.instructions.remove(call) }
        val restored = ClassWriter(0).also(node::accept).toByteArray()
        val normalized = ClassWriter(0).also { ClassReader(bytes).accept(it, 0) }.toByteArray()
        require(restored.contentEquals(normalized)) { "junkCode Application constructor inverse proof failed" }
        return JunkApplicationInjection(result, inserted.size)
    }
}
