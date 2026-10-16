package com.holin.android.hardening.runtime

import org.objectweb.asm.ClassReader
import org.objectweb.asm.ClassWriter
import org.objectweb.asm.Opcodes
import org.objectweb.asm.tree.ClassNode
import org.objectweb.asm.tree.InsnList
import org.objectweb.asm.tree.InsnNode
import org.objectweb.asm.tree.MethodInsnNode
import org.objectweb.asm.tree.MethodNode
import org.objectweb.asm.tree.VarInsnNode

/** Installs the cache context before Application.onCreate and provider initialization. */
object RuntimeApplicationBootstrap {
    fun install(bytes: ByteArray, helper: String): ByteArray {
        val node = ClassNode().also { ClassReader(bytes).accept(it, 0) }
        val descriptor = "(Landroid/content/Context;)V"
        val existing = node.methods.singleOrNull { it.name == "attachBaseContext" && it.desc == descriptor }
        val method = existing ?: MethodNode(Opcodes.ACC_PROTECTED, "attachBaseContext", descriptor, null, null).also {
            it.instructions.add(VarInsnNode(Opcodes.ALOAD, 0))
            it.instructions.add(VarInsnNode(Opcodes.ALOAD, 1))
            it.instructions.add(MethodInsnNode(Opcodes.INVOKESPECIAL, node.superName, "attachBaseContext", descriptor, false))
            it.instructions.add(InsnNode(Opcodes.RETURN))
            it.maxLocals = 2
            it.maxStack = 2
            node.methods.add(it)
        }
        require(method.access and (Opcodes.ACC_NATIVE or Opcodes.ACC_ABSTRACT or Opcodes.ACC_STATIC) == 0) {
            "Application.attachBaseContext cannot install runtime asset compatibility"
        }
        // The provided base context already has its package/cache directory. Installing
        // before the original body also covers asset reads in a custom attach method.
        val instructions = InsnList().apply {
            add(VarInsnNode(Opcodes.ALOAD, 1))
            add(MethodInsnNode(Opcodes.INVOKESTATIC, helper, "install", descriptor, false))
        }
        val inserted = instructions.toArray()
        val previousStack = method.maxStack
        method.instructions.insert(instructions)
        method.maxStack = maxOf(method.maxStack, 1)
        val result = ClassWriter(0).also(node::accept).toByteArray()
        inserted.forEach(method.instructions::remove)
        method.maxStack = previousStack
        if (existing == null) node.methods.remove(method)
        val restored = ClassWriter(0).also(node::accept).toByteArray()
        val normalized = ClassWriter(0).also { ClassReader(bytes).accept(it, 0) }.toByteArray()
        require(restored.contentEquals(normalized)) { "runtime Application bootstrap inverse proof failed" }
        return result
    }
}
