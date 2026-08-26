package com.holin.android.hardening.dex

import com.android.tools.smali.dexlib2.AccessFlags
import com.android.tools.smali.dexlib2.Opcode
import com.android.tools.smali.dexlib2.dexbacked.DexBackedDexFile
import com.android.tools.smali.dexlib2.iface.ClassDef
import com.android.tools.smali.dexlib2.iface.Method
import com.android.tools.smali.dexlib2.iface.instruction.ReferenceInstruction
import com.android.tools.smali.dexlib2.iface.reference.MethodReference

object DexClassAccessCompatibility {
    internal fun isInvokeInstruction(opcode: Opcode): Boolean = opcode.name.startsWith("invoke-")

    fun requiredPublicClassDescriptors(
        dexFiles: Collection<ByteArray>,
        ownedDescriptors: Set<String>,
    ): Set<String> {
        require(dexFiles.isNotEmpty()) { "DEX access compatibility input must not be empty" }
        val classes = dexFiles.flatMap { bytes ->
            DexBackedDexFile.fromInputStream(null, bytes.inputStream()).classes
        }
        val duplicateTypes = classes.groupBy(ClassDef::getType).filterValues { it.size > 1 }.keys
        require(duplicateTypes.isEmpty()) {
            "DEX access compatibility input contains duplicate classes: ${duplicateTypes.sorted()}"
        }
        val classesByType = classes.associateBy(ClassDef::getType)

        return classes.asSequence()
            .flatMap { caller -> caller.methods.asSequence().flatMap { method -> referencedMethods(caller, method) } }
            .mapNotNull { call ->
                val targetClass = classesByType[call.reference.definingClass] ?: return@mapNotNull null
                if (targetClass.type !in ownedDescriptors || !isPackagePrivate(targetClass.accessFlags)) {
                    return@mapNotNull null
                }
                if (packageName(call.caller.type) == packageName(targetClass.type)) return@mapNotNull null
                val targetMethod = targetClass.methods.singleOrNull { method -> method.matches(call.reference) }
                    ?: return@mapNotNull null
                targetClass.type.takeIf { targetMethod.isPublicStaticSyntheticBridge() }
            }
            .toSortedSet()
    }

    private fun referencedMethods(caller: ClassDef, method: Method): Sequence<ObservedMethodCall> =
        (method.implementation?.instructions?.asSequence() ?: emptySequence()).mapNotNull { instruction ->
            if (!isInvokeInstruction(instruction.opcode)) return@mapNotNull null
            val reference = (instruction as? ReferenceInstruction)?.reference as? MethodReference
                ?: return@mapNotNull null
            ObservedMethodCall(caller, reference)
        }

    private fun Method.matches(reference: MethodReference): Boolean =
        name == reference.name && parameterTypes == reference.parameterTypes && returnType == reference.returnType

    private fun Method.isPublicStaticSyntheticBridge(): Boolean =
        AccessFlags.PUBLIC.isSet(accessFlags) &&
            AccessFlags.STATIC.isSet(accessFlags) &&
            AccessFlags.SYNTHETIC.isSet(accessFlags)

    private fun isPackagePrivate(accessFlags: Int): Boolean =
        !AccessFlags.PUBLIC.isSet(accessFlags) &&
            !AccessFlags.PRIVATE.isSet(accessFlags) &&
            !AccessFlags.PROTECTED.isSet(accessFlags)

    private fun packageName(descriptor: String): String = descriptor.substringBeforeLast('/', "")

    private data class ObservedMethodCall(val caller: ClassDef, val reference: MethodReference)
}
