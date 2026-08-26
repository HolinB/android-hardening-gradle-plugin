package com.holin.android.hardening.code

import org.objectweb.asm.Opcodes

const val POTENTIAL_BEAN_FIELD_POLICY_VERSION: Int = 1

data class PotentialBeanField(
    val modulePath: String,
    val key: CodeSymbolKey,
    val access: Int,
) {
    init {
        require(modulePath.isNotBlank() && modulePath.startsWith(':')) {
            "potential Bean field has an invalid module path: $modulePath"
        }
        require(key.kind == CodeSymbolKind.FIELD) { "potential Bean contract must identify a field" }
    }
}

class PotentialBeanFieldPolicy {
    fun inventory(bytecode: BytecodeInventory): List<PotentialBeanField> =
        bytecode.ownedClasses.values.asSequence()
            .filter { owner -> owner.modulePath != null }
            .flatMap { owner ->
                owner.fields.asSequence()
                    .filter(::isPotentialBeanField)
                    .map { field -> PotentialBeanField(requireNotNull(owner.modulePath), fieldKey(field), field.access) }
            }
            .sortedWith(compareBy({ it.modulePath }, { it.key.canonicalIdentity }))
            .toList()

    fun exclusions(fields: Collection<PotentialBeanField>): List<CodeExclusion> = fields.map { field ->
        CodeExclusion(
            field.key,
            CodeExclusionReason.POTENTIAL_BEAN_INSTANCE_FIELD,
            "owned instance field JSON and persisted-name contract (${field.modulePath}, access=${field.access})",
        )
    }

    private fun isPotentialBeanField(field: BytecodeField): Boolean =
        field.access and (Opcodes.ACC_STATIC or Opcodes.ACC_TRANSIENT or Opcodes.ACC_SYNTHETIC) == 0
}
