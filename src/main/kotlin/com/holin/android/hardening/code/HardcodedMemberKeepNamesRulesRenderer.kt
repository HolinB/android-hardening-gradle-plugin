package com.holin.android.hardening.code

class HardcodedMemberKeepNamesRulesRenderer {
    fun render(plan: CodeNamePlan): String {
        val members = plan.exclusions.asSequence()
            .filter { it.reason == CodeExclusionReason.HARDCODED_MEMBER_NAME }
            .onEach { exclusion ->
                validateCodeSymbolKey(exclusion.key)
                require(exclusion.key.kind != CodeSymbolKind.CLASS) {
                    "hardcoded member exclusion cannot target a class: ${exclusion.key.canonicalIdentity}"
                }
                require(exclusion.key.owner in plan.ownedOriginalOwners) {
                    "hardcoded member exclusion belongs to a non-owned class: ${exclusion.key.owner}"
                }
            }
            .map(CodeExclusion::key)
            .distinct()
            .sortedBy(CodeSymbolKey::canonicalIdentity)
            .toList()
        if (members.isEmpty()) return ""
        return buildString {
            members.groupBy(CodeSymbolKey::owner).toSortedMap().forEach { (owner, ownedMembers) ->
                append("-keepclassmembers,allowoptimization class ")
                    .append(owner.replace('/', '.'))
                    .append(" {\n")
                ownedMembers.forEach { member ->
                    append("    ").append(renderMember(member)).append(";\n")
                }
                append("}\n")
            }
        }
    }

    private fun renderMember(key: CodeSymbolKey): String = when (key.kind) {
        CodeSymbolKind.FIELD -> "${ExactJvmDescriptor.fieldType(key.descriptor)} ${key.name}"
        CodeSymbolKind.METHOD -> ExactJvmDescriptor.methodType(key.descriptor).let { method ->
            "${method.returnType} ${key.name}(${method.parameterTypes.joinToString(",")})"
        }
        CodeSymbolKind.CLASS -> error("hardcoded member rule cannot render a class")
    }
}
