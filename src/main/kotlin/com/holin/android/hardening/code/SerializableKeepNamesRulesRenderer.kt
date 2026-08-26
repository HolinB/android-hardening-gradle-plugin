package com.holin.android.hardening.code

class SerializableKeepNamesRulesRenderer {
    fun render(plan: CodeNamePlan): String {
        val classes = plan.exclusions.asSequence()
            .filter { exclusion ->
                exclusion.reason == CodeExclusionReason.SERIALIZABLE && exclusion.key.kind == CodeSymbolKind.CLASS
            }
            .onEach { exclusion ->
                validateCodeSymbolKey(exclusion.key)
                require(exclusion.key.owner in plan.ownedOriginalOwners) {
                    "Serializable exclusion belongs to a non-owned class: ${exclusion.key.owner}"
                }
            }
            .map(CodeExclusion::key)
            .distinctBy(CodeSymbolKey::owner)
            .sortedBy(CodeSymbolKey::owner)
            .toList()
        return classes.joinToString(separator = "\n", postfix = if (classes.isEmpty()) "" else "\n") { key ->
            "-keepnames class ${key.owner.replace('/', '.')}"
        }
    }
}
