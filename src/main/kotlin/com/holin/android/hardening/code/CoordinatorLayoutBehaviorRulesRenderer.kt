package com.holin.android.hardening.code

class CoordinatorLayoutBehaviorRulesRenderer {
    fun render(plan: CodeNamePlan): String {
        val classes = plan.exclusions.asSequence()
            .filter { exclusion ->
                exclusion.reason == CodeExclusionReason.COORDINATOR_LAYOUT_BEHAVIOR_KEEP_RULE &&
                    exclusion.key.kind == CodeSymbolKind.CLASS
            }
            .onEach { exclusion ->
                validateCodeSymbolKey(exclusion.key)
                require(exclusion.key.owner in plan.ownedOriginalOwners) {
                    "CoordinatorLayout Behavior exclusion belongs to a non-owned class: ${exclusion.key.owner}"
                }
            }
            .map { exclusion -> exclusion.key.owner }
            .distinct()
            .sorted()
            .toList()
        return classes.joinToString(separator = "\n", postfix = if (classes.isEmpty()) "" else "\n") { owner ->
            """
            -keep,allowoptimization public class ${owner.replace('/', '.')} {
                public <init>(android.content.Context, android.util.AttributeSet);
            }
            """.trimIndent()
        }
    }
}
