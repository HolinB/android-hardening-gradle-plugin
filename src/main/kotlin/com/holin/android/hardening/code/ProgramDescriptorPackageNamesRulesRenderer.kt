package com.holin.android.hardening.code

class ProgramDescriptorPackageNamesRulesRenderer {
    fun render(plan: CodeNamePlan, programClasses: Set<String>): String {
        programClasses.forEach { internalName ->
            require(JvmClassName.isInternal(internalName)) { "invalid program class: $internalName" }
        }
        val descriptorClasses = programClasses - plan.ownedOriginalOwners
        val classes = plan.assignments.asSequence()
            .flatMap { assignment ->
                when (assignment.key.kind) {
                    CodeSymbolKind.CLASS -> emptySequence()
                    CodeSymbolKind.FIELD -> ExactJvmDescriptor.referencedInternalNamesInField(assignment.key.descriptor).asSequence()
                    CodeSymbolKind.METHOD -> ExactJvmDescriptor.referencedInternalNamesInMethod(assignment.key.descriptor).asSequence()
                }
            }
            .filter(descriptorClasses::contains)
            .distinct()
            .sorted()
            .toList()
        return classes.joinToString(separator = "\n", postfix = if (classes.isEmpty()) "" else "\n") { internalName ->
            "-keeppackagenames ${internalName.replace('/', '.')}"
        }
    }
}
