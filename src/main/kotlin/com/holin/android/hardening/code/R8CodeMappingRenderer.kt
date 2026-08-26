package com.holin.android.hardening.code

class R8CodeMappingRenderer {
    fun render(plan: CodeNamePlan): String {
        require(plan.assignments.all { it.key.owner in plan.ownedOriginalOwners }) {
            "R8 code mapping contains a non-owned assignment"
        }
        plan.assignments.forEach(::validateAssignedCodeName)
        return buildString {
        plan.assignments.groupBy { it.key.owner }.toSortedMap().forEach { (owner, assignments) ->
            val classAssignment = assignments.filter { it.key.kind == CodeSymbolKind.CLASS }.singleOrNull()
            val outputOwners = assignments.mapTo(sortedSetOf(), AssignedCodeName::outputOwner)
            require(outputOwners.size == 1) { "code mappings disagree on output owner for $owner" }
            val outputOwner = classAssignment?.outputOwner ?: outputOwners.single()
            require(classAssignment == null || classAssignment.key.descriptor == "L$owner;") {
                "class mapping descriptor does not match its owner: ${classAssignment?.key}"
            }
            append(owner.replace('/', '.'))
                .append(" -> ")
                .append(outputOwner.replace('/', '.'))
                .append(":\n")
            assignments.filter { it.key.kind != CodeSymbolKind.CLASS }
                .sortedBy { it.key.canonicalIdentity }
                .forEach { member ->
                    require(member.key.name !in SPECIAL_METHODS) { "constructors cannot be rendered in an exact R8 mapping" }
                    require(MEMBER_ALIAS.matches(member.alias)) { "invalid member alias: ${member.alias}" }
                    append("    ").append(renderMember(member)).append('\n')
                }
        }
        }
    }

    private fun renderMember(assignment: AssignedCodeName): String = when (assignment.key.kind) {
        CodeSymbolKind.FIELD -> {
            val type = ExactJvmDescriptor.fieldType(assignment.key.descriptor)
            "$type ${assignment.key.name} -> ${assignment.alias}"
        }
        CodeSymbolKind.METHOD -> {
            val type = ExactJvmDescriptor.methodType(assignment.key.descriptor)
            "${type.returnType} ${assignment.key.name}(${type.parameterTypes.joinToString(",")}) -> ${assignment.alias}"
        }
        CodeSymbolKind.CLASS -> error("class mapping is not a member")
    }

    private companion object {
        val MEMBER_ALIAS = Regex("[a-z][A-Za-z0-9]*")
        val SPECIAL_METHODS = setOf("<init>", "<clinit>")
    }
}
