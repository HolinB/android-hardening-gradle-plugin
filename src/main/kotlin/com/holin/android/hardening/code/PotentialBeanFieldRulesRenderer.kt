package com.holin.android.hardening.code

class PotentialBeanFieldRulesRenderer {
    fun render(
        fields: Collection<PotentialBeanField>,
        ownedOriginalOwners: Set<String>,
    ): String {
        require(fields.map(PotentialBeanField::key).distinct().size == fields.size) {
            "potential Bean field rules contain duplicate symbol keys"
        }
        fields.forEach { field ->
            validatePotentialBeanField(field)
            require(field.key.owner in ownedOriginalOwners) {
                "potential Bean field rules contain a non-owned owner: ${field.key.owner}"
            }
        }
        if (fields.isEmpty()) return ""
        return buildString {
            append("-keepattributes RuntimeVisibleAnnotations,RuntimeInvisibleAnnotations,AnnotationDefault\n")
            fields.groupBy { field -> field.key.owner }.toSortedMap().forEach { (owner, ownerFields) ->
                append("-keep,allowoptimization,allowobfuscation class ")
                    .append(owner.replace('/', '.')).append('\n')
                append("-keepclassmembers class ")
                    .append(owner.replace('/', '.')).append(" {\n")
                ownerFields.sortedWith(compareBy({ it.key.name }, { it.key.descriptor })).forEach { field ->
                    append("    ").append(ExactJvmDescriptor.fieldType(field.key.descriptor))
                        .append(' ').append(field.key.name).append(";\n")
                }
                append("}\n")
            }
        }
    }
}
