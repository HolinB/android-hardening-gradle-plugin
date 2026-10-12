package com.holin.android.hardening.code

/** Keeps owned lifecycle models reachable through generic signatures and framework factories. */
class ViewModelFactoryRulesRenderer {
    fun render(inventory: BytecodeInventory): String {
        val models = inventory.ownedClasses.values.filter { owner ->
            val visited = mutableSetOf<String>()
            var parent = owner.superName
            while (parent != null && visited.add(parent)) {
                if (parent == VIEW_MODEL || parent == ANDROID_VIEW_MODEL) return@filter true
                parent = inventory.hierarchyClasses[parent]?.superName
            }
            false
        }.sortedBy(BytecodeClass::internalName)
        if (models.isEmpty()) return ""
        return buildString {
            append("# Exact owned ViewModel factory contracts; generic-only types must not become Object.\n")
            append("-keepattributes Signature\n")
            models.forEach { owner ->
                // Do not allow shrinking or class merging: either invalidates reflective type identity.
                append("-keep,allowobfuscation class ")
                    .append(owner.internalName.replace('/', '.')).append(" {\n")
                owner.methods.filter { it.name == "<init>" }.sortedBy(BytecodeMethod::descriptor).forEach { method ->
                    val parameters = org.objectweb.asm.Type.getArgumentTypes(method.descriptor)
                        .joinToString(", ") { it.className }
                    append("    <init>(").append(parameters).append(");\n")
                }
                append("}\n")
            }
        }
    }

    private companion object {
        const val VIEW_MODEL = "androidx/lifecycle/ViewModel"
        const val ANDROID_VIEW_MODEL = "androidx/lifecycle/AndroidViewModel"
    }
}
