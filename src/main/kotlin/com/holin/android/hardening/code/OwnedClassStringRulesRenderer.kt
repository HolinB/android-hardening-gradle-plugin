package com.holin.android.hardening.code

class OwnedClassStringRulesRenderer {
    fun render(originalDescriptors: Collection<String>): String {
        val internalNames = originalDescriptors.asSequence()
            .map { descriptor ->
                require(descriptor.startsWith('L') && descriptor.endsWith(';')) {
                    "owned class string descriptor is malformed: $descriptor"
                }
                descriptor.substring(1, descriptor.lastIndex).also { internalName ->
                    require(JvmClassName.isInternal(internalName)) {
                        "owned class string descriptor is malformed: $descriptor"
                    }
                }
            }
            .distinct()
            .sorted()
            .toList()
        return internalNames.joinToString("\n", "", if (internalNames.isEmpty()) "" else "\n") { internalName ->
            val className = internalName.replace('/', '.')
            "-adaptclassstrings $className,$className${'$'}*"
        }
    }
}
