package com.holin.android.hardening.similarity

import java.io.BufferedReader
import java.io.StringReader

data class BaselineOwnedDescriptorAlignment(
    val baselineDescriptors: Set<String>,
    val currentDescriptors: Set<String>,
    val commonOriginalDescriptorCount: Int,
    val currentOnlyOrMixedOriginalDescriptorCount: Int,
)

class BaselineOwnedDescriptorAligner {
    fun align(
        baselineMappingText: String,
        currentMappingText: String,
        currentOwnedDescriptors: Set<String>,
    ): BaselineOwnedDescriptorAlignment {
        require(currentOwnedDescriptors.isNotEmpty()) { "current owned descriptors must not be empty" }
        val baseline = parseClassMappings(baselineMappingText)
        val current = parseClassMappings(currentMappingText)
        val currentOriginalsByOutput = current.originalsByOutputDescriptor
        val currentOwnedOriginalsByOutput = currentOwnedDescriptors.associateWith { output ->
            requireNotNull(currentOriginalsByOutput[output]) {
                "current owned descriptor is missing from the current R8 mapping: $output"
            }
        }
        val currentOwnedOriginals = currentOwnedOriginalsByOutput.values.flatten().toSet()
        val alignedOriginals = currentOwnedOriginals
            .filterTo(linkedSetOf()) { it in baseline.outputByOriginalDescriptor }
        var changed: Boolean
        do {
            changed = alignedOriginals.removeAll { original ->
                val baselineOutput = baseline.outputByOriginalDescriptor.getValue(original)
                val currentOutput = current.outputByOriginalDescriptor.getValue(original)
                baseline.originalsByOutputDescriptor.getValue(baselineOutput).any { it !in alignedOriginals } ||
                    current.originalsByOutputDescriptor.getValue(currentOutput).any { it !in alignedOriginals }
            }
        } while (changed)
        val alignedCurrent = alignedOriginals.asSequence()
            .map(current.outputByOriginalDescriptor::getValue)
            .toCollection(linkedSetOf())
        val alignedBaseline = alignedOriginals.asSequence()
            .map(baseline.outputByOriginalDescriptor::getValue)
            .toCollection(linkedSetOf())
        require(alignedBaseline.isNotEmpty() && alignedCurrent.isNotEmpty()) {
            "baseline and current R8 mappings have no common exact-owned descriptors"
        }
        return BaselineOwnedDescriptorAlignment(
            alignedBaseline,
            alignedCurrent,
            alignedOriginals.size,
            currentOwnedOriginals.size - alignedOriginals.size,
        )
    }

    private fun parseClassMappings(text: String): R8ClassMappings {
        val outputByOriginal = linkedMapOf<String, String>()
        val originalsByOutput = linkedMapOf<String, MutableSet<String>>()
        BufferedReader(StringReader(text)).useLines { lines ->
            lines.forEachIndexed { index, line ->
                val match = CLASS_MAPPING.matchEntire(line) ?: return@forEachIndexed
                val original = classNameToDescriptor(match.groupValues[1], index + 1)
                val outputName = match.groupValues[2]
                if (outputName.startsWith(REMOVED_CLASS_PREFIX)) return@forEachIndexed
                val output = classNameToDescriptor(outputName, index + 1)
                require(outputByOriginal.put(original, output) == null) {
                    "duplicate original R8 class mapping at line ${index + 1}: $original"
                }
                originalsByOutput.getOrPut(output, ::linkedSetOf).add(original)
            }
        }
        require(outputByOriginal.isNotEmpty()) { "R8 mapping contains no live class mappings" }
        return R8ClassMappings(
            outputByOriginal,
            originalsByOutput.mapValues { (_, originals) -> originals.toSet() },
        )
    }

    private fun classNameToDescriptor(className: String, lineNumber: Int): String {
        require(className.isNotBlank() && className.split('.').all { segment ->
            segment.isNotBlank() && segment.none { it.isWhitespace() || it in FORBIDDEN_CLASS_CHARACTERS }
        }) { "invalid R8 class mapping at line $lineNumber" }
        return "L${className.replace('.', '/')};"
    }

    private data class R8ClassMappings(
        val outputByOriginalDescriptor: Map<String, String>,
        val originalsByOutputDescriptor: Map<String, Set<String>>,
    )

    private companion object {
        val CLASS_MAPPING = Regex("^([^#\\s].*?) -> ([^\\s]+):$")
        const val REMOVED_CLASS_PREFIX = "R8\$\$REMOVED\$\$CLASS\$\$"
        val FORBIDDEN_CLASS_CHARACTERS = setOf('/', ';', '[', ']','(', ')')
    }
}
