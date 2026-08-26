package com.holin.android.hardening.verification

import com.android.tools.smali.dexlib2.dexbacked.DexBackedDexFile
import com.android.tools.smali.dexlib2.iface.ClassDef
import com.holin.android.hardening.artifact.BundleZipRewriter
import com.holin.android.hardening.code.JvmClassName
import java.io.IOException
import java.nio.file.Files
import java.nio.file.Path
import java.util.zip.ZipFile
import org.objectweb.asm.Type

data class MappingAabCompatibilityResult(
    val previousSymbolCount: Int,
    val candidateSymbolCount: Int,
    val removedSymbolCount: Int,
    val violations: List<String>,
) {
    val verified: Boolean get() = violations.isEmpty()

    init {
        require(previousSymbolCount >= 0 && candidateSymbolCount >= 0 && removedSymbolCount >= 0) {
            "mapping AAB compatibility counts must not be negative"
        }
        require(removedSymbolCount <= previousSymbolCount) {
            "removed mapping symbol count exceeds the previous mapping"
        }
    }
}

class MappingAabCompatibilityVerifier {
    fun verify(
        aab: Path,
        previous: ParsedR8Mapping,
        candidate: ParsedR8Mapping,
    ): MappingAabCompatibilityResult {
        require(Files.isRegularFile(aab)) { "hardened AAB is missing: $aab" }
        val violations = mutableListOf<String>()
        val classes = readBaseDexClasses(aab, violations)
        var removedSymbolCount = 0

        previous.symbols.keys.sortedWith(MappingContinuityVerifier.SYMBOL_ORDER).forEach { key ->
            val previousNames = previous.symbols.getValue(key)
            val candidateNames = candidate.symbols[key]
            when {
                candidateNames == previousNames -> Unit
                candidateNames == null -> {
                    if (isPresent(key, previousNames, previous, classes)) {
                        violations += "AAB-present ${key.kind} mapping ${identity(key)} was removed"
                    } else {
                        removedSymbolCount++
                    }
                }
                else -> {
                    val present = isPresent(key, previousNames, previous, classes) ||
                        isPresent(key, candidateNames, candidate, classes)
                    val scope = if (present) "AAB-present" else "AAB-absent"
                    violations += "$scope ${key.kind} mapping ${identity(key)} changed outputs from " +
                        "${previousNames.sorted()} to ${candidateNames.sorted()}"
                }
            }
        }
        (candidate.symbols.keys - previous.symbols.keys)
            .sortedWith(MappingContinuityVerifier.SYMBOL_ORDER)
            .forEach { key ->
                val candidateNames = candidate.symbols.getValue(key)
                val scope = if (isPresent(key, candidateNames, candidate, classes)) "AAB-present" else "AAB-absent"
                violations += "$scope ${key.kind} mapping ${identity(key)} was added"
            }

        return MappingAabCompatibilityResult(
            previous.symbols.size,
            candidate.symbols.size,
            removedSymbolCount,
            violations.distinct().sorted(),
        )
    }

    private fun isPresent(
        key: MappingSymbolKey,
        outputs: Set<String>,
        mapping: ParsedR8Mapping,
        classes: Map<String, List<ClassDef>>,
    ): Boolean = when (key.kind) {
        SymbolKind.CLASS -> outputs.any { output -> classes[descriptor(output)].orEmpty().isNotEmpty() }
        SymbolKind.FIELD -> finalOwners(key.originalOwner, mapping).any { owner ->
            classes[owner].orEmpty().any { classDef ->
                classDef.fields.any { field ->
                    field.name in outputs && field.type == mapDescriptor(key.jvmDescriptor, mapping)
                }
            }
        }
        SymbolKind.METHOD -> finalOwners(key.originalOwner, mapping).any { owner ->
            classes[owner].orEmpty().any { classDef ->
                classDef.methods.any { method ->
                    method.name in outputs &&
                        "(${method.parameterTypes.joinToString("")})${method.returnType}" == mapDescriptor(
                            key.jvmDescriptor,
                            mapping,
                        )
                }
            }
        }
    }

    private fun finalOwners(originalOwner: String, mapping: ParsedR8Mapping): Set<String> {
        val key = MappingSymbolKey(
            SymbolKind.CLASS,
            originalOwner,
            originalOwner,
            descriptor(originalOwner),
        )
        val names = mapping.symbols[key] ?: setOf(originalOwner)
        return names.mapTo(linkedSetOf(), ::descriptor)
    }

    private fun mapDescriptor(descriptor: String, mapping: ParsedR8Mapping): String {
        val type = try {
            Type.getType(descriptor)
        } catch (failure: RuntimeException) {
            throw IllegalArgumentException("invalid mapping JVM descriptor: $descriptor", failure)
        }
        return when (type.sort) {
            Type.METHOD -> Type.getMethodDescriptor(
                Type.getType(mapDescriptor(type.returnType.descriptor, mapping)),
                *type.argumentTypes.map { argument ->
                    Type.getType(mapDescriptor(argument.descriptor, mapping))
                }.toTypedArray(),
            )
            Type.ARRAY -> "[".repeat(type.dimensions) + mapDescriptor(type.elementType.descriptor, mapping)
            Type.OBJECT -> {
                val original = type.className
                val key = MappingSymbolKey(SymbolKind.CLASS, original, original, type.descriptor)
                val outputs = mapping.symbols[key] ?: setOf(original)
                require(outputs.size == 1) { "mapping has ambiguous class outputs for $original: ${outputs.sorted()}" }
                descriptor(outputs.single())
            }
            else -> descriptor
        }
    }

    private fun descriptor(dottedClassName: String): String {
        require(JvmClassName.isDotted(dottedClassName)) { "invalid mapped class name: $dottedClassName" }
        return "L${dottedClassName.replace('.', '/')};"
    }

    private fun identity(key: MappingSymbolKey): String =
        "${key.originalOwner}.${key.originalName}${key.jvmDescriptor}"

    private fun readBaseDexClasses(
        aab: Path,
        violations: MutableList<String>,
    ): Map<String, List<ClassDef>> = try {
        ZipFile(aab.toFile()).use { zip ->
            val entries = zip.entries().asSequence().toList()
            BundleZipRewriter.requireSafeUniqueEntryNames(entries.map { entry -> entry.name })
            val dexEntries = entries
                .filter { entry -> !entry.isDirectory && BASE_DEX_PATH.matches(entry.name) }
                .sortedBy { entry -> entry.name }
            require(dexEntries.isNotEmpty()) { "hardened AAB contains no base DEX entries" }
            val classes = linkedMapOf<String, MutableList<Pair<String, ClassDef>>>()
            dexEntries.forEach { entry ->
                val bytes = zip.getInputStream(entry).use { input -> input.readBytes() }
                val dex = try {
                    DexBackedDexFile.fromInputStream(null, bytes.inputStream())
                } catch (failure: RuntimeException) {
                    throw IllegalArgumentException("${entry.name} is not a readable DEX", failure)
                }
                dex.classes.forEach { classDef ->
                    classes.getOrPut(classDef.type, ::mutableListOf).add(entry.name to classDef)
                }
            }
            classes.toSortedMap().forEach { (classDescriptor, definitions) ->
                if (definitions.size > 1) {
                    violations += "duplicate class descriptor $classDescriptor across base DEX entries: " +
                        definitions.map(Pair<String, ClassDef>::first).sorted().joinToString()
                }
            }
            classes.mapValues { (_, definitions) -> definitions.map(Pair<String, ClassDef>::second) }
        }
    } catch (failure: IOException) {
        throw IllegalArgumentException("hardened AAB is not a readable ZIP: $aab", failure)
    }

    private companion object {
        val BASE_DEX_PATH = Regex("base/dex/classes(?:[0-9]+)?\\.dex")
    }
}
