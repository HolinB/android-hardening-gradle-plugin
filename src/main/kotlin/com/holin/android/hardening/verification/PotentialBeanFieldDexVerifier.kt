package com.holin.android.hardening.verification

import com.android.tools.smali.dexlib2.dexbacked.DexBackedDexFile
import com.android.tools.smali.dexlib2.iface.ClassDef
import com.holin.android.hardening.artifact.BundleZipRewriter
import com.holin.android.hardening.code.JvmClassName
import com.holin.android.hardening.code.PotentialBeanFieldManifest
import java.io.IOException
import java.nio.file.Files
import java.nio.file.Path
import java.util.zip.ZipFile
import org.objectweb.asm.Type

data class PotentialBeanFieldVerificationResult(
    val policyVersion: Int,
    val moduleFieldCounts: Map<String, Int>,
    val protectedFieldCount: Int,
    val survivingOwnerCount: Int,
    val shrunkOwnerCount: Int,
    val violations: List<String>,
) {
    val verified: Boolean get() = violations.isEmpty()

    init {
        require(policyVersion > 0) { "potential Bean field policy version must be positive" }
        require(moduleFieldCounts.values.all { it >= 0 }) { "potential Bean module field counts must not be negative" }
        require(protectedFieldCount >= 0 && survivingOwnerCount >= 0 && shrunkOwnerCount >= 0) {
            "potential Bean verification counts must not be negative"
        }
        require(moduleFieldCounts.values.sum() == protectedFieldCount) {
            "potential Bean module field counts differ from the protected field count"
        }
        require(survivingOwnerCount + shrunkOwnerCount <= protectedFieldCount) {
            "potential Bean owner counts exceed the protected field count"
        }
    }
}

class PotentialBeanFieldDexVerifier {
    fun verify(
        aab: Path,
        mapping: ParsedR8Mapping,
        manifest: PotentialBeanFieldManifest,
    ): PotentialBeanFieldVerificationResult {
        require(Files.isRegularFile(aab)) { "hardened AAB is missing: $aab" }
        val violations = mutableListOf<String>()
        val classes = readBaseDexClasses(aab, violations)
        val fieldsByOwner = manifest.fields.groupBy { field -> field.key.owner }
        var survivingOwnerCount = 0
        var shrunkOwnerCount = 0

        fieldsByOwner.toSortedMap().forEach { (originalOwner, fields) ->
            val mappedOwner = mapClassInternalName(originalOwner, mapping)
            fields.forEach { field -> validateFieldMapping(field.key.name, field.key.canonicalIdentity, originalOwner, field.key.descriptor, mapping, violations) }
            val mappedOwnerDescriptor = "L$mappedOwner;"
            val originalOwnerDescriptor = "L$originalOwner;"
            val mappedClasses = classes[mappedOwnerDescriptor].orEmpty()
            val originalClasses = classes[originalOwnerDescriptor].orEmpty()
            if (mappedClasses.isEmpty() && originalClasses.isEmpty()) {
                shrunkOwnerCount++
                return@forEach
            }
            survivingOwnerCount++
            val ownerWasRenamed = mappedOwnerDescriptor != originalOwnerDescriptor
            if (ownerWasRenamed && mappedClasses.isEmpty()) {
                violations += "mapped final owner $mappedOwnerDescriptor is missing for original owner $originalOwnerDescriptor"
                return@forEach
            }
            if (ownerWasRenamed && originalClasses.isNotEmpty()) {
                violations += "original owner $originalOwnerDescriptor remains alongside mapped final owner $mappedOwnerDescriptor"
            }
            val finalOwnerClasses = if (ownerWasRenamed) mappedClasses else originalClasses
            fields.forEach { field ->
                val mappedDescriptor = mapFieldDescriptor(field.key.descriptor, mapping)
                val matches = finalOwnerClasses.sumOf { owner ->
                    owner.fields.count { finalField ->
                        finalField.name == field.key.name && finalField.type == mappedDescriptor
                    }
                }
                if (matches != 1) {
                    violations += "required final field ${field.key.canonicalIdentity} with mapped descriptor " +
                        "$mappedDescriptor was found $matches times"
                }
            }
        }

        val moduleCounts = manifest.ownedModules.sorted().associateWith { module ->
            manifest.fields.count { field -> field.modulePath == module }
        }
        return PotentialBeanFieldVerificationResult(
            manifest.policyVersion,
            moduleCounts,
            manifest.fields.size,
            survivingOwnerCount,
            shrunkOwnerCount,
            violations.distinct().sorted(),
        )
    }

    private fun validateFieldMapping(
        originalName: String,
        identity: String,
        originalOwner: String,
        descriptor: String,
        mapping: ParsedR8Mapping,
        violations: MutableList<String>,
    ) {
        val key = MappingSymbolKey(
            SymbolKind.FIELD,
            originalOwner.replace('/', '.'),
            originalName,
            descriptor,
        )
        mapping.symbols[key]?.let { outputs ->
            if (outputs != setOf(originalName)) {
                violations += "R8 field mapping for $identity mapped to ${outputs.sorted().joinToString()} " +
                    "instead of original name $originalName"
            }
        }
    }

    private fun readBaseDexClasses(
        aab: Path,
        violations: MutableList<String>,
    ): Map<String, List<ClassDef>> = try {
        ZipFile(aab.toFile()).use { zip ->
            val entries = zip.entries().asSequence().toList()
            BundleZipRewriter.requireSafeUniqueEntryNames(entries.map { it.name })
            val dexEntries = entries.filter { entry -> !entry.isDirectory && BASE_DEX_PATH.matches(entry.name) }
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
            classes.toSortedMap().forEach { (descriptor, definitions) ->
                if (definitions.size > 1) {
                    violations += "duplicate class descriptor $descriptor across base DEX entries: " +
                        definitions.map(Pair<String, ClassDef>::first).sorted().joinToString()
                }
            }
            classes.mapValues { (_, definitions) -> definitions.map(Pair<String, ClassDef>::second) }
        }
    } catch (failure: IOException) {
        throw IllegalArgumentException("hardened AAB is not a readable ZIP: $aab", failure)
    }

    private fun mapFieldDescriptor(descriptor: String, mapping: ParsedR8Mapping): String {
        val type = try {
            Type.getType(descriptor)
        } catch (failure: RuntimeException) {
            throw IllegalArgumentException("invalid potential Bean field descriptor: $descriptor", failure)
        }
        return when (type.sort) {
            Type.ARRAY -> "[".repeat(type.dimensions) + mapFieldDescriptor(type.elementType.descriptor, mapping)
            Type.OBJECT -> "L${mapClassInternalName(type.internalName, mapping)};"
            Type.BOOLEAN, Type.BYTE, Type.CHAR, Type.SHORT, Type.INT, Type.FLOAT, Type.LONG, Type.DOUBLE -> descriptor
            else -> throw IllegalArgumentException("invalid potential Bean field descriptor: $descriptor")
        }
    }

    private fun mapClassInternalName(internalName: String, mapping: ParsedR8Mapping): String {
        require(JvmClassName.isInternal(internalName)) { "invalid mapping class internal name: $internalName" }
        val outputs = mapping.symbols[classMappingKey(internalName)] ?: return internalName
        require(outputs.size == 1) { "R8 mapping has ambiguous class outputs for $internalName: ${outputs.sorted()}" }
        val output = outputs.single()
        require(JvmClassName.isDotted(output)) { "R8 mapping has an invalid class output for $internalName: $output" }
        return output.replace('.', '/')
    }

    private fun classMappingKey(internalName: String) = MappingSymbolKey(
        SymbolKind.CLASS,
        internalName.replace('/', '.'),
        internalName.replace('/', '.'),
        "L$internalName;",
    )

    private companion object {
        val BASE_DEX_PATH = Regex("base/dex/classes(?:[0-9]+)?\\.dex")
    }
}
