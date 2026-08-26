package com.holin.android.hardening.similarity

import com.android.aapt.Resources
import com.google.protobuf.InvalidProtocolBufferException
import com.holin.android.hardening.artifact.BundleZipRewriter
import com.holin.android.hardening.resources.AaptResourceEntryCompat
import com.holin.android.hardening.resources.toResourceQualifier
import java.nio.file.Files
import java.nio.file.Path
import java.util.zip.ZipFile

class BaselineOwnedResourceLocationResolver {
    fun resolve(
        aab: Path,
        currentResources: Map<OwnedResourceKey, OwnedResourceLocation>,
    ): Map<OwnedResourceKey, OwnedResourceLocation> {
        require(Files.isRegularFile(aab)) { "baseline AAB is missing: $aab" }
        require(currentResources.isNotEmpty()) { "baseline resource re-evaluation set must not be empty" }
        return ZipFile(aab.toFile()).use { zip ->
            val zipEntries = zip.entries().asSequence().toList()
            BundleZipRewriter.requireSafeUniqueEntryNames(zipEntries.map { it.name })
            val resourceTableEntry = requireNotNull(zipEntries.singleOrNull { it.name == RESOURCE_TABLE && !it.isDirectory }) {
                "baseline AAB must contain exactly one $RESOURCE_TABLE"
            }
            val table = parseTable(zip.getInputStream(resourceTableEntry).use { it.readBytes() })
            val entriesById = indexEntries(table).groupBy(IndexedEntry::resourceId)
            val physicalEntries = zipEntries.asSequence().filterNot { it.isDirectory }.mapTo(hashSetOf()) { it.name }
            val resolved = currentResources.entries.sortedWith(
                compareBy<Map.Entry<OwnedResourceKey, OwnedResourceLocation>> { it.key.resourceId }
                    .thenBy { it.key.qualifier },
            ).associateTo(linkedMapOf()) { (key, current) ->
                val indexed = requireNotNull(entriesById[key.resourceId]) {
                    "baseline resource ${key.resourceId.hexId()}:${key.qualifier} was not found in resources.pb"
                }
                require(indexed.size == 1) {
                    "baseline resource ${key.resourceId.hexId()}:${key.qualifier} has an ambiguous resource ID mapping"
                }
                val references = directFileReferences(indexed.single(), physicalEntries)
                require(references.isNotEmpty()) {
                    "baseline resource ${key.resourceId.hexId()}:${key.qualifier} is not a file resource"
                }
                val matches = references.filter { it.qualifier == key.qualifier }
                require(matches.isNotEmpty()) {
                    "baseline resource ${key.resourceId.hexId()}:${key.qualifier} qualifier was not found in resources.pb"
                }
                require(matches.size == 1) {
                    "baseline resource ${key.resourceId.hexId()}:${key.qualifier} has an ambiguous physical path mapping"
                }
                val match = matches.single()
                key to OwnedResourceLocation(
                    entryName = match.entryName,
                    aabPath = match.aabPath,
                    apkPath = match.apkPath,
                    semanticHash = current.semanticHash,
                )
            }
            require(resolved.values.map(OwnedResourceLocation::aabPath).distinct().size == resolved.size) {
                "baseline resources contain ambiguous shared physical paths"
            }
            resolved
        }
    }

    private fun parseTable(bytes: ByteArray): Resources.ResourceTable {
        require(bytes.isNotEmpty()) { "baseline resources.pb is empty" }
        return try {
            Resources.ResourceTable.parseFrom(bytes)
        } catch (failure: InvalidProtocolBufferException) {
            throw IllegalArgumentException("baseline resources.pb is not a valid AAPT2 ResourceTable", failure)
        }
    }

    private fun indexEntries(table: Resources.ResourceTable): List<IndexedEntry> = buildList {
        table.packageList.forEachIndexed { packageIndex, resourcePackage ->
            require(resourcePackage.hasPackageId() && resourcePackage.packageId.id in 0..0xff) {
                "baseline resources.pb package at index $packageIndex has an invalid ID"
            }
            resourcePackage.typeList.forEachIndexed { typeIndex, type ->
                require(type.hasTypeId() && type.typeId.id in 0..0xff) {
                    "baseline resources.pb type at index $typeIndex has an invalid ID"
                }
                type.entryList.forEachIndexed { entryIndex, entry ->
                    require(entry.hasEntryId() && entry.entryId.id in 0..0xffff) {
                        "baseline resources.pb entry at index $entryIndex has an invalid ID"
                    }
                    add(
                        IndexedEntry(
                            resourceId = (resourcePackage.packageId.id shl 24) or
                                (type.typeId.id shl 16) or entry.entryId.id,
                            typeName = type.name,
                            entry = entry,
                        ),
                    )
                }
            }
        }
    }

    private fun directFileReferences(
        indexed: IndexedEntry,
        physicalEntries: Set<String>,
    ): List<ResolvedPath> = allConfigValues(indexed.entry).mapNotNull { configValue ->
        val tablePath = configValue.takeIf(Resources.ConfigValue::hasValue)
            ?.value
            ?.takeIf(Resources.Value::hasItem)
            ?.item
            ?.takeIf(Resources.Item::hasFile)
            ?.file
            ?.path
            ?: return@mapNotNull null
        val parsed = parseTablePath(tablePath, indexed.typeName)
        val configQualifier = configValue.config.toResourceQualifier()
        require(parsed.qualifier.isCompatibleWith(configQualifier)) {
            "baseline resource path qualifier '${parsed.qualifier}' is inconsistent with " +
                "resources.pb configuration '$configQualifier'"
        }
        require(parsed.aabPath in physicalEntries) {
            "baseline resources.pb references missing physical resource ${parsed.aabPath}"
        }
        parsed
    }

    private fun allConfigValues(entry: Resources.Entry): List<Resources.ConfigValue> = buildList {
        addAll(entry.configValueList)
        addAll(AaptResourceEntryCompat.flagDisabledConfigValues(entry))
        addAll(AaptResourceEntryCompat.readwriteConfigValues(entry))
    }

    private fun parseTablePath(path: String, typeName: String): ResolvedPath {
        require(path.isNotBlank() && !path.startsWith('/') && '\\' !in path && ".." !in path.split('/')) {
            "unsafe baseline resources.pb file path: $path"
        }
        val parts = path.split('/')
        require(parts.size == 3 && parts[0] == "res" && parts[2].isNotBlank()) {
            "baseline resources.pb file path must be res/<type-qualifier>/<file>: $path"
        }
        val directory = parts[1]
        require(directory == typeName || directory.startsWith("$typeName-")) {
            "baseline resources.pb file path $path is inconsistent with type $typeName"
        }
        val qualifier = directory.removePrefix(typeName).removePrefix("-")
        return ResolvedPath(
            qualifier = qualifier,
            entryName = parts[2],
            aabPath = "base/$path",
            apkPath = path,
        )
    }

    private fun String.isCompatibleWith(configQualifier: String): Boolean =
        this == configQualifier || when {
            configQualifier.isEmpty() -> VERSION_QUALIFIER.matches(this)
            else -> removePrefix("$configQualifier-").let { suffix ->
                suffix != this && VERSION_QUALIFIER.matches(suffix)
            }
        }

    private fun Int.hexId(): String = "0x" + toUInt().toString(16).padStart(8, '0')

    private data class IndexedEntry(
        val resourceId: Int,
        val typeName: String,
        val entry: Resources.Entry,
    )

    private data class ResolvedPath(
        val qualifier: String,
        val entryName: String,
        val aabPath: String,
        val apkPath: String,
    )

    private companion object {
        const val RESOURCE_TABLE = "base/resources.pb"
        val VERSION_QUALIFIER = Regex("v[1-9][0-9]*(?:\\.[0-9]+)?")
    }
}
