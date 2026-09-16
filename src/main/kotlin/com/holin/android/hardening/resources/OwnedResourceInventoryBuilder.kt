package com.holin.android.hardening.resources

import com.android.aapt.Resources
import com.google.protobuf.InvalidProtocolBufferException
import com.holin.android.hardening.HardeningOwnership
import com.holin.android.hardening.ImageFormat
import com.holin.android.hardening.inventory.GitIgnoreMatcher
import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path

data class OwnedResourceSourceName(
    val module: String,
    val type: ResourceType,
    val name: String,
    val source: Path,
    val moduleRelativePath: String = "",
    val webpDiversificationEnabled: Boolean = false,
    val qualifier: String = "",
    val sourcePriority: Int = Int.MAX_VALUE,
    val imageFormat: ImageFormat? = null,
    val imageDiversificationEnabled: Boolean = false,
)

/** Proves resource provenance from production source before joining it to the merged AAPT2 table. */
class OwnedResourceInventoryBuilder(
    repositoryRoot: Path,
    private val ownership: HardeningOwnership,
    private val gitIgnoreMatcher: GitIgnoreMatcher = GitIgnoreMatcher(repositoryRoot),
    private val externallyNamedResources: Set<Pair<ResourceType, String>> = emptySet(),
) {
    private val root = repositoryRoot.toAbsolutePath().normalize()

    fun scanSourceNames(): List<OwnedResourceSourceName> {
        return selectedSourceVariants()
            .groupBy { it.type to it.name }
            .map { (_, contenders) -> contenders.minWith(sourcePriorityComparator()) }
            .sortedWith(compareBy(OwnedResourceSourceName::type, OwnedResourceSourceName::name))
    }

    private fun selectedSourceVariants(): List<OwnedResourceSourceName> {
        val candidates = collectCandidates()
        val ignored = gitIgnoreMatcher.ignored(candidates.map(ResourceCandidate::source))
        val selected = candidates.asSequence()
            .filterNot { it.source in ignored }
            .flatMap(::logicalNames)
            .groupBy { Triple(it.type, it.name, it.qualifier) }
            .map { (_, contenders) -> contenders.minWith(sourcePriorityComparator()) }
            .sortedWith(
                compareBy(
                    OwnedResourceSourceName::type,
                    OwnedResourceSourceName::name,
                    OwnedResourceSourceName::qualifier,
                ),
            )
        ownership.requireMatchedWebpIncludes(
            selected.asSequence()
                .filter { it.source.fileName.toString().endsWith(".webp", true) }
                .groupBy(OwnedResourceSourceName::module)
                .mapValues { (_, names) -> names.mapTo(linkedSetOf(), OwnedResourceSourceName::moduleRelativePath) },
        )
        ownership.requireMatchedImageIncludes(
            selected.asSequence()
                .filter { it.imageFormat != null }
                .groupBy(OwnedResourceSourceName::module)
                .mapValues { (_, names) -> names.mapTo(linkedSetOf(), OwnedResourceSourceName::moduleRelativePath) },
        )
        return selected
    }

    fun build(resourcesPb: ByteArray, aabEntries: Map<String, ByteArray>): List<ResourceInventoryEntry> {
        val variants = selectedSourceVariants()
        val owned = variants.groupBy { it.type to it.name }
            .mapValues { (_, contenders) -> contenders.minWith(sourcePriorityComparator()) }
        val ownedVariants = variants.associateBy { Triple(it.type, it.name, it.qualifier) }
        require(owned.isNotEmpty()) { "no owned hardening resource families were found" }
        val table = try {
            Resources.ResourceTable.parseFrom(resourcesPb)
        } catch (failure: InvalidProtocolBufferException) {
            throw IllegalArgumentException("resources.pb is not a valid AAPT2 ResourceTable", failure)
        }
        val output = mutableListOf<ResourceInventoryEntry>()
        table.packageList.forEach { resourcePackage ->
            require(resourcePackage.hasPackageId()) { "resources.pb package is missing its ID" }
            resourcePackage.typeList.forEach typeLoop@ { tableType ->
                val type = ResourceType.values().firstOrNull { it.directoryName == tableType.name } ?: return@typeLoop
                require(tableType.hasTypeId()) { "resources.pb type ${tableType.name} is missing its ID" }
                tableType.entryList.forEach entryLoop@ { tableEntry ->
                    val source = owned[type to tableEntry.name] ?: return@entryLoop
                    require(tableEntry.hasEntryId()) { "resources.pb entry ${tableType.name}/${tableEntry.name} is missing its ID" }
                    val resourceId = (resourcePackage.packageId.id shl 24) or
                        (tableType.typeId.id shl 16) or tableEntry.entryId.id
                    val configs = buildList {
                        addAll(tableEntry.configValueList)
                        addAll(AaptResourceEntryCompat.flagDisabledConfigValues(tableEntry))
                        addAll(AaptResourceEntryCompat.readwriteConfigValues(tableEntry))
                    }
                    if (type == ResourceType.STYLE) {
                        require(configs.isNotEmpty()) { "owned style ${tableEntry.name} has no table values" }
                        configs.forEach { config ->
                            output += ResourceInventoryEntry(
                                source.module,
                                resourceId,
                                type,
                                tableEntry.name,
                                config.config.toResourceQualifier(),
                            )
                        }
                    } else {
                        val fileConfigs = configs.mapNotNull { config ->
                            val file = config.takeIf(Resources.ConfigValue::hasValue)?.value
                                ?.takeIf(Resources.Value::hasItem)?.item
                                ?.takeIf(Resources.Item::hasFile)?.file
                                ?: return@mapNotNull null
                            config to file.path
                        }
                        require(fileConfigs.isNotEmpty()) {
                            "owned ${type.directoryName}/${tableEntry.name} has no direct file reference"
                        }
                        fileConfigs.forEach { (_, tablePath) ->
                            val qualifier = fileQualifier(tablePath, type)
                            val qualifiedSource = ownedVariants[Triple(type, tableEntry.name, qualifier)] ?: source
                            val aabPath = "base/$tablePath"
                            val bytes = requireNotNull(aabEntries[aabPath]) {
                                "owned resource table path is missing from AAB: $aabPath"
                            }
                            output += ResourceInventoryEntry(
                                qualifiedSource.module,
                                resourceId,
                                type,
                                tableEntry.name,
                                // Keep the physical qualifier suffix. AAPT may retain a redundant
                                // trailing vNN in the file path while normalizing it out of Config.
                                qualifier,
                                aabPath,
                                bytes,
                                ResourceOrigin.OWNED,
                                type to tableEntry.name in externallyNamedResources,
                                type == ResourceType.DRAWABLE && tableEntry.name == "icon_notification",
                                false,
                                qualifiedSource.webpDiversificationEnabled,
                                qualifiedSource.imageFormat,
                                qualifiedSource.source,
                                qualifiedSource.imageDiversificationEnabled,
                            )
                        }
                    }
                }
            }
        }
        require(output.isNotEmpty()) { "owned resources could not be joined to resources.pb" }
        return output.sortedWith(compareBy(ResourceInventoryEntry::type, ResourceInventoryEntry::name, ResourceInventoryEntry::qualifier))
    }

    private fun collectCandidates(): List<ResourceCandidate> = buildList {
        ownership.modules.forEach { declaration ->
            val module = declaration.path
            val moduleDirectory = declaration.directory
            declaration.sourceRoots.resourceDirectories.forEachIndexed { sourcePriority, resourceRoot ->
                requireNoSymbolicLinks(resourceRoot, "resource root")
                if (!Files.isDirectory(resourceRoot, NOFOLLOW_LINKS)) return@forEachIndexed
                Files.walk(resourceRoot).use { paths ->
                    paths.sorted().toList().also { walked ->
                        walked.forEach { path -> requireNoSymbolicLinks(path, "resource path") }
                    }.asSequence()
                        .filter { path -> !isGeneratedOrTestPath(moduleDirectory.relativize(path)) }
                        .filter { path -> Files.isRegularFile(path, NOFOLLOW_LINKS) }
                        .forEach { source ->
                        val directory = resourceRoot.relativize(source).firstOrNull()?.toString().orEmpty()
                        val moduleRelativePath = portable(moduleDirectory.relativize(source))
                        add(ResourceCandidate(module, source, directory, sourcePriority, moduleRelativePath))
                    }
                }
            }
        }
    }

    private fun requireNoSymbolicLinks(path: Path, label: String) {
        val normalized = path.toAbsolutePath().normalize()
        require(normalized.startsWith(root)) { "$label is outside the repository: $normalized" }
        var current = root
        require(!Files.isSymbolicLink(current)) { "$label contains a symbolic link: $current" }
        root.relativize(normalized).forEach { component ->
            current = current.resolve(component)
            require(!Files.isSymbolicLink(current)) { "$label contains a symbolic link: $current" }
        }
    }

    private fun fileQualifier(tablePath: String, type: ResourceType): String {
        val parts = tablePath.split('/')
        require(parts.size == 3 && parts[0] == "res") { "invalid resources.pb file path: $tablePath" }
        val directory = parts[1]
        require(directory == type.directoryName || directory.startsWith("${type.directoryName}-")) {
            "resources.pb file path $tablePath does not match ${type.directoryName}"
        }
        return directory.removePrefix(type.directoryName).removePrefix("-")
    }

    private fun sourcePriorityComparator(): Comparator<OwnedResourceSourceName> =
        compareBy<OwnedResourceSourceName>({ ownership.priority(it.module) })
            .thenByDescending(OwnedResourceSourceName::sourcePriority)

    private fun logicalNames(candidate: ResourceCandidate): Sequence<OwnedResourceSourceName> {
        val baseDirectory = candidate.directory.substringBefore('-')
        return when (baseDirectory) {
            "values" -> STYLE_TAG.findAll(Files.readString(candidate.source)).map { match ->
                OwnedResourceSourceName(
                    candidate.module,
                    ResourceType.STYLE,
                    match.groupValues[1],
                    candidate.source,
                    candidate.moduleRelativePath,
                    false,
                    candidate.directory.substringAfter('-', ""),
                    candidate.sourcePriority,
                )
            }
            else -> FILE_TYPES_BY_DIRECTORY[baseDirectory]?.let { fileName(candidate, it) } ?: emptySequence()
        }
    }

    private fun fileName(candidate: ResourceCandidate, type: ResourceType): Sequence<OwnedResourceSourceName> {
        val file = candidate.source.fileName.toString()
        val name = when {
            file.endsWith(".9.png", ignoreCase = true) -> file.removeSuffix(".9.png")
            '.' in file -> file.substringBefore('.')
            type == ResourceType.RAW -> file
            else -> return emptySequence()
        }
        if (!FILE_NAME.matches(name)) return emptySequence()
        return sequenceOf(
            OwnedResourceSourceName(
                candidate.module,
                type,
                name,
                candidate.source,
                candidate.moduleRelativePath,
                ownership.isWebpIncluded(candidate.module, candidate.moduleRelativePath),
                candidate.directory.substringAfter('-', ""),
                candidate.sourcePriority,
                imageFormat(candidate.source),
                imageFormat(candidate.source)?.let {
                    ownership.isImageIncluded(candidate.module, candidate.moduleRelativePath, it)
                } == true,
            ),
        )
    }

    private data class ResourceCandidate(
        val module: String,
        val source: Path,
        val directory: String,
        val sourcePriority: Int,
        val moduleRelativePath: String,
    )

    private fun portable(path: Path): String = path.toString().replace('\\', '/')

    private fun imageFormat(path: Path): ImageFormat? = when {
        path.fileName.toString().endsWith(".png", true) -> ImageFormat.PNG
        path.fileName.toString().endsWith(".webp", true) -> ImageFormat.WEBP
        path.fileName.toString().endsWith(".jpg", true) || path.fileName.toString().endsWith(".jpeg", true) -> ImageFormat.JPEG
        else -> null
    }

    private fun isGeneratedOrTestPath(relative: Path): Boolean = relative.any { component ->
        component.toString()
            .replace(Regex("(?<=[a-z0-9])(?=[A-Z])"), " ")
            .lowercase()
            .split(Regex("[^a-z0-9]+"))
            .any { it == "build" || it == "generated" || it == "test" }
    }

    companion object {
        private val FILE_NAME = Regex("[a-z][a-z0-9_]*")
        private val STYLE_TAG = Regex("<style\\s+[^>]*name\\s*=\\s*[\"']([^\"']+)[\"']", RegexOption.IGNORE_CASE)
        private val FILE_TYPES_BY_DIRECTORY = ResourceType.values()
            .filterNot { it == ResourceType.STYLE }
            .associateBy(ResourceType::directoryName)
    }
}
