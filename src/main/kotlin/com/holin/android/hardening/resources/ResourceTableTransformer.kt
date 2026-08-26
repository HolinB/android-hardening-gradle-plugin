package com.holin.android.hardening.resources

import com.android.aapt.Resources
import com.google.protobuf.InvalidProtocolBufferException

data class ResourceTableEntryTransformReport(
    val resourceId: Int,
    val type: ResourceType,
    val oldName: String,
    val newName: String,
    val fileReferencesChanged: Int,
)

data class ResourceTableTransformReport(
    val schemaVersion: Int = 1,
    val renames: List<ResourceTableEntryTransformReport>,
)

data class ResourceTableTransformResult(
    val resourcesPb: ByteArray,
    val zipPathRenames: Map<String, String>,
    val logicalZipPathRenames: Map<String, String>,
    val report: ResourceTableTransformReport,
)

/**
 * Rewrites only explicitly authorized application resources in an AAPT2 proto resource table.
 *
 * The supplied [ResourceRenameReport] is treated as a closed-world contract: every requested
 * resource ID, original name, qualifier and file reference must agree with the table before any
 * bytes are emitted. The protobuf builders retain all fields and unknown fields; only Entry.name
 * and direct Item.file.path values are changed.
 */
class ResourceTableTransformer {
    fun transform(
        resourcesPb: ByteArray,
        renameReport: ResourceRenameReport,
    ): ResourceTableTransformResult {
        require(renameReport.schemaVersion == RESOURCE_RENAME_SCHEMA) {
            "unsupported resource rename report schema ${renameReport.schemaVersion}"
        }
        val table = parseTable(resourcesPb)
        val requests = validateRequests(renameReport.renames)
        if (requests.isEmpty()) {
            return ResourceTableTransformResult(
                resourcesPb = resourcesPb.copyOf(),
                zipPathRenames = emptyMap(),
                logicalZipPathRenames = emptyMap(),
                report = ResourceTableTransformReport(renames = emptyList()),
            )
        }

        val indexedEntries = indexEntries(table)
        val entriesById = indexedEntries.groupBy(IndexedEntry::resourceId)
        require(entriesById.values.none { it.size > 1 }) { "resources.pb contains duplicate resource IDs" }
        val fileOwners = indexedEntries.flatMap { indexed ->
            directFileReferences(indexed.entry).map { path -> path to indexed.resourceId }
        }.groupBy({ it.first }, { it.second })

        val prepared = requests.map { request ->
            prepare(request, requireNotNull(entriesById[request.resourceId]?.singleOrNull()) {
                "resource ${request.resourceId.hexId()} was not found in resources.pb"
            })
        }
        validateEntryNameCollisions(indexedEntries, prepared)
        validatePathCollisions(fileOwners, prepared)

        val builder = table.toBuilder()
        prepared.forEach { rewrite ->
            val entryBuilder = builder
                .getPackageBuilder(rewrite.indexed.packageIndex)
                .getTypeBuilder(rewrite.indexed.typeIndex)
                .getEntryBuilder(rewrite.indexed.entryIndex)
            if (!rewrite.pathOnly) entryBuilder.name = rewrite.request.newName
            val changed = rewriteFileReferences(entryBuilder, rewrite.tablePathRenames)
            check(changed == rewrite.tablePathRenames.size) {
                "resource ${rewrite.request.resourceId.hexId()} changed $changed file references, " +
                    "expected ${rewrite.tablePathRenames.size}"
            }
        }

        val rewritten = builder.build()
        val serialized = rewritten.toByteArray()
        parseTable(serialized)
        val zipPaths = prepared.flatMap { it.zipPathRenames.entries }
            .sortedBy(Map.Entry<String, String>::key)
            .associateTo(linkedMapOf()) { it.key to it.value }
        val logicalZipPaths = prepared.asSequence()
            .filterNot(PreparedRewrite::pathOnly)
            .flatMap { it.zipPathRenames.entries.asSequence() }
            .sortedBy(Map.Entry<String, String>::key)
            .associateTo(linkedMapOf()) { it.key to it.value }
        return ResourceTableTransformResult(
            resourcesPb = serialized,
            zipPathRenames = zipPaths,
            logicalZipPathRenames = logicalZipPaths,
            report = ResourceTableTransformReport(
                renames = prepared.filterNot(PreparedRewrite::pathOnly).map { rewrite ->
                    ResourceTableEntryTransformReport(
                        resourceId = rewrite.request.resourceId,
                        type = rewrite.request.type,
                        oldName = rewrite.request.oldName,
                        newName = rewrite.request.newName,
                        fileReferencesChanged = rewrite.tablePathRenames.size,
                    )
                }.sortedBy(ResourceTableEntryTransformReport::resourceId),
            ),
        )
    }

    private fun validateRequests(requests: List<ResourceRename>): List<ResourceRename> {
        require(requests.map(ResourceRename::resourceId).distinct().size == requests.size) {
            "duplicate resource rename request"
        }
        requests.forEach { request ->
            val pathOnly = request.oldName == request.newName
            require(!pathOnly || request.type == ResourceType.DRAWABLE && request.oldName == NOTIFICATION_ICON) {
                "resource ${request.resourceId.hexId()} logical-name preservation is reserved for drawable/$NOTIFICATION_ICON"
            }
            require(request.oldName != NOTIFICATION_ICON || pathOnly) {
                "$NOTIFICATION_ICON Entry.name must remain unchanged"
            }
            require(validName(request.type, request.oldName)) { "invalid original ${request.type} name ${request.oldName}" }
            require(validName(request.type, request.newName)) { "invalid replacement ${request.type} name ${request.newName}" }
            require(request.qualifiers.distinct().size == request.qualifiers.size) {
                "resource ${request.resourceId.hexId()} contains duplicate qualifiers"
            }
            require(request.entries.map(ResourceEntryRename::qualifier).distinct().size == request.entries.size) {
                "resource ${request.resourceId.hexId()} contains duplicate qualifier path mappings"
            }
            require(request.entries.map(ResourceEntryRename::oldPath).distinct().size == request.entries.size) {
                "resource ${request.resourceId.hexId()} contains duplicate old paths"
            }
            require(request.entries.map(ResourceEntryRename::newPath).distinct().size == request.entries.size) {
                "resource ${request.resourceId.hexId()} contains duplicate new paths"
            }
        }
        val oldZipPaths = requests.flatMap(ResourceRename::entries).map(ResourceEntryRename::oldPath)
        val newZipPaths = requests.flatMap(ResourceRename::entries).map(ResourceEntryRename::newPath)
        require(oldZipPaths.distinct().size == oldZipPaths.size) { "duplicate old ZIP resource path across requests" }
        require(newZipPaths.distinct().size == newZipPaths.size) { "duplicate new ZIP resource path across requests" }
        return requests.sortedBy(ResourceRename::resourceId)
    }

    private fun prepare(request: ResourceRename, indexed: IndexedEntry): PreparedRewrite {
        require(indexed.typeName == request.type.directoryName) {
            "resource ${request.resourceId.hexId()} has type ${indexed.typeName}, expected ${request.type.directoryName}"
        }
        require(indexed.entry.name == request.oldName) {
            "resource ${request.resourceId.hexId()} has name ${indexed.entry.name}, expected ${request.oldName}"
        }

        val fileReferences = directFileReferenceRecords(indexed.entry)
        val actualPaths = fileReferences.map(FileReferenceRecord::path)
        require(actualPaths.distinct().size == actualPaths.size) {
            "resource ${request.resourceId.hexId()} contains duplicate file references"
        }
        if (request.type == ResourceType.STYLE) {
            require(request.entries.isEmpty()) { "style ${request.resourceId.hexId()} must not declare file paths" }
            require(actualPaths.isEmpty()) { "style ${request.resourceId.hexId()} unexpectedly contains file references" }
            validateStyleQualifiers(request, indexed.entry)
            return PreparedRewrite(indexed, request, emptyMap(), emptyMap(), pathOnly = false)
        }

        require(request.entries.isNotEmpty()) {
            "resource ${request.resourceId.hexId()} has no qualifier path mappings"
        }
        require(request.qualifiers.toSet() == request.entries.map(ResourceEntryRename::qualifier).toSet()) {
            "resource ${request.resourceId.hexId()} qualifier list is inconsistent with its path mappings"
        }

        fileReferences.forEach { fileReference ->
            val pathQualifier = BundleResourcePath.parse(
                path = "table/${fileReference.path}",
                type = request.type,
                expectedName = request.oldName,
            ).qualifier
            val configQualifier = fileReference.config.toResourceQualifier()
            require(pathQualifier.isCompatibleWith(configQualifier)) {
                "resource ${request.resourceId.hexId()} path qualifier '$pathQualifier' is inconsistent with " +
                    "resources.pb configuration '$configQualifier'"
            }
        }

        val zipRenames = linkedMapOf<String, String>()
        val tableRenames = linkedMapOf<String, String>()
        val pathOnly = request.oldName == request.newName
        val physicalNames = linkedSetOf<String>()
        request.entries.sortedBy(ResourceEntryRename::oldPath).forEach { entry ->
            val oldPath = BundleResourcePath.parse(entry.oldPath, request.type, request.oldName)
            val newPath = BundleResourcePath.parse(
                entry.newPath,
                request.type,
                expectedName = request.newName.takeUnless { pathOnly },
            )
            physicalNames += newPath.fileName
            require(oldPath.moduleName == newPath.moduleName) {
                "resource ${request.resourceId.hexId()} cannot move between bundle modules"
            }
            require(oldPath.directory == newPath.directory && oldPath.extension == newPath.extension) {
                "resource ${request.resourceId.hexId()} path rename changes qualifier directory or extension"
            }
            require(entry.qualifier == oldPath.qualifier && entry.qualifier == newPath.qualifier) {
                "resource ${request.resourceId.hexId()} qualifier '${entry.qualifier}' is inconsistent with ${entry.oldPath}"
            }
            zipRenames[entry.oldPath] = entry.newPath
            tableRenames[oldPath.tablePath] = newPath.tablePath
        }
        if (pathOnly) {
            require(physicalNames.size == 1 && PHYSICAL_NOTIFICATION_NAME.matches(physicalNames.single())) {
                "notification-icon qualifier variants must reuse one typed pseudoword physical basename"
            }
        }
        require(actualPaths.toSet() == tableRenames.keys) {
            val missing = actualPaths.toSet() - tableRenames.keys
            val unknown = tableRenames.keys - actualPaths.toSet()
            "resource ${request.resourceId.hexId()} qualifier mappings do not cover resources.pb file references; " +
                "missing=$missing unknown=$unknown"
        }
        return PreparedRewrite(indexed, request, tableRenames, zipRenames, pathOnly)
    }

    private fun validateStyleQualifiers(request: ResourceRename, entry: Resources.Entry) {
        val configurations = allConfigValues(entry).map(Resources.ConfigValue::getConfig)
        require(configurations.map { it.toByteString() }.distinct().size == configurations.size) {
            "style ${request.resourceId.hexId()} contains duplicate configurations"
        }
        val tableQualifiers = configurations.map { it.toResourceQualifier() }
        require(request.qualifiers.toSet() == tableQualifiers.toSet() && request.qualifiers.size == tableQualifiers.size) {
            "style ${request.resourceId.hexId()} qualifiers ${request.qualifiers} are inconsistent with " +
                "resources.pb configurations $tableQualifiers"
        }
    }

    private fun validateEntryNameCollisions(entries: List<IndexedEntry>, rewrites: List<PreparedRewrite>) {
        val duplicateTargets = rewrites.groupBy { rewrite ->
            Triple(rewrite.indexed.packageIndex, rewrite.indexed.typeIndex, rewrite.request.newName)
        }.values.firstOrNull { it.size > 1 }
        require(duplicateTargets == null) {
            val ids = duplicateTargets.orEmpty().joinToString { it.request.resourceId.hexId() }
            "replacement name ${duplicateTargets?.firstOrNull()?.request?.newName} collides across resources $ids"
        }
        rewrites.forEach { rewrite ->
            val collision = entries.firstOrNull { candidate ->
                candidate.packageIndex == rewrite.indexed.packageIndex &&
                    candidate.typeIndex == rewrite.indexed.typeIndex &&
                    candidate.resourceId != rewrite.indexed.resourceId &&
                    candidate.entry.name == rewrite.request.newName
            }
            require(collision == null) {
                "resource ${rewrite.request.resourceId.hexId()} replacement name ${rewrite.request.newName} collides with " +
                    "${collision?.resourceId?.hexId()}"
            }
        }
    }

    private fun validatePathCollisions(
        fileOwners: Map<String, List<Int>>,
        rewrites: List<PreparedRewrite>,
    ) {
        val allOriginalPaths = fileOwners.keys
        val duplicateTargets = rewrites.flatMap { rewrite ->
            rewrite.tablePathRenames.values.map { newPath -> newPath to rewrite.request.resourceId }
        }.groupBy({ it.first }, { it.second }).entries.firstOrNull { it.value.size > 1 }
        require(duplicateTargets == null) {
            "replacement table path ${duplicateTargets?.key} collides across resources " +
                duplicateTargets?.value.orEmpty().joinToString { it.hexId() }
        }
        rewrites.forEach { rewrite ->
            rewrite.tablePathRenames.forEach { (oldPath, newPath) ->
                require(fileOwners[oldPath] == listOf(rewrite.request.resourceId)) {
                    "resource ${rewrite.request.resourceId.hexId()} old path $oldPath is missing or shared"
                }
                require(newPath !in allOriginalPaths) {
                    "resource ${rewrite.request.resourceId.hexId()} replacement path $newPath already exists"
                }
            }
        }
    }

    private fun rewriteFileReferences(
        entry: Resources.Entry.Builder,
        pathRenames: Map<String, String>,
    ): Int {
        var changed = 0
        repeat(entry.configValueCount) { index ->
            if (rewriteFileReference(entry.getConfigValueBuilder(index), pathRenames)) changed++
        }
        changed += AaptResourceEntryCompat.updateFlagDisabledConfigValues(entry) { config ->
            rewriteFileReference(config, pathRenames)
        }
        changed += AaptResourceEntryCompat.updateReadwriteConfigValues(entry) { config ->
            rewriteFileReference(config, pathRenames)
        }
        return changed
    }

    private fun rewriteFileReference(
        config: Resources.ConfigValue.Builder,
        pathRenames: Map<String, String>,
    ): Boolean {
        if (!config.hasValue() || !config.value.hasItem() || !config.value.item.hasFile()) return false
        val fileBuilder = config.valueBuilder.itemBuilder.fileBuilder
        val replacement = pathRenames[fileBuilder.path] ?: return false
        fileBuilder.path = replacement
        return true
    }

    private fun indexEntries(table: Resources.ResourceTable): List<IndexedEntry> = buildList {
        table.packageList.forEachIndexed { packageIndex, resourcePackage ->
            require(resourcePackage.hasPackageId()) { "resources.pb package at index $packageIndex has no ID" }
            require(resourcePackage.packageId.id in 0..0xff) { "invalid resources.pb package ID" }
            resourcePackage.typeList.forEachIndexed { typeIndex, type ->
                require(type.hasTypeId()) { "resources.pb type ${type.name} has no ID" }
                require(type.typeId.id in 0..0xff) { "invalid resources.pb type ID" }
                type.entryList.forEachIndexed { entryIndex, entry ->
                    require(entry.hasEntryId()) { "resources.pb entry ${type.name}/${entry.name} has no ID" }
                    require(entry.entryId.id in 0..0xffff) { "invalid resources.pb entry ID" }
                    add(
                        IndexedEntry(
                            packageIndex = packageIndex,
                            typeIndex = typeIndex,
                            entryIndex = entryIndex,
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

    private fun directFileReferences(entry: Resources.Entry): List<String> =
        directFileReferenceRecords(entry).map(FileReferenceRecord::path)

    private fun directFileReferenceRecords(entry: Resources.Entry): List<FileReferenceRecord> =
        allConfigValues(entry).mapNotNull { config ->
            val path = config.takeIf(Resources.ConfigValue::hasValue)
                ?.value
                ?.takeIf(Resources.Value::hasItem)
                ?.item
                ?.takeIf(Resources.Item::hasFile)
                ?.file
                ?.path
                ?: return@mapNotNull null
            FileReferenceRecord(path, config.config)
        }

    private fun allConfigValues(entry: Resources.Entry): List<Resources.ConfigValue> = buildList {
        addAll(entry.configValueList)
        addAll(AaptResourceEntryCompat.flagDisabledConfigValues(entry))
        addAll(AaptResourceEntryCompat.readwriteConfigValues(entry))
    }

    private fun parseTable(bytes: ByteArray): Resources.ResourceTable {
        require(bytes.isNotEmpty()) { "resources.pb is empty" }
        return try {
            Resources.ResourceTable.parseFrom(bytes)
        } catch (failure: InvalidProtocolBufferException) {
            throw IllegalArgumentException("resources.pb is not a valid AAPT2 ResourceTable", failure)
        }
    }

    private fun validName(type: ResourceType, name: String): Boolean = when (type) {
        ResourceType.STYLE -> STYLE_NAME.matches(name)
        ResourceType.LAYOUT,
        ResourceType.DRAWABLE,
        ResourceType.MIPMAP,
        ResourceType.FONT,
        ResourceType.RAW,
        ResourceType.ANIM,
        ResourceType.ANIMATOR,
        ResourceType.XML,
        -> FILE_RESOURCE_NAME.matches(name)
    }

    private data class IndexedEntry(
        val packageIndex: Int,
        val typeIndex: Int,
        val entryIndex: Int,
        val resourceId: Int,
        val typeName: String,
        val entry: Resources.Entry,
    )

    private data class PreparedRewrite(
        val indexed: IndexedEntry,
        val request: ResourceRename,
        val tablePathRenames: Map<String, String>,
        val zipPathRenames: Map<String, String>,
        val pathOnly: Boolean,
    )

    private data class FileReferenceRecord(
        val path: String,
        val config: com.android.aapt.ConfigurationOuterClass.Configuration,
    )

    private data class BundleResourcePath(
        val moduleName: String,
        val directory: String,
        val qualifier: String,
        val extension: String,
        val fileName: String,
        val tablePath: String,
    ) {
        companion object {
            fun parse(path: String, type: ResourceType, expectedName: String?): BundleResourcePath {
                require(path.isNotBlank() && !path.startsWith('/') && '\\' !in path && ".." !in path.split('/')) {
                    "unsafe bundle resource path: $path"
                }
                val parts = path.split('/')
                require(parts.size == 4 && parts[0].isNotBlank() && parts[1] == "res") {
                    "bundle resource path must be <module>/res/<type-qualifier>/<file>: $path"
                }
                val directory = parts[2]
                require(directory == type.directoryName || directory.startsWith("${type.directoryName}-")) {
                    "bundle resource path $path is inconsistent with type ${type.directoryName}"
                }
                val fileName = parts[3]
                val physicalName = fileName.substringBefore('.')
                require(FILE_RESOURCE_NAME.matches(physicalName)) {
                    "bundle resource path $path has an invalid physical basename"
                }
                require(expectedName == null || physicalName == expectedName) {
                    "bundle resource path $path is inconsistent with entry name $expectedName"
                }
                val extension = fileName.removePrefix(physicalName)
                require(extension.matches(EXTENSION)) { "unsupported resource path extension in $path" }
                return BundleResourcePath(
                    moduleName = parts[0],
                    directory = directory,
                    qualifier = directory.removePrefix(type.directoryName).removePrefix("-"),
                    extension = extension,
                    fileName = physicalName,
                    tablePath = parts.drop(1).joinToString("/"),
                )
            }
        }
    }

    private fun Int.hexId(): String = "0x" + toUInt().toString(16).padStart(8, '0')

    private fun String.isCompatibleWith(configQualifier: String): Boolean =
        this == configQualifier || when {
            configQualifier.isEmpty() -> VERSION_QUALIFIER.matches(this)
            else -> removePrefix("$configQualifier-").let { suffix ->
                suffix != this && VERSION_QUALIFIER.matches(suffix)
            }
        }

    companion object {
        private const val RESOURCE_RENAME_SCHEMA = 1
        private val FILE_RESOURCE_NAME = Regex("[a-z][a-z0-9_]*")
        private val PHYSICAL_NOTIFICATION_NAME = Regex("sl_drawable_[a-z]+_[a-z]+_[a-z]+")
        private val STYLE_NAME = Regex("[A-Za-z][A-Za-z0-9_.]*")
        private val EXTENSION = Regex("(?:\\.[A-Za-z0-9.]+)?")
        private val VERSION_QUALIFIER = Regex("v[1-9][0-9]*(?:\\.[0-9]+)?")
        private const val NOTIFICATION_ICON = "icon_notification"
    }
}
