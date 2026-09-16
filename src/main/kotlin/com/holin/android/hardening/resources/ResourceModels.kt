package com.holin.android.hardening.resources

import com.holin.android.hardening.ImageFormat
import java.nio.file.Path

enum class ResourceType(val directoryName: String) {
    LAYOUT("layout"),
    DRAWABLE("drawable"),
    STYLE("style"),
    MIPMAP("mipmap"),
    FONT("font"),
    RAW("raw"),
    ANIM("anim"),
    ANIMATOR("animator"),
    XML("xml"),
}

enum class ResourceOrigin {
    OWNED,
    DEPENDENCY,
    GENERATED,
}

data class ResourceInventoryEntry(
    val module: String,
    val resourceId: Int,
    val type: ResourceType,
    val name: String,
    val qualifier: String = "",
    val aabPath: String? = null,
    val bytes: ByteArray? = null,
    val origin: ResourceOrigin = ResourceOrigin.OWNED,
    val externallyNamed: Boolean = false,
    val notificationIcon: Boolean = false,
    val animation: Boolean = false,
    val webpDiversificationEnabled: Boolean = false,
    val imageFormat: ImageFormat? = null,
    val sourcePath: Path? = null,
    val imageDiversificationEnabled: Boolean = false,
)

data class ResourceKey(
    val module: String,
    val resourceId: Int,
    val type: ResourceType,
    val originalName: String,
)

data class ResourceNameAssignment(
    val key: ResourceKey,
    val alias: String,
    val keySha256: String,
)

data class ResourceNameTombstone(
    val type: ResourceType,
    val alias: String,
    val keySha256: String,
    val retiredGeneration: Long,
)

data class ResourceNameState(
    val schemaVersion: Int,
    val lineageSeedSha256: String,
    val generation: Long,
    val assignments: List<ResourceNameAssignment>,
    val tombstones: List<ResourceNameTombstone>,
)

data class ResourceEntryRename(
    val qualifier: String,
    val oldPath: String,
    val newPath: String,
)

data class ResourceRename(
    val module: String,
    val resourceId: Int,
    val type: ResourceType,
    val oldName: String,
    val newName: String,
    val qualifiers: List<String>,
    val entries: List<ResourceEntryRename>,
)

data class ResourceRenameReport(
    val schemaVersion: Int = 1,
    val renames: List<ResourceRename>,
)

data class ResourceNameAllocation(
    val report: ResourceRenameReport,
    val state: ResourceNameState,
)
