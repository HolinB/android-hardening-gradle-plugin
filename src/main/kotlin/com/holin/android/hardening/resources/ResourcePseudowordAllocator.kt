package com.holin.android.hardening.resources

import com.holin.android.hardening.naming.AliasRequest
import com.holin.android.hardening.naming.PseudowordRegistry
import com.holin.android.hardening.naming.RegistryKey
import com.holin.android.hardening.naming.RegistrySnapshot
import com.holin.android.hardening.naming.SymbolKind

data class ResourcePseudowordAllocation(
    val report: ResourceRenameReport,
    val registry: RegistrySnapshot,
)

class ResourcePseudowordAllocator(
    private val namespace: String,
    private val registry: PseudowordRegistry,
) {
    init {
        require(namespace.isNotBlank()) { "resource namespace must not be blank" }
    }

    fun allocate(inventory: Collection<ResourceInventoryEntry>, generation: Long): ResourcePseudowordAllocation {
        require(generation > 0) { "resource generation must be positive" }
        val groups = inventory.groupBy { Triple(it.module, it.type, it.name) }
        require(groups.isNotEmpty()) { "resource pseudoword allocation requires an owned inventory" }
        groups.values.forEach { variants ->
            require(variants.map(ResourceInventoryEntry::resourceId).distinct().size == 1) {
                "resource qualifier variants have conflicting IDs"
            }
            require(variants.map(ResourceInventoryEntry::notificationIcon).distinct().size == 1) {
                "resource qualifier variants disagree about notification-icon ownership"
            }
            require(variants.mapNotNull(ResourceInventoryEntry::aabPath).distinct().size == variants.mapNotNull(ResourceInventoryEntry::aabPath).size) {
                "resource qualifier variants contain duplicate paths"
            }
        }
        val requests = groups.keys.map { (_, type, name) ->
            val identity = "$namespace/${type.directoryName}/$name"
            AliasRequest(
                RegistryKey(identity, SymbolKind.RESOURCE, type.directoryName),
                "android-resource:${type.directoryName}",
            )
        }
        val aliases = registry.reconcileScoped(requests, generation, setOf(SymbolKind.RESOURCE))
        val renames = groups.map { (logical, variants) ->
            val (module, type, oldName) = logical
            val key = RegistryKey("$namespace/${type.directoryName}/$oldName", SymbolKind.RESOURCE, type.directoryName)
            val physicalName = "sl_${type.directoryName}_${aliases.getValue(key)}"
            val notificationIcon = variants.first().notificationIcon
            require(!notificationIcon || type == ResourceType.DRAWABLE && oldName == NOTIFICATION_ICON) {
                "notification-icon physical renaming requires drawable/$NOTIFICATION_ICON"
            }
            val newName = if (notificationIcon) oldName else physicalName
            ResourceRename(
                module = module,
                resourceId = variants.first().resourceId,
                type = type,
                oldName = oldName,
                newName = newName,
                qualifiers = variants.map(ResourceInventoryEntry::qualifier).distinct().sorted(),
                entries = variants.mapNotNull { variant ->
                    variant.aabPath?.let { oldPath ->
                        ResourceEntryRename(
                            qualifier = variant.qualifier,
                            oldPath = oldPath,
                            newPath = renamedPath(oldPath, oldName, physicalName),
                        )
                    }
                }.sortedBy(ResourceEntryRename::oldPath),
            )
        }.sortedWith(compareBy(ResourceRename::type, ResourceRename::oldName))
        return ResourcePseudowordAllocation(ResourceRenameReport(renames = renames), registry.snapshot(generation))
    }

    private fun renamedPath(oldPath: String, oldName: String, newName: String): String {
        val slash = oldPath.lastIndexOf('/')
        require(slash >= 0) { "invalid AAB resource path $oldPath" }
        val fileName = oldPath.substring(slash + 1)
        require(fileName == oldName || fileName.startsWith("$oldName.")) {
            "AAB resource path does not match $oldName: $oldPath"
        }
        return oldPath.substring(0, slash + 1) + newName + fileName.removePrefix(oldName)
    }

    private companion object {
        const val NOTIFICATION_ICON = "icon_notification"
    }
}
