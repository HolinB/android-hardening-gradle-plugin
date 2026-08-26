package com.holin.android.hardening.resources

import java.security.MessageDigest

class ResourceNameAllocator(
    lineageSeed: ByteArray,
    initialAssignments: Collection<ResourceNameAssignment> = emptyList(),
    initialTombstones: Collection<ResourceNameTombstone> = emptyList(),
    internal val candidateFactory: ((ResourceKey, Int) -> String)? = null,
) {
    private val seed = lineageSeed.copyOf()
    private val assignments = initialAssignments.associateBy(ResourceNameAssignment::key).toMutableMap()
    private val tombstones = initialTombstones.toMutableList()

    init {
        require(seed.size == SEED_BYTES) { "resource lineage seed must be exactly $SEED_BYTES bytes" }
        validateState(assignments.values, tombstones)
    }

    fun reconcile(entries: Collection<ResourceInventoryEntry>, generation: Long): ResourceNameAllocation {
        require(generation > 0) { "resource generation must be positive" }
        val groups = validateAndGroup(entries)
        val requestedKeys = groups.keys

        assignments.keys.filter { it !in requestedKeys }.forEach { removedKey ->
            val removed = assignments.remove(removedKey)!!
            tombstones += ResourceNameTombstone(
                type = removed.key.type,
                alias = removed.alias,
                keySha256 = removed.keySha256,
                retiredGeneration = generation,
            )
        }

        requestedKeys.sortedBy(::keyHash).forEach { key ->
            if (key !in assignments) assignments[key] = allocate(key)
        }

        val renames = groups.map { (key, variants) ->
            val alias = assignments.getValue(key).alias
            ResourceRename(
                module = key.module,
                resourceId = key.resourceId,
                type = key.type,
                oldName = key.originalName,
                newName = alias,
                qualifiers = variants.map(ResourceInventoryEntry::qualifier).distinct().sorted(),
                entries = variants.mapNotNull { variant ->
                    variant.aabPath?.let { oldPath ->
                        ResourceEntryRename(
                            qualifier = variant.qualifier,
                            oldPath = oldPath,
                            newPath = renamedPath(oldPath, key.originalName, alias),
                        )
                    }
                }.sortedBy(ResourceEntryRename::oldPath),
            )
        }.sortedWith(compareBy(ResourceRename::type, ResourceRename::module, ResourceRename::resourceId))

        return ResourceNameAllocation(
            report = ResourceRenameReport(renames = renames),
            state = snapshot(generation),
        )
    }

    private fun validateAndGroup(entries: Collection<ResourceInventoryEntry>): Map<ResourceKey, List<ResourceInventoryEntry>> {
        val seenPaths = mutableSetOf<String>()
        val logicalIds = mutableMapOf<Triple<String, ResourceType, String>, Int>()
        val idNames = mutableMapOf<Triple<String, ResourceType, Int>, String>()
        entries.forEach { entry ->
            require(entry.module.isNotBlank()) { "resource module must not be blank" }
            val namePattern = if (entry.type == ResourceType.STYLE) STYLE_NAME else FILE_RESOURCE_NAME
            require(namePattern.matches(entry.name)) { "invalid Android ${entry.type} resource name: ${entry.name}" }
            require(QUALIFIER.matches(entry.qualifier)) { "invalid resource qualifier: ${entry.qualifier}" }
            entry.aabPath?.let { path ->
                require(path.isNotBlank() && !path.startsWith('/') && '\\' !in path && ".." !in path.split('/')) {
                    "unsafe AAB resource path: $path"
                }
                require(seenPaths.add(path)) { "duplicate AAB resource path: $path" }
            }
            val logical = Triple(entry.module, entry.type, entry.name)
            require(logicalIds.putIfAbsent(logical, entry.resourceId) in listOf(null, entry.resourceId)) {
                "qualifier variants for ${entry.module}/${entry.type}/${entry.name} have conflicting resource IDs"
            }
            val byId = Triple(entry.module, entry.type, entry.resourceId)
            require(idNames.putIfAbsent(byId, entry.name) in listOf(null, entry.name)) {
                "resource ID ${entry.resourceId.toUInt().toString(16)} has conflicting names"
            }
        }
        return entries.groupBy { ResourceKey(it.module, it.resourceId, it.type, it.name) }
            .toSortedMap(compareBy(ResourceKey::type, ResourceKey::module, ResourceKey::resourceId, ResourceKey::originalName))
    }

    private fun allocate(key: ResourceKey): ResourceNameAssignment {
        val unavailable = buildSet {
            assignments.values.filter { it.key.type == key.type }.mapTo(this) { it.alias }
            tombstones.filter { it.type == key.type }.mapTo(this) { it.alias }
        }
        repeat(MAX_PROBES) { probe ->
            val candidate = candidateFactory?.invoke(key, probe) ?: defaultCandidate(key, probe)
            require(ALIAS.matches(candidate) && candidate.startsWith("sl_${key.type.directoryName}_")) {
                "invalid allocated ${key.type} resource name: $candidate"
            }
            if (candidate !in unavailable) {
                return ResourceNameAssignment(key, candidate, keyHash(key))
            }
        }
        error("resource name namespace exhausted for ${key.type}")
    }

    private fun defaultCandidate(key: ResourceKey, probe: Int): String {
        val digest = sha256(seed + key.canonicalBytes() + byteArrayOf(0) + probe.toString().toByteArray())
        return "sl_${key.type.directoryName}_${digest.toHex().take(16)}"
    }

    private fun renamedPath(oldPath: String, oldName: String, alias: String): String {
        val slash = oldPath.lastIndexOf('/')
        val fileName = oldPath.substring(slash + 1)
        require(fileName == oldName || fileName.startsWith("$oldName.")) {
            "AAB entry basename $fileName does not match resource name $oldName"
        }
        return oldPath.substring(0, slash + 1) + alias + fileName.removePrefix(oldName)
    }

    private fun snapshot(generation: Long) = ResourceNameState(
        schemaVersion = SCHEMA_VERSION,
        lineageSeedSha256 = sha256(seed).toHex(),
        generation = generation,
        assignments = assignments.values.sortedBy(ResourceNameAssignment::keySha256),
        tombstones = tombstones.sortedWith(compareBy(ResourceNameTombstone::keySha256, ResourceNameTombstone::retiredGeneration)),
    )

    private fun keyHash(key: ResourceKey): String = sha256(seed + key.canonicalBytes()).toHex()

    private fun ResourceKey.canonicalBytes(): ByteArray = listOf(
        module,
        resourceId.toUInt().toString(16),
        type.name,
        originalName,
    ).joinToString("\u0000").toByteArray(Charsets.UTF_8)

    companion object {
        private const val SCHEMA_VERSION = 1
        private const val SEED_BYTES = 32
        private const val MAX_PROBES = 100_000
        private val FILE_RESOURCE_NAME = Regex("[a-z][a-z0-9_]*")
        private val STYLE_NAME = Regex("[A-Za-z][A-Za-z0-9_.]*")
        private val QUALIFIER = Regex("[A-Za-z0-9_-]*")
        private val ALIAS = Regex("[a-z][a-z0-9_]*")

        fun restore(
            lineageSeed: ByteArray,
            state: ResourceNameState,
            candidateFactory: ((ResourceKey, Int) -> String)? = null,
        ): ResourceNameAllocator {
            require(state.schemaVersion == SCHEMA_VERSION) { "unsupported resource name state schema ${state.schemaVersion}" }
            require(state.lineageSeedSha256 == sha256(lineageSeed).toHex()) { "resource lineage seed hash mismatch" }
            require(state.generation > 0) { "resource state generation must be positive" }
            state.assignments.forEach { assignment ->
                require(assignment.keySha256 == sha256(lineageSeed + assignment.key.canonicalBytesStatic()).toHex()) {
                    "resource assignment key hash mismatch"
                }
            }
            return ResourceNameAllocator(lineageSeed, state.assignments, state.tombstones, candidateFactory)
        }

        private fun validateState(
            assignments: Collection<ResourceNameAssignment>,
            tombstones: Collection<ResourceNameTombstone>,
        ) {
            require(assignments.map(ResourceNameAssignment::key).distinct().size == assignments.size) {
                "duplicate resource name assignment"
            }
            val aliases = mutableSetOf<Pair<ResourceType, String>>()
            assignments.forEach { assignment ->
                require(assignment.keySha256.matches(Regex("[0-9a-f]{64}"))) { "invalid assignment key hash" }
                require(ALIAS.matches(assignment.alias)) { "invalid assigned resource name ${assignment.alias}" }
                require(aliases.add(assignment.key.type to assignment.alias)) { "duplicate assigned resource alias ${assignment.alias}" }
            }
            tombstones.forEach { tombstone ->
                require(tombstone.keySha256.matches(Regex("[0-9a-f]{64}"))) { "invalid tombstone key hash" }
                require(tombstone.retiredGeneration > 0) { "invalid tombstone generation" }
                require(ALIAS.matches(tombstone.alias)) { "invalid tombstoned resource name ${tombstone.alias}" }
                require(aliases.add(tombstone.type to tombstone.alias)) { "resource alias conflicts with tombstone ${tombstone.alias}" }
            }
        }

        private fun sha256(bytes: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(bytes)

        private fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }

        private fun ResourceKey.canonicalBytesStatic(): ByteArray = listOf(
            module,
            resourceId.toUInt().toString(16),
            type.name,
            originalName,
        ).joinToString("\u0000").toByteArray(Charsets.UTF_8)
    }
}
