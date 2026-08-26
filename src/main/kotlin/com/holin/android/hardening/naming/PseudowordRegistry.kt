package com.holin.android.hardening.naming

import com.holin.android.hardening.state.HmacSha256
import com.holin.android.hardening.state.Sha256
import java.nio.ByteBuffer
import java.util.Locale

enum class SymbolKind { CLASS, MEMBER, PACKAGE, RESOURCE }

data class RegistryKey(
    val originalIdentity: String,
    val kind: SymbolKind,
    val descriptor: String,
)

data class AliasRequest(
    val key: RegistryKey,
    val namespace: String,
    val predecessorKeys: Set<RegistryKey> = emptySet(),
)

data class AliasNamespace(val namespace: String, val kind: SymbolKind)

data class AliasAllocation(val namespace: String, val alias: String)

data class AliasTombstone(
    val namespace: String,
    val kind: SymbolKind,
    val alias: String,
    val keyHash: String = "0".repeat(64),
    val retiredGeneration: Long = 0,
)

data class RegistryAssignment(
    val key: RegistryKey,
    val namespace: String,
    val alias: String,
    val keyHash: String,
)

data class RegistrySnapshot(
    val schemaVersion: Int,
    val seedSha256: String,
    val generation: Long,
    val assignments: List<RegistryAssignment>,
    val tombstones: List<AliasTombstone>,
)

class PseudowordRegistry(
    lineageSeed: ByteArray,
    initialAssignments: Map<RegistryKey, AliasAllocation> = emptyMap(),
    tombstones: Set<AliasTombstone> = emptySet(),
    internal val candidateFactory: ((AliasRequest, Int) -> String)? = null,
) {
    private val seed = lineageSeed.copyOf()
    private val assignments = initialAssignments.toMutableMap()
    private val retired = tombstones.toMutableSet()

    init {
        require(lineageSeed.size == LINEAGE_SEED_BYTES) { "lineage seed must be exactly $LINEAGE_SEED_BYTES bytes" }
    }

    private fun allocate(request: AliasRequest, reserved: Set<String>): String {
        assignments[request.key]?.let { allocation ->
            require(allocation.namespace == request.namespace) {
                "registry identity ${request.key} was already allocated in namespace ${allocation.namespace}"
            }
            return allocation.alias
        }
        val unavailable = buildSet {
            addAll(reserved.map { aliasCollisionKey(request.key.kind, it) })
            assignments.forEach { (assignedKey, allocation) ->
                if (allocation.namespace == request.namespace && assignedKey.kind == request.key.kind) {
                    add(aliasCollisionKey(request.key.kind, allocation.alias))
                }
            }
            retired.forEach { tombstone ->
                if (tombstone.namespace == request.namespace && tombstone.kind == request.key.kind) {
                    add(aliasCollisionKey(request.key.kind, tombstone.alias))
                }
            }
        }
        repeat(MAX_PROBES) { probe ->
            val candidate = candidateFactory?.invoke(request, probe) ?: candidate(request.key, probe)
            if (aliasCollisionKey(request.key.kind, candidate) !in unavailable) {
                assignments[request.key] = AliasAllocation(request.namespace, candidate)
                return candidate
            }
        }
        error("pseudoword namespace exhausted for ${request.namespace}/${request.key.kind}")
    }

    fun reconcile(requests: Collection<AliasRequest>, generation: Long): Map<RegistryKey, String> {
        return reconcileScoped(requests, generation, SymbolKind.values().toSet())
    }

    fun reconcileScoped(
        requests: Collection<AliasRequest>,
        generation: Long,
        kinds: Set<SymbolKind>,
        reservedAliases: Map<AliasNamespace, Set<String>> = emptyMap(),
    ): Map<RegistryKey, String> {
        require(generation > 0) { "generation must be positive" }
        require(kinds.isNotEmpty()) { "registry reconciliation scope must not be empty" }
        require(requests.all { it.key.kind in kinds }) { "registry request is outside the reconciliation scope" }
        require(reservedAliases.keys.all { it.kind in kinds }) {
            "reserved alias kind is outside reconciliation scope"
        }
        reservedAliases.forEach { (scope, aliases) ->
            require(scope.namespace.isNotBlank()) { "reserved alias namespace must not be blank" }
            aliases.forEach { requireAliasShape(scope.kind, it) }
        }
        assignments.forEach { (key, allocation) ->
            require(
                reservedAliases[AliasNamespace(allocation.namespace, key.kind)].orEmpty().none {
                    aliasCollisionKey(key.kind, it) == aliasCollisionKey(key.kind, allocation.alias)
                },
            ) {
                "persisted registry alias conflicts with a reserved alias: ${allocation.namespace}/${key.kind}/${allocation.alias}"
            }
        }
        retired.forEach { tombstone ->
            require(
                reservedAliases[AliasNamespace(tombstone.namespace, tombstone.kind)].orEmpty().none {
                    aliasCollisionKey(tombstone.kind, it) == aliasCollisionKey(tombstone.kind, tombstone.alias)
                },
            ) {
                "registry tombstone conflicts with a reserved alias: ${tombstone.namespace}/${tombstone.kind}/${tombstone.alias}"
            }
        }
        return reconcileRequests(requests, generation, kinds) { request ->
            allocate(request, reservedAliases[AliasNamespace(request.namespace, request.key.kind)].orEmpty())
        }
    }

    private fun reconcileRequests(
        requests: Collection<AliasRequest>,
        generation: Long,
        kinds: Set<SymbolKind>,
        allocateRequest: (AliasRequest) -> String,
    ): Map<RegistryKey, String> {
        val requestedByKey = linkedMapOf<RegistryKey, AliasRequest>()
        requests.forEach { request ->
            val prior = requestedByKey.putIfAbsent(request.key, request)
            require(
                prior == null ||
                    prior.namespace == request.namespace && prior.predecessorKeys == request.predecessorKeys,
            ) {
                "registry identity ${request.key} requested in multiple namespaces"
            }
        }
        val predecessorClaims = requestedByKey.values.flatMap { request ->
            request.predecessorKeys.filter { it != request.key && it in assignments }.map { it to request }
        }.groupBy({ it.first }, { it.second })
        predecessorClaims.forEach { (predecessor, claims) ->
            require(predecessor.kind in kinds) { "registry predecessor is outside the reconciliation scope" }
            require(claims.size == 1) { "registry predecessor $predecessor is claimed by multiple identities" }
            require(predecessor !in requestedByKey) { "active registry identity cannot be replaced: $predecessor" }
            val request = claims.single()
            val priorAllocation = assignments.getValue(predecessor)
            require(priorAllocation.namespace == request.namespace) {
                "registry predecessor $predecessor belongs to namespace ${priorAllocation.namespace}"
            }
            assignments[request.key]?.let { current ->
                require(current == priorAllocation) { "registry predecessor alias conflicts with ${request.key}" }
            }
        }
        predecessorClaims.forEach { (predecessor, claims) ->
            val request = claims.single()
            val allocation = assignments.remove(predecessor)!!
            assignments.putIfAbsent(request.key, allocation)
        }
        assignments.keys.filter { it.kind in kinds && it !in requestedByKey }.forEach { removedKey ->
            val allocation = assignments.remove(removedKey)!!
            retired += AliasTombstone(
                namespace = allocation.namespace,
                kind = removedKey.kind,
                alias = allocation.alias,
                keyHash = keyHash(removedKey),
                retiredGeneration = generation,
            )
        }
        requestedByKey.values.sortedBy { keyHash(it.key) }.forEach { request -> allocateRequest(request) }
        return requestedByKey.keys.associateWith { assignments.getValue(it).alias }
    }

    fun snapshot(generation: Long): RegistrySnapshot {
        require(generation > 0) { "generation must be positive" }
        return RegistrySnapshot(
            schemaVersion = 1,
            seedSha256 = Sha256.hex(seed),
            generation = generation,
            assignments = assignments.map { (key, allocation) ->
                RegistryAssignment(key, allocation.namespace, allocation.alias, keyHash(key))
            }.sortedBy(RegistryAssignment::keyHash),
            tombstones = retired.sortedWith(compareBy(AliasTombstone::keyHash, AliasTombstone::retiredGeneration)),
        )
    }

    private fun keyHash(key: RegistryKey): String = HmacSha256.hex(seed, key.canonicalBytes())

    private fun candidate(key: RegistryKey, probe: Int): String {
        val identity = key.canonicalBytes() + byteArrayOf(0) + probe.toString().toByteArray(Charsets.UTF_8)
        val digest = HmacSha256.bytes(seed, identity)
        val first = WORDS[index(digest, 0)]
        val second = WORDS[index(digest, 4)]
        val third = WORDS[index(digest, 8)]
        return when (key.kind) {
            SymbolKind.CLASS -> first.title() + second.title() + third.title()
            SymbolKind.MEMBER -> first + second.title() + third.title()
            SymbolKind.PACKAGE -> first + second + third
            SymbolKind.RESOURCE -> "${first}_${second}_${third}"
        }
    }

    private fun index(bytes: ByteArray, offset: Int): Int =
        (ByteBuffer.wrap(bytes, offset, Int.SIZE_BYTES).int.toLong() and 0xffffffffL).rem(WORDS.size).toInt()

    private fun String.title(): String = replaceFirstChar(Char::uppercaseChar)

    private fun RegistryKey.canonicalBytes(): ByteArray = listOf(originalIdentity, kind.name, descriptor)
        .joinToString("\u0000")
        .toByteArray(Charsets.UTF_8)

    companion object {
        private const val MAX_PROBES = 100_000
        private const val LINEAGE_SEED_BYTES = 32
        private val WORDS = listOf(
            "amber", "brisk", "calm", "dawn", "ember", "fable", "gentle", "harbor",
            "ivory", "jade", "kindle", "lunar", "meadow", "noble", "opal", "pearl",
            "quiet", "river", "solar", "tidal", "umber", "velvet", "willow", "xenon",
            "young", "zephyr", "acorn", "birch", "cedar", "drift", "elm", "fern",
        )

        fun restore(lineageSeed: ByteArray, snapshot: RegistrySnapshot): PseudowordRegistry {
            require(snapshot.schemaVersion == 1) { "unsupported registry schema ${snapshot.schemaVersion}" }
            require(snapshot.seedSha256 == Sha256.hex(lineageSeed)) { "registry seed hash mismatch" }
            require(snapshot.generation > 0) { "registry generation must be positive" }
            val seenKeys = mutableSetOf<RegistryKey>()
            val seenKeyHashes = mutableSetOf<String>()
            val unavailableAliases = mutableSetOf<Triple<String, SymbolKind, String>>()
            val assignments = snapshot.assignments.associate { assignment ->
                require(seenKeys.add(assignment.key)) { "duplicate registry identity ${assignment.key}" }
                require(assignment.keyHash == HmacSha256.hex(lineageSeed, assignment.key.canonicalBytesStatic())) {
                    "registry key hash mismatch"
                }
                require(seenKeyHashes.add(assignment.keyHash)) { "duplicate registry key hash ${assignment.keyHash}" }
                require(assignment.namespace.isNotBlank()) { "registry assignment namespace must not be blank" }
                requireAliasShape(assignment.key.kind, assignment.alias)
                require(
                    unavailableAliases.add(
                        Triple(
                            assignment.namespace,
                            assignment.key.kind,
                            aliasCollisionKey(assignment.key.kind, assignment.alias),
                        ),
                    ),
                ) {
                    "duplicate registry alias ${assignment.namespace}/${assignment.key.kind}/${assignment.alias}"
                }
                assignment.key to AliasAllocation(assignment.namespace, assignment.alias)
            }
            val seenTombstones = mutableSetOf<AliasTombstone>()
            snapshot.tombstones.forEach { tombstone ->
                require(tombstone.keyHash.matches(Regex("[0-9a-f]{64}"))) { "tombstone keyHash must be a lowercase SHA-256" }
                require(seenTombstones.add(tombstone)) { "duplicate tombstone record $tombstone" }
                require(tombstone.retiredGeneration in 1..snapshot.generation) { "invalid tombstone retired generation" }
                require(tombstone.namespace.isNotBlank()) { "tombstone namespace must not be blank" }
                requireAliasShape(tombstone.kind, tombstone.alias)
                require(
                    unavailableAliases.add(
                        Triple(tombstone.namespace, tombstone.kind, aliasCollisionKey(tombstone.kind, tombstone.alias)),
                    ),
                ) {
                    "registry alias conflicts with a tombstone: ${tombstone.namespace}/${tombstone.kind}/${tombstone.alias}"
                }
            }
            return PseudowordRegistry(lineageSeed, assignments, snapshot.tombstones.toSet())
        }

        private fun requireAliasShape(kind: SymbolKind, alias: String) {
            val pattern = when (kind) {
                SymbolKind.CLASS -> Regex("[A-Z][A-Za-z0-9]*")
                SymbolKind.MEMBER -> Regex("[a-z][A-Za-z0-9]*")
                SymbolKind.PACKAGE -> Regex("[a-z][a-z0-9]*")
                SymbolKind.RESOURCE -> Regex("[a-z][a-z0-9]*_[a-z0-9_]+")
            }
            require(pattern.matches(alias)) { "invalid $kind alias shape: $alias" }
        }

        private fun aliasCollisionKey(kind: SymbolKind, alias: String): String =
            if (kind == SymbolKind.RESOURCE) alias else alias.lowercase(Locale.ROOT)

        private fun RegistryKey.canonicalBytesStatic(): ByteArray = listOf(originalIdentity, kind.name, descriptor)
            .joinToString("\u0000")
            .toByteArray(Charsets.UTF_8)
    }
}
