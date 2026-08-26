package com.holin.android.hardening.state

import com.holin.android.hardening.HardeningNames
import com.holin.android.hardening.naming.RegistrySnapshot
import com.holin.android.hardening.naming.PseudowordRegistry
import com.holin.android.hardening.naming.RegistryCodec
import com.holin.android.hardening.verification.MappingAabCompatibilityVerifier
import com.holin.android.hardening.verification.MappingVerificationReportCodec
import com.holin.android.hardening.verification.R8MappingParser
import java.nio.channels.FileChannel
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.StandardCopyOption.REPLACE_EXISTING
import java.nio.file.StandardCopyOption.ATOMIC_MOVE
import java.nio.file.StandardOpenOption.READ
import java.util.Base64
import java.util.Comparator
import java.util.UUID
import kotlin.io.path.exists
import kotlin.io.path.name
import kotlin.io.path.readBytes
import kotlin.io.path.readText

class StateStore internal constructor(
    private val entropy: EntropySource = SecureEntropySource,
    private val canonicalPayloadHash: (Path) -> String = Sha256::canonicalNode,
    private val atomicFiles: AtomicFiles = AtomicFiles(),
) {
    private val stateCodec = StateJsonCodec()
    private val registryCodec = RegistryCodec()

    fun prepare(request: PrepareRequest): PreparedState {
        validateRequest(request)
        if (request.root.exists()) validateNoSymlinks(request.root)
        require(!request.outputDirectory.exists() || Files.list(request.outputDirectory).use { it.findAny().isEmpty }) {
            "prepare output must be empty: ${request.outputDirectory}"
        }
        val current = request.root.resolve("current")
        var quarantined: Path? = null
        val reusable = if (!current.exists()) {
            null
        } else {
            val inspected = runCatching { inspectCurrent(request.root) }
            if (inspected.isFailure) {
                if (!request.quarantineInvalid) throw IllegalStateException("current state is invalid and quarantineInvalid=false", inspected.exceptionOrNull())
                quarantined = quarantine(request.root, current)
                null
            } else {
                inspected.getOrThrow()
            }
        }

        val identityMatches = reusable == null || reusable.manifest.identity.matches(request.coordinates)
        val selected = if (reusable != null && !identityMatches) {
            if (!request.quarantineInvalid) throw IllegalStateException("current state identity mismatch and quarantineInvalid=false")
            quarantined = quarantine(request.root, current)
            null
        } else {
            reusable
        }
        val historyExists = Files.isDirectory(request.root.resolve("history")) &&
            Files.list(request.root.resolve("history")).use { it.anyMatch { path -> Files.isDirectory(path) && !path.name.startsWith(".tmp-") } }
        val reason = when {
            selected != null -> LineageReason.REUSED_CURRENT
            quarantined != null && reusable != null -> LineageReason.IDENTITY_MISMATCH
            quarantined != null -> LineageReason.CORRUPT_CURRENT
            historyExists -> LineageReason.MISSING_CURRENT
            else -> LineageReason.FIRST_BUILD
        }
        val seed = selected?.seed ?: if (request.reproducibility.derivationMode == SeedDerivationMode.FIXED_SEED) {
            request.reproducibility.newLineageSeed()
        } else {
            entropy.nextBytes("lineage-seed", 32)
        }
        require(seed.size == 32) { "lineage seed entropy must return 32 bytes" }
        val expectedGeneration = selected?.pointer?.generation ?: 0L
        val generation = if (
            selected != null && request.reproducibility.derivationMode == SeedDerivationMode.FIXED_SEED
        ) {
            expectedGeneration
        } else {
            expectedGeneration + 1L
        }
        val lineageId = selected?.manifest?.identity?.lineageId
            ?: request.reproducibility.lineageId
            ?: UUID.randomUUID().toString().lowercase()
        val lineageReset = reason !in setOf(LineageReason.FIRST_BUILD, LineageReason.REUSED_CURRENT)

        Files.createDirectories(request.outputDirectory)
        val mapping = request.outputDirectory.resolve("mapping.txt")
        if (selected == null) Files.writeString(mapping, "") else Files.copy(selected.snapshot.resolve("mapping.txt"), mapping, REPLACE_EXISTING)
        val seedFile = request.outputDirectory.resolve("seed.bin")
        Files.write(seedFile, seed)
        val registrySnapshot = if (selected == null) {
            PseudowordRegistry(seed).snapshot(generation)
        } else {
            val prior = registryCodec.decode(selected.snapshot.resolve("registry.json").readText())
            PseudowordRegistry.restore(seed, prior).snapshot(generation)
        }
        val registry = request.outputDirectory.resolve("registry.json")
        Files.writeString(registry, registryCodec.encode(registrySnapshot))
        val payloadHashes = linkedMapOf(
            "mapping.txt" to Sha256.file(mapping),
            "registry.json" to Sha256.file(registry),
            "seed.bin" to Sha256.file(seedFile),
        )
        val identity = StateIdentity(
            STATE_SCHEMA_VERSION,
            request.coordinates.projectKey,
            request.coordinates.variant,
            request.coordinates.namespace,
            request.coordinates.applicationId,
            request.coordinates.configurationSha256,
            lineageId,
            generation,
            payloadHashes.getValue("seed.bin"),
            payloadHashes,
            lineageReset,
            request.reproducibility.derivationMode,
            request.reproducibility.fixedSeedSha256,
        )
        val manifest = SnapshotManifest(STATE_SCHEMA_VERSION, identity, reason, request.contentSaltSha256)
        Files.writeString(request.outputDirectory.resolve("manifest.json"), stateCodec.encodeManifest(manifest))
        return PreparedState(
            request.root,
            request.coordinates,
            request.outputDirectory,
            identity,
            reason,
            expectedGeneration,
            selected?.pointer?.payloadSha256,
            request.contentSaltSha256,
            quarantined,
            request.keepHistory,
        )
    }

    fun migrateConfiguration(request: StateConfigurationMigrationRequest): StateConfigurationMigrationResult {
        val coordinates = request.targetCoordinates
        HardeningNames.requireProjectKey(coordinates.projectKey)
        HardeningNames.requireVariant(coordinates.variant)
        require(coordinates.namespace.isNotBlank()) { "migration namespace must not be blank" }
        require(coordinates.applicationId.isNotBlank()) { "migration applicationId must not be blank" }
        coordinates.configurationSha256.requireSha("migration target configurationSha256")
        val expected = request.expected
        require(expected.toConfigurationSha256 == coordinates.configurationSha256) {
            "migration descriptor target state configuration does not match the requested configuration"
        }
        require(expected.namespace == coordinates.namespace && expected.applicationId == coordinates.applicationId) {
            "migration descriptor Android identity does not match the requested coordinates"
        }
        require(request.root.exists()) { "migration state root is missing: ${request.root}" }
        validateNoSymlinks(request.root)
        val sourceDomain = CanonicalContentDomain.require(expected.fromContentDomain)
        val targetDomain = CanonicalContentDomain.require(expected.toContentDomain)
        require(targetDomain == CanonicalContentDomain.HOLIN_1_2) {
            "migration target canonical content domain is not the 1.2.0 domain"
        }
        val current = inspectCurrentForMigration(request.root, expected, sourceDomain, targetDomain)
        val identity = current.manifest.identity
        require(
            identity.projectKey == coordinates.projectKey && identity.variant == coordinates.variant &&
                identity.namespace == coordinates.namespace && identity.applicationId == coordinates.applicationId,
        ) { "migration current state identity does not match the requested coordinates" }
        require(identity.lineageId == expected.lineageId) { "migration lineageId differs from its descriptor" }
        require(identity.generation == expected.generation && current.pointer.generation == expected.generation) {
            "migration generation differs from its descriptor"
        }
        val expectedPayloads = linkedMapOf(
            "mapping.txt" to expected.mappingSha256,
            "registry.json" to expected.registrySha256,
            "seed.bin" to expected.seedSha256,
        )
        require(identity.payloadHashes == expectedPayloads) {
            "migration state payload hashes differ from its descriptor"
        }
        require(identity.seedHash == expected.seedSha256) { "migration seed identity differs from its descriptor" }

        if (identity.configurationSha256 == expected.toConfigurationSha256) {
            return StateConfigurationMigrationResult(StateMigrationStatus.ALREADY_MIGRATED, current.pointer)
        }
        require(identity.configurationSha256 == expected.fromConfigurationSha256) {
            "migration source state configuration differs from its descriptor"
        }
        require(current.pointer.payloadSha256 == expected.activePayloadSha256) {
            "migration active payload differs from its descriptor"
        }

        val snapshots = request.root.resolve("current/snapshots")
        val stage = snapshots.resolve(".tmp-migration-${UUID.randomUUID()}")
        val migratedManifest = current.manifest.copy(
            identity = identity.copy(configurationSha256 = expected.toConfigurationSha256),
        )
        try {
            writeSnapshot(
                stage,
                current.snapshot.resolve("mapping.txt"),
                current.snapshot.resolve("registry.json"),
                current.snapshot.resolve("seed.bin"),
                migratedManifest,
            )
            val payloadSha256 = canonicalPayloadHash(stage).requireSha("migrated state payload")
            val snapshotId = "${identity.generation}-$payloadSha256"
            val target = snapshots.resolve(snapshotId)
            publishImmutable(stage, target)
            val pointer = ActivePointer(STATE_SCHEMA_VERSION, identity.generation, snapshotId, payloadSha256)
            atomicFiles.replace(
                request.root.resolve("current/active.json"),
                stateCodec.encodeActive(pointer).toByteArray(Charsets.UTF_8),
            )
            return StateConfigurationMigrationResult(StateMigrationStatus.MIGRATED, pointer)
        } finally {
            if (stage.exists()) deleteTree(stage)
        }
    }

    fun archive(request: ArchiveRequest): ArchiveResult {
        val prepared = request.preparedState
        require(request.versionCode > 0) { "versionCode must be positive" }
        request.aabSha256.requireSha("aabSha256")
        validatePrepared(prepared)
        validateNoSymlinks(prepared.preparedDirectory)
        if (prepared.root.exists()) validateNoSymlinks(prepared.root)

        val mapping = prepared.preparedDirectory.resolve("mapping.txt")
        val registry = prepared.preparedDirectory.resolve("registry.json")
        val seed = prepared.preparedDirectory.resolve("seed.bin")
        require(Files.isRegularFile(mapping) && Files.isRegularFile(registry) && Files.isRegularFile(seed)) {
            "prepared snapshot is incomplete"
        }
        val seedBytes = seed.readBytes()
        require(seedBytes.size == LINEAGE_SEED_BYTES) { "prepared lineage seed must be exactly $LINEAGE_SEED_BYTES bytes" }
        require(Sha256.file(seed) == prepared.identity.seedHash) { "prepared lineage seed hash mismatch" }
        val registrySnapshot = registryCodec.decode(registry.readText())
        require(registrySnapshot.seedSha256 == prepared.identity.seedHash) { "registry lineage seed hash mismatch" }
        require(registrySnapshot.generation == prepared.identity.generation) { "registry generation mismatch" }
        PseudowordRegistry.restore(seedBytes, registrySnapshot)

        val finalGeneration = committedGeneration(prepared, request.aabSha256)
        val finalRegistrySnapshot = registryForCommittedGeneration(prepared, registrySnapshot, finalGeneration)
        val finalRegistryBytes = registryCodec.encode(finalRegistrySnapshot).toByteArray(Charsets.UTF_8)
        val finalPayloadHashes = linkedMapOf(
            "mapping.txt" to Sha256.file(mapping),
            "registry.json" to Sha256.hex(finalRegistryBytes),
            "seed.bin" to Sha256.file(seed),
        )
        val finalIdentity = StateIdentity(
            prepared.identity.schemaVersion,
            prepared.identity.projectKey,
            prepared.identity.variant,
            prepared.identity.namespace,
            prepared.identity.applicationId,
            prepared.identity.configurationSha256,
            prepared.identity.lineageId,
            finalGeneration,
            finalPayloadHashes.getValue("seed.bin"),
            finalPayloadHashes,
            prepared.identity.lineageReset,
            prepared.identity.derivationMode,
            prepared.identity.fixedSeedSha256,
        )
        val manifest = SnapshotManifest(
            STATE_SCHEMA_VERSION,
            finalIdentity,
            prepared.reason,
            prepared.contentSaltSha256,
            request.aabSha256,
        )

        val historyParent = prepared.root.resolve("history")
        Files.createDirectories(historyParent)
        val historyTarget = historyParent.resolve("${request.versionCode}-${request.aabSha256}")
        reusePublishedCurrentIfIdentical(
            prepared,
            historyTarget,
            mapping,
            finalRegistrySnapshot,
            seedBytes,
            manifest,
        )?.let { existing -> return existing }
        val expectedSameAab = expectedSameAabSnapshot(prepared, finalGeneration, request.aabSha256)
        if (expectedSameAab != null) {
            validateSameAabHistory(prepared, historyTarget, request.aabSha256)
            verifySameAabMappingEvidence(request, expectedSameAab, mapping)
            assertGeneration(prepared)
            return publishCurrentOnly(
                prepared,
                historyTarget,
                mapping,
                finalRegistryBytes,
                seed,
                manifest,
            )
        }
        reuseFixedArchiveIfIdentical(
            prepared,
            request.aabSha256,
            historyTarget,
            mapping,
            registry,
            seed,
            manifest,
        )?.let { existing -> return existing }
        assertGeneration(prepared)
        val historyStage = historyParent.resolve(".tmp-${UUID.randomUUID()}")
        writeSnapshot(historyStage, mapping, finalRegistryBytes, seed, manifest)
        publishImmutable(historyStage, historyTarget)

        val snapshots = prepared.root.resolve("current/snapshots")
        Files.createDirectories(snapshots)
        val snapshotStage = snapshots.resolve(".tmp-${UUID.randomUUID()}")
        copyTree(historyTarget, snapshotStage)
        val payloadSha256 = canonicalPayloadHash(snapshotStage)
        val snapshotId = "${finalIdentity.generation}-$payloadSha256"
        val snapshotTarget = snapshots.resolve(snapshotId)
        publishImmutable(snapshotStage, snapshotTarget)

        assertGeneration(prepared)
        val pointer = ActivePointer(STATE_SCHEMA_VERSION, finalIdentity.generation, snapshotId, payloadSha256)
        atomicFiles.replace(prepared.root.resolve("current/active.json"), stateCodec.encodeActive(pointer).toByteArray())
        return ArchiveResult(historyTarget, snapshotTarget, pointer)
    }

    private fun expectedSameAabSnapshot(
        prepared: PreparedState,
        finalGeneration: Long,
        aabSha256: String,
    ): CurrentSnapshot? {
        if (
            prepared.identity.derivationMode != SeedDerivationMode.FIXED_SEED ||
            prepared.expectedGeneration == 0L ||
            finalGeneration != prepared.expectedGeneration + 1L
        ) {
            return null
        }
        val expected = inspectExpectedSnapshot(prepared)
        return expected.takeIf { snapshot -> snapshot.manifest.aabSha256 == aabSha256 }
    }

    private fun verifySameAabMappingEvidence(
        request: ArchiveRequest,
        expected: CurrentSnapshot,
        candidateMapping: Path,
    ) {
        val prepared = request.preparedState
        val evidence = requireNotNull(request.mappingVerificationEvidence) {
            "same-AAB state change requires DEX-backed schema-2 PASS evidence"
        }
        require(Files.isRegularFile(evidence.hardenedAab, LinkOption.NOFOLLOW_LINKS)) {
            "same-AAB evidence hardened AAB is missing"
        }
        require(Files.isRegularFile(evidence.schema2PassingReport, LinkOption.NOFOLLOW_LINKS)) {
            "same-AAB schema-2 PASS evidence report is missing"
        }
        require(!Files.isSymbolicLink(evidence.hardenedAab) && !Files.isSymbolicLink(evidence.schema2PassingReport)) {
            "same-AAB evidence must not use symlinks"
        }
        val actualAabSha256 = Sha256.file(evidence.hardenedAab)
        require(actualAabSha256 == request.aabSha256) {
            "same-AAB evidence identifies a different actual/requested AAB"
        }
        val provenance = MappingVerificationReportCodec.decodePassingProvenance(
            SafeStateFile.readUtf8(evidence.schema2PassingReport, MAX_MAPPING_VERIFICATION_REPORT_BYTES),
        )
        val expectedMapping = expected.snapshot.resolve("mapping.txt")
        val expectedMappingSha256 = Sha256.file(expectedMapping)
        val candidateMappingSha256 = Sha256.file(candidateMapping)
        require(provenance.variant == prepared.coordinates.variant) {
            "same-AAB schema-2 PASS evidence identifies a different variant"
        }
        require(provenance.activeMappingSha256 == expectedMappingSha256) {
            "same-AAB schema-2 PASS evidence identifies a different active mapping"
        }
        require(
            provenance.currentMappingSha256 == candidateMappingSha256 &&
                provenance.preparedMappingSha256 == candidateMappingSha256,
        ) {
            "same-AAB schema-2 PASS evidence identifies a different candidate mapping"
        }
        require(provenance.hardenedAabSha256 == actualAabSha256) {
            "same-AAB schema-2 PASS evidence identifies a different hardened AAB"
        }
        require(provenance.contentSaltSha256 == prepared.contentSaltSha256) {
            "same-AAB schema-2 PASS evidence belongs to a different invocation"
        }
        require(
            provenance.fixedSeedProvided &&
                provenance.fixedSeedHash == prepared.identity.fixedSeedSha256,
        ) {
            "same-AAB schema-2 PASS evidence has a different reproducibility identity"
        }
        val parser = R8MappingParser()
        val compatibility = MappingAabCompatibilityVerifier().verify(
            evidence.hardenedAab,
            parser.parse(expectedMapping, null),
            parser.parse(candidateMapping, null),
        )
        require(compatibility.verified) { compatibility.violations.joinToString("; ") }
    }

    private fun validateSameAabHistory(
        prepared: PreparedState,
        historyTarget: Path,
        aabSha256: String,
    ): SnapshotContents {
        val history = inspectSnapshotContents(historyTarget)
        require(history.manifest.aabSha256 == aabSha256) {
            "same-AAB immutable history identifies a different AAB"
        }
        require(history.manifest.identity.matches(prepared.coordinates)) {
            "same-AAB immutable history identifies different coordinates"
        }
        require(history.manifest.identity.lineageId == prepared.identity.lineageId) {
            "same-AAB immutable history identifies a different lineage"
        }
        return history
    }

    private fun publishCurrentOnly(
        prepared: PreparedState,
        historyTarget: Path,
        mapping: Path,
        registry: ByteArray,
        seed: Path,
        manifest: SnapshotManifest,
    ): ArchiveResult {
        val snapshots = prepared.root.resolve("current/snapshots")
        Files.createDirectories(snapshots)
        val snapshotStage = snapshots.resolve(".tmp-${UUID.randomUUID()}")
        writeSnapshot(snapshotStage, mapping, registry, seed, manifest)
        val payloadSha256 = canonicalPayloadHash(snapshotStage)
        val snapshotId = "${manifest.identity.generation}-$payloadSha256"
        val snapshotTarget = snapshots.resolve(snapshotId)
        publishImmutable(snapshotStage, snapshotTarget)
        assertGeneration(prepared)
        val pointer = ActivePointer(STATE_SCHEMA_VERSION, manifest.identity.generation, snapshotId, payloadSha256)
        atomicFiles.replace(prepared.root.resolve("current/active.json"), stateCodec.encodeActive(pointer).toByteArray())
        return ArchiveResult(historyTarget, snapshotTarget, pointer)
    }

    internal fun committedGeneration(prepared: PreparedState, aabSha256: String): Long {
        validatePrepared(prepared)
        aabSha256.requireSha("aabSha256")
        if (
            prepared.identity.derivationMode != SeedDerivationMode.FIXED_SEED ||
            prepared.expectedGeneration == 0L
        ) {
            return prepared.identity.generation
        }
        val expected = inspectExpectedSnapshot(prepared)
        require(expected.manifest.identity.matches(prepared.coordinates)) {
            "prepared expected snapshot identity differs from its coordinates"
        }
        val candidateContent = committedContentIdentity(
            prepared.identity,
            prepared.contentSaltSha256,
            aabSha256,
            prepared.preparedDirectory,
        )
        val expectedContent = committedContentIdentity(
            expected.manifest.identity,
            expected.manifest.contentSaltSha256,
            expected.manifest.aabSha256,
            expected.snapshot,
        )
        return if (candidateContent == expectedContent) {
            prepared.expectedGeneration
        } else {
            prepared.expectedGeneration + 1L
        }
    }

    private fun committedContentIdentity(
        identity: StateIdentity,
        contentSaltSha256: String,
        aabSha256: String?,
        snapshot: Path,
    ): CommittedStateContentIdentity {
        val mapping = snapshot.resolve("mapping.txt")
        val registryPath = snapshot.resolve("registry.json")
        val seed = snapshot.resolve("seed.bin")
        require(Files.isRegularFile(mapping) && Files.isRegularFile(registryPath) && Files.isRegularFile(seed)) {
            "committed state payload is incomplete"
        }
        val seedBytes = seed.readBytes()
        require(seedBytes.size == LINEAGE_SEED_BYTES) { "committed lineage seed must be exactly $LINEAGE_SEED_BYTES bytes" }
        require(Sha256.hex(seedBytes) == identity.seedHash) { "committed lineage seed hash mismatch" }
        val registry = registryCodec.decode(registryPath.readText())
        require(registry.seedSha256 == identity.seedHash) { "committed registry seed hash mismatch" }
        require(registry.generation == identity.generation) { "committed registry generation mismatch" }
        PseudowordRegistry.restore(seedBytes, registry)
        return committedContentIdentity(
            identity,
            contentSaltSha256,
            aabSha256,
            Sha256.file(mapping),
            registry,
            Sha256.file(seed),
        )
    }

    private fun committedContentIdentity(
        identity: StateIdentity,
        contentSaltSha256: String,
        aabSha256: String?,
        mappingSha256: String,
        registry: RegistrySnapshot,
        seedPayloadSha256: String,
    ): CommittedStateContentIdentity {
        require(identity.seedHash == seedPayloadSha256) { "committed lineage seed hash mismatch" }
        require(registry.seedSha256 == identity.seedHash) { "committed registry seed hash mismatch" }
        require(registry.generation == identity.generation) { "committed registry generation mismatch" }
        return CommittedStateContentIdentity(
            identity.schemaVersion,
            identity.projectKey,
            identity.variant,
            identity.namespace,
            identity.applicationId,
            identity.configurationSha256,
            identity.lineageId,
            identity.seedHash,
            identity.derivationMode,
            identity.fixedSeedSha256,
            contentSaltSha256,
            aabSha256,
            mappingSha256,
            canonicalRegistryContentSha256(registry),
            seedPayloadSha256,
        )
    }

    private fun canonicalRegistryContentSha256(registry: RegistrySnapshot): String {
        val canonical = RegistrySnapshot(
            registry.schemaVersion,
            registry.seedSha256,
            1L,
            registry.assignments.sortedBy { assignment -> assignment.keyHash },
            registry.tombstones.map { tombstone ->
                tombstone.copy(
                    tombstone.namespace,
                    tombstone.kind,
                    tombstone.alias,
                    tombstone.keyHash,
                    1L,
                )
            }.sortedBy { tombstone ->
                listOf(tombstone.keyHash, tombstone.namespace, tombstone.kind.name, tombstone.alias)
                    .joinToString("\u0000")
            },
        )
        return Sha256.hex(registryCodec.encode(canonical).toByteArray(Charsets.UTF_8))
    }

    internal fun registryForCommittedGeneration(
        prepared: PreparedState,
        registry: RegistrySnapshot,
        generation: Long,
    ): RegistrySnapshot {
        validatePrepared(prepared)
        require(registry.seedSha256 == prepared.identity.seedHash) {
            "prepared registry belongs to another lineage"
        }
        require(registry.generation == prepared.identity.generation) {
            "prepared registry generation differs from prepared state"
        }
        if (generation == registry.generation) return registry
        require(
            prepared.identity.derivationMode == SeedDerivationMode.FIXED_SEED &&
                prepared.expectedGeneration > 0L &&
                generation == prepared.expectedGeneration + 1L,
        ) { "committed registry generation differs from prepared state" }
        val priorRegistry = registryCodec.decode(
            inspectExpectedSnapshot(prepared).snapshot.resolve("registry.json").readText(),
        )
        val priorTombstones = priorRegistry.tombstones.mapTo(linkedSetOf()) { tombstone ->
            listOf(tombstone.namespace, tombstone.kind.name, tombstone.alias, tombstone.keyHash)
        }
        val tombstones = registry.tombstones.map { tombstone ->
            val identity = listOf(tombstone.namespace, tombstone.kind.name, tombstone.alias, tombstone.keyHash)
            if (identity in priorTombstones) {
                tombstone
            } else {
                require(tombstone.retiredGeneration == prepared.identity.generation) {
                    "new registry tombstone generation differs from prepared state"
                }
                tombstone.copy(
                    tombstone.namespace,
                    tombstone.kind,
                    tombstone.alias,
                    tombstone.keyHash,
                    generation,
                )
            }
        }
        return RegistrySnapshot(
            registry.schemaVersion,
            registry.seedSha256,
            generation,
            registry.assignments,
            tombstones,
        )
    }

    fun readActivePointer(root: Path): ActivePointer =
        readActivePointerOrNull(root) ?: throw IllegalStateException("active pointer is missing under $root")

    fun readArchivedMapping(
        root: Path,
        projectKey: String,
        variant: String,
        aabSha256: String,
        allowLegacyUnboundAab: Boolean = false,
    ): String {
        HardeningNames.requireProjectKey(projectKey)
        HardeningNames.requireVariant(variant)
        aabSha256.requireSha("aabSha256")
        require(Files.isDirectory(root, LinkOption.NOFOLLOW_LINKS)) { "hardening state root is missing: $root" }
        validateNoSymlinks(root)
        val history = root.resolve("history")
        require(Files.isDirectory(history, LinkOption.NOFOLLOW_LINKS)) { "hardening history is missing: $history" }
        val targetPattern = Regex("^[1-9][0-9]*-${Regex.escape(aabSha256)}$")
        val matches = Files.list(history).use { entries ->
            entries.filter { entry ->
                Files.isDirectory(entry, LinkOption.NOFOLLOW_LINKS) && targetPattern.matches(entry.fileName.toString())
            }.toList()
        }
        require(matches.size == 1) {
            "hardening history must contain exactly one mapping for AAB $aabSha256"
        }
        val snapshot = matches.single()
        val expectedFiles = setOf("mapping.txt", "manifest.json", "registry.json", "seed.bin")
        val actualFiles = Files.list(snapshot).use { entries -> entries.map { it.fileName.toString() }.toList().toSet() }
        require(actualFiles == expectedFiles) { "archived snapshot files must be exactly $expectedFiles" }
        val manifest = stateCodec.decodeManifest(
            SafeStateFile.readUtf8(snapshot.resolve("manifest.json"), MAX_MANIFEST_BYTES),
        )
        require(manifest.identity.projectKey == projectKey && manifest.identity.variant == variant) {
            "archived mapping identity does not match $projectKey/$variant"
        }
        require(
            manifest.aabSha256 == aabSha256 ||
                (allowLegacyUnboundAab && manifest.aabSha256 == null),
        ) {
            "archived mapping AAB identity does not match $aabSha256"
        }
        require(manifest.identity.payloadHashes.keys == setOf("mapping.txt", "registry.json", "seed.bin")) {
            "archived mapping payload hashes are incomplete"
        }
        manifest.identity.payloadHashes.forEach { (relative, expected) ->
            require(Sha256.file(snapshot.resolve(relative)) == expected) { "archived $relative hash mismatch" }
        }
        return SafeStateFile.readUtf8(snapshot.resolve("mapping.txt"), MAX_MAPPING_BYTES)
    }

    private fun validateRequest(request: PrepareRequest) {
        HardeningNames.requireProjectKey(request.coordinates.projectKey)
        HardeningNames.requireVariant(request.coordinates.variant)
        require(request.coordinates.namespace.isNotBlank()) { "namespace must not be blank" }
        require(request.coordinates.applicationId.isNotBlank()) { "applicationId must not be blank" }
        request.coordinates.configurationSha256.requireSha("configurationSha256")
        request.contentSaltSha256.requireSha("contentSaltSha256")
        validateReproducibility(request.reproducibility)
        require(request.reusePrevious) { "reusePrevious=false is unsupported in v1" }
        require(request.keepHistory) { "keepHistory=false is unsupported in v1" }
    }

    private fun validatePrepared(prepared: PreparedState) {
        HardeningNames.requireProjectKey(prepared.coordinates.projectKey)
        HardeningNames.requireVariant(prepared.coordinates.variant)
        require(prepared.coordinates.namespace.isNotBlank()) { "prepared namespace must not be blank" }
        require(prepared.coordinates.applicationId.isNotBlank()) { "prepared applicationId must not be blank" }
        prepared.coordinates.configurationSha256.requireSha("prepared configurationSha256")
        require(prepared.identity.matches(prepared.coordinates)) { "prepared identity does not match its coordinates or schema" }
        require(prepared.expectedGeneration >= 0) { "prepared expected generation must not be negative" }
        require(prepared.expectedGeneration < Long.MAX_VALUE) { "prepared expected generation cannot advance without overflow" }
        val requiredPreparedGeneration = if (
            prepared.identity.derivationMode == SeedDerivationMode.FIXED_SEED && prepared.expectedGeneration > 0L
        ) {
            prepared.expectedGeneration
        } else {
            prepared.expectedGeneration + 1L
        }
        require(prepared.identity.generation == requiredPreparedGeneration) {
            "prepared identity generation does not match its derivation mode and expected generation"
        }
        if (prepared.expectedGeneration == 0L) {
            require(prepared.expectedPayloadSha256 == null) { "first/reset generation must not expect an active payload" }
        } else {
            requireNotNull(prepared.expectedPayloadSha256).requireSha("expectedPayloadSha256")
        }
        prepared.identity.seedHash.requireSha("prepared seedHash")
        validateIdentityReproducibility(prepared.identity)
        require(prepared.identity.payloadHashes.keys == setOf("mapping.txt", "registry.json", "seed.bin")) {
            "prepared payload hashes are incomplete"
        }
        prepared.identity.payloadHashes.forEach { (name, hash) -> hash.requireSha("prepared $name hash") }
        prepared.contentSaltSha256.requireSha("prepared contentSaltSha256")
        require(prepared.keepHistory) { "keepHistory=false is unsupported for immutable archive" }
        when (prepared.reason) {
            LineageReason.FIRST_BUILD -> require(
                prepared.expectedGeneration == 0L && !prepared.identity.lineageReset && prepared.quarantinedDirectory == null,
            ) { "FIRST_BUILD prepared lineage invariants are inconsistent" }
            LineageReason.REUSED_CURRENT -> require(
                prepared.expectedGeneration > 0L && !prepared.identity.lineageReset && prepared.quarantinedDirectory == null,
            ) { "REUSED_CURRENT prepared lineage invariants are inconsistent" }
            LineageReason.MISSING_CURRENT -> require(
                prepared.expectedGeneration == 0L && prepared.identity.lineageReset && prepared.quarantinedDirectory == null,
            ) { "MISSING_CURRENT prepared lineage invariants are inconsistent" }
            LineageReason.CORRUPT_CURRENT,
            LineageReason.IDENTITY_MISMATCH,
            -> require(
                prepared.expectedGeneration == 0L && prepared.identity.lineageReset && prepared.quarantinedDirectory != null,
            ) { "quarantined prepared lineage invariants are inconsistent" }
        }
    }

    private fun inspectCurrent(
        root: Path,
        domain: CanonicalContentDomain = CanonicalContentDomain.HOLIN_1_2,
    ): CurrentSnapshot {
        val current = root.resolve("current")
        require(Files.isDirectory(current, LinkOption.NOFOLLOW_LINKS)) { "current is not a directory" }
        val currentEntries = Files.list(current).use { entries -> entries.map { it.fileName.toString() }.toList().toSet() }
        require(currentEntries == setOf("active.json", "snapshots")) {
            "current entries must be exactly active.json and snapshots"
        }
        val pointer = stateCodec.decodeActive(SafeStateFile.readUtf8(current.resolve("active.json"), MAX_ACTIVE_POINTER_BYTES))
        val snapshot = current.resolve("snapshots").resolve(pointer.snapshotId).normalize()
        require(snapshot.startsWith(current.resolve("snapshots").normalize())) { "snapshot path escapes current" }
        return inspectSnapshot(pointer, snapshot, domain)
    }

    private fun inspectCurrentForMigration(
        root: Path,
        expected: PortableStateIdentityMigration,
        sourceDomain: CanonicalContentDomain,
        targetDomain: CanonicalContentDomain,
    ): CurrentSnapshot {
        val current = root.resolve("current")
        require(Files.isDirectory(current, LinkOption.NOFOLLOW_LINKS)) { "current is not a directory" }
        val currentEntries = Files.list(current).use { entries -> entries.map { it.fileName.toString() }.toList().toSet() }
        require(currentEntries == setOf("active.json", "snapshots")) {
            "current entries must be exactly active.json and snapshots"
        }
        val pointer = stateCodec.decodeActive(SafeStateFile.readUtf8(current.resolve("active.json"), MAX_ACTIVE_POINTER_BYTES))
        val snapshots = current.resolve("snapshots").normalize()
        val snapshot = snapshots.resolve(pointer.snapshotId).normalize()
        require(snapshot.startsWith(snapshots)) { "snapshot path escapes current" }
        val configurationSha256 = inspectSnapshotContents(snapshot).manifest.identity.configurationSha256
        val domain = when (configurationSha256) {
            expected.fromConfigurationSha256 -> sourceDomain
            expected.toConfigurationSha256 -> targetDomain
            else -> throw IllegalArgumentException("migration source state configuration differs from its descriptor")
        }
        return inspectSnapshot(pointer, snapshot, domain)
    }

    private fun inspectExpectedSnapshot(prepared: PreparedState): CurrentSnapshot {
        val payloadSha256 = requireNotNull(prepared.expectedPayloadSha256) {
            "prepared state does not identify an expected snapshot"
        }
        val snapshotId = "${prepared.expectedGeneration}-$payloadSha256"
        val snapshots = prepared.root.resolve("current/snapshots").normalize()
        val snapshot = snapshots.resolve(snapshotId).normalize()
        require(snapshot.startsWith(snapshots)) { "expected snapshot path escapes current" }
        return inspectSnapshot(
            ActivePointer(STATE_SCHEMA_VERSION, prepared.expectedGeneration, snapshotId, payloadSha256),
            snapshot,
        )
    }

    private fun inspectSnapshot(
        pointer: ActivePointer,
        snapshot: Path,
        domain: CanonicalContentDomain = CanonicalContentDomain.HOLIN_1_2,
    ): CurrentSnapshot {
        val contents = inspectSnapshotContents(snapshot)
        val payloadSha256 = if (domain == CanonicalContentDomain.HOLIN_1_2) {
            canonicalPayloadHash(snapshot)
        } else {
            Sha256.canonicalNode(snapshot, domain)
        }
        require(payloadSha256 == pointer.payloadSha256) { "active snapshot payload hash mismatch" }
        require(contents.manifest.identity.generation == pointer.generation) { "manifest generation mismatch" }
        return CurrentSnapshot(pointer, snapshot, contents.manifest, contents.seed, contents.registry)
    }

    private fun inspectSnapshotContents(snapshot: Path): SnapshotContents {
        require(Files.isDirectory(snapshot, LinkOption.NOFOLLOW_LINKS)) { "state snapshot is missing" }
        validateNoSymlinks(snapshot)
        val expectedFiles = setOf("mapping.txt", "manifest.json", "registry.json", "seed.bin")
        val actualFiles = Files.list(snapshot).use { stream -> stream.map { it.fileName.toString() }.toList().toSet() }
        require(actualFiles == expectedFiles) { "state snapshot files must be exactly $expectedFiles" }
        val manifest = stateCodec.decodeManifest(snapshot.resolve("manifest.json").readText())
        require(manifest.identity.payloadHashes.keys == setOf("mapping.txt", "registry.json", "seed.bin")) { "manifest payload hashes are incomplete" }
        manifest.identity.payloadHashes.forEach { (relative, expected) ->
            require(Sha256.file(snapshot.resolve(relative)) == expected) { "$relative hash mismatch" }
        }
        val seed = snapshot.resolve("seed.bin").readBytes()
        require(seed.size == LINEAGE_SEED_BYTES) { "lineage seed must be exactly $LINEAGE_SEED_BYTES bytes" }
        require(Sha256.hex(seed) == manifest.identity.seedHash) { "lineage seed hash mismatch" }
        val registry = registryCodec.decode(snapshot.resolve("registry.json").readText())
        require(registry.seedSha256 == manifest.identity.seedHash) { "registry seed hash mismatch" }
        require(registry.generation == manifest.identity.generation) { "registry generation mismatch" }
        PseudowordRegistry.restore(seed, registry)
        return SnapshotContents(manifest, seed, registry)
    }

    private fun assertGeneration(prepared: PreparedState) {
        val actual = readActivePointerOrNull(prepared.root)
        if (prepared.expectedGeneration == 0L) {
            if (actual != null) throw GenerationConflictException("expected no active generation but found ${actual.generation}")
        } else if (actual == null || actual.generation != prepared.expectedGeneration || actual.payloadSha256 != prepared.expectedPayloadSha256) {
            throw GenerationConflictException(
                "prepared generation ${prepared.expectedGeneration}/${prepared.expectedPayloadSha256} is stale; " +
                    "active=${actual?.generation}/${actual?.payloadSha256}",
            )
        }
    }

    private fun readActivePointerOrNull(root: Path): ActivePointer? {
        val active = root.resolve("current/active.json")
        return if (Files.exists(active, LinkOption.NOFOLLOW_LINKS)) {
            stateCodec.decodeActive(SafeStateFile.readUtf8(active, MAX_ACTIVE_POINTER_BYTES))
        } else {
            null
        }
    }

    private fun quarantine(root: Path, current: Path): Path {
        val digest = canonicalPayloadHash(current).requireSha("quarantine payload")
        val target = root.resolve("quarantine").resolve(digest)
        if (Files.isRegularFile(current, LinkOption.NOFOLLOW_LINKS)) {
            return quarantineFile(current, target)
        }
        if (target.exists()) {
            require(Files.isDirectory(target, LinkOption.NOFOLLOW_LINKS)) {
                "quarantine SHA-256 collision at $target; existing target is not a directory"
            }
            if (!treesEqual(current, target)) {
                throw IllegalStateException("quarantine SHA-256 collision at $target; existing bytes differ")
            }
            deleteTree(current)
        } else {
            atomicFiles.publishDirectory(current, target)
        }
        return target
    }

    private fun quarantineFile(current: Path, target: Path): Path {
        val payload = target.resolve("payload")
        if (target.exists()) {
            require(Files.isDirectory(target, LinkOption.NOFOLLOW_LINKS)) {
                "quarantine SHA-256 collision at $target; existing target is not a directory"
            }
            val entries = relativeEntries(target)
            if (entries != listOf("f:payload") || !current.readBytes().contentEquals(payload.readBytes())) {
                throw IllegalStateException("quarantine SHA-256 collision at $target; existing bytes differ")
            }
            Files.delete(current)
            return target
        }
        val quarantine = target.parent
        Files.createDirectories(quarantine)
        val stage = quarantine.resolve(".tmp-${UUID.randomUUID()}")
        val stagedPayload = stage.resolve("payload")
        Files.createDirectory(stage)
        try {
            Files.move(current, stagedPayload, ATOMIC_MOVE)
            try {
                atomicFiles.publishDirectory(stage, target)
            } catch (failure: Throwable) {
                try {
                    Files.move(stagedPayload, current, ATOMIC_MOVE)
                    Files.deleteIfExists(stage)
                } catch (rollbackFailure: Throwable) {
                    failure.addSuppressed(rollbackFailure)
                    throw IllegalStateException(
                        "quarantine publish and rollback failed; invalid payload is preserved at $stagedPayload",
                        failure,
                    )
                }
                throw failure
            }
        } catch (failure: Throwable) {
            if (stage.exists() && (current.exists() || !stagedPayload.exists())) deleteTree(stage)
            throw failure
        }
        return target
    }

    private fun publishImmutable(stage: Path, target: Path) {
        if (target.exists()) {
            if (!treesEqual(stage, target)) {
                deleteTree(stage)
                throw IllegalStateException("immutable state collision at $target; existing bytes differ")
            }
            deleteTree(stage)
        } else {
            atomicFiles.publishDirectory(stage, target)
        }
    }

    private fun writeSnapshot(stage: Path, mapping: Path, registry: Path, seed: Path, manifest: SnapshotManifest) {
        writeSnapshot(stage, mapping, registry.readBytes(), seed, manifest)
    }

    private fun writeSnapshot(stage: Path, mapping: Path, registry: ByteArray, seed: Path, manifest: SnapshotManifest) {
        Files.createDirectory(stage)
        copyAndForce(mapping, stage.resolve("mapping.txt"))
        val registryPath = stage.resolve("registry.json")
        Files.write(registryPath, registry)
        FileChannel.open(registryPath, READ).use { it.force(true) }
        copyAndForce(seed, stage.resolve("seed.bin"))
        val manifestPath = stage.resolve("manifest.json")
        Files.writeString(manifestPath, stateCodec.encodeManifest(manifest))
        FileChannel.open(manifestPath, READ).use { it.force(true) }
    }

    private fun copyAndForce(source: Path, target: Path) {
        Files.copy(source, target)
        FileChannel.open(target, READ).use { it.force(true) }
    }

    private fun copyTree(source: Path, target: Path) {
        Files.createDirectory(target)
        Files.list(source).use { entries ->
            entries.sorted().forEach { entry -> copyAndForce(entry, target.resolve(entry.fileName.toString())) }
        }
    }

    private fun treesEqual(first: Path, second: Path): Boolean {
        validateNoSymlinks(first)
        validateNoSymlinks(second)
        val firstIsFile = Files.isRegularFile(first, LinkOption.NOFOLLOW_LINKS)
        val secondIsFile = Files.isRegularFile(second, LinkOption.NOFOLLOW_LINKS)
        if (firstIsFile || secondIsFile) return firstIsFile && secondIsFile && first.readBytes().contentEquals(second.readBytes())
        if (!Files.isDirectory(first, LinkOption.NOFOLLOW_LINKS) || !Files.isDirectory(second, LinkOption.NOFOLLOW_LINKS)) return false
        val firstEntries = relativeEntries(first)
        val secondEntries = relativeEntries(second)
        if (firstEntries != secondEntries) return false
        return firstEntries.filter { it.startsWith("f:") }.all { entry ->
            val relative = entry.removePrefix("f:")
            first.resolve(relative).readBytes().contentEquals(second.resolve(relative).readBytes())
        }
    }

    private fun relativeEntries(root: Path): List<String> = Files.walk(root).use { paths ->
        paths.filter { it != root }
            .map { path ->
                val type = when {
                    Files.isDirectory(path, LinkOption.NOFOLLOW_LINKS) -> "d:"
                    Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS) -> "f:"
                    else -> throw IllegalArgumentException("unsupported state entry: $path")
                }
                type + root.relativize(path).toString().replace('\\', '/')
            }
            .sorted()
            .toList()
    }

    private fun validateNoSymlinks(root: Path) {
        require(!Files.isSymbolicLink(root)) { "symlink is not allowed in state: $root" }
        if (!root.exists()) return
        Files.walk(root).use { paths ->
            paths.forEach { path -> require(!Files.isSymbolicLink(path)) { "symlink is not allowed in state: $path" } }
        }
    }

    private fun deleteTree(root: Path) {
        if (!root.exists()) return
        Files.walk(root).use { paths -> paths.sorted(Comparator.reverseOrder()).forEach(Files::delete) }
    }

    private fun StateIdentity.matches(coordinates: StateCoordinates): Boolean =
        schemaVersion in setOf(LEGACY_STATE_SCHEMA_VERSION, STATE_SCHEMA_VERSION) &&
            projectKey == coordinates.projectKey &&
            variant == coordinates.variant &&
            namespace == coordinates.namespace &&
            applicationId == coordinates.applicationId &&
            configurationSha256 == coordinates.configurationSha256

    private fun reuseFixedArchiveIfIdentical(
        prepared: PreparedState,
        aabSha256: String,
        historyTarget: Path,
        mapping: Path,
        registry: Path,
        seed: Path,
        manifest: SnapshotManifest,
    ): ArchiveResult? {
        if (prepared.identity.derivationMode != SeedDerivationMode.FIXED_SEED || !historyTarget.exists()) return null
        val existing = inspectSnapshotContents(historyTarget)
        val existingManifest = existing.manifest
        require(existingManifest.aabSha256 == aabSha256) {
            "immutable state collision at $historyTarget; existing AAB identity differs"
        }
        require(existingManifest.identity.matches(prepared.coordinates)) {
            "immutable state collision at $historyTarget; existing state identity differs"
        }
        require(
            existingManifest.identity.derivationMode == SeedDerivationMode.FIXED_SEED &&
                existingManifest.identity.fixedSeedSha256 == prepared.identity.fixedSeedSha256 &&
                existingManifest.contentSaltSha256 == prepared.contentSaltSha256,
        ) { "immutable state collision at $historyTarget; existing derivation identity differs" }
        require(existingManifest.identity.lineageId == prepared.identity.lineageId) {
            "history lineage identity differs from prepared state"
        }
        val preparedRegistry = registryCodec.decode(registry.readText())
        val committedRegistry = registryForCommittedGeneration(
            prepared,
            preparedRegistry,
            committedGeneration(prepared, aabSha256),
        )
        val candidateContent = committedContentIdentity(
            manifest.identity,
            manifest.contentSaltSha256,
            manifest.aabSha256,
            Sha256.file(mapping),
            committedRegistry,
            Sha256.file(seed),
        )
        val historyContent = committedContentIdentity(
            existingManifest.identity,
            existingManifest.contentSaltSha256,
            existingManifest.aabSha256,
            historyTarget,
        )
        require(
            candidateContent == historyContent,
        ) {
            "immutable state collision at $historyTarget; existing committed content differs"
        }
        if (prepared.expectedGeneration == 0L && prepared.identity.lineageReset) {
            return recoverResetCurrent(prepared, historyTarget, manifest)
        }
        val current = inspectCurrent(prepared.root)
        val currentContent = committedContentIdentity(
            current.manifest.identity,
            current.manifest.contentSaltSha256,
            current.manifest.aabSha256,
            current.snapshot,
        )
        require(historyContent == currentContent) {
            "idempotent fixed-seed history does not match active committed content"
        }
        val reusedExpectedGeneration = current.pointer.generation == prepared.expectedGeneration &&
            current.pointer.payloadSha256 == prepared.expectedPayloadSha256
        val convergedPreparedCommit = current.pointer.generation == prepared.expectedGeneration + 1L
        require(reusedExpectedGeneration || convergedPreparedCommit) {
            "idempotent fixed-seed archive lost its generation CAS"
        }
        return ArchiveResult(historyTarget, current.snapshot, current.pointer)
    }

    private fun reusePublishedCurrentIfIdentical(
        prepared: PreparedState,
        historyTarget: Path,
        mapping: Path,
        registry: RegistrySnapshot,
        seed: ByteArray,
        manifest: SnapshotManifest,
    ): ArchiveResult? {
        if (
            prepared.identity.derivationMode != SeedDerivationMode.FIXED_SEED ||
            prepared.expectedGeneration == 0L ||
            !historyTarget.exists()
        ) {
            return null
        }
        val current = inspectCurrent(prepared.root)
        val currentContent = committedContentIdentity(
            current.manifest.identity,
            current.manifest.contentSaltSha256,
            current.manifest.aabSha256,
            current.snapshot,
        )
        val candidateContent = committedContentIdentity(
            manifest.identity,
            manifest.contentSaltSha256,
            manifest.aabSha256,
            Sha256.file(mapping),
            registry,
            Sha256.hex(seed),
        )
        if (currentContent != candidateContent) return null
        val reusedExpectedGeneration = current.pointer.generation == prepared.expectedGeneration &&
            current.pointer.payloadSha256 == prepared.expectedPayloadSha256
        val convergedPreparedCommit = current.pointer.generation == prepared.expectedGeneration + 1L
        require(reusedExpectedGeneration || convergedPreparedCommit) {
            "idempotent fixed-seed current publication lost its generation CAS"
        }
        val history = validateSameAabHistory(
            prepared,
            historyTarget,
            requireNotNull(current.manifest.aabSha256),
        )
        val historyContent = committedContentIdentity(
            history.manifest.identity,
            history.manifest.contentSaltSha256,
            history.manifest.aabSha256,
            historyTarget,
        )
        if (history.manifest.identity.generation == current.manifest.identity.generation) {
            require(historyContent == currentContent) {
                "idempotent fixed-seed history does not match active committed content"
            }
        }
        return ArchiveResult(historyTarget, current.snapshot, current.pointer)
    }

    private fun recoverResetCurrent(
        prepared: PreparedState,
        historyTarget: Path,
        manifest: SnapshotManifest,
    ): ArchiveResult {
        require(manifest.identity.lineageReset && manifest.lineageReason == prepared.reason) {
            "reset current snapshot manifest does not match prepared lineage reset"
        }
        require(manifest.aabSha256 != null) { "reset current snapshot manifest is not bound to an AAB" }
        assertGeneration(prepared)
        val snapshots = prepared.root.resolve("current/snapshots")
        Files.createDirectories(snapshots)
        val snapshotStage = snapshots.resolve(".tmp-${UUID.randomUUID()}")
        copyTree(historyTarget, snapshotStage)
        atomicFiles.replace(
            snapshotStage.resolve("manifest.json"),
            stateCodec.encodeManifest(manifest).toByteArray(Charsets.UTF_8),
        )
        val payloadSha256 = canonicalPayloadHash(snapshotStage)
        val snapshotId = "${manifest.identity.generation}-$payloadSha256"
        val snapshotTarget = snapshots.resolve(snapshotId)
        publishImmutable(snapshotStage, snapshotTarget)
        assertGeneration(prepared)
        val pointer = ActivePointer(STATE_SCHEMA_VERSION, manifest.identity.generation, snapshotId, payloadSha256)
        atomicFiles.replace(prepared.root.resolve("current/active.json"), stateCodec.encodeActive(pointer).toByteArray())
        return ArchiveResult(historyTarget, snapshotTarget, pointer)
    }

    private fun validateReproducibility(reproducibility: StateReproducibility) {
        when (reproducibility.derivationMode) {
            SeedDerivationMode.SECURE_RANDOM -> require(reproducibility.fixedSeedSha256 == null) {
                "secure-random state must not identify a fixed seed"
            }
            SeedDerivationMode.FIXED_SEED -> {
                requireNotNull(reproducibility.fixedSeedSha256).requireSha("fixedSeedSha256")
                requireNotNull(reproducibility.lineageId) { "fixed-seed state requires deterministic lineage identity" }
                val seed = reproducibility.newLineageSeed()
                try {
                    require(seed.size == LINEAGE_SEED_BYTES) {
                        "fixed-seed lineage seed must be exactly $LINEAGE_SEED_BYTES bytes"
                    }
                } finally {
                    seed.fill(0)
                }
            }
        }
    }

    private fun validateIdentityReproducibility(identity: StateIdentity) {
        when (identity.derivationMode) {
            SeedDerivationMode.SECURE_RANDOM -> require(identity.fixedSeedSha256 == null) {
                "secure-random identity must not identify a fixed seed"
            }
            SeedDerivationMode.FIXED_SEED -> requireNotNull(identity.fixedSeedSha256)
                .requireSha("prepared fixedSeedSha256")
        }
    }

    private fun String.requireSha(label: String): String {
        require(matches(Regex("[0-9a-f]{64}"))) { "$label must be a lowercase SHA-256" }
        return this
    }

    private data class CurrentSnapshot(
        val pointer: ActivePointer,
        val snapshot: Path,
        val manifest: SnapshotManifest,
        val seed: ByteArray,
        val registry: RegistrySnapshot,
    )

    private data class SnapshotContents(
        val manifest: SnapshotManifest,
        val seed: ByteArray,
        val registry: RegistrySnapshot,
    )

    private data class CommittedStateContentIdentity(
        val schemaVersion: Int,
        val projectKey: String,
        val variant: String,
        val namespace: String,
        val applicationId: String,
        val configurationSha256: String,
        val lineageId: String,
        val seedSha256: String,
        val derivationMode: SeedDerivationMode,
        val fixedSeedSha256: String?,
        val contentSaltSha256: String,
        val aabSha256: String?,
        val mappingSha256: String,
        val registryContentSha256: String,
        val seedPayloadSha256: String,
    )

    private companion object {
        const val LINEAGE_SEED_BYTES = 32
        const val MAX_ACTIVE_POINTER_BYTES = 16 * 1024L
        const val MAX_MANIFEST_BYTES = 1024 * 1024L
        const val MAX_MAPPING_BYTES = 512 * 1024 * 1024L
        const val MAX_MAPPING_VERIFICATION_REPORT_BYTES = 4 * 1024 * 1024L
    }
}
