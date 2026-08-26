package com.holin.android.hardening.state

import com.holin.android.hardening.naming.AliasRequest
import com.holin.android.hardening.naming.PseudowordRegistry
import com.holin.android.hardening.naming.RegistryCodec
import com.holin.android.hardening.naming.RegistryKey
import com.holin.android.hardening.naming.SymbolKind
import java.nio.file.Files
import java.nio.file.Path
import java.time.Duration
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import kotlin.io.path.createDirectories
import kotlin.io.path.createDirectory
import kotlin.io.path.createSymbolicLinkPointingTo
import kotlin.io.path.exists
import kotlin.io.path.readBytes
import kotlin.io.path.readText
import kotlin.io.path.writeText
import kotlin.test.Test
import kotlin.test.assertContains
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue
import org.junit.jupiter.api.io.TempDir

class StateStoreTest {
    @TempDir
    lateinit var temporary: Path

    private val coordinates = StateCoordinates(
        projectKey = "demo",
        variant = "demoRelease",
        namespace = "com.example.demo.match",
        applicationId = "com.example.demo.match",
        configurationSha256 = CONFIGURATION_SHA256,
    )

    @Test
    fun `first prepare creates only a task snapshot with complete identity and salt hash`() {
        val entropy = RecordingEntropy()
        val store = StateStore(entropy = entropy)
        val root = stateRoot()
        val output = temporary.resolve("prepared")

        val prepared = store.prepare(prepareRequest(output, root = root))

        assertEquals(LineageReason.FIRST_BUILD, prepared.reason)
        assertFalse(prepared.identity.lineageReset)
        assertEquals(STATE_SCHEMA_VERSION, prepared.identity.schemaVersion)
        assertEquals("demo", prepared.identity.projectKey)
        assertEquals("demoRelease", prepared.identity.variant)
        assertEquals("com.example.demo.match", prepared.identity.namespace)
        assertEquals("com.example.demo.match", prepared.identity.applicationId)
        assertEquals(1, prepared.identity.generation)
        assertEquals(64, prepared.identity.seedHash.length)
        assertEquals(64, prepared.contentSaltSha256.length)
        assertEquals(setOf("mapping.txt", "registry.json", "seed.bin"), prepared.identity.payloadHashes.keys)
        assertEquals(prepared.identity.seedHash, Sha256.file(prepared.preparedDirectory.resolve("seed.bin")))
        assertNull(prepared.expectedPayloadSha256)
        assertFalse(root.resolve("current").exists())
        assertFalse(output.resolve("manifest.json").readText().contains("raw-content-salt"))
    }

    @Test
    fun `valid current snapshot is reused and mapping is copied to prepare output`() {
        val store = StateStore()
        val first = store.prepare(prepareRequest(temporary.resolve("prepared-1")))
        first.preparedDirectory.resolve("mapping.txt").writeText("Original -> CalmRiver:\n")
        val archived = store.archive(ArchiveRequest(first, versionCode = 10, aabSha256 = "a".repeat(64)))

        val second = store.prepare(prepareRequest(temporary.resolve("prepared-2")))

        assertEquals(LineageReason.REUSED_CURRENT, second.reason)
        assertEquals(archived.activePointer.generation, second.expectedGeneration)
        assertEquals(archived.activePointer.payloadSha256, second.expectedPayloadSha256)
        assertEquals(first.identity.lineageId, second.identity.lineageId)
        assertEquals("Original -> CalmRiver:\n", second.preparedDirectory.resolve("mapping.txt").readText())
        assertTrue(first.preparedDirectory.resolve("seed.bin").readBytes().contentEquals(second.preparedDirectory.resolve("seed.bin").readBytes()))
    }

    @Test
    fun `fixed seed creates deterministic fresh lineage and archives only hash metadata`() {
        val rawSeed = "fixture-fixed-seed-must-not-leak"
        val reproducibility = fixedReproducibility(rawSeed)
        val first = StateStore().prepare(
            prepareRequest(temporary.resolve("fixed-prepared-1"), temporary.resolve("fixed-store-1"), coordinates, reproducibility),
        )
        val second = StateStore().prepare(
            prepareRequest(temporary.resolve("fixed-prepared-2"), temporary.resolve("fixed-store-2"), coordinates, reproducibility),
        )

        assertEquals(SeedDerivationMode.FIXED_SEED, first.identity.derivationMode)
        assertEquals(reproducibility.fixedSeedSha256, first.identity.fixedSeedSha256)
        assertEquals(first.identity.lineageId, second.identity.lineageId)
        assertTrue(
            first.preparedDirectory.resolve("seed.bin").readBytes()
                .contentEquals(second.preparedDirectory.resolve("seed.bin").readBytes()),
        )
        assertFalse(first.preparedDirectory.resolve("manifest.json").readText().contains(rawSeed))
    }

    @Test
    fun `fixed seed reuses an existing lineage without replacing its stored seed`() {
        val store = StateStore()
        val firstMode = fixedReproducibility("first-fixed-seed")
        val first = store.prepare(prepareRequest(temporary.resolve("fixed-reuse-1"), stateRoot(), coordinates, firstMode))
        store.archive(ArchiveRequest(first, 10, "a".repeat(64)))
        val storedSeed = first.preparedDirectory.resolve("seed.bin").readBytes()
        val secondMode = fixedReproducibility("second-fixed-seed")

        val reused = store.prepare(prepareRequest(temporary.resolve("fixed-reuse-2"), stateRoot(), coordinates, secondMode))

        assertEquals(LineageReason.REUSED_CURRENT, reused.reason)
        assertEquals(first.identity.lineageId, reused.identity.lineageId)
        assertTrue(storedSeed.contentEquals(reused.preparedDirectory.resolve("seed.bin").readBytes()))
        assertEquals(secondMode.fixedSeedSha256, reused.identity.fixedSeedSha256)
    }

    @Test
    fun `preparing the next generation leaves active pointer and immutable history unchanged until archive`() {
        val store = StateStore()
        val first = store.prepare(prepareRequest(temporary.resolve("detached-prepared-1")))
        store.archive(ArchiveRequest(first, versionCode = 10, aabSha256 = "a".repeat(64)))
        val beforeActive = store.readActivePointer(stateRoot())
        val history = stateRoot().resolve("history")
        val beforeHistory = Sha256.canonicalNode(history)
        val beforeEntries = history.toFile().list()!!.sorted()

        val detached = store.prepare(prepareRequest(temporary.resolve("detached-prepared-2")))
        detached.preparedDirectory.resolve("mapping.txt").writeText("Unpublished -> QuietRiver:\n")

        assertEquals(beforeActive, store.readActivePointer(stateRoot()))
        assertEquals(beforeHistory, Sha256.canonicalNode(history))
        assertEquals(beforeEntries, history.toFile().list()!!.sorted())
        assertEquals(beforeActive.generation + 1, detached.identity.generation)
    }

    @Test
    fun `corrupt current is quarantined by canonical whole payload and starts a reset lineage`() {
        val store = StateStore()
        val first = store.prepare(prepareRequest(temporary.resolve("prepared-1")))
        val archived = store.archive(ArchiveRequest(first, 10, "a".repeat(64)))
        archived.snapshotDirectory.resolve("mapping.txt").writeText("tampered")
        val expectedDigest = Sha256.canonicalPayload(stateRoot().resolve("current"))

        val reset = store.prepare(prepareRequest(temporary.resolve("prepared-2")))

        assertEquals(LineageReason.CORRUPT_CURRENT, reset.reason)
        assertTrue(reset.identity.lineageReset)
        assertNotEquals(first.identity.lineageId, reset.identity.lineageId)
        assertEquals(stateRoot().resolve("quarantine").resolve(expectedDigest), reset.quarantinedDirectory)
        assertTrue(reset.quarantinedDirectory!!.resolve("active.json").exists())
        assertFalse(stateRoot().resolve("current").exists())
    }

    @Test
    fun `unexpected current top level entry quarantines the whole current state`() {
        val store = StateStore()
        val first = store.prepare(prepareRequest(temporary.resolve("top-level-prepared-1")))
        store.archive(ArchiveRequest(first, 10, "a".repeat(64)))
        stateRoot().resolve("current/unexpected.txt").writeText("unexpected")

        val reset = store.prepare(prepareRequest(temporary.resolve("top-level-prepared-2")))

        assertEquals(LineageReason.CORRUPT_CURRENT, reset.reason)
        assertTrue(reset.quarantinedDirectory!!.resolve("unexpected.txt").exists())
        assertFalse(stateRoot().resolve("current").exists())
    }

    @Test
    fun `state metadata reader rejects oversized non bounded input`() {
        val oversized = temporary.resolve("oversized-active.json")
        oversized.toFile().writeBytes(ByteArray(1025))

        assertFailsWith<IllegalArgumentException> {
            SafeStateFile.readUtf8(oversized, maxBytes = 1024)
        }
    }

    @Test
    fun `current regular file is quarantined and starts a reset lineage`() {
        val root = stateRoot()
        root.createDirectories()
        root.resolve("current").writeText("broken-current")

        val reset = StateStore().prepare(prepareRequest(temporary.resolve("prepared"), root = root))

        assertEquals(LineageReason.CORRUPT_CURRENT, reset.reason)
        assertTrue(reset.identity.lineageReset)
        assertTrue(Files.isDirectory(reset.quarantinedDirectory))
        assertEquals("broken-current", reset.quarantinedDirectory!!.resolve("payload").readText())
        assertFalse(root.resolve("current").exists())
    }

    @Test
    fun `duplicate fractional and overflowing active generations are quarantined`() {
        val corruptions = listOf(
            { json: String -> json.replace("\"generation\":1,", "\"generation\":1,\"generation\":1,") },
            { json: String -> json.replace("\"generation\":1,", "\"generation\":1.0,") },
            { json: String -> json.replace("\"generation\":1,", "\"generation\":18446744073709551617,") },
        )

        corruptions.forEachIndexed { index, corrupt ->
            val root = temporary.resolve("strict-$index/demo/demoRelease")
            val store = StateStore()
            val first = store.prepare(prepareRequest(temporary.resolve("strict-prepared-$index"), root = root))
            store.archive(ArchiveRequest(first, 10, "a".repeat(64)))
            val active = root.resolve("current/active.json")
            active.writeText(corrupt(active.readText()))

            val reset = store.prepare(prepareRequest(temporary.resolve("strict-reset-$index"), root = root))

            assertEquals(LineageReason.CORRUPT_CURRENT, reset.reason)
            assertTrue(reset.quarantinedDirectory!!.exists())
        }
    }

    @Test
    fun `identity mismatch is quarantined and never reused`() {
        val store = StateStore()
        val first = store.prepare(prepareRequest(temporary.resolve("prepared-1")))
        store.archive(ArchiveRequest(first, 10, "a".repeat(64)))

        val reset = store.prepare(
            prepareRequest(
                temporary.resolve("prepared-2"),
                requestedCoordinates = coordinates.copy(applicationId = "other.app"),
            ),
        )

        assertEquals(LineageReason.IDENTITY_MISMATCH, reset.reason)
        assertTrue(reset.identity.lineageReset)
        assertTrue(reset.quarantinedDirectory!!.exists())
    }

    @Test
    fun `hardening rule fingerprint mismatch quarantines the old mapping lineage`() {
        val store = StateStore()
        val first = store.prepare(prepareRequest(temporary.resolve("rules-prepared-1")))
        store.archive(ArchiveRequest(first, 10, "a".repeat(64)))

        val reset = store.prepare(
            prepareRequest(
                temporary.resolve("rules-prepared-2"),
                requestedCoordinates = coordinates.copy(configurationSha256 = "d".repeat(64)),
            ),
        )

        assertEquals(LineageReason.IDENTITY_MISMATCH, reset.reason)
        assertTrue(reset.identity.lineageReset)
        assertEquals("d".repeat(64), reset.identity.configurationSha256)
        assertTrue(reset.quarantinedDirectory!!.exists())
        assertEquals("", reset.preparedDirectory.resolve("mapping.txt").readText())
    }

    @Test
    fun `constrained migration preserves lineage payloads and history without quarantine`() {
        val store = StateStore()
        val first = store.prepare(prepareRequest(temporary.resolve("migration-prepared-1")))
        first.preparedDirectory.resolve("mapping.txt").writeText("com.example.Bean -> a.b:\n")
        val archived = store.archive(ArchiveRequest(first, 10, "a".repeat(64)))
        val (legacyPointer, oldSnapshot) = moveActiveSnapshotToLegacyDomain(
            archived.activePointer,
            archived.snapshotDirectory,
        )
        val oldManifest = StateJsonCodec().decodeManifest(oldSnapshot.resolve("manifest.json").readText())
        val oldHistorySha256 = Sha256.canonicalPayload(archived.historyDirectory)
        val request = StateConfigurationMigrationRequest(
            stateRoot(),
            coordinates.copy(configurationSha256 = "d".repeat(64)),
            PortableStateIdentityMigration(
                coordinates.namespace,
                coordinates.applicationId,
                CanonicalContentDomain.LEGACY_V1.id,
                CanonicalContentDomain.HOLIN_1_2.id,
                coordinates.configurationSha256,
                "d".repeat(64),
                oldManifest.identity.lineageId,
                legacyPointer.generation,
                legacyPointer.payloadSha256,
                Sha256.file(oldSnapshot.resolve("mapping.txt")),
                Sha256.file(oldSnapshot.resolve("registry.json")),
                Sha256.file(oldSnapshot.resolve("seed.bin")),
            ),
        )

        val migrated = store.migrateConfiguration(request)
        val newSnapshot = stateRoot().resolve("current/snapshots/${migrated.activePointer.snapshotId}")
        val newManifest = StateJsonCodec().decodeManifest(newSnapshot.resolve("manifest.json").readText())

        assertEquals(StateMigrationStatus.MIGRATED, migrated.status)
        assertEquals(archived.activePointer.generation, migrated.activePointer.generation)
        assertNotEquals(archived.activePointer.snapshotId, migrated.activePointer.snapshotId)
        assertEquals(oldManifest.identity.lineageId, newManifest.identity.lineageId)
        assertEquals("d".repeat(64), newManifest.identity.configurationSha256)
        listOf("mapping.txt", "registry.json", "seed.bin").forEach { name ->
            assertEquals(Sha256.file(oldSnapshot.resolve(name)), Sha256.file(newSnapshot.resolve(name)), name)
        }
        assertEquals(oldHistorySha256, Sha256.canonicalPayload(archived.historyDirectory))
        assertFalse(stateRoot().resolve("quarantine").exists())

        val alreadyMigrated = store.migrateConfiguration(request)

        assertEquals(StateMigrationStatus.ALREADY_MIGRATED, alreadyMigrated.status)
        assertEquals(migrated.activePointer, alreadyMigrated.activePointer)
        assertFalse(stateRoot().resolve("quarantine").exists())

        val reused = store.prepare(
            prepareRequest(
                temporary.resolve("migration-prepared-2"),
                requestedCoordinates = coordinates.copy(configurationSha256 = "d".repeat(64)),
            ),
        )
        assertEquals(LineageReason.REUSED_CURRENT, reused.reason)
        assertEquals(oldManifest.identity.lineageId, reused.identity.lineageId)
        assertFalse(reused.identity.lineageReset)
    }

    @Test
    fun `migration descriptor mismatch leaves active state untouched and does not quarantine`() {
        val store = StateStore()
        val first = store.prepare(prepareRequest(temporary.resolve("migration-mismatch-prepared")))
        val archived = store.archive(ArchiveRequest(first, 10, "a".repeat(64)))
        val (legacyPointer, snapshot) = moveActiveSnapshotToLegacyDomain(
            archived.activePointer,
            archived.snapshotDirectory,
        )
        val manifest = StateJsonCodec().decodeManifest(snapshot.resolve("manifest.json").readText())
        val request = StateConfigurationMigrationRequest(
            stateRoot(),
            coordinates.copy(configurationSha256 = "d".repeat(64)),
            PortableStateIdentityMigration(
                coordinates.namespace,
                coordinates.applicationId,
                CanonicalContentDomain.LEGACY_V1.id,
                CanonicalContentDomain.HOLIN_1_2.id,
                coordinates.configurationSha256,
                "d".repeat(64),
                manifest.identity.lineageId,
                legacyPointer.generation,
                legacyPointer.payloadSha256,
                "0".repeat(64),
                Sha256.file(snapshot.resolve("registry.json")),
                Sha256.file(snapshot.resolve("seed.bin")),
            ),
        )

        assertFailsWith<IllegalArgumentException> { store.migrateConfiguration(request) }

        assertEquals(legacyPointer, store.readActivePointer(stateRoot()))
        assertFalse(stateRoot().resolve("quarantine").exists())
    }

    @Test
    fun `legacy manifest without rule fingerprint remains readable for identity reset`() {
        val prepared = StateStore().prepare(prepareRequest(temporary.resolve("legacy-prepared")))
        val encoded = prepared.preparedDirectory.resolve("manifest.json").readText()
        val legacy = encoded
            .replace("\"schemaVersion\":$STATE_SCHEMA_VERSION", "\"schemaVersion\":$LEGACY_STATE_SCHEMA_VERSION")
            .replace(",\"configurationSha256\":\"$CONFIGURATION_SHA256\"", "")
            .replace(",\"derivationMode\":\"SECURE_RANDOM\"", "")

        val decoded = StateJsonCodec().decodeManifest(legacy)

        assertEquals("0".repeat(64), decoded.identity.configurationSha256)
    }

    @Test
    fun `missing current with history starts a reset lineage and never guesses history`() {
        val store = StateStore()
        val first = store.prepare(prepareRequest(temporary.resolve("prepared-1")))
        store.archive(ArchiveRequest(first, 10, "a".repeat(64)))
        deleteTree(stateRoot().resolve("current"))

        val reset = store.prepare(prepareRequest(temporary.resolve("prepared-2")))

        assertEquals(LineageReason.MISSING_CURRENT, reset.reason)
        assertTrue(reset.identity.lineageReset)
        assertEquals("", reset.preparedDirectory.resolve("mapping.txt").readText())
    }

    @Test
    fun `identical existing quarantine is idempotent`() {
        val root = stateRoot()
        val current = root.resolve("current").createDirectories()
        current.resolve("broken.txt").writeText("broken")
        val digest = Sha256.canonicalPayload(current)
        val existing = root.resolve("quarantine").resolve(digest)
        copyTree(current, existing)

        val result = StateStore().prepare(prepareRequest(temporary.resolve("prepared"), root = root))

        assertEquals(existing, result.quarantinedDirectory)
        assertFalse(current.exists())
        assertEquals("broken", existing.resolve("broken.txt").readText())
    }

    @Test
    fun `different quarantine bytes under the same digest are a hard collision`() {
        val root = stateRoot()
        root.resolve("current").createDirectories().resolve("broken.txt").writeText("first")
        root.resolve("quarantine").resolve("f".repeat(64)).createDirectories().resolve("broken.txt").writeText("second")
        val store = StateStore(canonicalPayloadHash = { "f".repeat(64) })

        assertFailsWith<IllegalStateException> {
            store.prepare(prepareRequest(temporary.resolve("prepared"), root = root))
        }
        assertTrue(root.resolve("current/broken.txt").exists())
    }

    @Test
    fun `archive publishes immutable history and snapshot then points active at it`() {
        val store = StateStore()
        val prepared = store.prepare(prepareRequest(temporary.resolve("prepared")))

        val archived = store.archive(ArchiveRequest(prepared, 42, "b".repeat(64)))

        assertEquals(stateRoot().resolve("history/42-${"b".repeat(64)}"), archived.historyDirectory)
        assertEquals(
            stateRoot().resolve("current/snapshots/${archived.activePointer.snapshotId}"),
            archived.snapshotDirectory,
        )
        assertEquals(Sha256.canonicalPayload(archived.snapshotDirectory), archived.activePointer.payloadSha256)
        assertTrue(stateRoot().resolve("current/active.json").readText().contains(archived.activePointer.snapshotId))
        assertTreeEquals(archived.historyDirectory, archived.snapshotDirectory)
    }

    @Test
    fun `identical fixed seed archive is idempotent while changed input advances state`() {
        val store = StateStore()
        val reproducibility = fixedReproducibility("idempotent-fixed-seed")
        val first = store.prepare(prepareRequest(temporary.resolve("fixed-cycle-1"), stateRoot(), coordinates, reproducibility))
        first.preparedDirectory.resolve("mapping.txt").writeText("Original -> CalmRiver:\n")
        val firstArchive = store.archive(ArchiveRequest(first, 42, "b".repeat(64)))
        val beforeHistory = Sha256.canonicalPayload(stateRoot().resolve("history"))

        val repeated = store.prepare(prepareRequest(temporary.resolve("fixed-cycle-2"), stateRoot(), coordinates, reproducibility))
        assertEquals(
            firstArchive.activePointer.generation,
            store.committedGeneration(repeated, "b".repeat(64)),
        )
        val repeatedArchive = store.archive(ArchiveRequest(repeated, 42, "b".repeat(64)))

        assertEquals(firstArchive.activePointer.generation, repeated.identity.generation)
        assertEquals(firstArchive.activePointer, repeatedArchive.activePointer)
        assertEquals(beforeHistory, Sha256.canonicalPayload(stateRoot().resolve("history")))

        val changed = store.prepare(prepareRequest(temporary.resolve("fixed-cycle-3"), stateRoot(), coordinates, reproducibility))
        changed.preparedDirectory.resolve("mapping.txt").writeText("Original -> CalmRiver:\nAdded -> QuietMeadow:\n")
        assertEquals(
            firstArchive.activePointer.generation + 1,
            store.committedGeneration(changed, "c".repeat(64)),
        )
        val changedArchive = store.archive(ArchiveRequest(changed, 43, "c".repeat(64)))

        assertEquals(firstArchive.activePointer.generation + 1, changedArchive.activePointer.generation)
        assertTrue(stateRoot().resolve("history/42-${"b".repeat(64)}").exists())
        assertTrue(stateRoot().resolve("history/43-${"c".repeat(64)}").exists())
    }

    @Test
    fun `same AAB mapping change advances fixed seed committed generation`() {
        val root = temporary.resolve("same-aab-mapping-generation")
        val store = StateStore()
        val reproducibility = fixedReproducibility("same-aab-mapping-generation")
        val aabSha256 = "b".repeat(64)
        val first = store.prepare(prepareRequest(temporary.resolve("same-aab-mapping-first"), root, coordinates, reproducibility))
        first.preparedDirectory.resolve("mapping.txt").writeText("Original -> CalmRiver:\n")
        val firstArchive = store.archive(ArchiveRequest(first, 42, aabSha256))
        val changed = store.prepare(
            prepareRequest(temporary.resolve("same-aab-mapping-changed"), root, coordinates, reproducibility),
        )
        changed.preparedDirectory.resolve("mapping.txt").writeText(
            "Original -> CalmRiver:\nEliminated -> QuietMeadow:\n",
        )

        assertEquals(
            firstArchive.activePointer.generation + 1,
            store.committedGeneration(changed, aabSha256),
        )
    }

    @Test
    fun `same AAB registry change advances fixed seed committed generation`() {
        val root = temporary.resolve("same-aab-registry-generation")
        val store = StateStore()
        val reproducibility = fixedReproducibility("same-aab-registry-generation")
        val aabSha256 = "b".repeat(64)
        val first = store.prepare(prepareRequest(temporary.resolve("same-aab-registry-first"), root, coordinates, reproducibility))
        val firstArchive = store.archive(ArchiveRequest(first, 42, aabSha256))
        val changed = store.prepare(
            prepareRequest(temporary.resolve("same-aab-registry-changed"), root, coordinates, reproducibility),
        )
        val registryPath = changed.preparedDirectory.resolve("registry.json")
        val seed = changed.preparedDirectory.resolve("seed.bin").readBytes()
        val registry = RegistryCodec().decode(registryPath.readText())
        val updated = PseudowordRegistry.restore(seed, registry)
        updated.reconcile(
            listOf(
                AliasRequest(
                    RegistryKey("eliminated.Type", SymbolKind.CLASS, "Leliminated/Type;"),
                    "eliminated",
                ),
            ),
            registry.generation,
        )
        registryPath.writeText(RegistryCodec().encode(updated.snapshot(registry.generation)))

        assertEquals(
            firstArchive.activePointer.generation + 1,
            store.committedGeneration(changed, aabSha256),
        )
    }

    @Test
    fun `matching fixed seed history recovers missing current as a reset snapshot`() {
        assertFixedHistoryRecovery(LineageReason.MISSING_CURRENT) { current ->
            deleteTree(current)
        }
    }

    @Test
    fun `matching fixed seed history recovers quarantined current as a reset snapshot`() {
        assertFixedHistoryRecovery(LineageReason.CORRUPT_CURRENT) { current ->
            current.resolve("unexpected.txt").writeText("force quarantine")
        }
    }

    @Test
    fun `fixed seed reset recovery rejects syntactically valid history payload hash tampering`() {
        assertFixedHistoryManifestTamperingRejected("payload-hash", "mapping.txt hash mismatch") { identity ->
            identity.withRecoveryFields(
                identity.lineageId,
                identity.generation,
                identity.seedHash,
                identity.payloadHashes + ("mapping.txt" to "f".repeat(64)),
            )
        }
    }

    @Test
    fun `fixed seed reset recovery rejects syntactically valid history seed hash tampering`() {
        assertFixedHistoryManifestTamperingRejected("seed-hash", "lineage seed hash mismatch") { identity ->
            identity.withRecoveryFields(
                identity.lineageId,
                identity.generation,
                "f".repeat(64),
                identity.payloadHashes,
            )
        }
    }

    @Test
    fun `fixed seed reset recovery rejects syntactically valid history generation tampering`() {
        assertFixedHistoryManifestTamperingRejected("generation", "registry generation mismatch") { identity ->
            identity.withRecoveryFields(
                identity.lineageId,
                identity.generation + 1,
                identity.seedHash,
                identity.payloadHashes,
            )
        }
    }

    @Test
    fun `fixed seed reset recovery rejects syntactically valid history lineage tampering`() {
        assertFixedHistoryManifestTamperingRejected("lineage", "history lineage identity differs") { identity ->
            identity.withRecoveryFields(
                "tampered-lineage",
                identity.generation,
                identity.seedHash,
                identity.payloadHashes,
            )
        }
    }

    @Test
    fun `concurrent identical fixed seed archives both succeed and converge`() {
        val reproducibility = fixedReproducibility("concurrent-fixed-seed")
        val prepared = listOf(
            StateStore().prepare(
                prepareRequest(temporary.resolve("concurrent-fixed-1"), stateRoot(), coordinates, reproducibility),
            ),
            StateStore().prepare(
                prepareRequest(temporary.resolve("concurrent-fixed-2"), stateRoot(), coordinates, reproducibility),
            ),
        )
        val ready = CountDownLatch(prepared.size)
        val start = CountDownLatch(1)
        val executor = Executors.newFixedThreadPool(prepared.size)
        val lockPath = stateRoot().resolve("locks/concurrent-state.lock")
        try {
            val futures = prepared.mapIndexed { index, state ->
                executor.submit<ArchiveResult> {
                    ready.countDown()
                    check(start.await(5, TimeUnit.SECONDS)) { "concurrent archive start timed out" }
                    StateLock(
                        lockPath,
                        ":concurrent-$index",
                        coordinates.variant,
                        Duration.ofSeconds(5),
                        temporary,
                    ).withLock {
                        StateStore().archive(ArchiveRequest(state, 42, "b".repeat(64)))
                    }
                }
            }
            assertTrue(ready.await(5, TimeUnit.SECONDS), "concurrent archives did not become ready")
            start.countDown()
            val results = futures.map { future -> future.get(10, TimeUnit.SECONDS) }

            assertEquals(1, results.map(ArchiveResult::activePointer).distinct().size)
            assertEquals(results.first().activePointer, StateStore().readActivePointer(stateRoot()))
            assertEquals(1, stateRoot().resolve("history").toFile().list()!!.count { name -> !name.startsWith(".tmp-") })
            assertTreeEquals(results.first().historyDirectory, results.first().snapshotDirectory)
        } finally {
            start.countDown()
            executor.shutdownNow()
        }
    }

    @Test
    fun `archived mapping is resolved by hardened AAB hash and verified before use`() {
        val store = StateStore()
        val prepared = store.prepare(prepareRequest(temporary.resolve("baseline-prepared")))
        val mapping = "com.example.First -> old.pkg.A:\n"
        prepared.preparedDirectory.resolve("mapping.txt").writeText(mapping)
        val aabSha256 = "d".repeat(64)
        val archived = store.archive(ArchiveRequest(prepared, 42, aabSha256))

        assertEquals(
            mapping,
            store.readArchivedMapping(
                stateRoot(),
                coordinates.projectKey,
                coordinates.variant,
                aabSha256,
            ),
        )

        archived.historyDirectory.resolve("mapping.txt").writeText("tampered")
        assertFailsWith<IllegalArgumentException> {
            store.readArchivedMapping(stateRoot(), coordinates.projectKey, coordinates.variant, aabSha256)
        }
    }

    @Test
    fun `legacy archived mapping requires explicit trusted migration`() {
        val store = StateStore()
        val prepared = store.prepare(prepareRequest(temporary.resolve("legacy-baseline-prepared")))
        val mapping = "com.example.Legacy -> old.pkg.L:\n"
        prepared.preparedDirectory.resolve("mapping.txt").writeText(mapping)
        val aabSha256 = "c".repeat(64)
        val archived = store.archive(ArchiveRequest(prepared, 41, aabSha256))
        val manifest = archived.historyDirectory.resolve("manifest.json")
        manifest.writeText(
            manifest.readText().replace(",\"aabSha256\":\"$aabSha256\"", ""),
        )

        assertFailsWith<IllegalArgumentException> {
            store.readArchivedMapping(
                stateRoot(),
                coordinates.projectKey,
                coordinates.variant,
                aabSha256,
            )
        }
        assertEquals(
            mapping,
            store.readArchivedMapping(
                stateRoot(),
                coordinates.projectKey,
                coordinates.variant,
                aabSha256,
                true,
            ),
        )
    }

    @Test
    fun `renamed archived mapping cannot impersonate another hardened AAB`() {
        val store = StateStore()
        val prepared = store.prepare(prepareRequest(temporary.resolve("renamed-baseline-prepared")))
        prepared.preparedDirectory.resolve("mapping.txt").writeText("com.example.First -> old.pkg.A:\n")
        val archivedHash = "e".repeat(64)
        val requestedHash = "d".repeat(64)
        val archived = store.archive(ArchiveRequest(prepared, 42, archivedHash))
        Files.move(
            archived.historyDirectory,
            archived.historyDirectory.resolveSibling("42-$requestedHash"),
        )

        assertFailsWith<IllegalArgumentException> {
            store.readArchivedMapping(
                stateRoot(),
                coordinates.projectKey,
                coordinates.variant,
                requestedHash,
            )
        }
    }

    @Test
    fun `different existing history is never overwritten and current remains absent`() {
        val store = StateStore()
        val prepared = store.prepare(prepareRequest(temporary.resolve("prepared")))
        val history = stateRoot().resolve("history/42-${"b".repeat(64)}").createDirectories()
        history.resolve("different.txt").writeText("do not overwrite")

        assertFailsWith<IllegalStateException> {
            store.archive(ArchiveRequest(prepared, 42, "b".repeat(64)))
        }
        assertEquals("do not overwrite", history.resolve("different.txt").readText())
        assertFalse(stateRoot().resolve("current/active.json").exists())
    }

    @Test
    fun `extra empty directory makes immutable history non identical`() {
        val store = StateStore()
        val prepared = store.prepare(prepareRequest(temporary.resolve("prepared")))
        val first = store.archive(ArchiveRequest(prepared, 42, "b".repeat(64)))
        deleteTree(stateRoot().resolve("current"))
        first.historyDirectory.resolve("unexpected-empty-directory").createDirectory()

        assertFailsWith<IllegalStateException> {
            store.archive(ArchiveRequest(prepared, 42, "b".repeat(64)))
        }
        assertFalse(stateRoot().resolve("current/active.json").exists())
    }

    @Test
    fun `generation CAS rejects a stale prepared state`() {
        val store = StateStore()
        val first = store.prepare(prepareRequest(temporary.resolve("prepared-1")))
        store.archive(ArchiveRequest(first, 1, "a".repeat(64)))
        val second = store.prepare(prepareRequest(temporary.resolve("prepared-2")))
        val stale = store.prepare(prepareRequest(temporary.resolve("prepared-stale")))
        val secondArchive = store.archive(ArchiveRequest(second, 2, "b".repeat(64)))

        assertFailsWith<GenerationConflictException> {
            store.archive(ArchiveRequest(stale, 3, "c".repeat(64)))
        }
        assertEquals(secondArchive.activePointer, store.readActivePointer(stateRoot()))
    }

    @Test
    fun `archive rejects a coordinated prepared generation rollback before publishing`() {
        val store = StateStore()
        var active: ActivePointer? = null
        repeat(5) { index ->
            val prepared = store.prepare(prepareRequest(temporary.resolve("rollback-prepared-$index")))
            active = store.archive(
                ArchiveRequest(prepared, index + 1, ('a'.code + index).toChar().toString().repeat(64)),
            ).activePointer
        }
        val prepared = store.prepare(prepareRequest(temporary.resolve("rollback-attack")))
        val registry = prepared.preparedDirectory.resolve("registry.json")
        registry.writeText(registry.readText().replace("\"generation\":6", "\"generation\":1"))
        val rollback = prepared.copy(identity = prepared.identity.copy(generation = 1))

        assertFailsWith<IllegalArgumentException> {
            store.archive(ArchiveRequest(rollback, 6, "f".repeat(64)))
        }

        assertEquals(5, active!!.generation)
        assertEquals(active, store.readActivePointer(stateRoot()))
        assertFalse(stateRoot().resolve("history/6-${"f".repeat(64)}").exists())
    }

    @Test
    fun `archive rejects a coordinated non 32 byte lineage seed before publishing`() {
        val store = StateStore()
        val prepared = store.prepare(prepareRequest(temporary.resolve("short-seed-prepared")))
        val seed = prepared.preparedDirectory.resolve("seed.bin")
        seed.toFile().writeBytes(ByteArray(31) { 7 })
        val registryPath = prepared.preparedDirectory.resolve("registry.json")
        val codec = RegistryCodec()
        val registry = codec.decode(registryPath.readText()).copy(seedSha256 = Sha256.file(seed))
        registryPath.writeText(codec.encode(registry))
        val corrupt = prepared.copy(
            identity = prepared.identity.copy(
                seedHash = Sha256.file(seed),
                payloadHashes = linkedMapOf(
                    "mapping.txt" to Sha256.file(prepared.preparedDirectory.resolve("mapping.txt")),
                    "registry.json" to Sha256.file(registryPath),
                    "seed.bin" to Sha256.file(seed),
                ),
            ),
        )

        assertFailsWith<IllegalArgumentException> {
            store.archive(ArchiveRequest(corrupt, 1, "a".repeat(64)))
        }

        assertFalse(stateRoot().resolve("history/1-${"a".repeat(64)}").exists())
    }

    @Test
    fun `prepare uses the supplied invocation content salt hash without inventing another`() {
        val store = StateStore()

        val first = store.prepare(prepareRequest(temporary.resolve("prepared-1")))
        val second = store.prepare(prepareRequest(temporary.resolve("prepared-2")))

        assertEquals(CONTENT_SALT_SHA256, first.contentSaltSha256)
        assertEquals(first.contentSaltSha256, second.contentSaltSha256)
        assertFalse(first.preparedDirectory.resolve("manifest.json").readText().contains("raw-content-salt"))
    }

    @Test
    fun `state symlinks are rejected without following or quarantining them`() {
        val root = stateRoot()
        val current = root.resolve("current").createDirectories()
        val outside = temporary.resolve("outside.txt").also { it.writeText("outside") }
        current.resolve("active.json").createSymbolicLinkPointingTo(outside)

        assertFailsWith<IllegalArgumentException> {
            StateStore().prepare(prepareRequest(temporary.resolve("prepared"), root = root))
        }
        assertEquals("outside", outside.readText())
        assertTrue(current.resolve("active.json").exists())
    }

    private fun stateRoot(): Path = temporary.resolve("store/demo/demoRelease")

    private fun prepareRequest(
        output: Path,
        root: Path = stateRoot(),
        requestedCoordinates: StateCoordinates = coordinates,
        reproducibility: StateReproducibility = StateReproducibility.secureRandom(),
    ): PrepareRequest = PrepareRequest(
        root,
        requestedCoordinates,
        output,
        CONTENT_SALT_SHA256,
        true,
        true,
        true,
        reproducibility,
    )

    private fun fixedReproducibility(rawSeed: String): StateReproducibility = StateReproducibility.fixed(
        FixedSeedDerivation.seedSha256(rawSeed),
        ReproducibilityContext(
            coordinates.projectKey,
            coordinates.variant,
            coordinates.configurationSha256,
        ),
    )

    private fun assertFixedHistoryRecovery(
        expectedReason: LineageReason,
        invalidateCurrent: (Path) -> Unit,
    ) {
        val root = temporary.resolve("fixed-history-recovery/${expectedReason.name.lowercase()}")
        val reproducibility = fixedReproducibility("fixed-history-recovery")
        val store = StateStore()
        val aabSha256 = "e".repeat(64)
        val first = store.prepare(
            prepareRequest(temporary.resolve("${expectedReason.name}-first"), root, coordinates, reproducibility),
        )
        val firstArchive = store.archive(ArchiveRequest(first, 42, aabSha256))
        val historyFingerprint = Sha256.canonicalPayload(firstArchive.historyDirectory)
        val historyManifest = firstArchive.historyDirectory.resolve("manifest.json").readBytes()

        invalidateCurrent(root.resolve("current"))
        val reset = store.prepare(
            prepareRequest(temporary.resolve("${expectedReason.name}-reset"), root, coordinates, reproducibility),
        )

        assertEquals(expectedReason, reset.reason)
        assertTrue(reset.identity.lineageReset)
        val recovered = store.archive(ArchiveRequest(reset, 42, aabSha256))

        assertEquals(historyFingerprint, Sha256.canonicalPayload(firstArchive.historyDirectory))
        assertTrue(
            historyManifest.contentEquals(firstArchive.historyDirectory.resolve("manifest.json").readBytes()),
            "immutable history manifest changed during current recovery",
        )
        assertEquals(recovered.activePointer, store.readActivePointer(root))
        val recoveredManifest = StateJsonCodec().decodeManifest(
            recovered.snapshotDirectory.resolve("manifest.json").readText(),
        )
        assertTrue(recoveredManifest.identity.lineageReset)
        assertEquals(expectedReason, recoveredManifest.lineageReason)
        assertEquals(recovered.activePointer.generation, recoveredManifest.identity.generation)
        assertFalse(
            historyManifest.contentEquals(recovered.snapshotDirectory.resolve("manifest.json").readBytes()),
            "reset current snapshot reused the non-reset history manifest",
        )
        val reused = store.prepare(
            prepareRequest(temporary.resolve("${expectedReason.name}-reused"), root, coordinates, reproducibility),
        )
        assertEquals(LineageReason.REUSED_CURRENT, reused.reason)
        assertEquals(recovered.activePointer.generation, reused.expectedGeneration)

        val replayed = store.archive(ArchiveRequest(reused, 42, aabSha256))
        assertEquals(recovered.activePointer, replayed.activePointer)
        assertEquals(recovered.snapshotDirectory, replayed.snapshotDirectory)
        assertEquals(historyFingerprint, Sha256.canonicalPayload(firstArchive.historyDirectory))
        assertTrue(
            historyManifest.contentEquals(firstArchive.historyDirectory.resolve("manifest.json").readBytes()),
            "immutable history manifest changed during reset-current replay",
        )
        val replayedManifest = StateJsonCodec().decodeManifest(
            replayed.snapshotDirectory.resolve("manifest.json").readText(),
        )
        assertTrue(replayedManifest.identity.lineageReset)
        assertEquals(expectedReason, replayedManifest.lineageReason)

        val replayPrepared = store.prepare(
            prepareRequest(temporary.resolve("${expectedReason.name}-replay"), root, coordinates, reproducibility),
        )
        val replayedAgain = store.archive(ArchiveRequest(replayPrepared, 42, aabSha256))
        assertEquals(recovered.activePointer, replayedAgain.activePointer)
        assertEquals(recovered.snapshotDirectory, replayedAgain.snapshotDirectory)
        assertEquals(historyFingerprint, Sha256.canonicalPayload(firstArchive.historyDirectory))
        assertTrue(
            historyManifest.contentEquals(firstArchive.historyDirectory.resolve("manifest.json").readBytes()),
            "immutable history manifest changed during repeated reset-current replay",
        )
    }

    private fun assertFixedHistoryManifestTamperingRejected(
        suffix: String,
        expectedMessage: String,
        tamper: (StateIdentity) -> StateIdentity,
    ) {
        val root = temporary.resolve("fixed-history-tamper/$suffix")
        val reproducibility = fixedReproducibility("fixed-history-tamper")
        val store = StateStore()
        val aabSha256 = "e".repeat(64)
        val first = store.prepare(
            prepareRequest(temporary.resolve("fixed-history-tamper-$suffix-first"), root, coordinates, reproducibility),
        )
        val firstArchive = store.archive(ArchiveRequest(first, 42, aabSha256))
        val manifestPath = firstArchive.historyDirectory.resolve("manifest.json")
        val codec = StateJsonCodec()
        val manifest = codec.decodeManifest(manifestPath.readText())
        val tampered = SnapshotManifest(
            manifest.schemaVersion,
            tamper(manifest.identity),
            manifest.lineageReason,
            manifest.contentSaltSha256,
            manifest.aabSha256,
        )
        manifestPath.writeText(codec.encodeManifest(tampered))
        val tamperedHistory = Sha256.canonicalPayload(firstArchive.historyDirectory)
        deleteTree(root.resolve("current"))
        val reset = store.prepare(
            prepareRequest(temporary.resolve("fixed-history-tamper-$suffix-reset"), root, coordinates, reproducibility),
        )

        val failure = assertFailsWith<IllegalArgumentException> {
            store.archive(ArchiveRequest(reset, 42, aabSha256))
        }

        assertContains(failure.message.orEmpty(), expectedMessage)
        assertEquals(tamperedHistory, Sha256.canonicalPayload(firstArchive.historyDirectory))
        assertFalse(root.resolve("current").exists())
    }

    private fun StateIdentity.withRecoveryFields(
        lineageId: String,
        generation: Long,
        seedHash: String,
        payloadHashes: Map<String, String>,
    ): StateIdentity = StateIdentity(
        schemaVersion,
        projectKey,
        variant,
        namespace,
        applicationId,
        configurationSha256,
        lineageId,
        generation,
        seedHash,
        payloadHashes,
        lineageReset,
        derivationMode,
        fixedSeedSha256,
    )

    private fun moveActiveSnapshotToLegacyDomain(
        pointer: ActivePointer,
        snapshot: Path,
    ): Pair<ActivePointer, Path> {
        val payloadSha256 = Sha256.canonicalNode(snapshot, CanonicalContentDomain.LEGACY_V1)
        val snapshotId = "${pointer.generation}-$payloadSha256"
        val legacySnapshot = snapshot.parent.resolve(snapshotId)
        Files.move(snapshot, legacySnapshot)
        val legacyPointer = ActivePointer(pointer.schemaVersion, pointer.generation, snapshotId, payloadSha256)
        Files.writeString(
            stateRoot().resolve("current/active.json"),
            StateJsonCodec().encodeActive(legacyPointer),
        )
        return legacyPointer to legacySnapshot
    }

    private fun copyTree(source: Path, target: Path) {
        Files.walk(source).use { paths ->
            paths.sorted().forEach { path ->
                val destination = target.resolve(source.relativize(path).toString())
                if (Files.isDirectory(path)) Files.createDirectories(destination) else Files.copy(path, destination)
            }
        }
    }

    private fun deleteTree(path: Path) {
        if (!path.exists()) return
        Files.walk(path).use { paths -> paths.sorted(Comparator.reverseOrder()).forEach(Files::delete) }
    }

    private fun assertTreeEquals(first: Path, second: Path) {
        val firstFiles = Files.walk(first).use { paths -> paths.filter(Files::isRegularFile).map { first.relativize(it).toString() }.sorted().toList() }
        val secondFiles = Files.walk(second).use { paths -> paths.filter(Files::isRegularFile).map { second.relativize(it).toString() }.sorted().toList() }
        assertEquals(firstFiles, secondFiles)
        firstFiles.forEach { relative -> assertTrue(first.resolve(relative).readBytes().contentEquals(second.resolve(relative).readBytes())) }
    }

    private class RecordingEntropy : EntropySource {
        override fun nextBytes(purpose: String, size: Int): ByteArray {
            assertEquals("lineage-seed", purpose)
            return "lineage-seed".toByteArray().copyOf(size)
        }
    }

    private companion object {
        val CONTENT_SALT_SHA256 = "c".repeat(64)
        val CONFIGURATION_SHA256 = "b".repeat(64)
    }
}
