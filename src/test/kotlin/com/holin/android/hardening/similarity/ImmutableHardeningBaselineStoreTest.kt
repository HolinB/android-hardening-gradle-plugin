package com.holin.android.hardening.similarity

import com.holin.android.hardening.state.Sha256
import com.holin.android.hardening.state.PortableBaselineIdentityMigration
import java.nio.file.Files
import java.nio.file.Path
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import kotlin.io.path.createDirectories
import kotlin.io.path.listDirectoryEntries
import kotlin.io.path.writeText
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import org.junit.jupiter.api.io.TempDir

class ImmutableHardeningBaselineStoreTest {
    @TempDir
    lateinit var repository: Path

    @Test
    fun `capture atomically publishes exactly four artifacts and baseline metadata once`() {
        val fixture = fixture()
        val store = store()

        val baseline = store.capture(fixture.request())

        assertEquals(repository.resolve(".hardening/baselines/demo/demoDebug/v1"), baseline.root)
        assertEquals(
            setOf("ordinary.aab", "hardened.aab", "ordinary-universal.apk", "hardened-universal.apk", "baseline.json"),
            baseline.root.listDirectoryEntries().mapTo(linkedSetOf()) { it.fileName.toString() },
        )
        assertEquals(fixture.report, store.load(fixture.expectation()).report)
        assertFailsWith<IllegalArgumentException> { store.capture(fixture.request()) }
    }

    @Test
    fun `baseline load rejects scorer ownership configuration and artifact hash mismatch`() {
        val fixture = fixture()
        val store = store()
        val baseline = store.capture(fixture.request())

        assertFailsWith<IllegalArgumentException> {
            store.load(fixture.expectation(scorerVersion = "owned-artifact-v2"))
        }
        assertFailsWith<IllegalArgumentException> {
            store.load(fixture.expectation(ownershipSha256 = "e".repeat(64)))
        }
        assertFailsWith<IllegalArgumentException> {
            store.load(fixture.expectation(configurationSha256 = "f".repeat(64)))
        }
        baseline.root.resolve("ordinary.aab").writeText("tampered")
        val failure = assertFailsWith<IllegalArgumentException> { store.load(fixture.expectation()) }
        assertTrue(failure.message.orEmpty().contains("hash"))
    }

    @Test
    fun `ownership re-evaluation load accepts ownership change and returns verified immutable artifacts`() {
        val fixture = fixture()
        val store = store()
        val baseline = store.capture(fixture.request())
        val before = baseline.root.listDirectoryEntries().associate { path ->
            path.fileName.toString() to Sha256.file(path)
        }

        val loaded = store.loadForOwnershipReevaluation(
            fixture.expectation(ownershipSha256 = "e".repeat(64)),
        )

        assertEquals(baseline.root.resolve("ordinary.aab"), loaded.artifacts.ordinaryAab)
        assertEquals(baseline.root.resolve("hardened.aab"), loaded.artifacts.hardenedAab)
        assertEquals(baseline.root.resolve("ordinary-universal.apk"), loaded.artifacts.ordinaryUniversalApk)
        assertEquals(baseline.root.resolve("hardened-universal.apk"), loaded.artifacts.hardenedUniversalApk)
        assertEquals(fixture.report, loaded.storedReport)
        assertEquals(
            before,
            baseline.root.listDirectoryEntries().associate { path -> path.fileName.toString() to Sha256.file(path) },
        )
    }

    @Test
    fun `ownership re-evaluation load rejects scorer configuration and artifact tampering`() {
        val fixture = fixture()
        val store = store()
        val baseline = store.capture(fixture.request())

        assertFailsWith<IllegalArgumentException> {
            store.loadForOwnershipReevaluation(fixture.expectation(scorerVersion = "owned-artifact-v2"))
        }
        assertFailsWith<IllegalArgumentException> {
            store.loadForOwnershipReevaluation(fixture.expectation(configurationSha256 = "f".repeat(64)))
        }
        baseline.root.resolve("hardened.aab").writeText("tampered")
        val failure = assertFailsWith<IllegalArgumentException> {
            store.loadForOwnershipReevaluation(fixture.expectation(ownershipSha256 = "e".repeat(64)))
        }
        assertTrue(failure.message.orEmpty().contains("hash"))
    }

    @Test
    fun `baseline path rejects a symlink below the repository boundary`() {
        val outside = repository.resolveSibling("${repository.fileName}-outside").createDirectories()
        Files.createSymbolicLink(repository.resolve(".hardening"), outside)

        val failure = assertFailsWith<IllegalArgumentException> { store().capture(fixture().request()) }

        assertTrue(failure.message.orEmpty().contains("symlink"))
        assertTrue(outside.listDirectoryEntries().isEmpty())
    }

    @Test
    fun `baseline load rejects a missing required file`() {
        val fixture = fixture()
        val store = store()
        val baseline = store.capture(fixture.request())
        Files.delete(baseline.root.resolve("ordinary.aab"))

        val failure = assertFailsWith<IllegalArgumentException> { store.load(fixture.expectation()) }

        assertTrue(failure.message.orEmpty().contains("exactly"))
    }

    @Test
    fun `baseline load rejects an extra file`() {
        val fixture = fixture()
        val store = store()
        val baseline = store.capture(fixture.request())
        baseline.root.resolve("extra.txt").writeText("unexpected")

        val failure = assertFailsWith<IllegalArgumentException> { store.load(fixture.expectation()) }

        assertTrue(failure.message.orEmpty().contains("exactly"))
    }

    @Test
    fun `baseline load rejects a leaf artifact symlink`() {
        val fixture = fixture()
        val store = store()
        val baseline = store.capture(fixture.request())
        val leaf = baseline.root.resolve("ordinary.aab")
        Files.delete(leaf)
        Files.createSymbolicLink(leaf, fixture.ordinaryAab)

        val failure = assertFailsWith<IllegalArgumentException> { store.load(fixture.expectation()) }

        assertTrue(failure.message.orEmpty().contains("unsafe"))
    }

    @Test
    fun `concurrent capture publishes once and never overwrites the winner`() {
        val fixture = fixture()
        val store = store()
        val ready = CountDownLatch(2)
        val start = CountDownLatch(1)
        val executor = Executors.newFixedThreadPool(2)
        try {
            val futures = List(2) {
                executor.submit<HardeningBaseline> {
                    ready.countDown()
                    start.await()
                    store.capture(fixture.request())
                }
            }
            ready.await()
            start.countDown()

            val results = futures.map { future -> runCatching { future.get() } }

            assertEquals(1, results.count(Result<HardeningBaseline>::isSuccess))
            assertEquals(1, results.count(Result<HardeningBaseline>::isFailure))
            assertEquals(fixture.report, store.load(fixture.expectation()).report)
            assertTrue(
                repository.resolve(".hardening/baselines/demo/demoDebug")
                    .listDirectoryEntries().none { it.fileName.toString().startsWith(".v1.tmp-") },
            )
        } finally {
            executor.shutdownNow()
        }
    }

    @Test
    fun `migration copies legacy v1 under a new configuration and atomically selects it`() {
        val fixture = fixture()
        val store = store()
        val legacy = store.capture(fixture.request())
        val legacySha256 = Sha256.canonicalPayload(legacy.root)
        val legacyFiles = legacy.root.listDirectoryEntries().associate { path ->
            path.fileName.toString() to Sha256.file(path)
        }

        val migrated = store.migrateLegacyV1(
            "demo",
            "demoDebug",
            "c".repeat(64),
            PortableBaselineIdentityMigration(
                OwnedArtifactSimilarityScorerV1.SCORER_VERSION,
                "a".repeat(64),
                "b".repeat(64),
                "c".repeat(64),
                legacySha256,
            ),
        )

        assertEquals(BaselineMigrationStatus.MIGRATED, migrated.status)
        assertEquals(legacySha256, Sha256.canonicalPayload(legacy.root))
        assertEquals(
            legacyFiles,
            legacy.root.listDirectoryEntries().associate { path -> path.fileName.toString() to Sha256.file(path) },
        )
        assertEquals(
            fixture.report,
            store.load(fixture.expectation(configurationSha256 = "c".repeat(64))).report,
        )
        assertEquals(migrated.root, store.load(fixture.expectation(configurationSha256 = "c".repeat(64))).root)
        assertTrue(repository.resolve(".hardening/baselines/demo/demoDebug/active.json").toFile().isFile)
    }

    @Test
    fun `baseline migration mismatch does not publish a version or active pointer`() {
        val fixture = fixture()
        val store = store()
        store.capture(fixture.request())
        val variantRoot = repository.resolve(".hardening/baselines/demo/demoDebug")

        assertFailsWith<IllegalArgumentException> {
            store.migrateLegacyV1(
                "demo",
                "demoDebug",
                "c".repeat(64),
                PortableBaselineIdentityMigration(
                    OwnedArtifactSimilarityScorerV1.SCORER_VERSION,
                    "a".repeat(64),
                    "b".repeat(64),
                    "c".repeat(64),
                    "0".repeat(64),
                ),
            )
        }

        assertTrue(!variantRoot.resolve("active.json").toFile().exists())
        assertTrue(!variantRoot.resolve("versions").toFile().exists())
    }

    private fun store() = ImmutableHardeningBaselineStore(
        repositoryRoot = repository,
        baselineDirectory = repository.resolve(".hardening/baselines"),
    )

    private fun fixture(): Fixture {
        val inputs = repository.resolve("inputs").createDirectories()
        val ordinaryAab = inputs.resolve("ordinary.aab").also { it.writeText("ordinary-aab") }
        val hardenedAab = inputs.resolve("hardened.aab").also { it.writeText("hardened-aab") }
        val ordinaryApk = inputs.resolve("ordinary.apk").also { it.writeText("ordinary-apk") }
        val hardenedApk = inputs.resolve("hardened.apk").also { it.writeText("hardened-apk") }
        return Fixture(
            ordinaryAab,
            hardenedAab,
            ordinaryApk,
            hardenedApk,
            SimilarityReport(
                scorerVersion = OwnedArtifactSimilarityScorerV1.SCORER_VERSION,
                ordinaryAabSha256 = Sha256.file(ordinaryAab),
                hardenedAabSha256 = Sha256.file(hardenedAab),
                ordinaryUniversalApkSha256 = Sha256.file(ordinaryApk),
                hardenedUniversalApkSha256 = Sha256.file(hardenedApk),
                ordinaryAabSize = Files.size(ordinaryAab),
                hardenedAabSize = Files.size(hardenedAab),
                ordinaryUniversalApkSize = Files.size(ordinaryApk),
                hardenedUniversalApkSize = Files.size(hardenedApk),
                dimensions = SimilarityDimension.values().associateWith { 50.0 },
            ),
        )
    }

    private data class Fixture(
        val ordinaryAab: Path,
        val hardenedAab: Path,
        val ordinaryApk: Path,
        val hardenedApk: Path,
        val report: SimilarityReport,
    ) {
        fun request() = HardeningBaselineCaptureRequest(
            projectKey = "demo",
            variant = "demoDebug",
            ordinaryAab = ordinaryAab,
            hardenedAab = hardenedAab,
            ordinaryUniversalApk = ordinaryApk,
            hardenedUniversalApk = hardenedApk,
            scorerVersion = OwnedArtifactSimilarityScorerV1.SCORER_VERSION,
            ownershipSha256 = "a".repeat(64),
            configurationSha256 = "b".repeat(64),
            report = report,
        )

        fun expectation(
            scorerVersion: String = OwnedArtifactSimilarityScorerV1.SCORER_VERSION,
            ownershipSha256: String = "a".repeat(64),
            configurationSha256: String = "b".repeat(64),
        ) = HardeningBaselineExpectation(
            projectKey = "demo",
            variant = "demoDebug",
            scorerVersion = scorerVersion,
            ownershipSha256 = ownershipSha256,
            configurationSha256 = configurationSha256,
        )
    }
}
