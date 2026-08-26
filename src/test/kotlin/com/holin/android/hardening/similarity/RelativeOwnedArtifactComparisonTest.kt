package com.holin.android.hardening.similarity

import com.holin.android.hardening.state.Sha256
import java.nio.file.Files
import java.nio.file.Path
import kotlin.io.path.createDirectories
import kotlin.io.path.exists
import kotlin.io.path.readText
import kotlin.io.path.writeText
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import org.junit.jupiter.api.io.TempDir

class RelativeOwnedArtifactComparisonTest {
    @TempDir
    lateinit var repository: Path

    @Test
    fun `candidate reports are published before every dimension is relatively gated`() {
        val fixture = fixture()
        val json = repository.resolve("build/reports/similarity-report.json")
        val markdown = repository.resolve("build/reports/similarity-report.md")
        val runner = OwnedArtifactComparisonRunner(
            { fixture.candidateProfiles },
            { _, _ -> fixture.candidateReport },
            { _, resources -> resources },
            { _, descriptors -> identityAlignment(descriptors) },
        )

        val failure = assertFailsWith<RelativeSimilarityGateException> {
            runner.compare(
                baselineStore = fixture.store,
                baselineExpectation = fixture.expectation,
                analysisRequest = fixture.analysisRequest,
                minimumImprovementPoints = 0.01,
                jsonReport = json,
                markdownReport = markdown,
            )
        }

        assertTrue(json.exists() && markdown.exists())
        assertTrue(json.readText().contains("\"code_methods\":49.995"))
        assertTrue(markdown.readText().contains("code_methods"))
        assertTrue(failure.message.orEmpty().contains("code_methods"))
    }

    @Test
    fun `comparison gates against recomputed baseline scores instead of stale stored scores`() {
        val fixture = fixture()
        val recomputedDimensions = SimilarityDimension.values().associateWith { 49.985 }
        val candidateDimensions = SimilarityDimension.values().associateWith { 49.98 }
        val reports = ArrayDeque(
            listOf(
                fixture.candidateReport.copy(dimensions = recomputedDimensions),
                fixture.candidateReport.copy(dimensions = candidateDimensions),
            ),
        )
        var analyses = 0
        val runner = OwnedArtifactComparisonRunner(
            { request ->
                analyses++
                if (analyses == 1) {
                    assertTrue(request.ordinaryAab.startsWith(fixture.baselineRoot))
                    assertTrue(request.hardenedAab.startsWith(fixture.baselineRoot))
                }
                fixture.candidateProfiles
            },
            { _, _ -> reports.removeFirst() },
            { _, resources -> resources },
            { _, descriptors -> identityAlignment(descriptors) },
        )

        val failure = assertFailsWith<RelativeSimilarityGateException> {
            runner.compare(
                baselineStore = fixture.store,
                baselineExpectation = fixture.expectation.copy(ownershipSha256 = "e".repeat(64)),
                analysisRequest = fixture.analysisRequest,
                minimumImprovementPoints = 0.01,
                jsonReport = repository.resolve("build/reports/recomputed.json"),
                markdownReport = repository.resolve("build/reports/recomputed.md"),
            )
        }

        assertTrue(failure.message.orEmpty().contains("baseline=49.985"))
        assertTrue(failure.message.orEmpty().contains("candidate=49.98"))
        assertTrue(reports.isEmpty())
        assertTrue(analyses == 2)
    }

    @Test
    fun `comparison cannot relax the immutable frozen baseline during ownership reevaluation`() {
        val fixture = fixture()
        val reports = ArrayDeque(
            listOf(
                fixture.candidateReport.copy(
                    dimensions = SimilarityDimension.values().associateWith { 100.0 },
                ),
                fixture.candidateReport.copy(
                    dimensions = SimilarityDimension.values().associateWith { 60.0 },
                ),
            ),
        )
        val runner = OwnedArtifactComparisonRunner(
            { fixture.candidateProfiles },
            { _, _ -> reports.removeFirst() },
            { _, resources -> resources },
            { _, descriptors -> identityAlignment(descriptors) },
        )

        val failure = assertFailsWith<RelativeSimilarityGateException> {
            runner.compare(
                fixture.store,
                fixture.expectation.copy(ownershipSha256 = "e".repeat(64)),
                fixture.analysisRequest,
                0.01,
                repository.resolve("build/reports/frozen.json"),
                repository.resolve("build/reports/frozen.md"),
            )
        }

        assertTrue(failure.message.orEmpty().contains("baseline=50.0"))
        assertTrue(failure.message.orEmpty().contains("candidate=60.0"))
        assertTrue(reports.isEmpty())
    }

    @Test
    fun `comparison analyzes baseline and candidate with lineage aligned descriptors`() {
        val fixture = fixture()
        val requests = mutableListOf<OwnedArtifactAnalysisRequest>()
        val reports = ArrayDeque(
            listOf(
                fixture.candidateReport.copy(dimensions = SimilarityDimension.values().associateWith { 50.0 }),
                fixture.candidateReport.copy(dimensions = SimilarityDimension.values().associateWith { 49.98 }),
            ),
        )
        val runner = OwnedArtifactComparisonRunner(
            { request ->
                requests += request
                fixture.candidateProfiles
            },
            { _, _ -> reports.removeFirst() },
            { _, resources -> resources },
            { _, currentDescriptors ->
                assertEquals(fixture.analysisRequest.ownedDescriptors.toSet(), currentDescriptors)
                BaselineOwnedDescriptorAlignment(
                    setOf("Lold/pkg/Owned;"),
                    setOf("La/b;"),
                    1,
                    0,
                )
            },
        )

        runner.compare(
            fixture.store,
            fixture.expectation.copy(ownershipSha256 = "e".repeat(64)),
            fixture.analysisRequest,
            0.01,
            repository.resolve("build/reports/aligned.json"),
            repository.resolve("build/reports/aligned.md"),
        )

        assertEquals(setOf("Lold/pkg/Owned;"), requests[0].ownedDescriptors.toSet())
        assertEquals(setOf("La/b;"), requests[1].ownedDescriptors.toSet())
        assertTrue(reports.isEmpty())
    }

    private fun fixture(): Fixture {
        val inputs = repository.resolve("inputs").createDirectories()
        val ordinaryAab = inputs.resolve("ordinary.aab").also { it.writeText("ordinary-aab") }
        val hardenedAab = inputs.resolve("hardened.aab").also { it.writeText("hardened-aab") }
        val ordinaryApk = inputs.resolve("ordinary.apk").also { it.writeText("ordinary-apk") }
        val hardenedApk = inputs.resolve("hardened.apk").also { it.writeText("hardened-apk") }
        val inventory = OwnedArtifactInventory(
            ownedModules = linkedSetOf(":app", ":core", ":compress", ":selector", ":ucrop"),
            ownedDescriptors = setOf("La/b;"),
            ordinaryOwnedResources = mapOf(
                OwnedResourceKey(1, "") to OwnedResourceLocation(
                    "home.xml", "base/res/layout/home.xml", "res/layout/home.xml", "a".repeat(64),
                ),
            ),
            hardenedOwnedResources = mapOf(
                OwnedResourceKey(1, "") to OwnedResourceLocation(
                    "screen.xml", "base/res/layout/screen.xml", "res/layout/screen.xml", "a".repeat(64),
                ),
            ),
        )
        val baselineDimensions = SimilarityDimension.values().associateWith { 50.0 }
        val candidateDimensions = baselineDimensions.toMutableMap().also {
            it[SimilarityDimension.CODE_METHODS] = 49.995
            it[SimilarityDimension.LONG_METHODS] = 49.98
            it[SimilarityDimension.RESOURCE_STRUCTURE] = 49.98
            it[SimilarityDimension.RESOURCE_CONTENT] = 49.98
        }
        val baselineReport = report(ordinaryAab, hardenedAab, ordinaryApk, hardenedApk, baselineDimensions)
        val store = ImmutableHardeningBaselineStore(repository, repository.resolve(".hardening/baselines"))
        store.capture(
            HardeningBaselineCaptureRequest(
                "demo", "demoDebug", ordinaryAab, hardenedAab, ordinaryApk, hardenedApk,
                OwnedArtifactSimilarityScorerV1.SCORER_VERSION, inventory.ownershipSha256, "b".repeat(64), baselineReport,
            ),
        )
        val candidateProfiles = profiles(ordinaryAab, hardenedAab, ordinaryApk, hardenedApk, candidateDimensions)
        val candidateReport = report(ordinaryAab, hardenedAab, ordinaryApk, hardenedApk, candidateDimensions)
        return Fixture(
            store,
            repository.resolve(".hardening/baselines/demo/demoDebug/v1"),
            HardeningBaselineExpectation(
                "demo", "demoDebug", OwnedArtifactSimilarityScorerV1.SCORER_VERSION,
                inventory.ownershipSha256, "b".repeat(64),
            ),
            OwnedArtifactAnalysisRequest(
                ordinaryAab, hardenedAab, ordinaryApk, hardenedApk, inventory.ownedDescriptors,
                inventory.ordinaryOwnedResources, inventory.hardenedOwnedResources,
            ),
            candidateProfiles,
            candidateReport,
        )
    }

    private fun identityAlignment(descriptors: Set<String>) = BaselineOwnedDescriptorAlignment(
        descriptors,
        descriptors,
        descriptors.size,
        0,
    )

    private fun profiles(
        ordinaryAab: Path,
        hardenedAab: Path,
        ordinaryApk: Path,
        hardenedApk: Path,
        dimensions: Map<SimilarityDimension, Double>,
    ): Pair<OwnedArtifactProfile, OwnedArtifactProfile> {
        val ordinary = profile(ordinaryAab, ordinaryApk, dimensions, ordinary = true)
        val hardened = profile(hardenedAab, hardenedApk, dimensions, ordinary = false)
        return ordinary to hardened
    }

    private fun profile(
        aab: Path,
        apk: Path,
        dimensions: Map<SimilarityDimension, Double>,
        ordinary: Boolean,
    ): OwnedArtifactProfile {
        val score = dimensions.getValue(SimilarityDimension.CODE_METHODS) / 100.0
        return OwnedArtifactProfile(
            Sha256.file(aab), Files.size(aab), Sha256.file(apk), Files.size(apk),
            methods = listOf(
                MethodFingerprint(
                    identifier = if (ordinary) "La/b;->m()V" else "La/b;->n()V",
                    instructionCount = 10,
                    opcodeTokens = if (ordinary) listOf("a", "b") else if (score < 0.5) listOf("x", "y") else listOf("a", "b"),
                    apiCalls = emptyList(), constants = emptyList(), blockSignature = emptyList(),
                ),
            ),
            resources = listOf(
                OwnedResourceFingerprint(
                    1, "", if (ordinary) "home.xml" else "screen.xml",
                    if (ordinary) "base/res/layout/home.xml" else "base/res/layout/screen.xml",
                    if (ordinary) "res/layout/home.xml" else "res/layout/screen.xml",
                    1, if (ordinary) "c".repeat(64) else "d".repeat(64), semanticHash = "a".repeat(64),
                ),
            ),
        )
    }

    private fun report(
        ordinaryAab: Path,
        hardenedAab: Path,
        ordinaryApk: Path,
        hardenedApk: Path,
        dimensions: Map<SimilarityDimension, Double>,
    ) = SimilarityReport(
        OwnedArtifactSimilarityScorerV1.SCORER_VERSION,
        Sha256.file(ordinaryAab), Sha256.file(hardenedAab), Sha256.file(ordinaryApk), Sha256.file(hardenedApk),
        Files.size(ordinaryAab), Files.size(hardenedAab), Files.size(ordinaryApk), Files.size(hardenedApk), dimensions,
    )

    private data class Fixture(
        val store: ImmutableHardeningBaselineStore,
        val baselineRoot: Path,
        val expectation: HardeningBaselineExpectation,
        val analysisRequest: OwnedArtifactAnalysisRequest,
        val candidateProfiles: Pair<OwnedArtifactProfile, OwnedArtifactProfile>,
        val candidateReport: SimilarityReport,
    )
}
