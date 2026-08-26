package com.holin.android.hardening.similarity

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class OwnedArtifactSimilarityScorerV1Test {
    @Test
    fun `uses the owned v1 feature weights`() {
        val baseline = method()

        assertEquals(55.0, OwnedArtifactSimilarityScorerV1.methodSimilarity(
            baseline,
            baseline.copy(opcodeTokens = listOf("different", "opcode", "families", "change", "all")),
        ) * 100.0, 0.0001)
        assertEquals(70.0, OwnedArtifactSimilarityScorerV1.methodSimilarity(
            baseline,
            baseline.copy(blockSignature = listOf("different-cfg")),
        ) * 100.0, 0.0001)
        assertEquals(85.0, OwnedArtifactSimilarityScorerV1.methodSimilarity(
            baseline,
            baseline.copy(apiCalls = listOf("network", "crypto")),
        ) * 100.0, 0.0001)
        assertEquals(90.0, OwnedArtifactSimilarityScorerV1.methodSimilarity(
            baseline,
            baseline.copy(constants = listOf("string:long")),
        ) * 100.0, 0.0001)
    }

    @Test
    fun `method scores are weighted by ordinary instruction mass and long methods start at one hundred`() {
        val ordinary = profile(
            methods = listOf(
                method("Lbefore/Large;->renamed()V", 100),
                method("Lbefore/Small;->renamed()V", 20),
            ),
        )
        val hardened = profile(
            hardened = true,
            methods = listOf(
                method("Lafter/A;->a()V", 100),
                method("Lafter/B;->b()V", 20).copy(opcodeTokens = listOf("different", "opcode", "families", "change", "all")),
            ),
        )

        val report = OwnedArtifactSimilarityScorerV1.compare(ordinary, hardened)

        assertEquals("owned-artifact-v1", report.scorerVersion)
        assertEquals(92.5, report.dimensions.getValue(SimilarityDimension.CODE_METHODS), 0.0001)
        assertEquals(100.0, report.dimensions.getValue(SimilarityDimension.LONG_METHODS), 0.0001)
        assertEquals("Lbefore/Large;->renamed()V", report.topUnchangedCode.single().ordinaryDescriptor)
    }

    @Test
    fun `resources pair only by id and qualifier and score original byte mass`() {
        val ordinary = profile(resources = listOf(
            resource(1, "", "hero", "base/res/drawable/hero.png", "res/drawable/hero.png", 900, "a"),
            resource(2, "land", "screen", "base/res/layout-land/screen.xml", "res/layout-land/screen.xml", 100, "b"),
        ))
        val hardened = profile(hardened = true, resources = listOf(
            resource(1, "", "hero", "base/res/drawable/hero.png", "res/drawable/hero.png", 1, "a"),
            resource(99, "land", "screen", "base/res/layout-land/screen.xml", "res/layout-land/screen.xml", 100, "b"),
            resource(2, "land", "renamed", "base/res/layout-land/renamed.xml", "res/layout-land/renamed.xml", 100, "c"),
        ))

        val report = OwnedArtifactSimilarityScorerV1.compare(ordinary, hardened)

        assertEquals(50.0, report.dimensions.getValue(SimilarityDimension.RESOURCE_STRUCTURE), 0.0001)
        assertEquals(90.0, report.dimensions.getValue(SimilarityDimension.RESOURCE_CONTENT), 0.0001)
        assertEquals(listOf(1), report.topUnchangedResources.map(ResourceSimilarityEvidence::resourceId))
    }

    @Test
    fun `report binds four artifacts and emits deterministic unchanged evidence`() {
        val ordinary = profile(methods = listOf(method("z", 10), method("a", 30)))
        val hardened = profile(hardened = true, methods = listOf(method("y", 10), method("b", 30)))

        val report = OwnedArtifactSimilarityScorerV1.compare(ordinary, hardened)

        assertEquals("1".repeat(64), report.ordinaryAabSha256)
        assertEquals("2".repeat(64), report.hardenedAabSha256)
        assertEquals("3".repeat(64), report.ordinaryUniversalApkSha256)
        assertEquals("4".repeat(64), report.hardenedUniversalApkSha256)
        assertEquals(listOf("a", "z"), report.topUnchangedCode.map(CodeSimilarityEvidence::ordinaryDescriptor))
        assertTrue(report.dimensions.keys == SimilarityDimension.values().toSet())
    }

    @Test
    fun `long method matching excludes hardened methods below one hundred instructions`() {
        val report = OwnedArtifactSimilarityScorerV1.compare(
            profile(methods = listOf(method("ordinary", 100))),
            profile(hardened = true, methods = listOf(method("hardened-short", 99))),
        )

        assertEquals(0.0, report.dimensions.getValue(SimilarityDimension.LONG_METHODS))
    }

    @Test
    fun `equal method similarity picks the closest instruction count deterministically`() {
        val report = OwnedArtifactSimilarityScorerV1.compare(
            profile(methods = listOf(method("ordinary", 100))),
            profile(hardened = true, methods = listOf(method("far", 20), method("near", 99))),
        )

        assertEquals("near", report.topUnchangedCode.single().hardenedDescriptor)
    }

    @Test
    fun `resource structure weights paired entries equally instead of by byte mass`() {
        val report = OwnedArtifactSimilarityScorerV1.compare(
            profile(resources = listOf(
                resource(1, "", "large", "base/res/drawable/large.png", "res/drawable/large.png", 900, "a"),
                resource(2, "", "small", "base/res/drawable/small.png", "res/drawable/small.png", 100, "b"),
            )),
            profile(hardened = true, resources = listOf(
                resource(1, "", "large", "base/res/drawable/large.png", "res/drawable/large.png", 1, "a"),
                resource(2, "", "renamed", "base/res/drawable/renamed.png", "res/drawable/renamed.png", 100, "b"),
            )),
        )

        assertEquals(50.0, report.dimensions.getValue(SimilarityDimension.RESOURCE_STRUCTURE))
    }

    @Test
    fun `resources reject missing or blank semantic validation hashes`() {
        assertFailsWith<IllegalArgumentException> {
            OwnedResourceFingerprint(1, "", "entry", "base/res/raw/entry", "res/raw/entry", 1, "a".repeat(64), missingSemanticHash = null)
        }
        assertFailsWith<IllegalArgumentException> {
            OwnedResourceFingerprint(1, "", "entry", "base/res/raw/entry", "res/raw/entry", 1, "a".repeat(64), semanticHash = "")
        }
    }

    @Test
    fun `unchanged evidence ranks largest ordinary mass first with stable ties`() {
        val report = OwnedArtifactSimilarityScorerV1.compare(
            profile(
                methods = listOf(method("small", 10), method("large", 30)),
                resources = listOf(
                    resource(1, "", "small", "base/res/raw/small", "res/raw/small", 10, "a"),
                    resource(2, "", "large", "base/res/raw/large", "res/raw/large", 100, "b"),
                ),
            ),
            profile(
                hardened = true,
                methods = listOf(method("small-h", 10), method("large-h", 30)),
                resources = listOf(
                    resource(1, "", "small", "base/res/raw/small", "res/raw/small", 10, "a"),
                    resource(2, "", "large", "base/res/raw/large", "res/raw/large", 100, "b"),
                ),
            ),
        )

        assertEquals(listOf("large", "small"), report.topUnchangedCode.map(CodeSimilarityEvidence::ordinaryDescriptor))
        assertEquals(listOf(2, 1), report.topUnchangedResources.map(ResourceSimilarityEvidence::resourceId))
    }

    @Test
    fun `diversifying a weighted owned XML APK entry lowers content without changing identity or semantics`() {
        val xml = resource(
            1,
            "land",
            "screen",
            "base/res/layout-land/screen.xml",
            "res/layout-land/screen.xml",
            900,
            "a",
        )
        val image = resource(
            2,
            "",
            "hero",
            "base/res/drawable/hero.png",
            "res/drawable/hero.png",
            100,
            "b",
        )
        val ordinary = profile(resources = listOf(xml, image))
        val byteIdentical = profile(hardened = true, resources = listOf(xml, image))
        val diversifiedXml = OwnedResourceFingerprint(
            resourceId = xml.resourceId,
            qualifier = xml.qualifier,
            originalEntryName = xml.originalEntryName,
            aabPath = xml.aabPath,
            apkPath = xml.apkPath,
            size = xml.size,
            sha256 = "d".repeat(64),
            currentEntryName = xml.currentEntryName,
            semanticHash = xml.semanticHash,
        )
        val diversified = profile(hardened = true, resources = listOf(diversifiedXml, image))

        val before = OwnedArtifactSimilarityScorerV1.compare(ordinary, byteIdentical)
        val after = OwnedArtifactSimilarityScorerV1.compare(ordinary, diversified)

        assertEquals(100.0, before.dimensions.getValue(SimilarityDimension.RESOURCE_CONTENT))
        assertEquals(10.0, after.dimensions.getValue(SimilarityDimension.RESOURCE_CONTENT))
        assertTrue(
            after.dimensions.getValue(SimilarityDimension.RESOURCE_CONTENT) <
                before.dimensions.getValue(SimilarityDimension.RESOURCE_CONTENT),
        )
        assertEquals(100.0, after.dimensions.getValue(SimilarityDimension.RESOURCE_STRUCTURE))
        assertEquals(xml.resourceId, diversifiedXml.resourceId)
        assertEquals(xml.qualifier, diversifiedXml.qualifier)
        assertEquals(xml.aabPath, diversifiedXml.aabPath)
        assertEquals(xml.apkPath, diversifiedXml.apkPath)
        assertEquals(xml.semanticHash, diversifiedXml.semanticHash)
    }

    private fun method(identifier: String = "method", count: Int = 10) = MethodFingerprint(
        identifier = identifier,
        instructionCount = count,
        canonicalHash = "ignored",
        opcodeTokens = listOf("move", "const", "invoke", "if", "return"),
        apiCalls = listOf("ui", "threading"),
        constants = listOf("string:short"),
        blockSignature = listOf("blocks:2", "edge:conditional"),
    )

    private fun resource(
        id: Int,
        qualifier: String,
        name: String,
        aabPath: String,
        apkPath: String,
        size: Long,
        hash: String,
    ) = OwnedResourceFingerprint(
        id, qualifier, name, aabPath, apkPath, size, hash.repeat(64), semanticHash = "c".repeat(64),
    )

    private fun profile(
        hardened: Boolean = false,
        methods: List<MethodFingerprint> = emptyList(),
        resources: List<OwnedResourceFingerprint> = emptyList(),
    ) = OwnedArtifactProfile(
        aabSha256 = (if (hardened) "2" else "1").repeat(64),
        aabSize = 1_000,
        universalApkSha256 = (if (hardened) "4" else "3").repeat(64),
        universalApkSize = 800,
        methods = methods,
        resources = resources,
    )
}
