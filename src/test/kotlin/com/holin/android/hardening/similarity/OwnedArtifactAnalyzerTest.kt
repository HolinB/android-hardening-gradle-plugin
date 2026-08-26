package com.holin.android.hardening.similarity

import com.android.tools.smali.dexlib2.AccessFlags
import com.android.tools.smali.dexlib2.Opcode
import com.android.tools.smali.dexlib2.Opcodes
import com.android.tools.smali.dexlib2.builder.MutableMethodImplementation
import com.android.tools.smali.dexlib2.builder.instruction.BuilderInstruction12x
import com.android.tools.smali.dexlib2.builder.instruction.BuilderInstruction31c
import com.android.tools.smali.dexlib2.dexbacked.DexBackedDexFile
import com.android.tools.smali.dexlib2.iface.instruction.Instruction
import com.android.tools.smali.dexlib2.iface.instruction.OffsetInstruction
import com.android.tools.smali.dexlib2.immutable.ImmutableClassDef
import com.android.tools.smali.dexlib2.immutable.ImmutableDexFile
import com.android.tools.smali.dexlib2.immutable.ImmutableMethod
import com.android.tools.smali.dexlib2.immutable.ImmutableMethodImplementation
import com.android.tools.smali.dexlib2.immutable.debug.ImmutableLineNumber
import com.android.tools.smali.dexlib2.immutable.instruction.ImmutableInstruction10x
import com.android.tools.smali.dexlib2.immutable.instruction.ImmutableInstruction11n
import com.android.tools.smali.dexlib2.immutable.instruction.ImmutableInstruction12x
import com.android.tools.smali.dexlib2.immutable.instruction.ImmutableInstruction21c
import com.android.tools.smali.dexlib2.immutable.instruction.ImmutableInstruction21t
import com.android.tools.smali.dexlib2.immutable.instruction.ImmutableInstruction30t
import com.android.tools.smali.dexlib2.immutable.instruction.ImmutableInstruction35c
import com.android.tools.smali.dexlib2.immutable.reference.ImmutableMethodReference
import com.android.tools.smali.dexlib2.immutable.reference.ImmutableStringReference
import com.android.tools.smali.dexlib2.writer.io.MemoryDataStore
import com.android.tools.smali.dexlib2.writer.pool.DexPool
import com.holin.android.hardening.dex.DexTransformRequest
import com.holin.android.hardening.dex.NopWeaveResult
import com.holin.android.hardening.dex.ReachableRelaySplitter
import com.holin.android.hardening.dex.SafeDexTransformer
import com.holin.android.hardening.dex.SafeNopWeaver
import com.holin.android.hardening.state.Sha256
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.charset.StandardCharsets
import java.nio.file.Path
import java.security.MessageDigest
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream
import kotlin.io.path.outputStream
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue
import org.junit.jupiter.api.io.TempDir

class OwnedArtifactAnalyzerTest {
    @TempDir
    lateinit var temporary: Path

    @Test
    fun `analyzes only caller owned descriptors and resource locations`() {
        val dex = dex(
            classWithMethods(OWNED_DESCRIPTOR, method("run", longBody())),
            classWithMethods("Lcom/dependency/Library;", method("run", longBody())),
            classWithMethods("Lcom/vendor/excluded/Hidden;", method("run", longBody())),
        )
        val artifacts = artifacts(dex)

        val (ordinary, hardened) = OwnedArtifactAnalyzer().analyzePair(request(artifacts))

        assertEquals(listOf("$OWNED_DESCRIPTOR->run()V"), ordinary.methods.map(MethodFingerprint::identifier))
        assertEquals(listOf("$OWNED_DESCRIPTOR->run()V"), hardened.methods.map(MethodFingerprint::identifier))
        assertEquals(listOf(RESOURCE_ID), ordinary.resources.map(OwnedResourceFingerprint::resourceId))
        assertEquals(listOf(RESOURCE_ID), hardened.resources.map(OwnedResourceFingerprint::resourceId))
        assertEquals(listOf("base/res/raw/owned.bin"), ordinary.resources.map(OwnedResourceFingerprint::aabPath))
        assertEquals(listOf("res/raw/owned.bin"), hardened.resources.map(OwnedResourceFingerprint::apkPath))
    }

    @Test
    fun `reads all multidex entries and rejects duplicate owned descriptors`() {
        val first = dex(classWithMethods(OWNED_DESCRIPTOR, method("first", longBody())))
        val second = dex(classWithMethods(SECOND_OWNED_DESCRIPTOR, method("second", longBody())))
        val artifacts = artifacts(first).copy(
            ordinaryAab = aab("ordinary-multidex.aab", first, mapOf("feature/dex/classes2.dex" to second)),
            ordinaryApk = apk("ordinary-multidex.apk", first, mapOf("classes2.dex" to second)),
            hardenedAab = aab("hardened-multidex.aab", first, mapOf("feature/dex/classes2.dex" to second)),
            hardenedApk = apk("hardened-multidex.apk", first, mapOf("classes2.dex" to second)),
        )

        val profiles = OwnedArtifactAnalyzer().analyzePair(
            request(artifacts, descriptors = setOf(OWNED_DESCRIPTOR, SECOND_OWNED_DESCRIPTOR)),
        )

        assertEquals(2, profiles.first.methods.size)
        val duplicate = artifacts.copy(
            ordinaryAab = aab("ordinary-duplicate.aab", first, mapOf("feature/dex/classes2.dex" to first)),
        )
        val failure = assertFailsWith<IllegalArgumentException> {
            OwnedArtifactAnalyzer().analyzePair(request(duplicate))
        }
        assertTrue(failure.message!!.contains("duplicate owned descriptor"))
    }

    @Test
    fun `rejects requested descriptors missing from any artifact`() {
        val ownedDex = dex(classWithMethods(OWNED_DESCRIPTOR, method("run", longBody())))
        val unrelatedDex = dex(classWithMethods("Lcom/dependency/Only;", method("run", longBody())))
        val artifacts = artifacts(ownedDex).copy(hardenedApk = apk("missing.apk", unrelatedDex))

        val failure = assertFailsWith<IllegalArgumentException> {
            OwnedArtifactAnalyzer().analyzePair(request(artifacts))
        }

        assertTrue(failure.message!!.contains("missing requested owned descriptors"))
    }

    @Test
    fun `rejects AAB and APK normalized method disagreement within one side`() {
        val ordinaryDex = dex(classWithMethods(OWNED_DESCRIPTOR, method("run", longBody())))
        val changedDex = dex(classWithMethods(OWNED_DESCRIPTOR, method("run", longBody(Opcode.CONST_4))))
        val artifacts = artifacts(ordinaryDex).copy(ordinaryApk = apk("mismatch.apk", changedDex))

        val failure = assertFailsWith<IllegalArgumentException> {
            OwnedArtifactAnalyzer().analyzePair(request(artifacts))
        }

        assertTrue(failure.message!!.contains("AAB/APK owned method fingerprints differ"))
    }

    @Test
    fun `rejects portable duplicate ZIP entry names`() {
        val dex = dex(classWithMethods(OWNED_DESCRIPTOR, method("run", longBody())))
        val base = artifacts(dex)
        val duplicate = base.copy(
            ordinaryApk = apk("duplicate-entry.apk", dex, mapOf("Classes.dex" to dex)),
        )

        val failure = assertFailsWith<IllegalArgumentException> {
            OwnedArtifactAnalyzer().analyzePair(request(duplicate))
        }

        assertTrue(failure.message!!.contains("duplicate or platform-ambiguous ZIP entry names"))
    }

    @Test
    fun `excludes methods without implementations and methods shorter than twelve instructions`() {
        val dex = dex(
            classWithMethods(
                OWNED_DESCRIPTOR,
                method("abstractMethod", null, AccessFlags.PUBLIC.value or AccessFlags.ABSTRACT.value),
                method("shortMethod", List(11) { ImmutableInstruction10x(Opcode.NOP) }),
                method("includedMethod", List(12) { ImmutableInstruction10x(Opcode.NOP) }),
            ),
        )

        val profile = OwnedArtifactAnalyzer().analyzePair(request(artifacts(dex))).first

        assertEquals(listOf("$OWNED_DESCRIPTOR->includedMethod()V"), profile.methods.map(MethodFingerprint::identifier))
    }

    @Test
    fun `normalizes registers literals referenced names and same-category platform APIs`() {
        val ordinaryDex = dex(
            classWithMethods(
                OWNED_DESCRIPTOR,
                method(
                    "run",
                    normalizedBody(0, 1, "alpha", "Landroid/os/Bundle;", "firstName"),
                    debugItems = listOf(ImmutableLineNumber(0, 10)),
                ),
            ),
        )
        val hardenedDex = dex(
            classWithMethods(
                OWNED_DESCRIPTOR,
                method(
                    "run",
                    normalizedBody(1, 7, "bravo", "Landroid/os/Handler;", "secondName"),
                    debugItems = listOf(ImmutableLineNumber(4, 999)),
                ),
            ),
        )
        val artifacts = artifacts(ordinaryDex, hardenedDex)

        val (ordinary, hardened) = OwnedArtifactAnalyzer().analyzePair(request(artifacts))
        val ordinaryMethod = ordinary.methods.single()
        val hardenedMethod = hardened.methods.single()

        assertEquals(ordinaryMethod.opcodeTokens, hardenedMethod.opcodeTokens)
        assertEquals(ordinaryMethod.apiCalls, hardenedMethod.apiCalls)
        assertEquals(ordinaryMethod.constants, hardenedMethod.constants)
        assertEquals(ordinaryMethod.blockSignature, hardenedMethod.blockSignature)
        assertEquals(1.0, OwnedArtifactSimilarityScorerV1.methodSimilarity(ordinaryMethod, hardenedMethod))
    }

    @Test
    fun `CFG fingerprint changes when the same branch opcodes form a different graph`() {
        val ordinaryDex = dex(classWithMethods(OWNED_DESCRIPTOR, method("run", branchingBody(4))))
        val hardenedDex = dex(classWithMethods(OWNED_DESCRIPTOR, method("run", branchingBody(8))))

        val (ordinary, hardened) = OwnedArtifactAnalyzer().analyzePair(request(artifacts(ordinaryDex, hardenedDex)))

        assertEquals(ordinary.methods.single().opcodeTokens, hardened.methods.single().opcodeTokens)
        assertNotEquals(ordinary.methods.single().blockSignature, hardened.methods.single().blockSignature)
        assertTrue(
            OwnedArtifactSimilarityScorerV1.methodSimilarity(ordinary.methods.single(), hardened.methods.single()) < 1.0,
        )
    }

    @Test
    fun `disabled detours remain bounded while frozen scorer remains greedy`() {
        val transformRequest = DexTransformRequest(
            ownedDescriptorPrefixes = setOf("Lcom/example/demo/match/"),
            ownedDescriptors = setOf(OWNED_DESCRIPTOR),
            salt = "scorer-detour-budget".encodeToByteArray(),
            minimumCoverage = 0.0,
            minimumSimHashDistance = 0,
            maximumGrowthRatio = 0.05,
            selectionRate = 1.0,
        )
        val anchorMethod = method("anchor", constantLongBody(200))
        val ordinaryDex = dex(
            classWithMethods(
                OWNED_DESCRIPTOR,
                anchorMethod,
                method("cross", crossMethodBody(FIXED_CROSS_METHOD_SIGNATURE), SYNTHETIC_PRIVATE_STATIC),
                sourceFile = "x".repeat(8_000),
            ),
        )
        val fittedTransformation = SafeDexTransformer().transform(ordinaryDex, transformRequest)
        val fullTransformation = SafeDexTransformer().transform(
            ordinaryDex,
            transformRequest.copy(enforceMaximumGrowth = false),
        )
        assertTrue(fittedTransformation.report.byteGrowthRatio <= 0.05)
        assertTrue(
            fullTransformation.report.methods
                .filter { it.reason == com.holin.android.hardening.dex.MethodEligibilityReason.TRANSFORMED }
                .all { it.insertedPayloadInstructionCount in 24..40 },
        )
        assertTrue(fullTransformation.report.methods.all { it.insertedRelayInstructionCount == 0 })
        val profiles = OwnedArtifactAnalyzer().analyzePair(request(artifacts(ordinaryDex, fullTransformation.dexBytes)))
        val score = OwnedArtifactSimilarityScorerV1.compare(profiles.first, profiles.second)
        assertTrue(score.dimensions.getValue(SimilarityDimension.CODE_METHODS) in 0.0..100.0)
        assertTrue(score.dimensions.getValue(SimilarityDimension.LONG_METHODS) in 0.0..100.0)
    }

    @Test
    fun `bounded opaque architecture lowers fixed greedy scores versus full cap relay architecture`() {
        val alphaBody = fixedScorerBody(FIXED_SCORER_ALPHA_BODY, 180)
        val betaBody = fixedScorerBody(FIXED_SCORER_BETA_BODY, 180)
        val ordinaryDex = dex(
            classWithMethods(
                OWNED_DESCRIPTOR,
                method("alpha", alphaBody, AccessFlags.PRIVATE.value),
                method("beta", betaBody, AccessFlags.PRIVATE.value),
            ),
        )
        val salt = "fixed-reachable-relay-scorer-corpus".encodeToByteArray()
        val opaqueTransformation = SafeDexTransformer().transform(
            ordinaryDex,
            DexTransformRequest(
                ownedDescriptorPrefixes = setOf("Lcom/example/demo/match/"),
                ownedDescriptors = setOf(OWNED_DESCRIPTOR),
                salt = salt,
                minimumCoverage = 0.0,
                minimumSimHashDistance = 0,
                maximumGrowthRatio = 0.0,
                enforceMaximumGrowth = false,
                selectionRate = 1.0,
            ),
        )
        val exactPriorMethods = listOf(
            exactPriorProductionRelayMethod("alpha", alphaBody, salt),
            exactPriorProductionRelayMethod("beta", betaBody, salt),
        )
        val legacyRelayDex = dex(
            classWithMethods(
                OWNED_DESCRIPTOR,
                exactPriorMethods[0].method,
                exactPriorMethods[1].method,
            ),
        )
        assertEquals(248, alphaBody.sumOf(Instruction::getCodeUnits))
        assertEquals(248, betaBody.sumOf(Instruction::getCodeUnits))
        assertEquals(
            listOf("alpha", "beta").map { name ->
                priorProductionDetourCap(248, salt, "$OWNED_DESCRIPTOR->$name()V")
            },
            exactPriorMethods.map(LegacyFullCapRelayMethod::payloadInstructionCount),
        )
        assertTrue(exactPriorMethods.all { it.payloadInstructionCount in 1_024..1_279 })
        assertTrue(exactPriorMethods.all { it.relayInstructionCount > 0 && it.relayInstructionCount % 2 == 0 })
        exactPriorMethods.forEach { reconstructed ->
            assertEquals(
                reconstructed.relayInstructionCount + 2,
                requireNotNull(reconstructed.method.implementation).instructions.count { it.opcode == Opcode.GOTO_32 },
            )
        }
        val opaqueProfiles = OwnedArtifactAnalyzer().analyzePair(
            request(artifacts(ordinaryDex, opaqueTransformation.dexBytes)),
        )
        val legacyProfiles = OwnedArtifactAnalyzer().analyzePair(request(artifacts(ordinaryDex, legacyRelayDex)))
        val ordinaryMethods = opaqueProfiles.first.methods.sortedBy(MethodFingerprint::identifier)
        val opaqueMethods = opaqueProfiles.second.methods.sortedBy(MethodFingerprint::identifier)
        val legacyMethods = legacyProfiles.second.methods.sortedBy(MethodFingerprint::identifier)
        val opaqueMatrix = ordinaryMethods.map { ordinary ->
            opaqueMethods.map { hardened -> OwnedArtifactSimilarityScorerV1.methodSimilarity(ordinary, hardened) }
        }
        val legacyMatrix = ordinaryMethods.map { ordinary ->
            legacyMethods.map { hardened -> OwnedArtifactSimilarityScorerV1.methodSimilarity(ordinary, hardened) }
        }
        val opaque = OwnedArtifactSimilarityScorerV1.compare(opaqueProfiles.first, opaqueProfiles.second)
        val legacy = OwnedArtifactSimilarityScorerV1.compare(legacyProfiles.first, legacyProfiles.second)
        val opaqueGreedyAssignment = fixedTwoMethodGreedyAssignment(ordinaryMethods, opaqueMethods, opaqueMatrix)
        val legacyGreedyAssignment = fixedTwoMethodGreedyAssignment(ordinaryMethods, legacyMethods, legacyMatrix)
        val opaqueGreedyScore = fixedTwoMethodGreedyScore(ordinaryMethods, opaqueMatrix, opaqueGreedyAssignment)
        val legacyGreedyScore = fixedTwoMethodGreedyScore(ordinaryMethods, legacyMatrix, legacyGreedyAssignment)

        assertEquals(listOf("alpha", "beta"), ordinaryMethods.map { it.identifier.substringAfter("->").substringBefore('(') })
        assertEquals(2, ordinaryMethods.count { it.instructionCount >= 100 })
        assertTrue(opaqueTransformation.report.methods.all { it.insertedOpaqueDiamondCount == 3 })
        assertTrue(opaqueTransformation.report.methods.all { it.insertedRelayInstructionCount == 0 })
        assertTrue(opaqueTransformation.report.methods.all { it.insertedPayloadInstructionCount in 24..40 })
        assertEquals(listOf(2, 2), opaqueMatrix.map(List<Double>::size))
        assertEquals(listOf(2, 2), legacyMatrix.map(List<Double>::size))
        assertEquals(listOf(0, 1), opaqueGreedyAssignment.sorted())
        assertEquals(listOf(0, 1), legacyGreedyAssignment.sorted())
        assertEquals(opaqueGreedyScore, opaque.dimensions.getValue(SimilarityDimension.CODE_METHODS))
        assertEquals(opaqueGreedyScore, opaque.dimensions.getValue(SimilarityDimension.LONG_METHODS))
        assertEquals(legacyGreedyScore, legacy.dimensions.getValue(SimilarityDimension.CODE_METHODS))
        assertEquals(legacyGreedyScore, legacy.dimensions.getValue(SimilarityDimension.LONG_METHODS))
        val evidence = "opaque=$opaqueMatrix legacy=$legacyMatrix"
        assertTrue(
            opaque.dimensions.getValue(SimilarityDimension.CODE_METHODS) <
                legacy.dimensions.getValue(SimilarityDimension.CODE_METHODS),
            evidence,
        )
        assertTrue(
            opaque.dimensions.getValue(SimilarityDimension.LONG_METHODS) <
                legacy.dimensions.getValue(SimilarityDimension.LONG_METHODS),
            evidence,
        )
    }

    @Test
    fun `dead marker categories strictly lower honest fixed greedy code scores`() {
        val ordinaryDex = dex(
            classWithMethods(
                OWNED_DESCRIPTOR,
                method("staticShort", honestScorerBody(36, listOf(Opcode.NEG_INT, Opcode.NOT_INT))),
                method(
                    "instanceShort",
                    honestScorerBody(52, listOf(Opcode.ADD_INT_2ADDR, Opcode.XOR_INT_2ADDR, Opcode.NOT_INT)),
                    AccessFlags.PRIVATE.value,
                ),
                method(
                    "instanceLong",
                    honestScorerBody(148, listOf(Opcode.SUB_INT_2ADDR, Opcode.NEG_INT, Opcode.XOR_INT_2ADDR)),
                    AccessFlags.PRIVATE.value,
                ),
            ),
        )
        val salt = "honest-dead-marker-greedy-corpus".encodeToByteArray()
        val control = SafeDexTransformer().transform(
            ordinaryDex,
            DexTransformRequest(
                ownedDescriptorPrefixes = setOf("Lcom/example/demo/match/"),
                ownedDescriptors = setOf(OWNED_DESCRIPTOR),
                salt = salt,
                minimumCoverage = 0.0,
                minimumSimHashDistance = 0,
                maximumGrowthRatio = 0.0,
                enforceMaximumGrowth = false,
                selectionRate = 1.0,
            ),
        )
        val diamondCounts = control.report.methods.associate {
            it.methodId to it.insertedOpaqueDiamondCount
        }
        val producedProfiles = OwnedArtifactAnalyzer().analyzePair(request(artifacts(ordinaryDex, control.dexBytes)))
        val producerHasMarkers = producedProfiles.second.methods.all { it.constants.toSet() == MARKER_CATEGORIES }
        val controlDex = if (producerHasMarkers) withoutDeadMarkerCategories(control.dexBytes) else control.dexBytes
        val markerDex = if (producerHasMarkers) control.dexBytes else withDeadMarkerCategories(control.dexBytes, diamondCounts)
        val controlProfiles = OwnedArtifactAnalyzer().analyzePair(request(artifacts(ordinaryDex, controlDex)))
        val markerProfiles = OwnedArtifactAnalyzer().analyzePair(request(artifacts(ordinaryDex, markerDex)))
        val ordinaryMethods = controlProfiles.first.methods.sortedBy(MethodFingerprint::identifier)
        val controlMethods = controlProfiles.second.methods.sortedBy(MethodFingerprint::identifier)
        val markerMethods = markerProfiles.second.methods.sortedBy(MethodFingerprint::identifier)
        val controlMatrix = ordinaryMethods.map { ordinary ->
            controlMethods.map { hardened -> OwnedArtifactSimilarityScorerV1.methodSimilarity(ordinary, hardened) }
        }
        val markerMatrix = ordinaryMethods.map { ordinary ->
            markerMethods.map { hardened -> OwnedArtifactSimilarityScorerV1.methodSimilarity(ordinary, hardened) }
        }
        val controlAssignment = greedyAssignment(ordinaryMethods, controlMethods, controlMatrix)
        val markerAssignment = greedyAssignment(ordinaryMethods, markerMethods, markerMatrix)
        val controlScore = OwnedArtifactSimilarityScorerV1.compare(controlProfiles.first, controlProfiles.second)
        val markerScore = OwnedArtifactSimilarityScorerV1.compare(markerProfiles.first, markerProfiles.second)
        val evidence = "controlMatrix=$controlMatrix markerMatrix=$markerMatrix " +
            "controlAssignment=$controlAssignment markerAssignment=$markerAssignment " +
            "control=${controlScore.dimensions} marker=${markerScore.dimensions}"

        assertEquals(listOf(0, 1, 3), control.report.methods.map { it.insertedOpaqueDiamondCount }.sorted(), evidence)
        assertTrue(
            markerScore.dimensions.getValue(SimilarityDimension.CODE_METHODS) <
                controlScore.dimensions.getValue(SimilarityDimension.CODE_METHODS),
            evidence,
        )
        assertTrue(
            markerScore.dimensions.getValue(SimilarityDimension.LONG_METHODS) <
                controlScore.dimensions.getValue(SimilarityDimension.LONG_METHODS),
            evidence,
        )
        assertEquals(
            List(3) { MARKER_CATEGORIES },
            producedProfiles.second.methods.sortedBy(MethodFingerprint::identifier).map { it.constants.toSet() },
            "current producer must emit the proposed exact marker categories; $evidence",
        )
    }

    @Test
    fun `resource profile uses exact APK bytes and preserves caller semantic hash`() {
        val dex = dex(classWithMethods(OWNED_DESCRIPTOR, method("run", longBody())))
        val aabBytes = "proto-xml-resource-encoding".toByteArray()
        val apkBytes = "binary-xml-resource-encoding".toByteArray()
        val artifacts = artifacts(dex, resourceBytes = aabBytes).copy(
            ordinaryApk = apk("ordinary-cross-format.apk", dex, resourceBytes = apkBytes),
        )

        val resource = OwnedArtifactAnalyzer().analyzePair(request(artifacts)).first.resources.single()

        assertEquals(apkBytes.size.toLong(), resource.size)
        assertEquals(Sha256.hex(apkBytes), resource.sha256)
        assertEquals(SEMANTIC_HASH, resource.semanticHash)
    }

    @Test
    fun `rejects missing unsafe and mismatched resource locations`() {
        assertFailsWith<IllegalArgumentException> {
            location(aabPath = "base/res/raw/../owned.bin")
        }
        assertFailsWith<IllegalArgumentException> {
            location(semanticHash = "not-a-sha")
        }
        val dex = dex(classWithMethods(OWNED_DESCRIPTOR, method("run", longBody())))
        val base = artifacts(dex)
        val missing = base.copy(ordinaryApk = apk("missing-resource.apk", dex, resourceBytes = null))
        assertTrue(assertFailsWith<IllegalArgumentException> {
            OwnedArtifactAnalyzer().analyzePair(request(missing))
        }.message!!.contains("missing owned resource"))

        val wrongType = request(base).copy(
            ordinaryOwnedResources = mapOf(
                OwnedResourceKey(RESOURCE_ID, "") to location(apkPath = "res/layout/owned.bin"),
            ),
        )
        assertTrue(assertFailsWith<IllegalArgumentException> {
            OwnedArtifactAnalyzer().analyzePair(wrongType)
        }.message!!.contains("inconsistent AAB/APK type"))

    }

    @Test
    fun `request rejects empty duplicate or inexact ownership inputs`() {
        val dex = dex(classWithMethods(OWNED_DESCRIPTOR, method("run", longBody())))
        val artifacts = artifacts(dex)
        val valid = request(artifacts)

        assertFailsWith<IllegalArgumentException> { valid.copy(ownedDescriptors = emptySet()) }
        assertFailsWith<IllegalArgumentException> {
            valid.copy(ownedDescriptors = listOf(OWNED_DESCRIPTOR, OWNED_DESCRIPTOR))
        }
        assertFailsWith<IllegalArgumentException> { valid.copy(ownedDescriptors = setOf("com.example.Owned")) }
        assertFailsWith<IllegalArgumentException> { valid.copy(ordinaryOwnedResources = emptyMap()) }
        assertFailsWith<IllegalArgumentException> { valid.copy(hardenedOwnedResources = emptyMap()) }
    }

    @Test
    fun `request rejects duplicate physical resource locations on either side`() {
        val dex = dex(classWithMethods(OWNED_DESCRIPTOR, method("run", longBody())))
        val valid = request(artifacts(dex))
        val duplicateLocations = mapOf(
            OwnedResourceKey(RESOURCE_ID, "") to location(),
            OwnedResourceKey(RESOURCE_ID + 1, "") to location(),
        )

        val ordinaryFailure = assertFailsWith<IllegalArgumentException> {
            valid.copy(ordinaryOwnedResources = duplicateLocations)
        }
        val hardenedFailure = assertFailsWith<IllegalArgumentException> {
            valid.copy(hardenedOwnedResources = duplicateLocations)
        }

        assertTrue(ordinaryFailure.message!!.contains("duplicate AAB/APK resource location pairs"))
        assertTrue(hardenedFailure.message!!.contains("duplicate AAB/APK resource location pairs"))
    }

    private fun request(
        artifacts: Artifacts,
        descriptors: Collection<String> = setOf(OWNED_DESCRIPTOR),
        ordinaryLocation: OwnedResourceLocation = location(),
        hardenedLocation: OwnedResourceLocation = location(),
    ) = OwnedArtifactAnalysisRequest(
        ordinaryAab = artifacts.ordinaryAab,
        hardenedAab = artifacts.hardenedAab,
        ordinaryUniversalApk = artifacts.ordinaryApk,
        hardenedUniversalApk = artifacts.hardenedApk,
        ownedDescriptors = descriptors,
        ordinaryOwnedResources = mapOf(OwnedResourceKey(RESOURCE_ID, "") to ordinaryLocation),
        hardenedOwnedResources = mapOf(OwnedResourceKey(RESOURCE_ID, "") to hardenedLocation),
    )

    private fun artifacts(
        ordinaryDex: ByteArray,
        hardenedDex: ByteArray = ordinaryDex,
        resourceBytes: ByteArray = RESOURCE_BYTES,
    ) = Artifacts(
        ordinaryAab = aab("ordinary-${temporary.toFile().list()?.size}.aab", ordinaryDex, resourceBytes = resourceBytes),
        ordinaryApk = apk("ordinary-${temporary.toFile().list()?.size}.apk", ordinaryDex, resourceBytes = resourceBytes),
        hardenedAab = aab("hardened-${temporary.toFile().list()?.size}.aab", hardenedDex, resourceBytes = resourceBytes),
        hardenedApk = apk("hardened-${temporary.toFile().list()?.size}.apk", hardenedDex, resourceBytes = resourceBytes),
    )

    private fun aab(
        name: String,
        dex: ByteArray,
        additionalEntries: Map<String, ByteArray> = emptyMap(),
        resourceBytes: ByteArray? = RESOURCE_BYTES,
    ) = artifact(
        name,
        buildMap {
            put("base/dex/classes.dex", dex)
            if (resourceBytes != null) put("base/res/raw/owned.bin", resourceBytes)
            put("base/res/raw/dependency.bin", "dependency".toByteArray())
            put("base/res/raw/com_vb_showcase_secret.bin", "showcase".toByteArray())
            putAll(additionalEntries)
        },
    )

    private fun apk(
        name: String,
        dex: ByteArray,
        additionalEntries: Map<String, ByteArray> = emptyMap(),
        resourceBytes: ByteArray? = RESOURCE_BYTES,
    ) = artifact(
        name,
        buildMap {
            put("classes.dex", dex)
            if (resourceBytes != null) put("res/raw/owned.bin", resourceBytes)
            put("res/raw/dependency.bin", "dependency".toByteArray())
            put("res/raw/com_vb_showcase_secret.bin", "showcase".toByteArray())
            putAll(additionalEntries)
        },
    )

    private fun artifact(name: String, entries: Map<String, ByteArray>): Path = temporary.resolve(name).also { path ->
        ZipOutputStream(path.outputStream()).use { output ->
            entries.forEach { (entryName, bytes) ->
                output.putNextEntry(ZipEntry(entryName))
                output.write(bytes)
                output.closeEntry()
            }
        }
    }

    private fun classWithMethods(
        descriptor: String,
        vararg methods: ImmutableMethod,
        sourceFile: String? = null,
    ) = ImmutableClassDef(
        descriptor,
        AccessFlags.PUBLIC.value,
        "Ljava/lang/Object;",
        emptyList(),
        sourceFile,
        emptySet(),
        emptyList(),
        methods.toList().map { method ->
            ImmutableMethod(
                descriptor,
                method.name,
                method.parameters,
                method.returnType,
                method.accessFlags,
                method.annotations,
                method.hiddenApiRestrictions,
                method.implementation,
            )
        },
    )

    private fun method(
        name: String,
        instructions: List<Instruction>?,
        accessFlags: Int = AccessFlags.PUBLIC.value or AccessFlags.STATIC.value,
        debugItems: List<ImmutableLineNumber> = emptyList(),
    ) = ImmutableMethod(
        OWNED_DESCRIPTOR,
        name,
        emptyList(),
        "V",
        accessFlags,
        emptySet(),
        emptySet(),
        instructions?.let { ImmutableMethodImplementation(2, it, emptyList(), debugItems) },
    )

    private fun longBody(replacement: Opcode? = null): List<Instruction> = buildList {
        repeat(12) { index ->
            add(
                if (index == 5 && replacement != null) ImmutableInstruction11n(replacement, 0, 0)
                else ImmutableInstruction10x(Opcode.NOP),
            )
        }
        add(ImmutableInstruction10x(Opcode.RETURN_VOID))
    }

    private fun constantLongBody(instructionCount: Int): List<Instruction> = buildList {
        repeat(instructionCount) { index -> add(ImmutableInstruction11n(Opcode.CONST_4, 0, index and 0x7)) }
        add(ImmutableInstruction10x(Opcode.RETURN_VOID))
    }

    private fun crossMethodBody(payloadShingle: List<Opcode>): List<Instruction> = buildList {
        payloadShingle.forEach { opcode -> add(instructionForPayloadOpcode(opcode)) }
        repeat(121) { add(ImmutableInstruction12x(Opcode.NEG_INT, 0, 0)) }
        add(ImmutableInstruction10x(Opcode.RETURN_VOID))
    }

    private fun fixedScorerBody(pattern: List<Opcode>, instructionCount: Int): List<Instruction> {
        val preexistingPayload = List(FIXED_SCORER_PREEXISTING_PAYLOAD_SIZE) { index ->
            instructionForPayloadOpcode(pattern[index % pattern.size])
        }
        return buildList {
            add(ImmutableInstruction30t(Opcode.GOTO_32, 3 + preexistingPayload.sumOf(Instruction::getCodeUnits)))
            addAll(preexistingPayload)
            repeat(instructionCount) { index -> add(instructionForPayloadOpcode(pattern[index % pattern.size])) }
            add(ImmutableInstruction10x(Opcode.RETURN_VOID))
        }
    }

    private fun honestScorerBody(instructionCount: Int, pattern: List<Opcode>): List<Instruction> = buildList {
        add(ImmutableInstruction11n(Opcode.CONST_4, 0, 1))
        repeat(instructionCount - 2) { index ->
            add(ImmutableInstruction12x(pattern[index % pattern.size], 0, 0))
        }
        add(ImmutableInstruction10x(Opcode.RETURN_VOID))
    }

    private fun withDeadMarkerCategories(
        controlDex: ByteArray,
        diamondCounts: Map<String, Int>,
    ): ByteArray {
        val dex = DexBackedDexFile(Opcodes.getDefault(), controlDex)
        val markerValues = listOf(
            "",
            "SLH:S:1",
            "SLH:M:" + "a".repeat(10),
            "SLH:L:" + "b".repeat(58),
            "SLH:VL:" + "c".repeat(153),
        )
        val rewritten = dex.classes.map { classDef ->
            ImmutableClassDef(
                classDef.type,
                classDef.accessFlags,
                classDef.superclass,
                classDef.interfaces,
                classDef.sourceFile,
                classDef.annotations,
                classDef.fields,
                classDef.methods.map { method ->
                    val id = "${method.definingClass}->${method.name}(${method.parameterTypes.joinToString("")})${method.returnType}"
                    val implementation = method.implementation
                    if (id !in diamondCounts || implementation == null) {
                        ImmutableMethod.of(method)
                    } else {
                        val mutable = MutableMethodImplementation(implementation)
                        val payloadChunks = entryPayloadIndexChunks(implementation.instructions.toList(), diamondCounts.getValue(id))
                        val replacementIndexes = payloadChunks.flatMap { it.drop(1) }.take(markerValues.size)
                        check(replacementIndexes.size == markerValues.size)
                        replacementIndexes.zip(markerValues).forEach { (index, value) ->
                            mutable.replaceInstruction(
                                index,
                                BuilderInstruction31c(
                                    Opcode.CONST_STRING_JUMBO,
                                    0,
                                    ImmutableStringReference(value),
                                ),
                            )
                        }
                        ImmutableMethod(
                            method.definingClass,
                            method.name,
                            method.parameters,
                            method.returnType,
                            method.accessFlags,
                            method.annotations,
                            method.hiddenApiRestrictions,
                            ImmutableMethodImplementation.of(mutable),
                        )
                    }
                },
            )
        }
        return dex(*rewritten.toTypedArray())
    }

    private fun entryPayloadIndexChunks(instructions: List<Instruction>, diamondCount: Int): List<List<Int>> {
        val addresses = IntArray(instructions.size)
        var address = 0
        instructions.forEachIndexed { index, instruction ->
            addresses[index] = address
            address += instruction.codeUnits
        }
        val indexByAddress = addresses.withIndex().associate { it.value to it.index }
        if (diamondCount == 0) {
            val jump = instructions.first() as OffsetInstruction
            val continuation = indexByAddress.getValue(jump.codeOffset)
            return listOf((1 until continuation).toList())
        }
        var current = 0
        return List(diamondCount) {
            val jumpIndex = current + 1
            val jump = instructions[jumpIndex] as OffsetInstruction
            val continuation = indexByAddress.getValue(addresses[jumpIndex] + jump.codeOffset)
            val payload = ((current + 3) until continuation).toList()
            current = continuation
            payload
        }
    }

    private fun withoutDeadMarkerCategories(markerDex: ByteArray): ByteArray {
        val dex = DexBackedDexFile(Opcodes.getDefault(), markerDex)
        val rewritten = dex.classes.map { classDef ->
            ImmutableClassDef(
                classDef.type,
                classDef.accessFlags,
                classDef.superclass,
                classDef.interfaces,
                classDef.sourceFile,
                classDef.annotations,
                classDef.fields,
                classDef.methods.map { method ->
                    val implementation = method.implementation
                    if (implementation == null) {
                        ImmutableMethod.of(method)
                    } else {
                        val mutable = MutableMethodImplementation(implementation)
                        implementation.instructions.forEachIndexed { index, instruction ->
                            if (instruction.opcode == Opcode.CONST_STRING_JUMBO) {
                                mutable.replaceInstruction(index, BuilderInstruction12x(Opcode.NEG_INT, 0, 0))
                            }
                        }
                        ImmutableMethod(
                            method.definingClass,
                            method.name,
                            method.parameters,
                            method.returnType,
                            method.accessFlags,
                            method.annotations,
                            method.hiddenApiRestrictions,
                            ImmutableMethodImplementation.of(mutable),
                        )
                    }
                },
            )
        }
        return dex(*rewritten.toTypedArray())
    }

    private fun exactPriorProductionRelayMethod(
        name: String,
        instructions: List<Instruction>,
        salt: ByteArray,
    ): LegacyFullCapRelayMethod {
        val original = method(name, instructions, AccessFlags.PRIVATE.value)
        val methodId = "$OWNED_DESCRIPTOR->$name()V"
        val split = requireNotNull(
            ReachableRelaySplitter().split(
                implementation = requireNotNull(original.implementation),
                salt = salt,
                methodId = methodId,
                maximumPairs = 256,
            ),
        )
        val payloadInstructionCount = priorProductionDetourCap(
            originalCodeUnits = instructions.sumOf(Instruction::getCodeUnits),
            salt = salt,
            methodId = methodId,
        )
        val weave = SafeNopWeaver().weave(
            implementation = split.implementation,
            salt = salt,
            methodId = methodId,
            detourPaddingNopCount = payloadInstructionCount,
            expandConditionals = true,
        ) as? NopWeaveResult.Candidate ?: error("exact prior-production scorer method was not transformable")
        check(weave.insertedPayloadInstructionCount == payloadInstructionCount)
        check(weave.insertedRelayInstructionCount == 0)
        return LegacyFullCapRelayMethod(
            method = ImmutableMethod(
                original.definingClass,
                original.name,
                original.parameters,
                original.returnType,
                original.accessFlags,
                original.annotations,
                original.hiddenApiRestrictions,
                weave.implementation,
            ),
            payloadInstructionCount = payloadInstructionCount,
            relayInstructionCount = split.pairCount * 2,
        )
    }

    private fun priorProductionDetourCap(originalCodeUnits: Int, salt: ByteArray, methodId: String): Int {
        val absoluteCap = maxOf(2_048, originalCodeUnits * 4).coerceAtMost(4_096)
        val minimumSaltedCap = minOf(absoluteCap, 1_024)
        val digest = MessageDigest.getInstance("SHA-256").apply {
            update("demo-safe-dex-v1\u0000".toByteArray(StandardCharsets.UTF_8))
            update(ByteBuffer.allocate(Int.SIZE_BYTES).order(ByteOrder.BIG_ENDIAN).putInt(salt.size).array())
            update(salt)
            val methodBytes = "$methodId\u0000detour-cap".toByteArray(StandardCharsets.UTF_8)
            update(ByteBuffer.allocate(Int.SIZE_BYTES).order(ByteOrder.BIG_ENDIAN).putInt(methodBytes.size).array())
            update(methodBytes)
        }.digest()
        val bucket = digest[0].toInt() and 0xff
        return minimumSaltedCap + bucket % (absoluteCap - minimumSaltedCap + 1)
    }

    private data class LegacyFullCapRelayMethod(
        val method: ImmutableMethod,
        val payloadInstructionCount: Int,
        val relayInstructionCount: Int,
    )

    private fun instructionForPayloadOpcode(opcode: Opcode): Instruction = when (opcode) {
        Opcode.NOP -> ImmutableInstruction10x(Opcode.NOP)
        Opcode.CONST_4 -> ImmutableInstruction11n(Opcode.CONST_4, 0, 0)
        Opcode.MOVE -> ImmutableInstruction12x(Opcode.MOVE, 0, 0)
        else -> error("Unexpected detour payload opcode $opcode")
    }

    private fun selfOnlyScore(
        ordinary: List<MethodFingerprint>,
        hardenedById: Map<String, MethodFingerprint>,
    ): Double = weightedScore(*ordinary.map { method -> method to hardenedById.getValue(method.identifier) }.toTypedArray())

    private fun weightedScore(vararg matches: Pair<MethodFingerprint, MethodFingerprint>): Double {
        val total = matches.sumOf { (ordinary, _) -> ordinary.instructionCount }
        return 100.0 * matches.sumOf { (ordinary, hardened) ->
            ordinary.instructionCount * OwnedArtifactSimilarityScorerV1.methodSimilarity(ordinary, hardened)
        } / total
    }

    private fun fixedTwoMethodGreedyScore(
        ordinary: List<MethodFingerprint>,
        matrix: List<List<Double>>,
        assignment: List<Int>,
    ): Double {
        require(ordinary.size == 2 && matrix.size == 2 && matrix.all { it.size == 2 } && assignment.size == 2)
        val total = ordinary.sumOf(MethodFingerprint::instructionCount)
        val matched = ordinary.indices.sumOf { ordinaryIndex ->
            ordinary[ordinaryIndex].instructionCount * matrix[ordinaryIndex][assignment[ordinaryIndex]]
        }
        return 100.0 * matched / total
    }

    private fun fixedTwoMethodGreedyAssignment(
        ordinary: List<MethodFingerprint>,
        hardened: List<MethodFingerprint>,
        matrix: List<List<Double>>,
    ): List<Int> {
        require(ordinary.size == 2 && hardened.size == 2 && matrix.size == 2 && matrix.all { it.size == 2 })
        val ordinaryIndexById = ordinary.withIndex().associate { it.value.identifier to it.index }
        val used = mutableSetOf<Int>()
        val assignment = IntArray(ordinary.size)
        ordinary.sortedWith(
            compareByDescending<MethodFingerprint> { it.instructionCount }.thenBy { it.identifier },
        ).forEach { before ->
            val ordinaryIndex = ordinaryIndexById.getValue(before.identifier)
            val hardenedIndex = hardened.indices.filterNot(used::contains).maxWith(
                compareBy<Int> { matrix[ordinaryIndex][it] }
                    .thenByDescending { kotlin.math.abs(before.instructionCount - hardened[it].instructionCount) }
                    .thenByDescending { hardened[it].identifier },
            )
            used += hardenedIndex
            assignment[ordinaryIndex] = hardenedIndex
        }
        return assignment.toList()
    }

    private fun greedyAssignment(
        ordinary: List<MethodFingerprint>,
        hardened: List<MethodFingerprint>,
        matrix: List<List<Double>>,
    ): List<Int> {
        val ordinaryIndexById = ordinary.withIndex().associate { it.value.identifier to it.index }
        val used = mutableSetOf<Int>()
        val assignment = IntArray(ordinary.size)
        ordinary.sortedWith(compareByDescending<MethodFingerprint> { it.instructionCount }.thenBy { it.identifier })
            .forEach { before ->
                val ordinaryIndex = ordinaryIndexById.getValue(before.identifier)
                val hardenedIndex = hardened.indices.filterNot(used::contains).maxWith(
                    compareBy<Int> { matrix[ordinaryIndex][it] }
                        .thenByDescending { kotlin.math.abs(before.instructionCount - hardened[it].instructionCount) }
                        .thenByDescending { hardened[it].identifier },
                )
                used += hardenedIndex
                assignment[ordinaryIndex] = hardenedIndex
            }
        return assignment.toList()
    }

    private fun normalizedBody(
        register: Int,
        literal: Int,
        text: String,
        platformClass: String,
        platformMember: String,
    ): List<Instruction> =
        buildList {
            add(ImmutableInstruction11n(Opcode.CONST_4, register, literal))
            add(ImmutableInstruction21c(Opcode.CONST_STRING, register, ImmutableStringReference(text)))
            add(
                ImmutableInstruction35c(
                    Opcode.INVOKE_STATIC,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    ImmutableMethodReference(platformClass, platformMember, emptyList<String>(), "V"),
                ),
            )
            add(ImmutableInstruction21t(Opcode.IF_EQZ, register, 4))
            repeat(8) { add(ImmutableInstruction10x(Opcode.NOP)) }
            add(ImmutableInstruction10x(Opcode.RETURN_VOID))
        }

    private fun branchingBody(branchOffset: Int): List<Instruction> = buildList {
        add(ImmutableInstruction11n(Opcode.CONST_4, 0, 0))
        add(ImmutableInstruction10x(Opcode.NOP))
        add(ImmutableInstruction21t(Opcode.IF_EQZ, 0, branchOffset))
        repeat(9) { add(ImmutableInstruction10x(Opcode.NOP)) }
        add(ImmutableInstruction10x(Opcode.RETURN_VOID))
    }

    private fun dex(vararg classes: ImmutableClassDef): ByteArray {
        val store = MemoryDataStore()
        DexPool.writeTo(store, ImmutableDexFile(Opcodes.getDefault(), classes.toList()))
        return store.data
    }

    private fun location(
        aabPath: String = "base/res/raw/owned.bin",
        apkPath: String = "res/raw/owned.bin",
        semanticHash: String = SEMANTIC_HASH,
    ) = OwnedResourceLocation("owned.bin", aabPath, apkPath, semanticHash)

    private data class Artifacts(
        val ordinaryAab: Path,
        val ordinaryApk: Path,
        val hardenedAab: Path,
        val hardenedApk: Path,
    )

    private companion object {
        const val OWNED_DESCRIPTOR = "Lcom/example/demo/match/Owned;"
        const val SECOND_OWNED_DESCRIPTOR = "Lcom/example/demo/match/Second;"
        const val RESOURCE_ID = 0x7f120001
        const val SYNTHETIC_PRIVATE_STATIC = 0x100a
        val FIXED_CROSS_METHOD_SIGNATURE = listOf(
            Opcode.MOVE,
            Opcode.CONST_4,
            Opcode.NOP,
            Opcode.CONST_4,
            Opcode.CONST_4,
        )
        val FIXED_SCORER_ALPHA_BODY = listOf(Opcode.CONST_4, Opcode.MOVE)
        val FIXED_SCORER_BETA_BODY = listOf(Opcode.MOVE, Opcode.CONST_4, Opcode.CONST_4)
        const val FIXED_SCORER_PREEXISTING_PAYLOAD_SIZE = 64
        val MARKER_CATEGORIES = setOf(
            "string:empty",
            "string:short",
            "string:medium",
            "string:long",
            "string:very-long",
        )
        val RESOURCE_BYTES = "owned resource".toByteArray()
        val SEMANTIC_HASH = "a".repeat(64)
    }
}
