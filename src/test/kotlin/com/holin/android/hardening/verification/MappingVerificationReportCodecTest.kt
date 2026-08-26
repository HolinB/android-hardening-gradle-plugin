package com.holin.android.hardening.verification

import com.holin.android.hardening.state.Sha256
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class MappingVerificationReportCodecTest {
    @Test
    fun `report encoding is stable and sorts diagnostics`() {
        val report = MappingVerificationReport(
            variant = "demoRelease",
            status = MappingVerificationStatus.FAIL,
            r8Version = "8.13.19",
            previousMappingSha256 = "a".repeat(64),
            currentMappingSha256 = "b".repeat(64),
            preparedMappingSha256 = "b".repeat(64),
            hardenedAabSha256 = "c".repeat(64),
            transformationReportSha256 = "d".repeat(64),
            bundleVerificationReportSha256 = "e".repeat(64),
            ordinaryAabSha256 = "f".repeat(64),
            contentSaltSha256 = "1".repeat(64),
            potentialBeanFieldManifestSha256 = "2".repeat(64),
            potentialBeanFields = fieldResult(listOf("field-z", "field-a")),
            renamedOwnedClasses = 3,
            renamedOwnedMethods = 4,
            retiredLegacyFieldAssignmentCount = 2,
            previousSymbols = MappingSymbolCounts(1, 2, 3),
            currentSymbols = MappingSymbolCounts(4, 5, 6),
            continuity = MappingContinuityResult(
                previousCount = 6,
                applicableCount = 5,
                stableCount = 4,
                noLongerPresentCount = 1,
                mismatches = listOf(
                    MappingContinuityMismatch(
                        MappingSymbolKey(SymbolKind.METHOD, "com.example.Foo", "run", "()V"),
                        listOf("a"),
                        listOf("b"),
                    ),
                ),
            ),
            retraceInputFrame = "at a.b(HardeningSource:7)",
            retracedFrames = listOf("at com.example.Foo.run(Foo.kt:42)"),
            retraceVerified = false,
            violations = listOf("z-last", "a-first"),
        )

        val first = MappingVerificationReportCodec.encode(report)
        val second = MappingVerificationReportCodec.encode(report)

        assertEquals(first, second)
        assertTrue(first.indexOf("a-first") < first.indexOf("z-last"))
        assertTrue(first.indexOf("field-a") < first.indexOf("field-z"))
        assertTrue(first.startsWith("{\"schemaVersion\":2"))
        assertTrue(first.endsWith("\n"))
    }

    @Test
    fun `passing provenance decoder retains archive linkage`() {
        val encoded = MappingVerificationReportCodec.encode(passingReport())

        val provenance = decodePassing(encoded)

        assertEquals("demoDebug", provenance.variant)
        assertEquals("8.13.19", provenance.r8Version)
        assertEquals("a".repeat(64), provenance.previousMappingSha256)
        assertEquals("9".repeat(64), provenance.activeMappingSha256)
        assertEquals("b".repeat(64), provenance.currentMappingSha256)
        assertEquals("b".repeat(64), provenance.preparedMappingSha256)
        assertEquals("c".repeat(64), provenance.hardenedAabSha256)
        assertEquals("e".repeat(64), provenance.bundleVerificationReportSha256)
        assertEquals("f".repeat(64), provenance.ordinaryAabSha256)
        assertEquals("1".repeat(64), provenance.contentSaltSha256)
        assertEquals("2".repeat(64), provenance.potentialBeanFieldManifestSha256)
        assertEquals(2, provenance.retiredLegacyFieldAssignmentCount)
        assertFalse(provenance.fixedSeedProvided)
        assertEquals(null, provenance.fixedSeedHash)
        assertTrue(encoded.contains("\"fixedSeedProvided\":false,\"fixedSeedHash\":null"))
        assertTrue(encoded.indexOf("\"previousMappingSha256\"") < encoded.indexOf("\"currentMappingSha256\""))
        assertTrue(encoded.indexOf("\"currentMappingSha256\"") < encoded.indexOf("\"preparedMappingSha256\""))
        assertTrue(encoded.contains("\"mismatches\":[]"))
        assertTrue(encoded.contains("\"potentialBeanFields\":{\"policyVersion\":1"))
        assertTrue(encoded.contains("\"verified\":true"))
    }

    @Test
    fun `passing provenance records only the correlated fixed seed hash`() {
        val rawFixedSeed = "mapping report raw fixed seed must not be serialized"
        val fixedSeedHash = Sha256.hex(rawFixedSeed.toByteArray())
        val encoded = MappingVerificationReportCodec.encode(passingReport(fixedSeedHash))

        val provenance = decodePassing(encoded)

        assertTrue(provenance.fixedSeedProvided)
        assertEquals(fixedSeedHash, provenance.fixedSeedHash)
        assertTrue(encoded.contains("\"fixedSeedProvided\":true,\"fixedSeedHash\":\"$fixedSeedHash\""))
        assertFalse(encoded.contains(rawFixedSeed))
        assertFailsWith<IllegalArgumentException> {
            decodePassing(encoded.replace("\"fixedSeedProvided\":true", "\"fixedSeedProvided\":false"))
        }
        assertFailsWith<IllegalArgumentException> {
            decodePassing(encoded.replace("\"fixedSeedHash\":\"$fixedSeedHash\"", "\"fixedSeedHash\":null"))
        }
        assertFailsWith<IllegalArgumentException> {
            decodePassing(encoded.replace(fixedSeedHash, fixedSeedHash.uppercase()))
        }
    }

    @Test
    fun `passing provenance decoder rejects failed and malformed reports`() {
        val failed = MappingVerificationReportCodec.encode(
            passingReport().copy(
                status = MappingVerificationStatus.FAIL,
                retraceVerified = false,
                violations = listOf("mapping continuity failed"),
            ),
        )

        assertFailsWith<IllegalArgumentException> {
            decodePassing(failed)
        }
        assertFailsWith<IllegalArgumentException> {
            decodePassing("{not-json}\n")
        }
        assertFailsWith<IllegalArgumentException> {
            decodePassing(
                MappingVerificationReportCodec.encode(passingReport()).replace("\"schemaVersion\":2", "\"schemaVersion\":1"),
            )
        }
    }

    @Test
    fun `passing provenance rejects field failures and invalid rename acceptance counts`() {
        assertFailsWith<IllegalArgumentException> {
            passingReport().copy(potentialBeanFields = fieldResult(listOf("field renamed")))
        }
        assertFailsWith<IllegalArgumentException> {
            passingReport().copy(renamedOwnedClasses = 0)
        }
        assertFailsWith<IllegalArgumentException> {
            passingReport().copy(renamedOwnedMethods = 0)
        }
    }

    @Test
    fun `passing provenance is bound to the actual potential Bean manifest`() {
        val encoded = MappingVerificationReportCodec.encode(passingReport())

        assertFailsWith<IllegalArgumentException> {
            MappingVerificationReportCodec.decodePassingProvenance(
                encoded,
                "9".repeat(64),
                2,
            )
        }
        assertFailsWith<IllegalArgumentException> {
            MappingVerificationReportCodec.decodePassingProvenance(
                encoded,
                "2".repeat(64),
                3,
            )
        }
    }

    @Test
    fun `passing provenance rejects malformed nested schema 2 values`() {
        val encoded = MappingVerificationReportCodec.encode(passingReport())

        assertFailsWith<IllegalArgumentException> {
            decodePassing(encoded.replace("\"retraceInputFrame\":\"at a.b(HardeningSource:7)\"", "\"retraceInputFrame\":7"))
        }
        assertFailsWith<IllegalArgumentException> {
            decodePassing(
                encoded.replace(
                    "\"retracedFrames\":[\"at com.example.Foo.run(Foo.kt:42)\"]",
                    "\"retracedFrames\":[7]",
                ),
            )
        }
        assertFailsWith<IllegalArgumentException> {
            decodePassing(encoded.replace("\"shrunkOwnerCount\":1", "\"shrunkOwnerCount\":2"))
        }
        assertFailsWith<IllegalArgumentException> {
            decodePassing(
                encoded.replace(
                    "\"moduleFieldCounts\":{\":app\":2,\":compress\":0,\":core\":1,\":selector\":0,\":ucrop\":0}",
                    "\"moduleFieldCounts\":{}",
                ),
            )
        }
    }

    private fun passingReport(fixedSeedHash: String? = null) = MappingVerificationReport(
        "demoDebug",
        MappingVerificationStatus.PASS,
        "8.13.19",
        "a".repeat(64),
        "9".repeat(64),
        "b".repeat(64),
        "b".repeat(64),
        "c".repeat(64),
        "d".repeat(64),
        "e".repeat(64),
        "f".repeat(64),
        "1".repeat(64),
        "2".repeat(64),
        fieldResult(),
        3,
        4,
        2,
        MappingSymbolCounts(1, 2, 3),
        MappingSymbolCounts(4, 5, 6),
        MappingContinuityResult(6, 6, 6, 0, emptyList()),
        "at a.b(HardeningSource:7)",
        listOf("at com.example.Foo.run(Foo.kt:42)"),
        true,
        emptyList(),
        fixedSeedHash != null,
        fixedSeedHash,
    )

    private fun decodePassing(json: String): PassingMappingVerificationProvenance =
        MappingVerificationReportCodec.decodePassingProvenance(
            json,
            "2".repeat(64),
            2,
        )

    private fun fieldResult(violations: List<String> = emptyList()) = PotentialBeanFieldVerificationResult(
        1,
        mapOf(":app" to 2, ":core" to 1, ":compress" to 0, ":selector" to 0, ":ucrop" to 0),
        3,
        2,
        1,
        violations,
    )
}
