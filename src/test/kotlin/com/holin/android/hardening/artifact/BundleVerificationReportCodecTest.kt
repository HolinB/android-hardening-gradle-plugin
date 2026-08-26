package com.holin.android.hardening.artifact

import com.holin.android.hardening.state.Sha256
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class BundleVerificationReportCodecTest {
    @Test
    fun `report round trips the invocation salt and verified artifact identity`() {
        val report = BundleVerificationReport(
            variant = "demoRelease",
            contentSaltSha256 = "a".repeat(64),
            ordinaryAabSha256 = "b".repeat(64),
            hardenedAabSha256 = "c".repeat(64),
            signerCertificateSha256 = "d".repeat(64),
            preservedEntryCount = 7,
            bundletoolValidated = true,
        )

        val encoded = BundleVerificationReportCodec.encode(report)

        assertEquals(report, BundleVerificationReportCodec.decode(encoded))
        assertTrue(encoded.contains("\"fixedSeedProvided\":false,\"fixedSeedHash\":null"))
    }

    @Test
    fun `report records only the correlated fixed seed hash`() {
        val rawFixedSeed = "bundle report raw fixed seed must not be serialized"
        val fixedSeedHash = Sha256.hex(rawFixedSeed.toByteArray())
        val report = BundleVerificationReport(
            "demoRelease",
            "a".repeat(64),
            "b".repeat(64),
            "c".repeat(64),
            "d".repeat(64),
            7,
            true,
            true,
            fixedSeedHash,
        )

        val encoded = BundleVerificationReportCodec.encode(report)

        assertEquals(report, BundleVerificationReportCodec.decode(encoded))
        assertTrue(encoded.contains("\"fixedSeedProvided\":true,\"fixedSeedHash\":\"$fixedSeedHash\""))
        assertFalse(encoded.contains(rawFixedSeed))
        assertFailsWith<IllegalArgumentException> {
            BundleVerificationReportCodec.decode(
                encoded.replace("\"fixedSeedProvided\":true", "\"fixedSeedProvided\":false"),
            )
        }
        assertFailsWith<IllegalArgumentException> {
            BundleVerificationReportCodec.decode(
                encoded.replace("\"fixedSeedHash\":\"$fixedSeedHash\"", "\"fixedSeedHash\":null"),
            )
        }
        assertFailsWith<IllegalArgumentException> {
            BundleVerificationReportCodec.decode(encoded.replace(fixedSeedHash, fixedSeedHash.uppercase()))
        }
    }

    @Test
    fun `report rejects unknown or reordered content`() {
        assertFailsWith<IllegalArgumentException> {
            BundleVerificationReportCodec.decode("{\"schemaVersion\":2}\n")
        }
    }
}
