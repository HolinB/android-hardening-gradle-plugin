package com.holin.android.hardening.artifact

import com.holin.android.hardening.state.Sha256
import java.nio.file.Files
import java.nio.file.Path
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream
import kotlin.io.path.listDirectoryEntries
import kotlin.io.path.readText
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import org.junit.jupiter.api.io.TempDir

class UniversalApkArtifactTest {
    @TempDir
    lateinit var temporary: Path

    @Test
    fun `verified universal APK and report publish as one pair`() {
        val fixture = fixture()
        val expectedSigner = "a".repeat(64)
        val apkBytes = "signed-universal-apk".toByteArray()
        val operations = mutableListOf<String>()
        val assembler = UniversalApkAssembler(
            apksBuilder = UniversalApksBuilder { _, output, _, _ -> apks(output, apkBytes) },
            aabSigner = { expectedSigner },
            apkSigner = {
                operations += "verify-signature"
                expectedSigner
            },
            payloadRewriter = ApkPayloadRewriteOperation { source, output, _, targets ->
                operations += "rewrite"
                Files.copy(source, output)
                ApkPayloadRewriteResult(targets.sorted())
            },
            zipaligner = object : ApkZipalignOperation {
                override fun align(zipalignExecutable: Path, inputApk: Path, outputApk: Path) {
                    operations += "align"
                    Files.copy(inputApk, outputApk)
                }

                override fun verify(zipalignExecutable: Path, signedApk: Path) {
                    operations += "verify-zipalign"
                }
            },
            apkSigning = ApkSigningOperation { input, output, _ ->
                operations += "sign"
                Files.copy(input, output)
                ApkSigningResult(expectedSigner)
            },
            payloadVerifier = ApkPayloadVerificationOperation { _, _, targets ->
                operations += "verify-payload"
                ApkPayloadDiversificationVerification(targets.toSet())
            },
        )

        val report = assembler.assemble(fixture.request(expectedSigner))

        assertEquals(Sha256.hex(apkBytes), report.universalApkSha256)
        assertEquals(apkBytes.toList(), Files.readAllBytes(fixture.outputApk).toList())
        assertEquals(report, UniversalApkVerificationReportCodec.decode(fixture.outputReport.readText()))
        assertEquals(1, report.binaryXmlDiversifiedCount)
        assertEquals(
            ApkBinaryXmlTargetPathDigest.sha256(listOf("res/layout/hardened_screen.xml")),
            report.binaryXmlTargetPathsSha256,
        )
        assertTrue(report.zipalignVerified)
        assertEquals(
            listOf(
                "verify-signature",
                "rewrite",
                "align",
                "sign",
                "verify-zipalign",
                "verify-signature",
                "verify-payload",
            ),
            operations,
        )
        assertTrue(temporary.listDirectoryEntries().none { it.fileName.toString().startsWith(".hardening-universal-") })
    }

    @Test
    fun `APK signer mismatch publishes neither APK nor report`() {
        val fixture = fixture()
        val assembler = UniversalApkAssembler(
            apksBuilder = UniversalApksBuilder { _, output, _, _ -> apks(output, "apk".toByteArray()) },
            aabSigner = { "a".repeat(64) },
            apkSigner = { "b".repeat(64) },
        )

        val failure = assertFailsWith<IllegalArgumentException> {
            assembler.assemble(fixture.request("a".repeat(64)))
        }

        assertEquals(
            "universal APK signer certificate does not match the verified hardened AAB",
            failure.message,
        )
        assertFalse(Files.exists(fixture.outputApk))
        assertFalse(Files.exists(fixture.outputReport))
    }

    @Test
    fun `AAB report mismatch fails before bundletool is invoked`() {
        val fixture = fixture()
        var invoked = false
        val assembler = UniversalApkAssembler(
            apksBuilder = UniversalApksBuilder { _, _, _, _ -> invoked = true },
            aabSigner = { "a".repeat(64) },
            apkSigner = { "a".repeat(64) },
        )
        val request = fixture.request("a".repeat(64)).copy(
            bundleVerification = fixture.bundleReport("a".repeat(64)).copy(
                hardenedAabSha256 = "f".repeat(64),
            ),
        )

        val failure = assertFailsWith<IllegalArgumentException> { assembler.assemble(request) }

        assertEquals("verified hardened AAB hash differs from its published report", failure.message)
        assertFalse(invoked)
        assertFalse(Files.exists(fixture.outputApk))
        assertFalse(Files.exists(fixture.outputReport))
    }

    @Test
    fun `every APK post-processing failure boundary cleans intermediates and publishes nothing`() {
        listOf("rewrite", "align", "sign", "zipalign-check", "final-signer", "payload").forEach { stage ->
            val fixture = fixture()
            val expectedSigner = "a".repeat(64)
            var apkVerificationCount = 0
            val assembler = UniversalApkAssembler(
                apksBuilder = UniversalApksBuilder { _, output, _, _ -> apks(output, "bundletool-apk".encodeToByteArray()) },
                aabSigner = { expectedSigner },
                apkSigner = {
                    apkVerificationCount++
                    if (stage == "final-signer" && apkVerificationCount == 2) "b".repeat(64) else expectedSigner
                },
                payloadRewriter = ApkPayloadRewriteOperation { source, output, _, targets ->
                    Files.copy(source, output)
                    if (stage == "rewrite") error("rewrite failure")
                    ApkPayloadRewriteResult(targets.sorted())
                },
                zipaligner = object : ApkZipalignOperation {
                    override fun align(zipalignExecutable: Path, inputApk: Path, outputApk: Path) {
                        Files.copy(inputApk, outputApk)
                        if (stage == "align") error("align failure")
                    }

                    override fun verify(zipalignExecutable: Path, signedApk: Path) {
                        if (stage == "zipalign-check") error("zipalign check failure")
                    }
                },
                apkSigning = ApkSigningOperation { input, output, _ ->
                    Files.copy(input, output)
                    if (stage == "sign") error("sign failure")
                    ApkSigningResult(expectedSigner)
                },
                payloadVerifier = ApkPayloadVerificationOperation { _, _, targets ->
                    if (stage == "payload") error("payload failure")
                    ApkPayloadDiversificationVerification(targets.toSet())
                },
            )

            assertFailsWith<Exception> { assembler.assemble(fixture.request(expectedSigner)) }
            assertFalse(Files.exists(fixture.outputApk))
            assertFalse(Files.exists(fixture.outputReport))
            assertTrue(temporary.listDirectoryEntries().none { it.fileName.toString().startsWith(".hardening-universal-") })
        }
    }

    @Test
    fun `verification report rejects an unverified APK`() {
        val valid = UniversalApkVerificationReport(
            variant = "demoRelease",
            contentSaltSha256 = "1".repeat(64),
            hardenedAabSha256 = "2".repeat(64),
            universalApkSha256 = "3".repeat(64),
            signerCertificateSha256 = "4".repeat(64),
            bundletoolVersion = BUNDLETOOL_VERSION,
            binaryXmlDiversifiedCount = 2,
            binaryXmlTargetPathsSha256 = "5".repeat(64),
            zipalignVerified = true,
            apkSignatureVerified = true,
        )
        val invalid = UniversalApkVerificationReportCodec.encode(valid)
            .replace("\"apkSignatureVerified\":true", "\"apkSignatureVerified\":false")

        val failure = assertFailsWith<IllegalArgumentException> {
            UniversalApkVerificationReportCodec.decode(invalid)
        }

        assertEquals("universal APK report did not pass APK signature verification", failure.message)
    }

    @Test
    fun `verification report strictly validates binary XML and zipalign accounting`() {
        val valid = UniversalApkVerificationReport(
            variant = "demoRelease",
            contentSaltSha256 = "1".repeat(64),
            hardenedAabSha256 = "2".repeat(64),
            universalApkSha256 = "3".repeat(64),
            signerCertificateSha256 = "4".repeat(64),
            bundletoolVersion = BUNDLETOOL_VERSION,
            binaryXmlDiversifiedCount = 2,
            binaryXmlTargetPathsSha256 = "5".repeat(64),
            zipalignVerified = true,
            apkSignatureVerified = true,
        )
        val encoded = UniversalApkVerificationReportCodec.encode(valid)

        assertEquals(valid, UniversalApkVerificationReportCodec.decode(encoded))
        listOf(
            encoded.replace("\"binaryXmlDiversifiedCount\":2,", ""),
            encoded.replace("\"binaryXmlDiversifiedCount\":2", "\"binaryXmlDiversifiedCount\":2,\"extra\":true"),
            encoded.replace("\"binaryXmlDiversifiedCount\":2", "\"binaryXmlDiversifiedCount\":-1"),
            encoded.replace("\"binaryXmlTargetPathsSha256\":\"${"5".repeat(64)}\"", "\"binaryXmlTargetPathsSha256\":\"invalid\""),
            encoded.replace("\"zipalignVerified\":true", "\"zipalignVerified\":false"),
        ).forEach { invalid ->
            assertFailsWith<IllegalArgumentException> { UniversalApkVerificationReportCodec.decode(invalid) }
        }
    }

    @Test
    fun `verification report accepts zero when an invocation owns no rewritten XML`() {
        val report = UniversalApkVerificationReport(
            variant = "demoDebug",
            contentSaltSha256 = "1".repeat(64),
            hardenedAabSha256 = "2".repeat(64),
            universalApkSha256 = "3".repeat(64),
            signerCertificateSha256 = "4".repeat(64),
            bundletoolVersion = BUNDLETOOL_VERSION,
            binaryXmlDiversifiedCount = 0,
            binaryXmlTargetPathsSha256 = ApkBinaryXmlTargetPathDigest.sha256(emptyList()),
            zipalignVerified = true,
            apkSignatureVerified = true,
        )

        assertEquals(report, UniversalApkVerificationReportCodec.decode(UniversalApkVerificationReportCodec.encode(report)))
    }

    @Test
    fun `verification report rejects inconsistent empty target provenance`() {
        val nonEmptyDigest = "5".repeat(64)
        val emptyDigest = ApkBinaryXmlTargetPathDigest.sha256(emptyList())
        val valid = UniversalApkVerificationReport(
            variant = "demoRelease",
            contentSaltSha256 = "1".repeat(64),
            hardenedAabSha256 = "2".repeat(64),
            universalApkSha256 = "3".repeat(64),
            signerCertificateSha256 = "4".repeat(64),
            bundletoolVersion = BUNDLETOOL_VERSION,
            binaryXmlDiversifiedCount = 2,
            binaryXmlTargetPathsSha256 = nonEmptyDigest,
            zipalignVerified = true,
            apkSignatureVerified = true,
        )
        val encoded = UniversalApkVerificationReportCodec.encode(valid)

        listOf(
            encoded
                .replace("\"binaryXmlDiversifiedCount\":2", "\"binaryXmlDiversifiedCount\":0"),
            encoded
                .replace("\"binaryXmlTargetPathsSha256\":\"$nonEmptyDigest\"", "\"binaryXmlTargetPathsSha256\":\"$emptyDigest\""),
        ).forEach { invalid ->
            assertFailsWith<IllegalArgumentException> {
                UniversalApkVerificationReportCodec.decode(invalid)
            }
        }
    }

    @Test
    fun `ordinary universal APK uses the shared bundletool builder and verifies signer parity`() {
        val fixture = fixture()
        val expectedSigner = "a".repeat(64)
        var invoked = false
        val assembler = OrdinaryUniversalApkAssembler(
            apksBuilder = UniversalApksBuilder { bundle, output, aapt2, material ->
                assertEquals(fixture.bundle, bundle)
                assertEquals(fixture.aapt2, aapt2)
                assertEquals(fixture.signingMaterial.configName, material.configName)
                invoked = true
                apks(output, "ordinary-universal-apk".toByteArray())
            },
            aabSigner = { expectedSigner },
            apkSigner = { expectedSigner },
        )

        val hash = assembler.assemble(
            OrdinaryUniversalApkAssemblyRequest(
                ordinaryBundle = fixture.bundle,
                aapt2Executable = fixture.aapt2,
                targetApk = fixture.outputApk,
                signingMaterial = fixture.signingMaterial,
            ),
        )

        assertTrue(invoked)
        assertEquals(Sha256.file(fixture.outputApk), hash)
    }

    private fun fixture(): Fixture {
        val bundle = temporary.resolve("verified.aab")
        Files.writeString(bundle, "verified-hardened-aab")
        val aapt2 = temporary.resolve("aapt2")
        Files.writeString(aapt2, "fixture")
        val zipalign = temporary.resolve("zipalign")
        Files.writeString(zipalign, "fixture")
        val keyStore = temporary.resolve("signing.p12")
        Files.writeString(keyStore, "fixture")
        return Fixture(
            bundle = bundle,
            aapt2 = aapt2,
            zipalign = zipalign,
            signingMaterial = SigningMaterial.create(
                configName = "fixture",
                storeFile = keyStore,
                storePassword = "store-password",
                keyAlias = "fixture-key",
                keyPassword = "key-password",
                storeType = "PKCS12",
            ),
            outputApk = temporary.resolve("demoRelease-hardened-universal.apk"),
            outputReport = temporary.resolve("universal-apk-verification.json"),
        )
    }

    private fun apks(path: Path, apkBytes: ByteArray) {
        ZipOutputStream(Files.newOutputStream(path)).use { output ->
            output.putNextEntry(ZipEntry("toc.pb"))
            output.write("toc".toByteArray())
            output.closeEntry()
            output.putNextEntry(ZipEntry("universal.apk"))
            output.write(apkBytes)
            output.closeEntry()
        }
    }

    private data class Fixture(
        val bundle: Path,
        val aapt2: Path,
        val zipalign: Path,
        val signingMaterial: SigningMaterial,
        val outputApk: Path,
        val outputReport: Path,
    ) {
        fun request(signer: String): UniversalApkAssemblyRequest = UniversalApkAssemblyRequest(
            variant = "demoRelease",
            contentSaltSha256 = "1".repeat(64),
            hardenedBundle = bundle,
            aapt2Executable = aapt2,
            zipalignExecutable = zipalign,
            bundleVerification = bundleReport(signer),
            rewriteManifest = rewriteManifest(),
            targetApk = outputApk,
            targetReport = outputReport,
            signingMaterial = signingMaterial,
        )

        fun bundleReport(signer: String): BundleVerificationReport = BundleVerificationReport(
            variant = "demoRelease",
            contentSaltSha256 = "1".repeat(64),
            ordinaryAabSha256 = "2".repeat(64),
            hardenedAabSha256 = Sha256.file(bundle),
            signerCertificateSha256 = signer,
            preservedEntryCount = 1,
            bundletoolValidated = true,
        )

        private fun rewriteManifest(): BundleRewriteManifest = BundleRewriteManifest(
            originalAabSha256 = "2".repeat(64),
            contentSaltSha256 = "1".repeat(64),
            entries = listOf(
                BundleRewriteEntry.renamed(
                    oldPath = "base/res/layout/screen.xml",
                    newPath = "base/res/layout/hardened_screen.xml",
                    sha256 = "6".repeat(64),
                ),
            ),
        )
    }
}
