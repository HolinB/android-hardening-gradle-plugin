package com.holin.android.hardening.artifact

import java.nio.file.Files
import java.nio.file.Path
import java.util.zip.ZipEntry
import java.util.zip.ZipFile
import java.util.zip.ZipOutputStream
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import org.junit.jupiter.api.io.TempDir

class BundleSigningAndVerificationTest {
    @TempDir
    lateinit var temporary: Path

    @Test
    fun `bundletool validation rejects a structurally invalid bundle`() {
        val invalid = temporary.resolve("invalid.aab")
        zip(invalid)

        val failure = assertFailsWith<IllegalArgumentException> {
            BundletoolBundleValidator.validate(invalid)
        }

        assertEquals("bundletool rejected the hardened AAB", failure.message)
    }

    @Test
    fun `rewritten bundle is signed with the ordinary signer and published only after verification`() {
        val material = createSigningMaterial("first")
        val raw = temporary.resolve("raw.aab")
        zip(raw)
        val ordinary = temporary.resolve("ordinary.aab")
        BundleJarSigner().sign(raw, ordinary, material)
        val saltHash = "c".repeat(64)
        val unsigned = temporary.resolve("unsigned.aab")
        val rewrite = BundleZipRewriter().rewrite(ordinary, unsigned, saltHash)
        val staged = temporary.resolve("staged.aab")
        BundleJarSigner().sign(unsigned, staged, material)
        val published = temporary.resolve("published.aab")

        val report = SignedBundleVerifier(bundleValidator = {}).verifyAndPublish(
            ordinaryBundle = ordinary,
            signedCandidate = staged,
            outputBundle = published,
            contentSaltSha256 = saltHash,
            rewriteManifest = rewrite.manifest,
            semanticResults = emptyList(),
        )

        assertTrue(Files.isRegularFile(published))
        assertEquals(report.ordinarySignerCertificateSha256, report.hardenedSignerCertificateSha256)
        assertEquals(report.originalAabSha256, rewrite.manifest.originalAabSha256)
        assertEquals(saltHash, rewrite.manifest.contentSaltSha256)
    }

    @Test
    fun `certificate mismatch fails without publishing a candidate`() {
        val raw = temporary.resolve("raw.aab")
        zip(raw)
        val ordinary = temporary.resolve("ordinary.aab")
        BundleJarSigner().sign(raw, ordinary, createSigningMaterial("first"))
        val saltHash = "d".repeat(64)
        val unsigned = temporary.resolve("unsigned.aab")
        val rewrite = BundleZipRewriter().rewrite(ordinary, unsigned, saltHash)
        val staged = temporary.resolve("staged.aab")
        BundleJarSigner().sign(unsigned, staged, createSigningMaterial("second"))
        val published = temporary.resolve("must-not-exist.aab")

        val failure = assertFailsWith<IllegalArgumentException> {
            SignedBundleVerifier(bundleValidator = {}).verifyAndPublish(
                ordinaryBundle = ordinary,
                signedCandidate = staged,
                outputBundle = published,
                contentSaltSha256 = saltHash,
                rewriteManifest = rewrite.manifest,
                semanticResults = emptyList(),
            )
        }

        assertEquals("hardened AAB signer certificate does not match the ordinary release AAB", failure.message)
        assertTrue(Files.notExists(published))
    }

    @Test
    fun `resolved signing material exposes only its selected certificate digest`() {
        val material = createSigningMaterial("identity")
        val raw = temporary.resolve("identity-raw.aab")
        zip(raw)
        val signed = temporary.resolve("identity-signed.aab")
        BundleJarSigner().sign(raw, signed, material)

        assertEquals(
            SignedArtifactCertificates.aabSignerCertificateSha256(signed),
            material.certificateSha256(),
        )
    }

    @Test
    fun `bundle signer produces identical verified bytes for identical input and key`() {
        val material = createSigningMaterial("deterministic")
        val unsigned = temporary.resolve("deterministic-unsigned.aab")
        zip(unsigned)
        val first = temporary.resolve("deterministic-first.aab")
        val second = temporary.resolve("deterministic-second.aab")

        BundleJarSigner().sign(unsigned, first, material)
        Thread.sleep(2_100L)
        BundleJarSigner().sign(unsigned, second, material)

        assertEquals(material.certificateSha256(), SignedArtifactCertificates.aabSignerCertificateSha256(first))
        assertEquals(material.certificateSha256(), SignedArtifactCertificates.aabSignerCertificateSha256(second))
        val firstEntries = zipEntries(first)
        val secondEntries = zipEntries(second)
        val differingEntries = firstEntries.keys.filter { name ->
            !firstEntries.getValue(name).contentEquals(secondEntries.getValue(name))
        }
        assertContentEquals(
            Files.readAllBytes(first),
            Files.readAllBytes(second),
            "signed content differs in $differingEntries",
        )
    }

    private fun createSigningMaterial(name: String): SigningMaterial {
        val keyStore = temporary.resolve("$name.p12")
        val password = "fixture-password"
        val alias = "fixture-$name"
        val keytool = Path.of(System.getProperty("java.home"), "bin", "keytool")
        val process = ProcessBuilder(
            keytool.toString(),
            "-genkeypair",
            "-alias",
            alias,
            "-keystore",
            keyStore.toString(),
            "-storetype",
            "PKCS12",
            "-storepass",
            password,
            "-keypass",
            password,
            "-keyalg",
            "RSA",
            "-keysize",
            "2048",
            "-validity",
            "3650",
            "-dname",
            "CN=Hardening Fixture",
            "-noprompt",
        ).redirectErrorStream(true).start()
        val output = process.inputStream.bufferedReader().readText()
        check(process.waitFor() == 0) { "fixture keytool failed: $output" }
        return SigningMaterial.create("fixture", keyStore, password, alias, password, "PKCS12")
    }

    private fun zip(path: Path) {
        ZipOutputStream(Files.newOutputStream(path)).use { output ->
            linkedMapOf(
                "base/manifest/AndroidManifest.xml" to "manifest".toByteArray(),
                "base/dex/classes.dex" to "dex".toByteArray(),
            ).forEach { (name, bytes) ->
                output.putNextEntry(ZipEntry(name))
                output.write(bytes)
                output.closeEntry()
            }
        }
    }

    private fun zipEntries(path: Path): Map<String, ByteArray> = ZipFile(path.toFile()).use { archive ->
        archive.entries().asSequence().associate { entry ->
            entry.name to archive.getInputStream(entry).use { input -> input.readBytes() }
        }
    }
}
