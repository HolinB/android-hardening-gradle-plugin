package com.holin.android.hardening.artifact

import com.android.apksig.ApkVerifier
import java.nio.file.Files
import java.nio.file.Path
import java.util.zip.ZipEntry
import java.util.zip.ZipFile
import java.util.zip.ZipOutputStream
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import org.junit.jupiter.api.io.TempDir

class ApkSigningTest {
    @TempDir
    lateinit var temporary: Path

    @Test
    fun `APK signer retains certificate parity and enables minSdk 26 schemes`() {
        val material = createSigningMaterial("valid")
        val unsigned = temporary.resolve("aligned-unsigned.apk").also(::apk)
        val signed = temporary.resolve("signed.apk")

        val result = ApkSignerEngine().sign(unsigned, signed, material)

        val verification = ApkVerifier.Builder(signed.toFile())
            .setMinCheckedPlatformVersion(26)
            .build()
            .verify()
        assertTrue(verification.isVerified, verification.errors.joinToString())
        assertTrue(verification.isVerifiedUsingV2Scheme)
        ZipFile(signed.toFile()).use { archive ->
            assertTrue(archive.entries().asSequence().any { entry -> BundleZipRewriter.isPreviousSignature(entry.name) })
        }
        assertEquals(material.certificateSha256(), result.signerCertificateSha256)
        assertEquals(
            result.signerCertificateSha256,
            verification.signerCertificates.single().let { certificate ->
                com.holin.android.hardening.state.Sha256.hex(certificate.encoded)
            },
        )
    }

    @Test
    fun `credential load failure is redacted and removes partial output`() {
        val valid = createSigningMaterial("redaction")
        val secret = "DO_NOT_LEAK_THIS_PASSWORD"
        val invalid = SigningMaterial.create(
            configName = valid.configName,
            storeFile = valid.storeFile,
            storePassword = secret,
            keyAlias = valid.keyAlias,
            keyPassword = secret,
            storeType = valid.storeType,
        )
        val unsigned = temporary.resolve("unsigned.apk").also(::apk)
        val signed = temporary.resolve("must-not-exist.apk")

        val failure = assertFailsWith<IllegalStateException> {
            ApkSignerEngine().sign(unsigned, signed, invalid)
        }

        assertFalse(failure.message.orEmpty().contains(secret))
        assertFalse(Files.exists(signed))
    }

    @Test
    fun `APK signer produces identical verified bytes for identical input and key`() {
        val material = createSigningMaterial("deterministic")
        val unsigned = temporary.resolve("deterministic-unsigned.apk").also(::apk)
        val first = temporary.resolve("deterministic-first.apk")
        val second = temporary.resolve("deterministic-second.apk")

        ApkSignerEngine().sign(unsigned, first, material)
        Thread.sleep(2_100L)
        ApkSignerEngine().sign(unsigned, second, material)

        listOf(first, second).forEach { signed ->
            val verification = ApkVerifier.Builder(signed.toFile())
                .setMinCheckedPlatformVersion(26)
                .build()
                .verify()
            assertTrue(verification.isVerified, verification.errors.joinToString())
            assertTrue(verification.isVerifiedUsingV2Scheme)
        }
        assertContentEquals(Files.readAllBytes(first), Files.readAllBytes(second))
    }

    private fun createSigningMaterial(name: String): SigningMaterial {
        val keyStore = temporary.resolve("$name.p12")
        val password = "fixture-password-$name"
        val alias = "fixture-$name"
        val passwordVariable = "DEMO_HARDENING_TEST_PASSWORD"
        val processBuilder = ProcessBuilder(
            Path.of(System.getProperty("java.home"), "bin", "keytool").toString(),
            "-genkeypair",
            "-alias",
            alias,
            "-keystore",
            keyStore.toString(),
            "-storetype",
            "PKCS12",
            "-storepass:env",
            passwordVariable,
            "-keypass:env",
            passwordVariable,
            "-keyalg",
            "RSA",
            "-keysize",
            "2048",
            "-validity",
            "3650",
            "-dname",
            "CN=Hardening APK Fixture",
            "-noprompt",
        ).redirectErrorStream(true)
        processBuilder.environment()[passwordVariable] = password
        val process = processBuilder.start()
        val output = process.inputStream.bufferedReader().readText()
        check(process.waitFor() == 0) { "fixture keytool failed: $output" }
        return SigningMaterial.create("fixture", keyStore, password, alias, password, "PKCS12")
    }

    private fun apk(path: Path) {
        ZipOutputStream(Files.newOutputStream(path)).use { output ->
            output.putNextEntry(ZipEntry("AndroidManifest.xml"))
            output.write("manifest".encodeToByteArray())
            output.closeEntry()
            output.putNextEntry(ZipEntry("classes.dex"))
            output.write("dex".encodeToByteArray())
            output.closeEntry()
        }
    }
}
