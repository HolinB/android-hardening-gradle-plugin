package com.holin.android.hardening.artifact

import com.android.apksig.ApkSigner
import com.android.apksig.ApkVerifier
import com.holin.android.hardening.state.Sha256
import java.nio.file.Files
import java.nio.file.Path
import java.security.KeyStore
import java.security.cert.X509Certificate
import java.util.Arrays

data class ApkSigningResult(
    val signerCertificateSha256: String,
)

fun interface ApkSigningOperation {
    fun sign(alignedUnsignedApk: Path, signedOutput: Path, material: SigningMaterial): ApkSigningResult
}

@Suppress("DEPRECATION")
class ApkSignerEngine : ApkSigningOperation {
    override fun sign(
        alignedUnsignedApk: Path,
        signedOutput: Path,
        material: SigningMaterial,
    ): ApkSigningResult {
        val input = alignedUnsignedApk.toAbsolutePath().normalize()
        val output = signedOutput.toAbsolutePath().normalize()
        require(Files.isRegularFile(input)) { "aligned unsigned APK input is missing" }
        require(input != output) { "APK signing input and output must be distinct" }
        require(!Files.exists(output)) { "signed APK output already exists" }
        Files.createDirectories(requireNotNull(output.parent))
        val storePassword = material.storePassword.toCharArray()
        val keyPassword = material.keyPassword.toCharArray()
        var protection: KeyStore.PasswordProtection? = null
        try {
            val keyStore = KeyStore.getInstance(material.storeType)
            Files.newInputStream(material.storeFile).use { stream -> keyStore.load(stream, storePassword) }
            protection = KeyStore.PasswordProtection(keyPassword)
            val privateKeyEntry = keyStore.getEntry(material.keyAlias, protection) as? KeyStore.PrivateKeyEntry
                ?: throw IllegalStateException("signing key unavailable")
            val certificates = privateKeyEntry.certificateChain.map { certificate ->
                certificate as? X509Certificate ?: throw IllegalStateException("signing certificate invalid")
            }
            val signerConfig = ApkSigner.SignerConfig.Builder(
                material.configName,
                privateKeyEntry.privateKey,
                certificates,
            ).build()
            ApkSigner.Builder(listOf(signerConfig))
                .setInputApk(input.toFile())
                .setOutputApk(output.toFile())
                .setMinSdkVersion(MIN_SDK)
                .setV1SigningEnabled(true)
                .setV2SigningEnabled(true)
                .setV3SigningEnabled(false)
                .setV4SigningEnabled(false)
                .build()
                .sign()
            require(Files.isRegularFile(output)) { "APK signer did not produce an output" }
            val verification = ApkVerifier.Builder(output.toFile())
                .setMinCheckedPlatformVersion(MIN_SDK)
                .build()
                .verify()
            require(verification.isVerified) { "APK signature verification failed" }
            val signerHashes = verification.signerCertificates.map { certificate -> Sha256.hex(certificate.encoded) }.toSet()
            require(signerHashes.size == 1) { "signed APK must have exactly one signer certificate" }
            return ApkSigningResult(signerHashes.single())
        } catch (failure: Exception) {
            runCatching { Files.deleteIfExists(output) }
            throw IllegalStateException("APK signing failed (${failure.javaClass.simpleName})")
        } finally {
            runCatching { protection?.destroy() }
            Arrays.fill(storePassword, '\u0000')
            Arrays.fill(keyPassword, '\u0000')
        }
    }

    private companion object {
        const val MIN_SDK = 26
    }
}
