package com.holin.android.hardening.artifact

import com.android.apksig.ApkSigner
import com.android.tools.build.bundletool.commands.ValidateBundleCommand
import com.holin.android.hardening.state.Sha256
import java.nio.channels.FileChannel
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardCopyOption.ATOMIC_MOVE
import java.nio.file.StandardCopyOption.REPLACE_EXISTING
import java.nio.file.StandardOpenOption.READ
import java.security.KeyStore
import java.security.cert.X509Certificate
import java.util.Arrays
import java.util.UUID
import java.util.zip.CRC32
import java.util.zip.ZipEntry
import java.util.zip.ZipFile
import java.util.zip.ZipOutputStream

object BundletoolBundleValidator {
    fun validate(bundle: Path) {
        try {
            ValidateBundleCommand.builder()
                .setBundlePath(bundle)
                .setPrintOutput(false)
                .build()
                .execute()
        } catch (_: Exception) {
            throw IllegalArgumentException("bundletool rejected the hardened AAB")
        }
    }
}

class SigningMaterial private constructor(
    val configName: String,
    internal val storeFile: Path,
    internal val storePassword: String,
    internal val keyAlias: String,
    internal val keyPassword: String,
    internal val storeType: String,
) {
    override fun toString(): String = "SigningMaterial([redacted])"

    internal fun certificateSha256(): String {
        val password = storePassword.toCharArray()
        return try {
            val keyStore = KeyStore.getInstance(storeType)
            Files.newInputStream(storeFile).use { input -> keyStore.load(input, password) }
            val certificate = requireNotNull(keyStore.getCertificate(keyAlias)) {
                "selected hardening signing certificate is unavailable"
            }
            Sha256.hex(certificate.encoded)
        } catch (failure: IllegalArgumentException) {
            throw failure
        } catch (_: Exception) {
            throw IllegalArgumentException("selected hardening signing certificate is unavailable")
        } finally {
            Arrays.fill(password, '\u0000')
        }
    }

    companion object {
        fun create(
            configName: String,
            storeFile: Path?,
            storePassword: String?,
            keyAlias: String?,
            keyPassword: String?,
            storeType: String?,
        ): SigningMaterial {
            require(
                configName.isNotBlank() &&
                    storeFile != null &&
                    !storePassword.isNullOrBlank() &&
                    !keyAlias.isNullOrBlank() &&
                    !keyPassword.isNullOrBlank() &&
                    !storeType.isNullOrBlank(),
            ) { "selected hardening signing configuration is incomplete" }
            return SigningMaterial(
                configName = configName,
                storeFile = storeFile.toAbsolutePath().normalize(),
                storePassword = storePassword,
                keyAlias = keyAlias,
                keyPassword = keyPassword,
                storeType = storeType,
            )
        }
    }
}

object SigningMaterialResolver {
    fun resolve(
        buildType: SigningMaterial?,
        flavors: List<SigningMaterial>,
        defaultConfig: SigningMaterial?,
    ): SigningMaterial {
        if (buildType != null) return buildType
        val distinctFlavors = flavors.distinctBy(SigningMaterial::configName)
        require(distinctFlavors.size <= 1) {
            "selected hardening variant has ambiguous flavor signing configurations"
        }
        return distinctFlavors.singleOrNull()
            ?: requireNotNull(defaultConfig) { "selected hardening signing configuration is incomplete" }
    }
}

/** Signs an unsigned AAB without exposing credentials through a command line. */
@Suppress("DEPRECATION")
class BundleJarSigner {
    fun sign(unsignedBundle: Path, signedBundle: Path, material: SigningMaterial) {
        val source = unsignedBundle.toAbsolutePath().normalize()
        val target = signedBundle.toAbsolutePath().normalize()
        require(source != target) { "AAB signing must use a distinct output" }
        require(Files.isRegularFile(source)) { "unsigned AAB input is missing" }
        Files.createDirectories(requireNotNull(target.parent))
        val signedTemporary = target.parent.resolve(".${target.fileName}.signed-${UUID.randomUUID()}")
        val temporary = target.parent.resolve(".${target.fileName}.tmp-${UUID.randomUUID()}")
        val storePassword = material.storePassword.toCharArray()
        val keyPassword = material.keyPassword.toCharArray()
        try {
            val keyStore = KeyStore.getInstance(material.storeType)
            Files.newInputStream(material.storeFile).use { input -> keyStore.load(input, storePassword) }
            val protection = KeyStore.PasswordProtection(keyPassword)
            val entry = try {
                keyStore.getEntry(material.keyAlias, protection) as? KeyStore.PrivateKeyEntry
            } finally {
                protection.destroy()
            }
            requireNotNull(entry) { "selected hardening signing key is unavailable" }
            val certificates = entry.certificateChain.map { certificate ->
                certificate as? X509Certificate
                    ?: throw IllegalArgumentException("selected hardening signing certificate is invalid")
            }
            val signerConfig = ApkSigner.SignerConfig.Builder(
                "HARDEN",
                entry.privateKey,
                certificates,
            ).build()
            ApkSigner.Builder(listOf(signerConfig))
                .setInputApk(source.toFile())
                .setOutputApk(signedTemporary.toFile())
                .setMinSdkVersion(MIN_JAR_SIGNATURE_SDK)
                .setV1SigningEnabled(true)
                .setV2SigningEnabled(false)
                .setV3SigningEnabled(false)
                .setV4SigningEnabled(false)
                .setCreatedBy("Holin Android Hardening")
                .build()
                .sign()
            canonicalizeSignedJar(signedTemporary, temporary)
            require(
                SignedArtifactCertificates.aabSignerCertificateSha256(temporary) == material.certificateSha256(),
            ) { "canonicalized AAB signer certificate differs from the selected signing configuration" }
            FileChannel.open(temporary, READ).use { it.force(true) }
            Files.move(temporary, target, ATOMIC_MOVE, REPLACE_EXISTING)
            forceDirectory(target.parent)
        } catch (failure: Exception) {
            throw IllegalStateException("AAB signing failed (${failure.javaClass.simpleName})")
        } finally {
            Arrays.fill(storePassword, '\u0000')
            Arrays.fill(keyPassword, '\u0000')
            runCatching { Files.deleteIfExists(signedTemporary) }
            runCatching { Files.deleteIfExists(temporary) }
        }
    }

    private companion object {
        const val MIN_JAR_SIGNATURE_SDK = 26
    }
}

private fun canonicalizeSignedJar(source: Path, target: Path) {
    ZipFile(source.toFile()).use { archive ->
        val entries = archive.entries().asSequence().toList().sortedBy(ZipEntry::getName)
        BundleZipRewriter.requireSafeUniqueEntryNames(entries.map(ZipEntry::getName))
        ZipOutputStream(Files.newOutputStream(target)).use { output ->
            entries.forEach { entry ->
                require(entry.method == ZipEntry.STORED || entry.method == ZipEntry.DEFLATED) {
                    "signed AAB contains an unsupported ZIP compression method"
                }
                val bytes = if (entry.isDirectory) ByteArray(0) else {
                    archive.getInputStream(entry).use { input -> input.readBytes() }
                }
                val canonical = ZipEntry(entry.name).apply {
                    method = entry.method
                    time = DETERMINISTIC_ZIP_TIMESTAMP_MILLIS
                    comment = null
                    extra = null
                    if (method == ZipEntry.STORED) {
                        size = bytes.size.toLong()
                        compressedSize = bytes.size.toLong()
                        crc = CRC32().apply { update(bytes) }.value
                    }
                }
                output.putNextEntry(canonical)
                if (!entry.isDirectory) output.write(bytes)
                output.closeEntry()
            }
        }
    }
}

data class SignedBundleVerificationReport(
    val originalAabSha256: String,
    val hardenedAabSha256: String,
    val ordinarySignerCertificateSha256: String,
    val hardenedSignerCertificateSha256: String,
    val preservedEntryCount: Int,
)

class SignedBundleVerifier(
    private val bundleValidator: (Path) -> Unit,
) {
    fun verifyAndPublish(
        ordinaryBundle: Path,
        signedCandidate: Path,
        outputBundle: Path,
        contentSaltSha256: String,
        rewriteManifest: BundleRewriteManifest,
        semanticResults: List<BundleSemanticVerificationResult>,
    ): SignedBundleVerificationReport {
        val originalHash = Sha256.file(ordinaryBundle)
        require(rewriteManifest.originalAabSha256 == originalHash) {
            "rewrite manifest does not identify the ordinary release AAB"
        }
        require(rewriteManifest.contentSaltSha256 == contentSaltSha256) {
            "rewrite manifest content salt does not match this invocation"
        }
        val rewrite = BundleRewriteVerifier().verify(
            ordinaryBundle = ordinaryBundle,
            candidateBundle = signedCandidate,
            manifest = rewriteManifest,
            semanticResults = semanticResults,
        )

        val ordinarySigner = SignedArtifactCertificates.aabSignerCertificateSha256(ordinaryBundle)
        val hardenedSigner = SignedArtifactCertificates.aabSignerCertificateSha256(signedCandidate)
        require(ordinarySigner == hardenedSigner) {
            "hardened AAB signer certificate does not match the ordinary release AAB"
        }
        bundleValidator(signedCandidate)

        val target = outputBundle.toAbsolutePath().normalize()
        Files.createDirectories(requireNotNull(target.parent))
        val temporary = target.parent.resolve(".${target.fileName}.tmp-${UUID.randomUUID()}")
        try {
            Files.copy(signedCandidate, temporary)
            FileChannel.open(temporary, READ).use { it.force(true) }
            Files.move(temporary, target, ATOMIC_MOVE, REPLACE_EXISTING)
            forceDirectory(target.parent)
        } finally {
            Files.deleteIfExists(temporary)
        }
        return SignedBundleVerificationReport(
            originalAabSha256 = originalHash,
            hardenedAabSha256 = Sha256.file(target),
            ordinarySignerCertificateSha256 = ordinarySigner,
            hardenedSignerCertificateSha256 = hardenedSigner,
            preservedEntryCount = rewrite.preservedEntryCount,
        )
    }

}

private fun forceDirectory(directory: Path) {
    runCatching { FileChannel.open(directory, READ).use { it.force(true) } }
}
