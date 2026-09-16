package com.holin.android.hardening.artifact

import com.android.apksig.ApkVerifier
import com.android.tools.build.bundletool.androidtools.Aapt2Command
import com.android.tools.build.bundletool.commands.BuildApksCommand
import com.android.tools.build.bundletool.model.SigningConfiguration
import com.holin.android.hardening.HardeningNames
import com.holin.android.hardening.state.Sha256
import java.nio.channels.FileChannel
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardOpenOption.CREATE_NEW
import java.nio.file.StandardOpenOption.READ
import java.nio.file.StandardOpenOption.WRITE
import java.nio.file.StandardCopyOption.ATOMIC_MOVE
import java.nio.file.StandardCopyOption.REPLACE_EXISTING
import java.security.KeyStore
import java.security.cert.X509Certificate
import java.util.Arrays
import java.util.UUID
import java.util.jar.JarFile
import java.util.zip.ZipFile

internal const val BUNDLETOOL_VERSION = "1.18.1"

internal object SignedArtifactCertificates {
    fun aabSignerCertificateSha256(bundle: Path): String {
        val signerHashes = linkedSetOf<String>()
        try {
            JarFile(bundle.toFile(), true).use { archive ->
                archive.entries().asSequence()
                    .filterNot { it.isDirectory || BundleZipRewriter.isPreviousSignature(it.name) }
                    .forEach { entry ->
                        archive.getInputStream(entry).use { input ->
                            val buffer = ByteArray(DEFAULT_BUFFER_SIZE)
                            while (input.read(buffer) >= 0) Unit
                        }
                        val signers = requireNotNull(entry.codeSigners) { "AAB contains an unsigned payload entry" }
                        signers.forEach { signer ->
                            val certificate = signer.signerCertPath.certificates.first()
                            signerHashes += Sha256.hex(certificate.encoded)
                        }
                    }
            }
        } catch (failure: IllegalArgumentException) {
            throw failure
        } catch (_: Exception) {
            throw IllegalArgumentException("AAB JAR signature verification failed")
        }
        require(signerHashes.size == 1) { "AAB must have exactly one payload signer certificate" }
        return signerHashes.single()
    }

    fun apkSignerCertificateSha256(apk: Path): String {
        val result = try {
            ApkVerifier.Builder(apk.toFile()).build().verify()
        } catch (_: Exception) {
            throw IllegalArgumentException("universal APK signature verification failed")
        }
        require(result.isVerified) { "universal APK signature verification failed" }
        val signerHashes = result.signerCertificates
            .map { certificate -> Sha256.hex(certificate.encoded) }
            .toSet()
        require(signerHashes.size == 1) { "universal APK must have exactly one signer certificate" }
        return signerHashes.single()
    }
}

internal fun interface UniversalApksBuilder {
    fun build(bundle: Path, outputArchive: Path, aapt2Executable: Path, signingMaterial: SigningMaterial)
}

internal class BundletoolUniversalApksBuilder : UniversalApksBuilder {
    override fun build(
        bundle: Path,
        outputArchive: Path,
        aapt2Executable: Path,
        signingMaterial: SigningMaterial,
    ) {
        require(Files.isRegularFile(bundle)) { "verified hardened AAB input is missing" }
        require(Files.isRegularFile(aapt2Executable)) { "AGP AAPT2 executable is missing" }
        require(!Files.exists(outputArchive)) { "temporary universal APK archive already exists" }
        val storePassword = signingMaterial.storePassword.toCharArray()
        val keyPassword = signingMaterial.keyPassword.toCharArray()
        var keyProtection: KeyStore.PasswordProtection? = null
        try {
            val keyStore = KeyStore.getInstance(signingMaterial.storeType)
            Files.newInputStream(signingMaterial.storeFile).use { input -> keyStore.load(input, storePassword) }
            val protection = KeyStore.PasswordProtection(keyPassword)
            keyProtection = protection
            val entry = keyStore.getEntry(signingMaterial.keyAlias, protection) as? KeyStore.PrivateKeyEntry
            requireNotNull(entry) { "selected hardening signing key is unavailable" }
            val certificate = entry.certificate as? X509Certificate
                ?: throw IllegalArgumentException("selected hardening signing certificate is invalid")
            val signingConfiguration = SigningConfiguration.builder()
                .setSignerConfig(entry.privateKey, certificate)
                .build()
            BuildApksCommand.builder()
                .setBundlePath(bundle)
                .setOutputFile(outputArchive)
                .setOverwriteOutput(false)
                .setApkBuildMode(BuildApksCommand.ApkBuildMode.UNIVERSAL)
                .setAapt2Command(Aapt2Command.createFromExecutablePath(aapt2Executable))
                .setSigningConfiguration(signingConfiguration)
                .build()
                .execute()
            require(Files.isRegularFile(outputArchive)) { "bundletool did not produce a universal APK archive" }
        } catch (failure: Exception) {
            throw IllegalStateException(
                "bundletool failed to build the signed universal APK (${failure.javaClass.simpleName})",
                failure,
            )
        } finally {
            runCatching { keyProtection?.destroy() }
            Arrays.fill(storePassword, '\u0000')
            Arrays.fill(keyPassword, '\u0000')
        }
    }
}

internal data class UniversalApkAssemblyRequest(
    val variant: String,
    val contentSaltSha256: String,
    val hardenedBundle: Path,
    val aapt2Executable: Path,
    val zipalignExecutable: Path,
    val bundleVerification: BundleVerificationReport,
    val rewriteManifest: BundleRewriteManifest,
    val targetApk: Path,
    val targetReport: Path,
    val signingMaterial: SigningMaterial,
)

internal data class OrdinaryUniversalApkAssemblyRequest(
    val ordinaryBundle: Path,
    val aapt2Executable: Path,
    val targetApk: Path,
    val signingMaterial: SigningMaterial,
)

internal class OrdinaryUniversalApkAssembler(
    private val apksBuilder: UniversalApksBuilder = BundletoolUniversalApksBuilder(),
    private val aabSigner: (Path) -> String = SignedArtifactCertificates::aabSignerCertificateSha256,
    private val apkSigner: (Path) -> String = SignedArtifactCertificates::apkSignerCertificateSha256,
) {
    fun assemble(request: OrdinaryUniversalApkAssemblyRequest): String {
        require(Files.isRegularFile(request.ordinaryBundle)) { "ordinary AAB input is missing" }
        Files.createDirectories(requireNotNull(request.targetApk.parent))
        val nonce = UUID.randomUUID().toString()
        val apksArchive = request.targetApk.resolveSibling(".ordinary-universal-$nonce.apks")
        val candidateApk = request.targetApk.resolveSibling(".ordinary-universal-$nonce.apk")
        try {
            apksBuilder.build(request.ordinaryBundle, apksArchive, request.aapt2Executable, request.signingMaterial)
            extractUniversalApk(apksArchive, candidateApk)
            val expectedSigner = aabSigner(request.ordinaryBundle)
            require(apkSigner(candidateApk) == expectedSigner) {
                "ordinary universal APK signer certificate does not match the ordinary AAB"
            }
            FileChannel.open(candidateApk, READ).use { channel -> channel.force(true) }
            try {
                Files.move(candidateApk, request.targetApk, ATOMIC_MOVE, REPLACE_EXISTING)
            } catch (failure: java.nio.file.AtomicMoveNotSupportedException) {
                throw IllegalStateException("atomic ordinary universal APK publication is not supported", failure)
            }
            return Sha256.file(request.targetApk)
        } finally {
            runCatching { Files.deleteIfExists(apksArchive) }
            runCatching { Files.deleteIfExists(candidateApk) }
        }
    }
}

internal data class UniversalApkVerificationReport(
    val variant: String,
    val contentSaltSha256: String,
    val hardenedAabSha256: String,
    val universalApkSha256: String,
    val signerCertificateSha256: String,
    val bundletoolVersion: String,
    val binaryXmlDiversifiedCount: Int,
    val binaryXmlTargetPathsSha256: String,
    val zipalignVerified: Boolean,
    val apkSignatureVerified: Boolean,
)

internal object UniversalApkVerificationReportCodec {
    fun encode(report: UniversalApkVerificationReport): String {
        validate(report)
        return "{" +
            "\"schemaVersion\":2," +
            "\"variant\":\"${report.variant}\"," +
            "\"contentSaltSha256\":\"${report.contentSaltSha256}\"," +
            "\"hardenedAabSha256\":\"${report.hardenedAabSha256}\"," +
            "\"universalApkSha256\":\"${report.universalApkSha256}\"," +
            "\"signerCertificateSha256\":\"${report.signerCertificateSha256}\"," +
            "\"bundletoolVersion\":\"${report.bundletoolVersion}\"," +
            "\"binaryXmlDiversifiedCount\":${report.binaryXmlDiversifiedCount}," +
            "\"binaryXmlTargetPathsSha256\":\"${report.binaryXmlTargetPathsSha256}\"," +
            "\"zipalignVerified\":${report.zipalignVerified}," +
            "\"apkSignatureVerified\":${report.apkSignatureVerified}}\n"
    }

    fun decode(text: String): UniversalApkVerificationReport {
        val match = requireNotNull(FORMAT.matchEntire(text)) {
            "hardening universal APK verification report is invalid"
        }
        return UniversalApkVerificationReport(
            variant = match.groupValues[1],
            contentSaltSha256 = match.groupValues[2],
            hardenedAabSha256 = match.groupValues[3],
            universalApkSha256 = match.groupValues[4],
            signerCertificateSha256 = match.groupValues[5],
            bundletoolVersion = match.groupValues[6],
            binaryXmlDiversifiedCount = match.groupValues[7].toInt(),
            binaryXmlTargetPathsSha256 = match.groupValues[8],
            zipalignVerified = match.groupValues[9].toBooleanStrict(),
            apkSignatureVerified = match.groupValues[10].toBooleanStrict(),
        ).also(::validate)
    }

    private fun validate(report: UniversalApkVerificationReport) {
        HardeningNames.requireVariant(report.variant)
        listOf(
            report.contentSaltSha256,
            report.hardenedAabSha256,
            report.universalApkSha256,
            report.signerCertificateSha256,
            report.binaryXmlTargetPathsSha256,
        ).forEach { hash -> require(SHA_256.matches(hash)) { "universal APK report contains an invalid SHA-256" } }
        require(report.bundletoolVersion == BUNDLETOOL_VERSION) { "universal APK report has an unexpected bundletool version" }
        require(report.binaryXmlDiversifiedCount >= 0) {
            "universal APK report has an invalid binary XML diversification count"
        }
        val emptyTargetDigest = ApkBinaryXmlTargetPathDigest.sha256(emptyList())
        require((report.binaryXmlDiversifiedCount == 0) ==
            (report.binaryXmlTargetPathsSha256 == emptyTargetDigest)
        ) { "universal APK report has inconsistent binary XML target provenance" }
        require(report.zipalignVerified) { "universal APK report did not pass zipalign verification" }
        require(report.apkSignatureVerified) { "universal APK report did not pass APK signature verification" }
    }

    private val SHA_256 = Regex("[0-9a-f]{64}")
    private val FORMAT = Regex(
        "\\{\"schemaVersion\":2,\"variant\":\"([A-Za-z][A-Za-z0-9]*)\"," +
            "\"contentSaltSha256\":\"([0-9a-f]{64})\"," +
            "\"hardenedAabSha256\":\"([0-9a-f]{64})\"," +
            "\"universalApkSha256\":\"([0-9a-f]{64})\"," +
            "\"signerCertificateSha256\":\"([0-9a-f]{64})\"," +
            "\"bundletoolVersion\":\"([^\"]+)\",\"binaryXmlDiversifiedCount\":(0|[1-9][0-9]*)," +
            "\"binaryXmlTargetPathsSha256\":\"([0-9a-f]{64})\",\"zipalignVerified\":(true|false)," +
            "\"apkSignatureVerified\":(true|false)}\\n",
    )
}

internal class UniversalApkAssembler(
    private val apksBuilder: UniversalApksBuilder = BundletoolUniversalApksBuilder(),
    private val aabSigner: (Path) -> String = SignedArtifactCertificates::aabSignerCertificateSha256,
    private val apkSigner: (Path) -> String = SignedArtifactCertificates::apkSignerCertificateSha256,
    private val targetSelector: OwnedApkBinaryXmlTargetSelector = OwnedApkBinaryXmlTargetSelector(),
    private val payloadRewriter: ApkPayloadRewriteOperation = ApkPayloadRewriter(),
    private val zipaligner: ApkZipalignOperation = ApkZipaligner(),
    private val apkSigning: ApkSigningOperation = ApkSignerEngine(),
    private val payloadVerifier: ApkPayloadVerificationOperation = ApkPayloadDiversificationVerifier(),
    private val publisher: VerifiedArtifactPublisher = VerifiedArtifactPublisher(),
) {
    fun assemble(request: UniversalApkAssemblyRequest): UniversalApkVerificationReport {
        HardeningNames.requireVariant(request.variant)
        require(request.bundleVerification.variant == request.variant) {
            "bundle verification report variant does not match the universal APK task"
        }
        require(request.bundleVerification.contentSaltSha256 == request.contentSaltSha256) {
            "bundle verification report belongs to a different hardening invocation"
        }
        require(request.rewriteManifest.contentSaltSha256 == request.contentSaltSha256) {
            "rewrite manifest belongs to a different hardening invocation"
        }
        require(request.rewriteManifest.originalAabSha256 == request.bundleVerification.ordinaryAabSha256) {
            "rewrite manifest ordinary AAB provenance differs from the bundle verification report"
        }
        val hardenedAabHash = Sha256.file(request.hardenedBundle)
        require(request.bundleVerification.hardenedAabSha256 == hardenedAabHash) {
            "verified hardened AAB hash differs from its published report"
        }
        val aabSignerHash = aabSigner(request.hardenedBundle)
        require(request.bundleVerification.signerCertificateSha256 == aabSignerHash) {
            "verified hardened AAB signer differs from its published report"
        }
        require(Files.isRegularFile(request.zipalignExecutable)) { "SDK zipalign executable is missing" }
        val binaryXmlTargets = targetSelector.select(request.rewriteManifest)

        Files.createDirectories(requireNotNull(request.targetApk.parent))
        Files.createDirectories(requireNotNull(request.targetReport.parent))
        val nonce = UUID.randomUUID().toString()
        val apksArchive = request.targetApk.resolveSibling(".hardening-universal-$nonce.apks")
        val bundletoolApk = request.targetApk.resolveSibling(".hardening-universal-$nonce-bundletool.apk")
        val unsignedApk = request.targetApk.resolveSibling(".hardening-universal-$nonce-unsigned.apk")
        val alignedApk = request.targetApk.resolveSibling(".hardening-universal-$nonce-aligned.apk")
        val candidateApk = request.targetApk.resolveSibling(".hardening-universal-$nonce-signed.apk")
        val candidateReport = request.targetReport.resolveSibling(".hardening-universal-$nonce.json")
        try {
            apksBuilder.build(
                request.hardenedBundle,
                apksArchive,
                request.aapt2Executable,
                request.signingMaterial,
            )
            extractUniversalApk(apksArchive, bundletoolApk)
            requireBundleMetadataNotDelivered(bundletoolApk)
            val bundletoolApkSignerHash = apkSigner(bundletoolApk)
            require(bundletoolApkSignerHash == aabSignerHash) {
                "universal APK signer certificate does not match the verified hardened AAB"
            }
            val rewrite = payloadRewriter.rewrite(
                bundletoolApk,
                unsignedApk,
                request.contentSaltSha256,
                binaryXmlTargets,
            )
            require(rewrite.changedTargetPaths == binaryXmlTargets) {
                "APK rewrite changed-target accounting differs from the manifest-selected set"
            }
            zipaligner.align(request.zipalignExecutable, unsignedApk, alignedApk)
            val signing = apkSigning.sign(alignedApk, candidateApk, request.signingMaterial)
            zipaligner.verify(request.zipalignExecutable, candidateApk)
            val finalApkSignerHash = apkSigner(candidateApk)
            require(signing.signerCertificateSha256 == finalApkSignerHash &&
                finalApkSignerHash == bundletoolApkSignerHash &&
                finalApkSignerHash == aabSignerHash
            ) { "final universal APK signer certificate does not match verified provenance" }
            val payloadVerification = payloadVerifier.verify(bundletoolApk, candidateApk, binaryXmlTargets)
            require(payloadVerification.changedTargetPaths == binaryXmlTargets.toSet()) {
                "verified APK changed-target accounting differs from the manifest-selected set"
            }
            val report = UniversalApkVerificationReport(
                variant = request.variant,
                contentSaltSha256 = request.contentSaltSha256,
                hardenedAabSha256 = hardenedAabHash,
                universalApkSha256 = Sha256.file(candidateApk),
                signerCertificateSha256 = finalApkSignerHash,
                bundletoolVersion = BUNDLETOOL_VERSION,
                binaryXmlDiversifiedCount = binaryXmlTargets.size,
                binaryXmlTargetPathsSha256 = ApkBinaryXmlTargetPathDigest.sha256(binaryXmlTargets),
                zipalignVerified = true,
                apkSignatureVerified = true,
            )
            Files.writeString(
                candidateReport,
                UniversalApkVerificationReportCodec.encode(report),
                CREATE_NEW,
                WRITE,
            )
            force(candidateApk)
            force(candidateReport)
            publisher.publish(
                sourceBundle = candidateApk,
                sourceReport = candidateReport,
                targetBundle = request.targetApk,
                targetReport = request.targetReport,
                commit = {},
            )
            require(Sha256.file(request.targetApk) == report.universalApkSha256) {
                "published universal APK hash differs from its verification report"
            }
            return report
        } finally {
            runCatching { Files.deleteIfExists(apksArchive) }
            runCatching { Files.deleteIfExists(bundletoolApk) }
            runCatching { Files.deleteIfExists(unsignedApk) }
            runCatching { Files.deleteIfExists(alignedApk) }
            runCatching { Files.deleteIfExists(candidateApk) }
            runCatching { Files.deleteIfExists(candidateReport) }
        }
    }

    private fun force(path: Path) {
        FileChannel.open(path, READ).use { channel -> channel.force(true) }
    }
}

internal fun requireBundleMetadataNotDelivered(apk: Path) {
    val signature = Files.newInputStream(apk).use { input -> ByteArray(4).also { input.read(it) } }
    if (!signature.copyOfRange(0, 2).contentEquals(byteArrayOf('P'.code.toByte(), 'K'.code.toByte()))) return
    ZipFile(apk.toFile()).use { archive ->
        val names = archive.entries().asSequence().map { it.name }.toList()
        BundleZipRewriter.requireSafeUniqueEntryNames(names)
        require(names.none { name ->
            name.equals(BundleZipRewriter.DEPENDENCY_METADATA_PATH, true) ||
                name.startsWith(BundleStructuralMetadata.STRUCTURE_PREFIX, true)
        }) { "AAB-only hardening metadata was delivered into the universal APK" }
    }
}

private fun extractUniversalApk(apksArchive: Path, output: Path) {
    require(Files.isRegularFile(apksArchive)) { "bundletool universal APK archive is missing" }
    ZipFile(apksArchive.toFile()).use { archive ->
        val entries = archive.entries().asSequence()
            .filter { entry -> !entry.isDirectory && entry.name == UNIVERSAL_APK_ENTRY }
            .toList()
        require(entries.size == 1) { "bundletool archive must contain exactly one universal APK" }
        archive.getInputStream(entries.single()).use { input ->
            Files.newOutputStream(output, CREATE_NEW, WRITE).use { destination -> input.copyTo(destination) }
        }
    }
    require(Files.isRegularFile(output) && Files.size(output) > 0L) {
        "bundletool universal APK output is empty"
    }
}

private const val UNIVERSAL_APK_ENTRY = "universal.apk"
