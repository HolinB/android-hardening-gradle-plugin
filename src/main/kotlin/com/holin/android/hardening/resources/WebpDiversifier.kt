package com.holin.android.hardening.resources

import java.awt.image.BufferedImage
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.security.MessageDigest
import javax.imageio.IIOImage
import javax.imageio.ImageIO
import javax.imageio.ImageReader
import javax.imageio.ImageWriteParam
import javax.imageio.ImageWriter
import kotlin.math.floor
import kotlin.math.max

enum class WebpIneligibilityReason {
    TRANSFORMED,
    UNOWNED_MODULE,
    OUTSIDE_CONFIGURED_WEBP_SCOPE,
    ANIMATION,
    NOTIFICATION_ICON,
    EXTERNALLY_NAMED,
    UNSUPPORTED_FORMAT,
    DEPENDENCY_RESOURCE,
    GENERATED_RESOURCE,
    UNVERIFIED_WEBP,
    NO_SAFE_PERTURBATION,
    BYTE_GROWTH_LIMIT,
}

data class WebpComparisonMetrics(
    val width: Int,
    val height: Int,
    val alphaPreserved: Boolean,
    val ssim: Double,
    val pHashDistance: Int,
    val originalSha256: String,
    val transformedSha256: String,
    val byteGrowthRatio: Double,
)

data class WebpDiversificationResult(
    val status: ImageTransformStatus,
    val reason: WebpIneligibilityReason,
    val transformedBytes: ByteArray? = null,
    val metrics: WebpComparisonMetrics? = null,
    val bestRejectedSize: Int? = null,
    val bestRejectedMetrics: WebpComparisonMetrics? = null,
)

internal data class WebpEncodingProfile(
    val type: String,
    val quality: Float,
    val method: Int,
    val useTargetSize: Boolean = false,
)

internal data class WebpEncodingPlan(
    val fast: List<WebpEncodingProfile>,
    val fallback: List<WebpEncodingProfile>,
)

internal fun interface WebpByteEncoder {
    fun encode(image: BufferedImage, profile: WebpEncodingProfile, maximumOutputBytes: Int): ByteArray?
}

enum class WebpEncodingPolicy {
    PER_IMAGE,
    GLOBAL_AAB_BUDGET,
    ;

    internal companion object {
        fun forSource(bytes: ByteArray): WebpEncodingPlan {
            val preferredType = when (payloadType(bytes)) {
                "VP8L" -> "Lossless"
                else -> "Lossy"
            }
            return if (preferredType == "Lossless") {
                WebpEncodingPlan(
                    fast = listOf(WebpEncodingProfile("Lossless", quality = 1.0f, method = 4)),
                    fallback = listOf(WebpEncodingProfile("Lossless", quality = 1.0f, method = 6)),
                )
            } else {
                WebpEncodingPlan(
                    fast = listOf(WebpEncodingProfile("Lossy", quality = 0.98f, method = 4)),
                    fallback = listOf(
                        WebpEncodingProfile("Lossy", quality = 0.96f, method = 6, useTargetSize = true),
                    ),
                )
            }
        }

        private fun payloadType(bytes: ByteArray): String? {
            var offset = 12
            while (offset + 8 <= bytes.size) {
                val type = bytes.copyOfRange(offset, offset + 4).toString(Charsets.ISO_8859_1)
                val length = littleEndianInt(bytes, offset + 4)
                if (length < 0 || offset + 8L + length > bytes.size) return null
                if (type == "VP8 " || type == "VP8L") return type.trim()
                offset += 8 + length + (length and 1)
            }
            return null
        }
    }
}

object WebpImageMetrics {
    fun compare(original: ByteArray, transformed: ByteArray): WebpComparisonMetrics {
        val before = VerifiedWebp.read(original)
            ?: throw IllegalArgumentException("original bytes are not a verified WebP")
        val after = VerifiedWebp.read(transformed)
            ?: throw IllegalArgumentException("transformed bytes are not a verified WebP")
        require(before.width == after.width && before.height == after.height) { "WebP dimensions changed" }
        val imageMetrics = compareImages(before, after)
        return WebpComparisonMetrics(
            width = before.width,
            height = before.height,
            alphaPreserved = imageMetrics.alphaPreserved,
            ssim = imageMetrics.ssim,
            pHashDistance = imageMetrics.pHashDistance,
            originalSha256 = ImageMetrics.sha256(original),
            transformedSha256 = ImageMetrics.sha256(transformed),
            byteGrowthRatio = (transformed.size.toDouble() - original.size) / original.size,
        )
    }

    internal fun compareImages(
        before: BufferedImage,
        after: BufferedImage,
        knownPHashDistance: Int? = null,
    ): DecodedImageMetrics {
        require(before.width == after.width && before.height == after.height) { "image dimensions changed" }
        return DecodedImageMetrics(
            alphaPreserved = ImageMetrics.alphaSamplesEqual(before, after),
            ssim = ImageMetrics.structuralSimilarity(before, after),
            pHashDistance = knownPHashDistance ?: pHashDistance(
                ImageMetrics.perceptualHash(before),
                ImageMetrics.perceptualHash(after),
            ),
        )
    }

    internal fun pHashDistance(before: PerceptualHash, after: PerceptualHash): Int =
        before.bits.zip(after.bits).count { (left, right) -> left != right }
}

class WebpDiversifier(
    private val minimumSsim: Double = HARD_MINIMUM_SSIM,
    private val minimumPHashDistance: Int = HARD_MINIMUM_PHASH_DISTANCE,
    private val maximumByteGrowthRatio: Double = HARD_MAXIMUM_BYTE_GROWTH_RATIO,
    private val encodingPolicy: WebpEncodingPolicy = WebpEncodingPolicy.PER_IMAGE,
) {
    private var encoder: WebpByteEncoder = ImageIoWebpByteEncoder

    internal constructor(
        minimumSsim: Double,
        minimumPHashDistance: Int,
        maximumByteGrowthRatio: Double,
        encodingPolicy: WebpEncodingPolicy = WebpEncodingPolicy.PER_IMAGE,
        encoder: WebpByteEncoder,
    ) : this(minimumSsim, minimumPHashDistance, maximumByteGrowthRatio, encodingPolicy) {
        this.encoder = encoder
    }

    init {
        require(minimumSsim in HARD_MINIMUM_SSIM..1.0) {
            "minimum SSIM must be in $HARD_MINIMUM_SSIM..1"
        }
        require(minimumPHashDistance in HARD_MINIMUM_PHASH_DISTANCE..64) {
            "minimum pHash distance must be in $HARD_MINIMUM_PHASH_DISTANCE..64"
        }
        require(maximumByteGrowthRatio in 0.0..HARD_MAXIMUM_BYTE_GROWTH_RATIO) {
            "maximum byte growth ratio must be in 0..$HARD_MAXIMUM_BYTE_GROWTH_RATIO"
        }
    }

    fun diversify(entry: ResourceInventoryEntry, contentSalt: ByteArray): WebpDiversificationResult {
        require(contentSalt.isNotEmpty()) { "content salt must not be empty" }
        exclusion(entry)?.let { return excluded(it) }
        val bytes = requireNotNull(entry.bytes)
        if (isAnimatedWebp(bytes)) return excluded(WebpIneligibilityReason.ANIMATION)
        val source = VerifiedWebp.read(bytes) ?: return ineligible(WebpIneligibilityReason.UNVERIFIED_WEBP)
        if (source.width < 2 || source.height < 2) {
            return ineligible(WebpIneligibilityReason.NO_SAFE_PERTURBATION)
        }

        val sourceDigest = MessageDigest.getInstance("SHA-256").digest(bytes)
        val resourceIdentity = requireNotNull(entry.aabPath).toByteArray(Charsets.UTF_8)
        val saltedSeed = MessageDigest.getInstance("SHA-256").digest(contentSalt + sourceDigest + resourceIdentity)
        val sourceHash = ImageMetrics.perceptualHash(source)
        val ratioLimitedBytes = floor(bytes.size * (1.0 + maximumByteGrowthRatio)).toInt()
        val maximumOutputBytes = if (maximumByteGrowthRatio == HARD_MAXIMUM_BYTE_GROWTH_RATIO) {
            max(ratioLimitedBytes, bytes.size + SMALL_FILE_OVERHEAD_BYTES)
        } else {
            ratioLimitedBytes
        }
        var rejectedForGrowth = false
        var bestRejectedCandidate: QualityCandidate? = null

        val encodingPlan = WebpEncodingPolicy.forSource(bytes)
        val originalSha256 = ImageMetrics.sha256(bytes)
        var encodedTransparentCandidates = 0
        var encodedDctCandidates = 0
        var generatedDctCandidates = 0
        for (candidate in ImageDiversificationCandidates.generateDetailed(
            source = source,
            minimumPHashDistance = minimumPHashDistance,
            seed = seedLong(saltedSeed),
        )) {
            if (candidate.kind == ImageDiversificationCandidateKind.DIRECTED_DCT) {
                if (generatedDctCandidates >= MAX_DCT_SEARCH_CANDIDATES) break
                generatedDctCandidates++
            }
            val candidateImage = candidate.image
            val candidateHash = ImageMetrics.perceptualHash(candidateImage)
            val pHashDistance = WebpImageMetrics.pHashDistance(sourceHash, candidateHash)
            if (pHashDistance < minimumPHashDistance) continue
            if (!ImageMetrics.alphaSamplesEqual(source, candidateImage)) continue
            val quickSimilarity = ImageMetrics.quickVisibleSimilarity(source, candidateImage)
            if (quickSimilarity < minimumSsim - QUICK_SSIM_PREFILTER_MARGIN) continue
            when (candidate.kind) {
                ImageDiversificationCandidateKind.TRANSPARENT_RGB -> {
                    if (encodedTransparentCandidates >= MAX_TRANSPARENT_ENCODING_CANDIDATES) continue
                    encodedTransparentCandidates++
                }
                ImageDiversificationCandidateKind.DIRECTED_DCT -> {
                    if (encodedDctCandidates >= MAX_DCT_ENCODING_CANDIDATES) break
                    encodedDctCandidates++
                }
            }
            var fastEncoded = false
            for (profile in encodingPlan.fast) {
                val attempt = evaluateEncoding(
                    originalBytes = bytes,
                    originalSha256 = originalSha256,
                    source = source,
                    sourceHash = sourceHash,
                    candidate = candidateImage,
                    profile = profile,
                    maximumOutputBytes = maximumOutputBytes,
                )
                fastEncoded = fastEncoded || attempt.encoded
                val qualityCandidate = attempt.qualityCandidate ?: continue
                if (qualityCandidate.bytes.size <= maximumOutputBytes) {
                    return transformed(qualityCandidate)
                }
                rejectedForGrowth = true
                bestRejectedCandidate = smaller(bestRejectedCandidate, qualityCandidate)
            }
            if (!fastEncoded) continue
            for (profile in encodingPlan.fallback) {
                val attempt = evaluateEncoding(
                    originalBytes = bytes,
                    originalSha256 = originalSha256,
                    source = source,
                    sourceHash = sourceHash,
                    candidate = candidateImage,
                    profile = profile,
                    maximumOutputBytes = maximumOutputBytes,
                )
                val qualityCandidate = attempt.qualityCandidate ?: continue
                if (qualityCandidate.bytes.size <= maximumOutputBytes) {
                    return transformed(qualityCandidate)
                }
                rejectedForGrowth = true
                bestRejectedCandidate = smaller(bestRejectedCandidate, qualityCandidate)
            }
        }
        if (encodingPolicy == WebpEncodingPolicy.GLOBAL_AAB_BUDGET) {
            bestRejectedCandidate?.let { return transformed(it) }
        }
        return ineligible(
            reason = if (rejectedForGrowth) WebpIneligibilityReason.BYTE_GROWTH_LIMIT
            else WebpIneligibilityReason.NO_SAFE_PERTURBATION,
            bestRejectedCandidate = bestRejectedCandidate,
        )
    }

    private fun evaluateEncoding(
        originalBytes: ByteArray,
        originalSha256: String,
        source: BufferedImage,
        sourceHash: PerceptualHash,
        candidate: BufferedImage,
        profile: WebpEncodingProfile,
        maximumOutputBytes: Int,
    ): EncodingAttempt {
        val candidateBytes = encoder.encode(candidate, profile, maximumOutputBytes)
            ?: return EncodingAttempt(encoded = false)
        if (candidateBytes.contentEquals(originalBytes)) return EncodingAttempt(encoded = true)
        val after = VerifiedWebp.read(candidateBytes) ?: return EncodingAttempt(encoded = true)
        if (source.width != after.width || source.height != after.height) return EncodingAttempt(encoded = true)
        val afterHash = ImageMetrics.perceptualHash(after)
        val imageMetrics = WebpImageMetrics.compareImages(
            source,
            after,
            WebpImageMetrics.pHashDistance(sourceHash, afterHash),
        )
        val metrics = WebpComparisonMetrics(
            width = source.width,
            height = source.height,
            alphaPreserved = imageMetrics.alphaPreserved,
            ssim = imageMetrics.ssim,
            pHashDistance = imageMetrics.pHashDistance,
            originalSha256 = originalSha256,
            transformedSha256 = ImageMetrics.sha256(candidateBytes),
            byteGrowthRatio = (candidateBytes.size.toDouble() - originalBytes.size) / originalBytes.size,
        )
        val successful = metrics.alphaPreserved &&
            metrics.ssim >= minimumSsim &&
            metrics.pHashDistance >= minimumPHashDistance &&
            metrics.originalSha256 != metrics.transformedSha256
        if (!successful) return EncodingAttempt(encoded = true)
        return EncodingAttempt(
            encoded = true,
            qualityCandidate = QualityCandidate(candidateBytes, metrics),
        )
    }

    private fun smaller(current: QualityCandidate?, candidate: QualityCandidate?): QualityCandidate? = when {
        candidate == null -> current
        current == null || candidate.bytes.size < current.bytes.size -> candidate
        else -> current
    }

    private fun exclusion(entry: ResourceInventoryEntry): WebpIneligibilityReason? = when {
        entry.origin == ResourceOrigin.DEPENDENCY -> WebpIneligibilityReason.DEPENDENCY_RESOURCE
        entry.origin == ResourceOrigin.GENERATED -> WebpIneligibilityReason.GENERATED_RESOURCE
        entry.externallyNamed -> WebpIneligibilityReason.EXTERNALLY_NAMED
        entry.notificationIcon -> WebpIneligibilityReason.NOTIFICATION_ICON
        entry.animation -> WebpIneligibilityReason.ANIMATION
        entry.type != ResourceType.DRAWABLE || entry.aabPath?.lowercase()?.endsWith(".webp") != true ||
            entry.bytes == null -> WebpIneligibilityReason.UNSUPPORTED_FORMAT
        !entry.webpDiversificationEnabled -> WebpIneligibilityReason.OUTSIDE_CONFIGURED_WEBP_SCOPE
        else -> null
    }

    private fun isAnimatedWebp(bytes: ByteArray): Boolean {
        if (!hasWebpHeader(bytes)) return false
        var offset = 12
        while (offset + 8 <= bytes.size) {
            val type = bytes.copyOfRange(offset, offset + 4).toString(Charsets.ISO_8859_1)
            val length = littleEndianInt(bytes, offset + 4)
            if (length < 0 || offset + 8L + length > bytes.size) return false
            if (type == "ANIM" || type == "ANMF") return true
            if (type == "VP8X" && length >= 1 && bytes[offset + 8].toInt() and ANIMATION_FLAG != 0) return true
            offset += 8 + length + (length and 1)
        }
        return false
    }

    private fun excluded(reason: WebpIneligibilityReason) = WebpDiversificationResult(
        status = ImageTransformStatus.EXCLUDED,
        reason = reason,
    )

    private fun ineligible(
        reason: WebpIneligibilityReason,
        bestRejectedCandidate: QualityCandidate? = null,
    ) = WebpDiversificationResult(
        status = ImageTransformStatus.INELIGIBLE,
        reason = reason,
        bestRejectedSize = bestRejectedCandidate?.bytes?.size,
        bestRejectedMetrics = bestRejectedCandidate?.metrics,
    )

    private fun transformed(candidate: QualityCandidate) = WebpDiversificationResult(
        status = ImageTransformStatus.TRANSFORMED,
        reason = WebpIneligibilityReason.TRANSFORMED,
        transformedBytes = candidate.bytes,
        metrics = candidate.metrics,
    )

    private fun seedLong(bytes: ByteArray): Long {
        var value = 0L
        for (index in 0 until minOf(8, bytes.size)) value = (value shl 8) or (bytes[index].toLong() and 0xff)
        return value
    }

    private data class EncodingAttempt(
        val encoded: Boolean,
        val qualityCandidate: QualityCandidate? = null,
    )

    private data class QualityCandidate(
        val bytes: ByteArray,
        val metrics: WebpComparisonMetrics,
    )

    companion object {
        const val HARD_MINIMUM_SSIM: Double = 0.995
        const val HARD_MINIMUM_PHASH_DISTANCE: Int = 11
        const val HARD_MAXIMUM_BYTE_GROWTH_RATIO: Double = 0.10

        private const val ANIMATION_FLAG = 0x02
        private const val SMALL_FILE_OVERHEAD_BYTES = 16_384
        private const val QUICK_SSIM_PREFILTER_MARGIN = 0.01
        private const val MAX_TRANSPARENT_ENCODING_CANDIDATES = 1
        private const val MAX_DCT_ENCODING_CANDIDATES = 4
        private const val MAX_DCT_SEARCH_CANDIDATES = 32
    }
}

private object ImageIoWebpByteEncoder : WebpByteEncoder {
    override fun encode(
        image: BufferedImage,
        profile: WebpEncodingProfile,
        maximumOutputBytes: Int,
    ): ByteArray? = runCatching {
        val writer = fixedWebpWriter()
        try {
            val output = ByteArrayOutputStream()
            ImageIO.createImageOutputStream(output).use { imageOutput ->
                requireNotNull(imageOutput)
                writer.output = imageOutput
                val parameters = writer.defaultWriteParam
                parameters.compressionMode = ImageWriteParam.MODE_EXPLICIT
                parameters.compressionType = requireNotNull(parameters.compressionTypes)
                    .first { it.equals(profile.type, ignoreCase = true) }
                parameters.compressionQuality = profile.quality
                invokeOptionalSetter(parameters, "setMethod", Int::class.javaPrimitiveType, profile.method)
                invokeOptionalSetter(parameters, "setExact", Boolean::class.javaPrimitiveType, true)
                invokeOptionalSetter(parameters, "setAlphaQuality", Int::class.javaPrimitiveType, 100)
                invokeOptionalSetter(parameters, "setThreadLevel", Int::class.javaPrimitiveType, 1)
                if (profile.useTargetSize) {
                    invokeOptionalSetter(parameters, "setTargetSize", Int::class.javaPrimitiveType, maximumOutputBytes)
                }
                if (profile.type == "Lossy") {
                    invokeOptionalSetter(parameters, "setUseSharpYUV", Boolean::class.javaPrimitiveType, true)
                }
                writer.write(null, IIOImage(image, null, null), parameters)
            }
            output.toByteArray()
        } finally {
            writer.dispose()
        }
    }.getOrNull()
}

private fun invokeOptionalSetter(
    target: Any,
    name: String,
    parameterType: Class<*>?,
    value: Any,
) {
    runCatching { target.javaClass.getMethod(name, requireNotNull(parameterType)).invoke(target, value) }
}

internal data class DecodedImageMetrics(
    val alphaPreserved: Boolean,
    val ssim: Double,
    val pHashDistance: Int,
)

private object VerifiedWebp {
    private const val MAX_PIXELS = 16_777_216L

    fun read(bytes: ByteArray): BufferedImage? {
        if (!hasWebpHeader(bytes)) return null
        return runCatching {
            ImageIO.createImageInputStream(ByteArrayInputStream(bytes)).use { input ->
                requireNotNull(input)
                val reader = fixedWebpReader()
                try {
                    reader.input = input
                    require(reader.getNumImages(true) == 1)
                    val width = reader.getWidth(0)
                    val height = reader.getHeight(0)
                    require(width > 0 && height > 0 && width.toLong() * height <= MAX_PIXELS)
                    requireNotNull(reader.read(0))
                } finally {
                    reader.dispose()
                }
            }
        }.getOrNull()
    }
}

private fun fixedWebpWriter(): ImageWriter {
    val writers = ImageIO.getImageWritersByMIMEType("image/webp")
    while (writers.hasNext()) {
        val writer = writers.next()
        if (writer.javaClass.name.startsWith(FIXED_WEBP_PACKAGE)) return writer
        writer.dispose()
    }
    error("fixed webp-imageio writer SPI is unavailable")
}

private fun fixedWebpReader(): ImageReader {
    val readers = ImageIO.getImageReadersByMIMEType("image/webp")
    while (readers.hasNext()) {
        val reader = readers.next()
        if (reader.javaClass.name.startsWith(FIXED_WEBP_PACKAGE)) return reader
        reader.dispose()
    }
    error("fixed webp-imageio reader SPI is unavailable")
}

private const val FIXED_WEBP_PACKAGE = "com.luciad.imageio.webp."

private fun hasWebpHeader(bytes: ByteArray): Boolean =
    bytes.size >= 16 &&
        bytes.copyOfRange(0, 4).contentEquals("RIFF".toByteArray()) &&
        bytes.copyOfRange(8, 12).contentEquals("WEBP".toByteArray()) &&
        littleEndianInt(bytes, 4).toLong() + 8L == bytes.size.toLong() &&
        bytes.copyOfRange(12, 16).toString(Charsets.ISO_8859_1) in setOf("VP8 ", "VP8L", "VP8X")

private fun littleEndianInt(bytes: ByteArray, offset: Int): Int {
    if (offset < 0 || offset + 4 > bytes.size) return -1
    return (bytes[offset].toInt() and 0xff) or
        ((bytes[offset + 1].toInt() and 0xff) shl 8) or
        ((bytes[offset + 2].toInt() and 0xff) shl 16) or
        ((bytes[offset + 3].toInt() and 0xff) shl 24)
}
