package com.holin.android.hardening.resources

import java.awt.image.BufferedImage
import java.io.ByteArrayOutputStream
import java.security.MessageDigest
import javax.imageio.ImageIO

enum class ImageTransformStatus {
    TRANSFORMED,
    INELIGIBLE,
    EXCLUDED,
}

enum class ImageIneligibilityReason {
    TRANSFORMED,
    UNOWNED_MODULE,
    OUTSIDE_CONFIGURED_WEBP_SCOPE,
    NINE_PATCH,
    ANIMATION,
    NOTIFICATION_ICON,
    EXTERNALLY_NAMED,
    WEBP_UNSUPPORTED,
    UNSUPPORTED_FORMAT,
    DEPENDENCY_RESOURCE,
    GENERATED_RESOURCE,
    UNVERIFIED_PNG,
    UNVERIFIED_WEBP,
    NO_SAFE_PERTURBATION,
    BYTE_GROWTH_LIMIT,
}

data class PngDiversificationResult(
    val status: ImageTransformStatus,
    val reason: ImageIneligibilityReason,
    val transformedBytes: ByteArray? = null,
    val metrics: PngComparisonMetrics? = null,
)

class PngDiversifier(
    private val minimumSsim: Double = 0.995,
    private val minimumPHashDistance: Int = 11,
) {
    init {
        require(minimumSsim in HARD_MINIMUM_SSIM..1.0) {
            "minimum SSIM must be in $HARD_MINIMUM_SSIM..1"
        }
        require(minimumPHashDistance in HARD_MINIMUM_PHASH_DISTANCE..64) {
            "minimum pHash distance must be in $HARD_MINIMUM_PHASH_DISTANCE..64"
        }
    }

    fun diversify(entry: ResourceInventoryEntry, contentSalt: ByteArray): PngDiversificationResult {
        require(contentSalt.isNotEmpty()) { "content salt must not be empty" }
        exclusion(entry)?.let { return excluded(it) }
        val path = requireNotNull(entry.aabPath)
        val bytes = requireNotNull(entry.bytes)
        val lowerPath = path.lowercase()
        if (lowerPath.endsWith(".9.png")) return excluded(ImageIneligibilityReason.NINE_PATCH)
        if (lowerPath.endsWith(".webp")) return excluded(ImageIneligibilityReason.WEBP_UNSUPPORTED)
        if (!lowerPath.endsWith(".png")) return excluded(ImageIneligibilityReason.UNSUPPORTED_FORMAT)
        if (containsPngChunk(bytes, "acTL")) return excluded(ImageIneligibilityReason.ANIMATION)
        val verified = VerifiedPng.read(bytes) ?: return ineligible(ImageIneligibilityReason.UNVERIFIED_PNG)
        if (verified.image.width < 2 || verified.image.height < 2) {
            return ineligible(ImageIneligibilityReason.NO_SAFE_PERTURBATION)
        }

        val sourceHash = MessageDigest.getInstance("SHA-256").digest(bytes)
        val resourceIdentity = path.toByteArray(Charsets.UTF_8)
        val saltedImageSeed = MessageDigest.getInstance("SHA-256").digest(contentSalt + sourceHash + resourceIdentity)
        val sourceHashSignature = ImageMetrics.perceptualHash(verified.image)
        for (candidateImage in ImageDiversificationCandidates.generate(
            source = verified.image,
            minimumPHashDistance = minimumPHashDistance,
            seed = seedLong(saltedImageSeed),
        )) {
            val candidateHash = ImageMetrics.perceptualHash(candidateImage)
            val decodedDistance = sourceHashSignature.bits.zip(candidateHash.bits).count { (left, right) -> left != right }
            if (decodedDistance < minimumPHashDistance) continue
            if (!ImageMetrics.alphaSamplesEqual(verified.image, candidateImage)) continue
            if (ImageMetrics.structuralSimilarity(verified.image, candidateImage) < minimumSsim) continue

            val candidateBytes = encode(candidateImage) ?: continue
            if (candidateBytes.contentEquals(bytes)) continue
            val metrics = runCatching { ImageMetrics.comparePng(bytes, candidateBytes) }.getOrNull() ?: continue
            if (
                metrics.alphaPreserved &&
                metrics.ssim >= minimumSsim &&
                metrics.pHashDistance >= minimumPHashDistance &&
                metrics.originalSha256 != metrics.transformedSha256
            ) {
                return PngDiversificationResult(
                    status = ImageTransformStatus.TRANSFORMED,
                    reason = ImageIneligibilityReason.TRANSFORMED,
                    transformedBytes = candidateBytes,
                    metrics = metrics,
                )
            }
        }
        return ineligible(ImageIneligibilityReason.NO_SAFE_PERTURBATION)
    }

    private fun exclusion(entry: ResourceInventoryEntry): ImageIneligibilityReason? = when {
        entry.origin == ResourceOrigin.DEPENDENCY -> ImageIneligibilityReason.DEPENDENCY_RESOURCE
        entry.origin == ResourceOrigin.GENERATED -> ImageIneligibilityReason.GENERATED_RESOURCE
        entry.externallyNamed -> ImageIneligibilityReason.EXTERNALLY_NAMED
        entry.notificationIcon -> ImageIneligibilityReason.NOTIFICATION_ICON
        entry.animation -> ImageIneligibilityReason.ANIMATION
        entry.type != ResourceType.DRAWABLE || entry.aabPath == null || entry.bytes == null ->
            ImageIneligibilityReason.UNSUPPORTED_FORMAT
        else -> null
    }

    private fun encode(image: BufferedImage): ByteArray? = runCatching {
        ByteArrayOutputStream().use { output ->
            check(ImageIO.write(image, "png", output)) { "JDK PNG writer unavailable" }
            output.toByteArray()
        }
    }.getOrNull()

    private fun containsPngChunk(bytes: ByteArray, expectedType: String): Boolean {
        if (bytes.size < 12) return false
        var offset = 8
        while (offset + 12 <= bytes.size) {
            val length = ((bytes[offset].toLong() and 0xff) shl 24) or
                ((bytes[offset + 1].toLong() and 0xff) shl 16) or
                ((bytes[offset + 2].toLong() and 0xff) shl 8) or
                (bytes[offset + 3].toLong() and 0xff)
            if (length > Int.MAX_VALUE || offset + 12L + length > bytes.size) return false
            val type = bytes.copyOfRange(offset + 4, offset + 8).toString(Charsets.ISO_8859_1)
            if (type == expectedType) return true
            offset += 12 + length.toInt()
        }
        return false
    }

    private fun excluded(reason: ImageIneligibilityReason) = PngDiversificationResult(
        status = ImageTransformStatus.EXCLUDED,
        reason = reason,
    )

    private fun ineligible(reason: ImageIneligibilityReason) = PngDiversificationResult(
        status = ImageTransformStatus.INELIGIBLE,
        reason = reason,
    )

    private fun seedLong(bytes: ByteArray): Long {
        var value = 0L
        for (index in 0 until minOf(8, bytes.size)) value = (value shl 8) or (bytes[index].toLong() and 0xff)
        return value
    }

    companion object {
        const val HARD_MINIMUM_SSIM: Double = 0.995
        const val HARD_MINIMUM_PHASH_DISTANCE: Int = 11
    }
}
