package com.holin.android.hardening.resources

import java.awt.image.BufferedImage
import java.io.ByteArrayInputStream
import java.security.MessageDigest
import java.util.Collections
import java.util.Random
import javax.imageio.ImageIO
import kotlin.math.ceil
import kotlin.math.cos
import kotlin.math.roundToInt
import kotlin.math.sqrt

data class PngComparisonMetrics(
    val width: Int,
    val height: Int,
    val alphaPreserved: Boolean,
    val ssim: Double,
    val pHashDistance: Int,
    val originalSha256: String,
    val transformedSha256: String,
    val nearestCorpusPHashDistance: Int? = null,
)

object ImageMetrics {
    fun comparePng(original: ByteArray, transformed: ByteArray): PngComparisonMetrics {
        val before = VerifiedPng.read(original) ?: throw IllegalArgumentException("original bytes are not a verified PNG")
        val after = VerifiedPng.read(transformed) ?: throw IllegalArgumentException("transformed bytes are not a verified PNG")
        require(before.image.width == after.image.width && before.image.height == after.image.height) {
            "PNG dimensions changed"
        }
        val alphaPreserved = alphaSamplesEqual(before, after)
        return PngComparisonMetrics(
            before.image.width,
            before.image.height,
            alphaPreserved,
            structuralSimilarity(before.image, after.image),
            perceptualHash(before.image).bits.zip(perceptualHash(after.image).bits)
                .count { (left, right) -> left != right },
            sha256(original),
            sha256(transformed),
        )
    }

    internal fun perceptualHash(image: BufferedImage): PerceptualHash {
        val sample = resizedLuminance(image, PHASH_SIZE)
        val coefficients = DoubleArray(PHASH_BITS)
        var index = 0
        for (verticalFrequency in 0 until PHASH_HASH_SIZE) {
            for (horizontalFrequency in 0 until PHASH_HASH_SIZE) {
                var coefficient = 0.0
                for (y in 0 until PHASH_SIZE) {
                    val verticalBasis = PHASH_COSINES[verticalFrequency][y]
                    for (x in 0 until PHASH_SIZE) {
                        coefficient += sample[y * PHASH_SIZE + x] *
                            PHASH_COSINES[horizontalFrequency][x] * verticalBasis
                    }
                }
                coefficients[index++] = coefficient
            }
        }
        val median = coefficients.sorted()[coefficients.size / 2]
        return PerceptualHash(coefficients, median, BooleanArray(coefficients.size) { coefficients[it] > median })
    }

    private fun resizedLuminance(image: BufferedImage, size: Int): DoubleArray {
        val output = DoubleArray(size * size)
        for (targetY in 0 until size) {
            val sourceY = (targetY + 0.5) * image.height / size - 0.5
            val y0 = sourceY.toInt().coerceIn(0, image.height - 1)
            val y1 = (y0 + 1).coerceAtMost(image.height - 1)
            val yWeight = (sourceY - sourceY.toInt()).coerceIn(0.0, 1.0)
            for (targetX in 0 until size) {
                val sourceX = (targetX + 0.5) * image.width / size - 0.5
                val x0 = sourceX.toInt().coerceIn(0, image.width - 1)
                val x1 = (x0 + 1).coerceAtMost(image.width - 1)
                val xWeight = (sourceX - sourceX.toInt()).coerceIn(0.0, 1.0)
                val top = luminance(image.getRGB(x0, y0)) * (1.0 - xWeight) +
                    luminance(image.getRGB(x1, y0)) * xWeight
                val bottom = luminance(image.getRGB(x0, y1)) * (1.0 - xWeight) +
                    luminance(image.getRGB(x1, y1)) * xWeight
                output[targetY * size + targetX] = top * (1.0 - yWeight) + bottom * yWeight
            }
        }
        return output
    }

    internal fun structuralSimilarity(before: BufferedImage, after: BufferedImage): Double {
        val window = minOf(8, before.width, before.height)
        if (window < 2) return if (pixelsEqual(before, after)) 1.0 else 0.0
        val step = maxOf(1, window / 2)
        var sum = 0.0
        var windows = 0
        var startY = 0
        while (startY < before.height) {
            val y0 = minOf(startY, before.height - window)
            var startX = 0
            while (startX < before.width) {
                val x0 = minOf(startX, before.width - window)
                sum += windowSsim(before, after, x0, y0, window)
                windows++
                if (x0 == before.width - window) break
                startX += step
            }
            if (y0 == before.height - window) break
            startY += step
        }
        return (sum / windows).coerceIn(-1.0, 1.0)
    }

    /** Cheap conservative prefilter; the final encoded image still uses the full windowed SSIM gate. */
    internal fun quickVisibleSimilarity(before: BufferedImage, after: BufferedImage): Double {
        require(before.width == after.width && before.height == after.height) { "image dimensions changed" }
        val pixelCount = before.width.toLong() * before.height
        val stride = ceil(sqrt(pixelCount.toDouble() / QUICK_SSIM_MAX_SAMPLES)).toInt().coerceAtLeast(1)
        var count = 0
        var beforeMean = 0.0
        var afterMean = 0.0
        for (y in 0 until before.height step stride) {
            for (x in 0 until before.width step stride) {
                beforeMean += visibleLuminance(before.getRGB(x, y))
                afterMean += visibleLuminance(after.getRGB(x, y))
                count++
            }
        }
        if (count < 2) return if (pixelsEqual(before, after)) 1.0 else 0.0
        beforeMean /= count
        afterMean /= count
        var beforeVariance = 0.0
        var afterVariance = 0.0
        var covariance = 0.0
        for (y in 0 until before.height step stride) {
            for (x in 0 until before.width step stride) {
                val beforeDelta = visibleLuminance(before.getRGB(x, y)) - beforeMean
                val afterDelta = visibleLuminance(after.getRGB(x, y)) - afterMean
                beforeVariance += beforeDelta * beforeDelta
                afterVariance += afterDelta * afterDelta
                covariance += beforeDelta * afterDelta
            }
        }
        val divisor = count - 1
        return ssim(
            beforeMean = beforeMean,
            afterMean = afterMean,
            beforeVariance = beforeVariance / divisor,
            afterVariance = afterVariance / divisor,
            covariance = covariance / divisor,
        ).coerceIn(-1.0, 1.0)
    }

    private fun windowSsim(before: BufferedImage, after: BufferedImage, x0: Int, y0: Int, size: Int): Double {
        val count = size * size
        var beforeMean = 0.0
        var afterMean = 0.0
        for (y in y0 until y0 + size) {
            for (x in x0 until x0 + size) {
                beforeMean += visibleLuminance(before.getRGB(x, y))
                afterMean += visibleLuminance(after.getRGB(x, y))
            }
        }
        beforeMean /= count
        afterMean /= count
        var beforeVariance = 0.0
        var afterVariance = 0.0
        var covariance = 0.0
        for (y in y0 until y0 + size) {
            for (x in x0 until x0 + size) {
                val beforeDelta = visibleLuminance(before.getRGB(x, y)) - beforeMean
                val afterDelta = visibleLuminance(after.getRGB(x, y)) - afterMean
                beforeVariance += beforeDelta * beforeDelta
                afterVariance += afterDelta * afterDelta
                covariance += beforeDelta * afterDelta
            }
        }
        val divisor = maxOf(1, count - 1)
        beforeVariance /= divisor
        afterVariance /= divisor
        covariance /= divisor
        return ssim(beforeMean, afterMean, beforeVariance, afterVariance, covariance)
    }

    private fun ssim(
        beforeMean: Double,
        afterMean: Double,
        beforeVariance: Double,
        afterVariance: Double,
        covariance: Double,
    ): Double {
        val c1 = 6.5025
        val c2 = 58.5225
        return ((2 * beforeMean * afterMean + c1) * (2 * covariance + c2)) /
            ((beforeMean * beforeMean + afterMean * afterMean + c1) *
                (beforeVariance + afterVariance + c2))
    }

    private fun alphaSamplesEqual(before: VerifiedPng, after: VerifiedPng): Boolean {
        if (before.hasAlpha != after.hasAlpha) return false
        return alphaSamplesEqual(before.image, after.image)
    }

    internal fun alphaSamplesEqual(before: BufferedImage, after: BufferedImage): Boolean {
        if (before.width != after.width || before.height != after.height) return false
        for (y in 0 until before.height) {
            for (x in 0 until before.width) {
                if ((before.getRGB(x, y) ushr 24) != (after.getRGB(x, y) ushr 24)) return false
            }
        }
        return true
    }

    private fun pixelsEqual(before: BufferedImage, after: BufferedImage): Boolean {
        for (y in 0 until before.height) {
            for (x in 0 until before.width) {
                if (before.getRGB(x, y) != after.getRGB(x, y)) return false
            }
        }
        return true
    }

    internal fun luminance(argb: Int): Double {
        val red = argb ushr 16 and 0xff
        val green = argb ushr 8 and 0xff
        val blue = argb and 0xff
        return 0.299 * red + 0.587 * green + 0.114 * blue
    }

    private fun visibleLuminance(argb: Int): Double {
        val alpha = (argb ushr 24 and 0xff) / 255.0
        return luminance(argb) * alpha
    }

    internal fun sha256(bytes: ByteArray): String = MessageDigest.getInstance("SHA-256")
        .digest(bytes).joinToString("") { "%02x".format(it) }

    private const val PHASH_SIZE = 32
    private const val PHASH_HASH_SIZE = 8
    private const val PHASH_BITS = PHASH_HASH_SIZE * PHASH_HASH_SIZE
    private const val QUICK_SSIM_MAX_SAMPLES = 16_384.0
    private val PHASH_COSINES = Array(PHASH_HASH_SIZE) { frequency ->
        DoubleArray(PHASH_SIZE) { position ->
            val normalization = if (frequency == 0) sqrt(1.0 / PHASH_SIZE) else sqrt(2.0 / PHASH_SIZE)
            normalization * cos(Math.PI * (2 * position + 1) * frequency / (2.0 * PHASH_SIZE))
        }
    }
}

/**
 * Produces deterministic, low-entropy image candidates. The first tier changes only RGB hidden
 * behind alpha=0. The second tier crosses the closest pHash decision boundaries with a directed
 * inverse DCT whose per-frequency amplitude is proportional to the actual boundary distance.
 */
internal object ImageDiversificationCandidates {
    fun generate(
        source: BufferedImage,
        minimumPHashDistance: Int,
        seed: Long,
    ): Sequence<BufferedImage> = generateDetailed(source, minimumPHashDistance, seed).map { it.image }

    fun generateDetailed(
        source: BufferedImage,
        minimumPHashDistance: Int,
        seed: Long,
    ): Sequence<ImageDiversificationCandidate> = sequence {
        require(minimumPHashDistance in 1..63) { "minimum pHash distance must be in 1..63" }

        val colorRandom = Random(seed)
        val colorMask = colorRandom.nextInt() and RGB_MASK
        val transparentColors = TRANSPARENT_RGB.map { rgb -> rgb xor colorMask }.distinct().toMutableList()
        Collections.shuffle(transparentColors, colorRandom)
        transparentColors.forEach { rgb ->
            recolorFullyTransparentPixels(source, rgb)?.let {
                yield(ImageDiversificationCandidate(it, ImageDiversificationCandidateKind.TRANSPARENT_RGB))
            }
        }

        val originalHash = ImageMetrics.perceptualHash(source)
        val orderedFrequencies = (1 until PHASH_BITS).sortedBy { index ->
            kotlin.math.abs(originalHash.coefficients[index] - originalHash.median)
        }
        TARGET_EXTRAS.forEachIndexed { planIndex, extra ->
            val targetCount = (minimumPHashDistance + extra).coerceAtMost(PHASH_BITS - 1)
            val selected = saltedSelection(
                orderedFrequencies,
                targetCount,
                seed xor (planIndex + 1L) * PLAN_SEED_MIX,
                SALTED_POOL_SIZE,
            )
            DCT_MARGINS.forEach { margin ->
                directedCandidate(source, originalHash, selected, margin)?.let {
                    yield(ImageDiversificationCandidate(it, ImageDiversificationCandidateKind.DIRECTED_DCT))
                }
            }
        }

        FALLBACK_TARGET_EXTRAS.forEachIndexed { planIndex, extra ->
            val targetCount = (minimumPHashDistance + extra).coerceAtMost(PHASH_BITS - 1)
            val selected = saltedSelection(
                orderedFrequencies,
                targetCount,
                seed xor (planIndex + 1L) * FALLBACK_PLAN_SEED_MIX,
                FALLBACK_SALTED_POOL_SIZE,
            )
            DCT_MARGINS.forEach { margin ->
                directedCandidate(source, originalHash, selected, margin)?.let {
                    yield(ImageDiversificationCandidate(it, ImageDiversificationCandidateKind.FALLBACK_DCT))
                }
            }
        }

        HIDDEN_DCT_TARGET_EXTRAS.forEachIndexed { planIndex, extra ->
            val targetCount = (minimumPHashDistance + extra).coerceAtMost(PHASH_BITS - 1)
            val selected = saltedSelection(
                orderedFrequencies,
                targetCount,
                seed xor (planIndex + 1L) * HIDDEN_DCT_PLAN_SEED_MIX,
                HIDDEN_DCT_SALTED_POOL_SIZE,
            )
            HIDDEN_DCT_MARGINS.forEach { margin ->
                directedCandidate(source, originalHash, selected, margin, true)?.let {
                    yield(ImageDiversificationCandidate(it, ImageDiversificationCandidateKind.HIDDEN_DCT))
                }
            }
        }
    }

    private fun saltedSelection(
        ordered: List<Int>,
        targetCount: Int,
        seed: Long,
        poolSize: Int,
    ): List<Int> {
        if (targetCount >= ordered.size) return ordered
        val pool = ordered.take((targetCount + poolSize).coerceAtMost(ordered.size)).toMutableList()
        Collections.shuffle(pool, Random(seed))
        return pool.take(targetCount)
    }

    private fun recolorFullyTransparentPixels(source: BufferedImage, rgb: Int): BufferedImage? {
        if (!source.colorModel.hasAlpha()) return null
        val output = BufferedImage(source.width, source.height, BufferedImage.TYPE_INT_ARGB)
        var changed = false
        for (y in 0 until source.height) {
            for (x in 0 until source.width) {
                val argb = source.getRGB(x, y)
                val updated = if (argb ushr 24 == 0) rgb and RGB_MASK else argb
                if (updated != argb) changed = true
                output.setRGB(x, y, updated)
            }
        }
        return output.takeIf { changed }
    }

    private fun directedCandidate(
        source: BufferedImage,
        originalHash: PerceptualHash,
        selectedFrequencies: List<Int>,
        margin: Double,
        transparentOnly: Boolean = false,
    ): BufferedImage? {
        val weights = Array(PHASH_HASH_SIZE) { DoubleArray(PHASH_HASH_SIZE) }
        selectedFrequencies.forEach { index ->
            val coefficient = originalHash.coefficients[index]
            val distance = kotlin.math.abs(coefficient - originalHash.median)
            val direction = if (originalHash.bits[index]) -1.0 else 1.0
            weights[index / PHASH_HASH_SIZE][index % PHASH_HASH_SIZE] = direction * (distance + margin)
        }
        val vertical = normalizedBasis(source.height)
        val horizontal = normalizedBasis(source.width)
        val outputType = if (source.colorModel.hasAlpha()) BufferedImage.TYPE_INT_ARGB else BufferedImage.TYPE_INT_RGB
        val output = BufferedImage(source.width, source.height, outputType)
        var changed = false
        for (y in 0 until source.height) {
            val rowWeights = DoubleArray(PHASH_HASH_SIZE)
            for (verticalFrequency in 0 until PHASH_HASH_SIZE) {
                for (horizontalFrequency in 0 until PHASH_HASH_SIZE) {
                    rowWeights[horizontalFrequency] +=
                        weights[verticalFrequency][horizontalFrequency] * vertical[verticalFrequency][y]
                }
            }
            for (x in 0 until source.width) {
                var luminanceDelta = 0.0
                for (frequency in 0 until PHASH_HASH_SIZE) {
                    luminanceDelta += rowWeights[frequency] * horizontal[frequency][x]
                }
                val delta = luminanceDelta.roundToInt()
                val argb = source.getRGB(x, y)
                val alpha = argb ushr 24 and 0xff
                if (transparentOnly && alpha != 0) {
                    output.setRGB(x, y, argb)
                    continue
                }
                val red = ((argb ushr 16 and 0xff) + delta).coerceIn(0, 255)
                val green = ((argb ushr 8 and 0xff) + delta).coerceIn(0, 255)
                val blue = ((argb and 0xff) + delta).coerceIn(0, 255)
                val updated = (alpha shl 24) or (red shl 16) or (green shl 8) or blue
                if (updated != argb) changed = true
                output.setRGB(x, y, updated)
            }
        }
        return output.takeIf { changed }
    }

    private fun normalizedBasis(size: Int): Array<DoubleArray> = Array(PHASH_HASH_SIZE) { frequency ->
        val normalization = if (frequency == 0) sqrt(1.0 / PHASH_SAMPLE_SIZE) else sqrt(2.0 / PHASH_SAMPLE_SIZE)
        DoubleArray(size) { position ->
            normalization * cos(Math.PI * frequency * (position + 0.5) / size)
        }
    }

    private const val PHASH_SAMPLE_SIZE = 32
    private const val PHASH_HASH_SIZE = 8
    private const val PHASH_BITS = PHASH_HASH_SIZE * PHASH_HASH_SIZE
    private const val RGB_MASK = 0x00ffffff
    private const val SALTED_POOL_SIZE = 6
    private const val FALLBACK_SALTED_POOL_SIZE = 28
    private const val HIDDEN_DCT_SALTED_POOL_SIZE = 36
    private const val PLAN_SEED_MIX = -7046029254386353131L
    private const val FALLBACK_PLAN_SEED_MIX = -4658895280553007687L
    private const val HIDDEN_DCT_PLAN_SEED_MIX = -7723592293110705685L
    private val TARGET_EXTRAS = intArrayOf(1, 3, 5, 9, 13, 21)
    private val FALLBACK_TARGET_EXTRAS = intArrayOf(3, 7, 13, 21)
    private val HIDDEN_DCT_TARGET_EXTRAS = intArrayOf(3, 7, 13, 21, 29)
    private val DCT_MARGINS = doubleArrayOf(0.5, 1.0, 2.0, 3.0, 4.0, 6.0, 8.0, 12.0, 16.0, 24.0, 32.0)
    private val HIDDEN_DCT_MARGINS = doubleArrayOf(16.0, 32.0, 64.0, 96.0, 128.0, 192.0, 256.0, 384.0)
    private val TRANSPARENT_RGB = intArrayOf(
        0x101010,
        0x202020,
        0x404040,
        0x606060,
        0x808080,
        0xa0a0a0,
        0xc0c0c0,
        0xe0e0e0,
        0xffffff,
        0xff0000,
        0x00ff00,
        0x0000ff,
        0xff00ff,
        0x00ffff,
        0xffff00,
        0x7f1fdf,
    )
}

internal enum class ImageDiversificationCandidateKind {
    TRANSPARENT_RGB,
    DIRECTED_DCT,
    FALLBACK_DCT,
    HIDDEN_DCT,
}

internal data class ImageDiversificationCandidate(
    val image: BufferedImage,
    val kind: ImageDiversificationCandidateKind,
)

internal data class PerceptualHash(
    val coefficients: DoubleArray,
    val median: Double,
    val bits: BooleanArray,
)

internal data class VerifiedPng(val image: BufferedImage, val hasAlpha: Boolean) {
    companion object {
        private val SIGNATURE = byteArrayOf(-119, 80, 78, 71, 13, 10, 26, 10)
        private const val MAX_PIXELS = 16_777_216L

        fun read(bytes: ByteArray): VerifiedPng? {
            if (bytes.size < SIGNATURE.size || !bytes.copyOfRange(0, SIGNATURE.size).contentEquals(SIGNATURE)) return null
            return runCatching {
                ImageIO.createImageInputStream(ByteArrayInputStream(bytes)).use { input ->
                    requireNotNull(input)
                    val readers = ImageIO.getImageReaders(input)
                    require(readers.hasNext())
                    val reader = readers.next()
                    try {
                        require(reader.formatName.equals("png", ignoreCase = true))
                        reader.input = input
                        require(reader.getNumImages(true) == 1)
                        val width = reader.getWidth(0)
                        val height = reader.getHeight(0)
                        require(width > 0 && height > 0 && width.toLong() * height <= MAX_PIXELS)
                        val image = requireNotNull(reader.read(0))
                        VerifiedPng(image, image.colorModel.hasAlpha())
                    } finally {
                        reader.dispose()
                    }
                }
            }.getOrNull()
        }
    }
}
