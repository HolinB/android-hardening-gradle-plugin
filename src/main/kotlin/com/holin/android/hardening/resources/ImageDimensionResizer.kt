package com.holin.android.hardening.resources

import com.holin.android.hardening.ImageFormat
import java.awt.image.BufferedImage
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.math.BigInteger
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.zip.CRC32
import javax.imageio.ImageIO
import kotlin.math.floor
import kotlin.math.roundToInt

enum class ImageDimensionFallbackReason {
    DECODE_FAILED,
    ENCODE_FAILED,
}

data class ImageDimensionResult(
    val status: ImageTransformStatus,
    val originalWidth: Int?,
    val originalHeight: Int?,
    val newWidth: Int?,
    val newHeight: Int?,
    val transformedBytes: ByteArray?,
    val dimensionChanged: Boolean,
    val fallback: Boolean,
    val fallbackReason: ImageDimensionFallbackReason? = null,
)

/** Resizes an encoded image by one pixel on its short side, preserving its format. */
class ImageDimensionResizer(fixedSeed: ByteArray? = null) {
    private val fixedSeed = fixedSeed?.copyOf()

    fun resize(bytes: ByteArray, format: ImageFormat, contentSalt: ByteArray? = null): ImageDimensionResult {
        require(bytes.isNotEmpty()) { "image bytes must not be empty" }
        if (!hasFormatSignature(bytes, format)) return fallback(ImageDimensionFallbackReason.DECODE_FAILED)
        val source = runCatching {
            ByteArrayInputStream(bytes).use { ImageIO.read(it) }
        }.getOrNull() ?: return fallback(ImageDimensionFallbackReason.DECODE_FAILED)
        if (source.width < 1 || source.height < 1) return fallback(ImageDimensionFallbackReason.DECODE_FAILED)

        val (targetWidth, targetHeight) = targetDimensions(source.width, source.height)
        val resized = resizePremultiplied(source, targetWidth, targetHeight)
        val salt = contentSalt?.copyOf() ?: fixedSeed?.copyOf() ?: ByteArray(16).also(SecureRandom()::nextBytes)
        val encoded = encode(resized, format)?.let { decorate(it, format, salt, bytes) }
            ?: return ImageDimensionResult(
                ImageTransformStatus.INELIGIBLE,
                source.width,
                source.height,
                targetWidth,
                targetHeight,
                null,
                false,
                true,
                ImageDimensionFallbackReason.ENCODE_FAILED,
            )
        return ImageDimensionResult(
            ImageTransformStatus.TRANSFORMED,
            source.width,
            source.height,
            targetWidth,
            targetHeight,
            encoded,
            targetWidth != source.width || targetHeight != source.height,
            false,
        )
    }

    fun resize(entry: ResourceInventoryEntry): ImageDimensionResult {
        val format = requireNotNull(entry.imageFormat) { "resource does not carry an image format" }
        return resize(requireNotNull(entry.bytes), format)
    }

    private fun fallback(reason: ImageDimensionFallbackReason): ImageDimensionResult = ImageDimensionResult(
        ImageTransformStatus.INELIGIBLE,
        null,
        null,
        null,
        null,
        null,
        false,
        true,
        reason,
    )

    private fun targetDimensions(width: Int, height: Int): Pair<Int, Int> {
        val short = minOf(width, height)
        val long = maxOf(width, height)
        val newShort = (short.toLong() + 1L).coerceAtMost(Int.MAX_VALUE.toLong()).toInt().coerceAtLeast(1)
        val numerator = BigInteger.valueOf(long.toLong()).multiply(BigInteger.valueOf(newShort.toLong()))
        val denominator = BigInteger.valueOf(short.toLong())
        val rounded = numerator.divide(denominator).let { quotient ->
            if (numerator.remainder(denominator).shiftLeft(1) >= denominator) quotient + BigInteger.ONE else quotient
        }
        val newLong = rounded.coerceAtLeast(BigInteger.ONE).intValueExact()
        return if (width <= height) newShort to newLong else newLong to newShort
    }

    private fun resizePremultiplied(source: BufferedImage, width: Int, height: Int): BufferedImage {
        val outputType = if (source.colorModel.hasAlpha()) BufferedImage.TYPE_INT_ARGB else BufferedImage.TYPE_INT_RGB
        val output = BufferedImage(width, height, outputType)
        val sourceWidth = source.width
        val sourceHeight = source.height
        for (y in 0 until height) {
            val sourceY = ((y + 0.5) * sourceHeight / height - 0.5).coerceIn(0.0, (sourceHeight - 1).toDouble())
            val y0 = floor(sourceY).toInt()
            val y1 = minOf(y0 + 1, sourceHeight - 1)
            val yWeight = sourceY - y0
            for (x in 0 until width) {
                val sourceX = ((x + 0.5) * sourceWidth / width - 0.5).coerceIn(0.0, (sourceWidth - 1).toDouble())
                val x0 = floor(sourceX).toInt()
                val x1 = minOf(x0 + 1, sourceWidth - 1)
                val xWeight = sourceX - x0
                val topLeft = source.getRGB(x0, y0)
                val topRight = source.getRGB(x1, y0)
                val bottomLeft = source.getRGB(x0, y1)
                val bottomRight = source.getRGB(x1, y1)
                val alpha = blend(
                    channel(topLeft, 24),
                    channel(topRight, 24),
                    channel(bottomLeft, 24),
                    channel(bottomRight, 24),
                    xWeight,
                    yWeight,
                ).roundToInt().coerceIn(0, 255)
                val red = blendPremultiplied(topLeft, topRight, bottomLeft, bottomRight, 16, alpha, xWeight, yWeight)
                val green = blendPremultiplied(topLeft, topRight, bottomLeft, bottomRight, 8, alpha, xWeight, yWeight)
                val blue = blendPremultiplied(topLeft, topRight, bottomLeft, bottomRight, 0, alpha, xWeight, yWeight)
                output.setRGB(x, y, (alpha shl 24) or (red shl 16) or (green shl 8) or blue)
            }
        }
        return output
    }

    private fun encode(image: BufferedImage, format: ImageFormat): ByteArray? = runCatching {
        val compatible = if (format == ImageFormat.JPEG) {
            BufferedImage(image.width, image.height, BufferedImage.TYPE_INT_RGB).also { rgb ->
                val graphics = rgb.createGraphics()
                graphics.drawImage(image, 0, 0, null)
                graphics.dispose()
            }
        } else image
        ByteArrayOutputStream().use { output ->
            val writer = ImageIO.getImageWritersByFormatName(format.writerName).asSequence().firstOrNull()
                ?: return@use null
            ImageIO.createImageOutputStream(output).use { imageOutput ->
                writer.output = imageOutput
                writer.write(compatible)
            }
            writer.dispose()
            output.toByteArray().takeIf { hasFormatSignature(it, format) }
        }
    }.getOrNull()

    private fun decorate(bytes: ByteArray, format: ImageFormat, salt: ByteArray, source: ByteArray): ByteArray {
        val marker = MessageDigest.getInstance("SHA-256")
            .digest(salt + MessageDigest.getInstance("SHA-256").digest(source))
            .joinToString("") { byte -> "%02x".format(byte) }
        return when (format) {
            ImageFormat.PNG -> addPngText(bytes, marker)
            ImageFormat.JPEG -> addJpegComment(bytes, marker)
            ImageFormat.WEBP -> addWebpChunk(bytes, marker)
        }
    }

    private fun addPngText(bytes: ByteArray, marker: String): ByteArray {
        val iend = byteArrayOf(
            0, 0, 0, 0, 73, 69, 78, 68, -82, 66, 96, -126,
        ).map { it.toByte() }.toByteArray()
        val index = bytes.indexOfSubsequence(iend)
        if (index < 0) return bytes
        val type = "tEXt".encodeToByteArray()
        val payload = "hardening".encodeToByteArray() + byteArrayOf(0) + marker.encodeToByteArray()
        val crc = CRC32().apply {
            update(type)
            update(payload)
        }.value.toInt()
        val chunk = ByteArrayOutputStream().use { output ->
            output.write(intBytes(payload.size))
            output.write(type)
            output.write(payload)
            output.write(intBytes(crc))
            output.toByteArray()
        }
        return bytes.copyOfRange(0, index) + chunk + bytes.copyOfRange(index, bytes.size)
    }

    private fun addJpegComment(bytes: ByteArray, marker: String): ByteArray {
        if (bytes.size < 2 || bytes[0] != 0xff.toByte() || bytes[1] != 0xd8.toByte()) return bytes
        val payload = marker.encodeToByteArray()
        val segment = byteArrayOf(0xff.toByte(), 0xfe.toByte()) +
            shortBytes(payload.size + 2) + payload
        return bytes.copyOfRange(0, 2) + segment + bytes.copyOfRange(2, bytes.size)
    }

    private fun addWebpChunk(bytes: ByteArray, marker: String): ByteArray {
        if (!hasFormatSignature(bytes, ImageFormat.WEBP) || bytes.size < 12) return bytes
        val payload = marker.encodeToByteArray()
        val chunk = "hard".encodeToByteArray() + intBytesLittleEndian(payload.size) + payload +
            if (payload.size % 2 == 1) byteArrayOf(0) else byteArrayOf()
        val output = bytes + chunk
        val riffSize = output.size - 8
        output[4] = (riffSize and 0xff).toByte()
        output[5] = ((riffSize ushr 8) and 0xff).toByte()
        output[6] = ((riffSize ushr 16) and 0xff).toByte()
        output[7] = ((riffSize ushr 24) and 0xff).toByte()
        return output
    }

    private fun hasFormatSignature(bytes: ByteArray, format: ImageFormat): Boolean = when (format) {
        ImageFormat.PNG -> bytes.size >= 8 && bytes.copyOfRange(0, 8).contentEquals(
            byteArrayOf(137.toByte(), 80, 78, 71, 13, 10, 26, 10),
        )
        ImageFormat.JPEG -> bytes.size >= 3 && bytes[0] == 0xff.toByte() && bytes[1] == 0xd8.toByte() &&
            bytes[2] == 0xff.toByte()
        ImageFormat.WEBP -> bytes.size >= 16 && bytes.copyOfRange(0, 4).contentEquals("RIFF".encodeToByteArray()) &&
            bytes.copyOfRange(8, 12).contentEquals("WEBP".encodeToByteArray())
    }

    private fun intBytes(value: Int): ByteArray = byteArrayOf(
        (value ushr 24).toByte(),
        (value ushr 16).toByte(),
        (value ushr 8).toByte(),
        value.toByte(),
    )

    private fun intBytesLittleEndian(value: Int): ByteArray = byteArrayOf(
        value.toByte(),
        (value ushr 8).toByte(),
        (value ushr 16).toByte(),
        (value ushr 24).toByte(),
    )

    private fun shortBytes(value: Int): ByteArray = byteArrayOf((value ushr 8).toByte(), value.toByte())

    private fun ByteArray.indexOfSubsequence(needle: ByteArray): Int {
        if (needle.isEmpty() || needle.size > size) return -1
        for (index in 0..(size - needle.size)) {
            if (copyOfRange(index, index + needle.size).contentEquals(needle)) return index
        }
        return -1
    }

    private fun blendPremultiplied(a: Int, b: Int, c: Int, d: Int, shift: Int, alpha: Int, xWeight: Double, yWeight: Double): Int {
        val value = blend(
            channel(a, 24) * channel(a, shift),
            channel(b, 24) * channel(b, shift),
            channel(c, 24) * channel(c, shift),
            channel(d, 24) * channel(d, shift),
            xWeight,
            yWeight,
        )
        return if (alpha == 0) 0 else (value.toDouble() / alpha).coerceIn(0.0, 255.0).roundToInt()
    }

    private fun blend(a: Int, b: Int, c: Int, d: Int, xWeight: Double, yWeight: Double): Double {
        val top = a * (1.0 - xWeight) + b * xWeight
        val bottom = c * (1.0 - xWeight) + d * xWeight
        return (top * (1.0 - yWeight) + bottom * yWeight).coerceIn(0.0, Int.MAX_VALUE.toDouble())
    }

    private fun channel(value: Int, shift: Int): Int = (value ushr shift) and 0xff

    private val ImageFormat.writerName: String
        get() = when (this) {
            ImageFormat.PNG -> "png"
            ImageFormat.WEBP -> "webp"
            ImageFormat.JPEG -> "jpeg"
        }
}
