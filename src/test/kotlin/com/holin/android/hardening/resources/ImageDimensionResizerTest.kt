package com.holin.android.hardening.resources

import com.holin.android.hardening.ImageFormat
import java.awt.Color
import java.awt.image.BufferedImage
import java.io.ByteArrayOutputStream
import javax.imageio.IIOImage
import javax.imageio.ImageIO
import javax.imageio.ImageWriteParam
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

class ImageDimensionResizerTest {
    private val resizer = ImageDimensionResizer()

    @Test
    fun `grows short side by one and rounds long side half up`() {
        val result = resizer.resize(encode("png", 3, 5), ImageFormat.PNG)

        assertEquals(ImageTransformStatus.TRANSFORMED, result.status)
        assertEquals(3, result.originalWidth)
        assertEquals(5, result.originalHeight)
        assertEquals(4, result.newWidth)
        assertEquals(7, result.newHeight)
        assertTrue(result.dimensionChanged)
        assertFalse(result.fallback)
        val decoded = ImageIO.read(result.transformedBytes!!.inputStream())
        assertEquals(4, decoded.width)
        assertEquals(7, decoded.height)
    }

    @Test
    fun `resizes square and preserves premultiplied transparent edge`() {
        val source = BufferedImage(2, 2, BufferedImage.TYPE_INT_ARGB)
        source.setRGB(0, 0, Color(255, 0, 0, 0).rgb)
        source.setRGB(1, 0, Color(255, 0, 0, 255).rgb)
        source.setRGB(0, 1, Color(255, 0, 0, 255).rgb)
        source.setRGB(1, 1, Color(255, 0, 0, 255).rgb)

        val result = resizer.resize(encode(source, "png"), ImageFormat.PNG)
        val decoded = ImageIO.read(result.transformedBytes!!.inputStream())
        assertEquals(3, decoded.width)
        assertEquals(3, decoded.height)
        val mixed = Color(decoded.getRGB(1, 0), true)
        assertTrue(mixed.alpha in 100..230)
        assertTrue(mixed.red >= mixed.green)
    }

    @Test
    fun `preserves jpeg encoding and falls back for invalid bytes`() {
        val jpeg = resizer.resize(encode("jpeg", 4, 2), ImageFormat.JPEG)
        assertEquals(ImageTransformStatus.TRANSFORMED, jpeg.status)
        assertEquals(6, jpeg.newWidth)
        assertEquals(3, jpeg.newHeight)
        assertTrue(jpeg.transformedBytes!!.startsWithJpegSignature())

        val invalid = resizer.resize(byteArrayOf(1, 2, 3), ImageFormat.PNG)
        assertEquals(ImageTransformStatus.INELIGIBLE, invalid.status)
        assertTrue(invalid.fallback)
        assertEquals(ImageDimensionFallbackReason.DECODE_FAILED, invalid.fallbackReason)
        assertNull(invalid.transformedBytes)
        assertFalse(invalid.dimensionChanged)
    }

    @Test
    fun `rejects a payload whose declared format does not match`() {
        val png = encode("png", 2, 2)
        val result = resizer.resize(png, ImageFormat.JPEG)

        assertEquals(ImageTransformStatus.INELIGIBLE, result.status)
        assertEquals(ImageDimensionFallbackReason.DECODE_FAILED, result.fallbackReason)
        assertTrue(result.fallback)
    }

    @Test
    fun `fixed seed is deterministic while an unseeded invocation gets a different marker`() {
        val source = encode("png", 3, 3)
        val first = ImageDimensionResizer("stable".encodeToByteArray()).resize(source, ImageFormat.PNG)
        val second = ImageDimensionResizer("stable".encodeToByteArray()).resize(source, ImageFormat.PNG)
        val randomFirst = resizer.resize(source, ImageFormat.PNG)
        val randomSecond = resizer.resize(source, ImageFormat.PNG)

        assertTrue(first.transformedBytes!!.contentEquals(second.transformedBytes!!))
        assertFalse(randomFirst.transformedBytes!!.contentEquals(randomSecond.transformedBytes!!))
    }

    @Test
    fun `preserves webp encoding and decoder dimensions`() {
        val source = BufferedImage(5, 3, BufferedImage.TYPE_INT_ARGB)
        val webp = encodeWebp(source)
        val result = resizer.resize(webp, ImageFormat.WEBP, "webp-salt".encodeToByteArray())

        assertEquals(ImageTransformStatus.TRANSFORMED, result.status)
        assertEquals(7, result.newWidth)
        assertEquals(4, result.newHeight)
        val decoded = ImageIO.read(result.transformedBytes!!.inputStream())
        assertEquals(7, decoded.width)
        assertEquals(4, decoded.height)
    }

    private fun encode(format: String, width: Int, height: Int): ByteArray =
        encode(BufferedImage(width, height, BufferedImage.TYPE_INT_RGB), format)

    private fun encode(image: BufferedImage, format: String): ByteArray = ByteArrayOutputStream().use { output ->
        check(ImageIO.write(image, format, output))
        output.toByteArray()
    }

    private fun ByteArray.startsWithJpegSignature(): Boolean =
        size >= 3 && this[0] == 0xff.toByte() && this[1] == 0xd8.toByte() && this[2] == 0xff.toByte()

    private fun encodeWebp(image: BufferedImage): ByteArray = ByteArrayOutputStream().use { output ->
        val writers = ImageIO.getImageWritersByMIMEType("image/webp")
        check(writers.hasNext())
        val writer = writers.next()
        try {
            ImageIO.createImageOutputStream(output).use { imageOutput ->
                writer.output = imageOutput
                val params = writer.defaultWriteParam
                params.compressionMode = ImageWriteParam.MODE_EXPLICIT
                params.compressionType = params.compressionTypes.first()
                params.compressionQuality = 1.0f
                writer.write(null, IIOImage(image, null, null), params)
            }
        } finally {
            writer.dispose()
        }
        output.toByteArray()
    }
}
