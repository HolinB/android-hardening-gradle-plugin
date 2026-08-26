package com.holin.android.hardening.resources

import java.awt.Color
import java.awt.image.BufferedImage
import java.io.ByteArrayOutputStream
import javax.imageio.ImageIO
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

class PngDiversifierTest {
    private val diversifier = PngDiversifier(minimumSsim = 0.995, minimumPHashDistance = 11)

    @Test
    fun `hard metric floors cannot be configured downward`() {
        assertFailsWith<IllegalArgumentException> { PngDiversifier(minimumSsim = 0.9949, minimumPHashDistance = 11) }
        assertFailsWith<IllegalArgumentException> { PngDiversifier(minimumSsim = 0.995, minimumPHashDistance = 10) }
    }

    @Test
    fun `safe PNG changes by salt while preserving dimensions alpha and metric gates`() {
        val source = texturedPng(width = 96, height = 80, withAlpha = true)
        val first = diversifier.diversify(
            entry = drawable("base/res/drawable-xhdpi/hero.png", source),
            contentSalt = "shared-prefix-A".toByteArray(),
        )
        val repeated = diversifier.diversify(
            entry = drawable("base/res/drawable-xhdpi/hero.png", source),
            contentSalt = "shared-prefix-A".toByteArray(),
        )
        val secondSalt = diversifier.diversify(
            entry = drawable("base/res/drawable-xhdpi/hero.png", source),
            contentSalt = "shared-prefix-B".toByteArray(),
        )

        assertEquals(ImageTransformStatus.TRANSFORMED, first.status)
        val transformed = requireNotNull(first.transformedBytes)
        assertContentEquals(transformed, repeated.transformedBytes)
        assertFalse(transformed.contentEquals(source))
        assertFalse(transformed.contentEquals(requireNotNull(secondSalt.transformedBytes)))

        val independentlyMeasured = ImageMetrics.comparePng(source, transformed)
        assertEquals(96, independentlyMeasured.width)
        assertEquals(80, independentlyMeasured.height)
        assertTrue(independentlyMeasured.alphaPreserved)
        assertTrue(independentlyMeasured.ssim >= 0.995, "actual SSIM was ${independentlyMeasured.ssim}")
        assertTrue(independentlyMeasured.pHashDistance >= 11, "actual pHash distance was ${independentlyMeasured.pHashDistance}")
        assertNotEquals(independentlyMeasured.originalSha256, independentlyMeasured.transformedSha256)
        assertEquals(independentlyMeasured, first.metrics)
    }

    @Test
    fun `fully transparent RGB does not reduce perceptual similarity`() {
        val before = transparentRgbPng(red = 0, green = 0, blue = 0)
        val after = transparentRgbPng(red = 231, green = 47, blue = 159)

        val metrics = ImageMetrics.comparePng(before, after)

        assertTrue(metrics.alphaPreserved)
        assertEquals(1.0, metrics.ssim, absoluteTolerance = 1e-12)
        assertNotEquals(metrics.originalSha256, metrics.transformedSha256)
    }

    @Test
    fun `unsupported and policy excluded images never emit bytes`() {
        val png = texturedPng(48, 48, withAlpha = false)
        val cases = listOf(
            drawable("base/res/drawable/panel.9.png", png) to ImageIneligibilityReason.NINE_PATCH,
            drawable("base/res/drawable/panel.webp", byteArrayOf(1, 2, 3)) to ImageIneligibilityReason.WEBP_UNSUPPORTED,
            drawable("base/res/drawable/panel.jpg", byteArrayOf(1, 2, 3)) to ImageIneligibilityReason.UNSUPPORTED_FORMAT,
            drawable("base/res/drawable/panel.png", png).copy(animation = true) to ImageIneligibilityReason.ANIMATION,
            drawable("base/res/drawable/panel.png", png).copy(notificationIcon = true) to ImageIneligibilityReason.NOTIFICATION_ICON,
            drawable("base/res/drawable/panel.png", png).copy(externallyNamed = true) to ImageIneligibilityReason.EXTERNALLY_NAMED,
            drawable("base/res/drawable/panel.png", png).copy(origin = ResourceOrigin.DEPENDENCY) to ImageIneligibilityReason.DEPENDENCY_RESOURCE,
            drawable("base/res/drawable/panel.png", png).copy(origin = ResourceOrigin.GENERATED) to ImageIneligibilityReason.GENERATED_RESOURCE,
        )

        cases.forEach { (entry, expectedReason) ->
            val result = diversifier.diversify(entry, "salt".toByteArray())
            assertEquals(ImageTransformStatus.EXCLUDED, result.status)
            assertEquals(expectedReason, result.reason)
            assertNull(result.transformedBytes)
            assertNull(result.metrics)
        }
    }

    @Test
    fun `unverified or untransformable PNG is ineligible without emitted bytes`() {
        val corrupt = diversifier.diversify(
            drawable("base/res/drawable/corrupt.png", "not-png".toByteArray()),
            "salt".toByteArray(),
        )
        val tooSmall = diversifier.diversify(
            drawable("base/res/drawable/dot.png", texturedPng(1, 1, withAlpha = true)),
            "salt".toByteArray(),
        )

        assertEquals(ImageTransformStatus.INELIGIBLE, corrupt.status)
        assertEquals(ImageIneligibilityReason.UNVERIFIED_PNG, corrupt.reason)
        assertNull(corrupt.transformedBytes)
        assertEquals(ImageTransformStatus.INELIGIBLE, tooSmall.status)
        assertEquals(ImageIneligibilityReason.NO_SAFE_PERTURBATION, tooSmall.reason)
        assertNull(tooSmall.transformedBytes)
    }

    private fun drawable(path: String, bytes: ByteArray) = ResourceInventoryEntry(
        module = ":app",
        resourceId = 0x7f020001,
        type = ResourceType.DRAWABLE,
        name = path.substringAfterLast('/').substringBefore('.'),
        qualifier = "xhdpi",
        aabPath = path,
        bytes = bytes,
    )

    private fun texturedPng(width: Int, height: Int, withAlpha: Boolean): ByteArray {
        val type = if (withAlpha) BufferedImage.TYPE_INT_ARGB else BufferedImage.TYPE_INT_RGB
        val image = BufferedImage(width, height, type)
        for (y in 0 until height) {
            for (x in 0 until width) {
                val wave = ((x * 11 + y * 7 + (x xor y) * 3) % 96)
                val red = 72 + wave
                val green = 64 + (wave * 3 / 4)
                val blue = 80 + (wave / 2)
                val alpha = if (withAlpha) 96 + ((x * 5 + y * 3) % 160) else 255
                image.setRGB(x, y, Color(red, green, blue, alpha).rgb)
            }
        }
        return ByteArrayOutputStream().use { output ->
            assertTrue(ImageIO.write(image, "png", output))
            output.toByteArray()
        }
    }

    private fun transparentRgbPng(red: Int, green: Int, blue: Int): ByteArray {
        val image = BufferedImage(48, 48, BufferedImage.TYPE_INT_ARGB)
        for (y in 0 until image.height) {
            for (x in 0 until image.width) {
                image.setRGB(x, y, Color(red, green, blue, 0).rgb)
            }
        }
        return ByteArrayOutputStream().use { output ->
            assertTrue(ImageIO.write(image, "png", output))
            output.toByteArray()
        }
    }

}
