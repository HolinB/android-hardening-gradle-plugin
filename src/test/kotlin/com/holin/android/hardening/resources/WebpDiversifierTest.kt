package com.holin.android.hardening.resources

import java.awt.Color
import java.awt.image.BufferedImage
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import javax.imageio.IIOImage
import javax.imageio.ImageIO
import javax.imageio.ImageWriteParam
import kotlin.math.cos
import kotlin.math.roundToInt
import kotlin.math.sin
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

class WebpDiversifierTest {
    private val diversifier = WebpDiversifier(
        minimumSsim = 0.995,
        minimumPHashDistance = 11,
        maximumByteGrowthRatio = 0.10,
    )

    @Test
    fun `hard safety gates cannot be configured downward or relaxed`() {
        assertFailsWith<IllegalArgumentException> {
            WebpDiversifier(minimumSsim = 0.9949, minimumPHashDistance = 11)
        }
        assertFailsWith<IllegalArgumentException> {
            WebpDiversifier(minimumSsim = 0.995, minimumPHashDistance = 10)
        }
        assertFailsWith<IllegalArgumentException> {
            WebpDiversifier(maximumByteGrowthRatio = 0.1001)
        }
    }

    @Test
    fun `safe WebP changes by salt while preserving dimensions alpha and metric gates`() {
        val source = texturedWebp(width = 128, height = 96, withAlpha = true)
        val first = diversifier.diversify(
            entry = drawable("base/res/drawable-xhdpi/hero.webp", source),
            contentSalt = "shared-prefix-A".toByteArray(),
        )
        val repeated = diversifier.diversify(
            entry = drawable("base/res/drawable-xhdpi/hero.webp", source),
            contentSalt = "shared-prefix-A".toByteArray(),
        )
        val secondSalt = diversifier.diversify(
            entry = drawable("base/res/drawable-xhdpi/hero.webp", source),
            contentSalt = "shared-prefix-B".toByteArray(),
        )

        assertEquals(ImageTransformStatus.TRANSFORMED, first.status, first.toString())
        assertEquals(ImageTransformStatus.TRANSFORMED, repeated.status, repeated.toString())
        assertEquals(ImageTransformStatus.TRANSFORMED, secondSalt.status, secondSalt.toString())
        val transformed = requireNotNull(first.transformedBytes)
        assertContentEquals(transformed, repeated.transformedBytes)
        assertFalse(transformed.contentEquals(source))
        assertFalse(transformed.contentEquals(requireNotNull(secondSalt.transformedBytes)))

        val independentlyMeasured = WebpImageMetrics.compare(source, transformed)
        assertEquals(128, independentlyMeasured.width)
        assertEquals(96, independentlyMeasured.height)
        assertTrue(independentlyMeasured.alphaPreserved)
        assertTrue(independentlyMeasured.ssim >= 0.995, "actual SSIM was ${independentlyMeasured.ssim}")
        assertTrue(
            independentlyMeasured.pHashDistance >= 11,
            "actual pHash distance was ${independentlyMeasured.pHashDistance}",
        )
        assertTrue(independentlyMeasured.byteGrowthRatio <= 0.10)
        assertNotEquals(independentlyMeasured.originalSha256, independentlyMeasured.transformedSha256)
        assertEquals(independentlyMeasured, first.metrics)
    }

    @Test
    fun `lossy alpha WebP can satisfy growth quality and perceptual gates together`() {
        val source = photoLikeLossyWebp(width = 192, height = 128)
        val result = diversifier.diversify(
            entry = drawable("base/res/drawable-xxhdpi/cover.webp", source),
            contentSalt = "lossy-alpha-salt".toByteArray(),
        )

        assertEquals(ImageTransformStatus.TRANSFORMED, result.status, result.toString())
        val transformed = requireNotNull(result.transformedBytes)
        val metrics = WebpImageMetrics.compare(source, transformed)
        assertEquals(192, metrics.width)
        assertEquals(128, metrics.height)
        assertTrue(metrics.alphaPreserved)
        assertTrue(metrics.ssim >= 0.995, "actual SSIM was ${metrics.ssim}")
        assertTrue(metrics.pHashDistance >= 11, "actual pHash distance was ${metrics.pHashDistance}")
        assertTrue(metrics.byteGrowthRatio <= 0.10, "actual growth was ${metrics.byteGrowthRatio}")
        assertEquals(metrics, result.metrics)
    }

    @Test
    fun `compact transparent icon satisfies all gates without random canvas noise`() {
        val source = compactTransparentIconWebp(width = 120, height = 120)
        val result = diversifier.diversify(
            entry = drawable("base/res/drawable-xxhdpi/compact_icon.webp", source),
            contentSalt = "compact-alpha-icon-salt".toByteArray(),
        )

        assertEquals(ImageTransformStatus.TRANSFORMED, result.status, result.toString())
        val transformed = requireNotNull(result.transformedBytes)
        val metrics = WebpImageMetrics.compare(source, transformed)
        assertTrue(metrics.alphaPreserved)
        assertTrue(metrics.ssim >= 0.995, "actual SSIM was ${metrics.ssim}")
        assertTrue(metrics.pHashDistance >= 11, "actual pHash distance was ${metrics.pHashDistance}")
        assertTrue(transformed.size <= source.size + 4_096, "small-file overhead was ${transformed.size - source.size}")
    }

    @Test
    fun `origin scope and safety excluded WebP files never emit bytes`() {
        val webp = texturedWebp(64, 64, withAlpha = false)
        val cases = listOf(
            drawable("base/res/drawable/panel.webp", webp).copy(webpDiversificationEnabled = false) to
                WebpIneligibilityReason.OUTSIDE_CONFIGURED_WEBP_SCOPE,
            drawable("base/res/drawable/panel.webp", webp).copy(type = ResourceType.LAYOUT) to
                WebpIneligibilityReason.UNSUPPORTED_FORMAT,
            drawable("base/res/drawable/panel.png", webp) to
                WebpIneligibilityReason.UNSUPPORTED_FORMAT,
            drawable("base/res/drawable/panel.webp", webp).copy(animation = true) to
                WebpIneligibilityReason.ANIMATION,
            drawable("base/res/drawable/panel.webp", webp).copy(
                notificationIcon = true,
                webpDiversificationEnabled = false,
            ) to
                WebpIneligibilityReason.NOTIFICATION_ICON,
            drawable("base/res/drawable/panel.webp", webp).copy(externallyNamed = true) to
                WebpIneligibilityReason.EXTERNALLY_NAMED,
            drawable("base/res/drawable/panel.webp", webp).copy(origin = ResourceOrigin.DEPENDENCY) to
                WebpIneligibilityReason.DEPENDENCY_RESOURCE,
            drawable("base/res/drawable/panel.webp", webp).copy(origin = ResourceOrigin.GENERATED) to
                WebpIneligibilityReason.GENERATED_RESOURCE,
            drawable("base/res/drawable/panel.webp", animatedWebpHeader()) to
                WebpIneligibilityReason.ANIMATION,
        )

        cases.forEach { (entry, expectedReason) ->
            val result = diversifier.diversify(entry, "salt".toByteArray())
            assertEquals(ImageTransformStatus.EXCLUDED, result.status, entry.toString())
            assertEquals(expectedReason, result.reason, entry.toString())
            assertNull(result.transformedBytes)
            assertNull(result.metrics)
        }
    }

    @Test
    fun `selector owned WebP is admitted without an app module special case`() {
        val result = diversifier.diversify(
            drawable("base/res/drawable/selector_panel.webp", "not-webp".toByteArray()).copy(":selector"),
            "salt".toByteArray(),
        )

        assertEquals(ImageTransformStatus.INELIGIBLE, result.status)
        assertEquals(WebpIneligibilityReason.UNVERIFIED_WEBP, result.reason)
    }

    @Test
    fun `unverified and untransformable WebP fail closed without emitted bytes`() {
        val corrupt = diversifier.diversify(
            drawable("base/res/drawable/corrupt.webp", "not-webp".toByteArray()),
            "salt".toByteArray(),
        )
        val tooSmall = diversifier.diversify(
            drawable("base/res/drawable/dot.webp", texturedWebp(1, 1, withAlpha = true)),
            "salt".toByteArray(),
        )

        assertEquals(ImageTransformStatus.INELIGIBLE, corrupt.status)
        assertEquals(WebpIneligibilityReason.UNVERIFIED_WEBP, corrupt.reason)
        assertNull(corrupt.transformedBytes)
        assertEquals(ImageTransformStatus.INELIGIBLE, tooSmall.status)
        assertEquals(WebpIneligibilityReason.NO_SAFE_PERTURBATION, tooSmall.reason)
        assertNull(tooSmall.transformedBytes)
    }

    @Test
    fun `byte growth gate fails closed`() {
        val compactSource = solidWebp(width = 96, height = 96)
        val result = WebpDiversifier(maximumByteGrowthRatio = 0.0).diversify(
            drawable("base/res/drawable/solid.webp", compactSource),
            "salt-with-frequency-variation".toByteArray(),
        )

        assertEquals(ImageTransformStatus.INELIGIBLE, result.status, result.toString())
        assertEquals(WebpIneligibilityReason.BYTE_GROWTH_LIMIT, result.reason)
        assertNull(result.transformedBytes)
        assertNull(result.metrics)
        assertTrue(requireNotNull(result.bestRejectedSize) > compactSource.size)
        val rejectedMetrics = requireNotNull(result.bestRejectedMetrics)
        assertTrue(rejectedMetrics.alphaPreserved)
        assertTrue(rejectedMetrics.ssim >= 0.995)
        assertTrue(rejectedMetrics.pHashDistance >= 11)
    }

    @Test
    fun `global AAB budget emits the smallest quality candidate beyond the per image cap`() {
        val compactSource = solidWebp(width = 96, height = 96)
        val entry = drawable("base/res/drawable/solid.webp", compactSource)
        val salt = "salt-with-frequency-variation".toByteArray()
        val perImage = WebpDiversifier(maximumByteGrowthRatio = 0.0).diversify(entry, salt)

        val global = WebpDiversifier(
            maximumByteGrowthRatio = 0.0,
            encodingPolicy = WebpEncodingPolicy.GLOBAL_AAB_BUDGET,
        ).diversify(entry, salt)

        assertEquals(WebpIneligibilityReason.BYTE_GROWTH_LIMIT, perImage.reason)
        assertEquals(ImageTransformStatus.TRANSFORMED, global.status, global.toString())
        val transformed = requireNotNull(global.transformedBytes)
        assertEquals(perImage.bestRejectedSize, transformed.size)
        val metrics = requireNotNull(global.metrics)
        assertTrue(metrics.alphaPreserved)
        assertTrue(metrics.ssim >= 0.995)
        assertTrue(metrics.pHashDistance >= 11)
        assertTrue(metrics.byteGrowthRatio > 0.0)
    }

    @Test
    fun `global AAB budget returns immediately when a quality candidate fits the fast budget`() {
        val source = texturedWebp(width = 128, height = 96, withAlpha = true)
        val entry = drawable("base/res/drawable-xhdpi/hero.webp", source)
        val salt = "shared-prefix-A".toByteArray()
        val acceptedBytes = requireNotNull(diversifier.diversify(entry, salt).transformedBytes)
        var encodingAttempts = 0
        val global = WebpDiversifier(
            minimumSsim = 0.995,
            minimumPHashDistance = 11,
            maximumByteGrowthRatio = 0.10,
            encodingPolicy = WebpEncodingPolicy.GLOBAL_AAB_BUDGET,
            encoder = WebpByteEncoder { _, _, _ ->
                encodingAttempts++
                acceptedBytes
            },
        ).diversify(entry, salt)

        assertEquals(ImageTransformStatus.TRANSFORMED, global.status, global.toString())
        assertEquals(1, encodingAttempts)
    }

    @Test
    fun `encoding policy prefers the source payload and reserves method six for fallback`() {
        val lossyProfiles = WebpEncodingPolicy.forSource(photoLikeLossyWebp(96, 72))
        val losslessProfiles = WebpEncodingPolicy.forSource(texturedWebp(96, 72, withAlpha = true))

        assertEquals("Lossy", lossyProfiles.fast.single().type)
        assertEquals(4, lossyProfiles.fast.single().method)
        assertEquals("Lossy", lossyProfiles.fallback.single().type)
        assertEquals(6, lossyProfiles.fallback.single().method)
        assertEquals("Lossless", losslessProfiles.fast.single().type)
        assertEquals(4, losslessProfiles.fast.single().method)
        assertEquals("Lossless", losslessProfiles.fallback.single().type)
        assertEquals(6, losslessProfiles.fallback.single().method)
    }

    @Test
    fun `failed encodes have a strict bounded candidate budget`() {
        val source = compactTransparentIconWebp(width = 120, height = 120)
        val attempts = mutableListOf<WebpEncodingProfile>()
        val bounded = WebpDiversifier(
            minimumSsim = 0.995,
            minimumPHashDistance = 11,
            maximumByteGrowthRatio = 0.10,
            encoder = WebpByteEncoder { _, profile, _ ->
                attempts += profile
                source
            },
        )

        val result = bounded.diversify(
            entry = drawable("base/res/drawable-xxhdpi/bounded.webp", source),
            contentSalt = "bounded-attempt-salt".toByteArray(),
        )

        assertEquals(ImageTransformStatus.INELIGIBLE, result.status)
        assertTrue(attempts.isNotEmpty())
        assertTrue(attempts.size <= 10, "encoding attempts were ${attempts.size}")
        assertEquals(4, attempts.first().method)
        assertTrue(attempts.count { it.method == 6 } <= attempts.count { it.method == 4 })
    }

    @Test
    fun `large image candidate search streams full size canvases instead of retaining a collection`() {
        val source = compactTransparentIconWebp(width = 1_536, height = 1_536)
        var attempts = 0
        val streaming = WebpDiversifier(
            minimumSsim = 0.995,
            minimumPHashDistance = 11,
            maximumByteGrowthRatio = 0.10,
            encoder = WebpByteEncoder { _, _, _ ->
                attempts++
                source
            },
        )

        val result = streaming.diversify(
            entry = drawable("base/res/drawable-xxhdpi/large_streamed.webp", source),
            contentSalt = "large-streaming-salt".toByteArray(),
        )

        assertEquals(ImageTransformStatus.INELIGIBLE, result.status)
        assertTrue(attempts in 1..10, "encoding attempts were $attempts")
    }

    private fun drawable(path: String, bytes: ByteArray) = ResourceInventoryEntry(
        module = ":app",
        resourceId = 0x7f020001,
        type = ResourceType.DRAWABLE,
        name = path.substringAfterLast('/').substringBefore('.'),
        qualifier = "xhdpi",
        aabPath = path,
        bytes = bytes,
        webpDiversificationEnabled = true,
    )

    private fun texturedWebp(width: Int, height: Int, withAlpha: Boolean): ByteArray {
        val type = if (withAlpha) BufferedImage.TYPE_INT_ARGB else BufferedImage.TYPE_INT_RGB
        val image = BufferedImage(width, height, type)
        for (y in 0 until height) {
            for (x in 0 until width) {
                val noise = coordinateNoise(x, y)
                val red = 48 + (noise and 0x7f)
                val green = 48 + (noise ushr 8 and 0x7f)
                val blue = 48 + (noise ushr 16 and 0x7f)
                val alpha = if (withAlpha) 96 + (noise ushr 24 and 0x9f) else 255
                image.setRGB(x, y, Color(red, green, blue, alpha).rgb)
            }
        }
        return encodeWebp(image, compressionType = "Lossless", compressionQuality = 0.0f)
    }

    private fun coordinateNoise(x: Int, y: Int): Int {
        var value = x * 0x45d9f3b xor y * 0x119de1f3 xor x * y * 0x27d4eb2d
        value = (value xor (value ushr 16)) * 0x45d9f3b
        return value xor (value ushr 16)
    }

    private fun solidWebp(width: Int, height: Int): ByteArray {
        val image = BufferedImage(width, height, BufferedImage.TYPE_INT_RGB)
        for (y in 0 until height) {
            for (x in 0 until width) image.setRGB(x, y, Color(96, 104, 112).rgb)
        }
        return encodeWebp(image, compressionType = "Lossless", compressionQuality = 1.0f)
    }

    private fun photoLikeLossyWebp(width: Int, height: Int): ByteArray {
        val image = BufferedImage(width, height, BufferedImage.TYPE_INT_ARGB)
        for (y in 0 until height) {
            for (x in 0 until width) {
                val wave = (sin(x / 8.0) * 18.0 + cos(y / 11.0) * 15.0 + sin((x + y) / 17.0) * 9.0)
                    .roundToInt()
                val red = (118 + wave + x * 34 / width).coerceIn(0, 255)
                val green = (104 + wave / 2 + y * 42 / height).coerceIn(0, 255)
                val blue = (132 - wave / 3 + (x + y) * 22 / (width + height)).coerceIn(0, 255)
                val alpha = 80 + coordinateNoise(x, y).ushr(24).and(0xaf)
                image.setRGB(x, y, Color(red, green, blue, alpha).rgb)
            }
        }
        return encodeWebp(image, compressionType = "Lossy", compressionQuality = 0.92f)
    }

    private fun compactTransparentIconWebp(width: Int, height: Int): ByteArray {
        val image = BufferedImage(width, height, BufferedImage.TYPE_INT_ARGB)
        val centerX = width / 2.0
        val centerY = height / 2.0
        val outerRadius = minOf(width, height) * 0.34
        val innerRadius = outerRadius * 0.52
        for (y in 0 until height) {
            for (x in 0 until width) {
                val distance = kotlin.math.hypot(x + 0.5 - centerX, y + 0.5 - centerY)
                val color = when {
                    distance <= innerRadius -> Color(246, 248, 252, 255)
                    distance <= outerRadius -> Color(74, 118, 246, 255)
                    else -> Color(0, 0, 0, 0)
                }
                image.setRGB(x, y, color.rgb)
            }
        }
        return encodeWebp(image, compressionType = "Lossy", compressionQuality = 0.90f)
    }

    private fun encodeWebp(
        image: BufferedImage,
        compressionType: String,
        compressionQuality: Float,
    ): ByteArray {
        val writers = ImageIO.getImageWritersByMIMEType("image/webp")
        assertTrue(writers.hasNext(), "webp-imageio writer SPI was not registered")
        val writer = writers.next()
        return try {
            val output = ByteArrayOutputStream()
            ImageIO.createImageOutputStream(output).use { imageOutput ->
                writer.output = imageOutput
                val parameters = writer.defaultWriteParam
                parameters.compressionMode = ImageWriteParam.MODE_EXPLICIT
                parameters.compressionType = requireNotNull(parameters.compressionTypes)
                    .first { it.equals(compressionType, ignoreCase = true) }
                parameters.compressionQuality = compressionQuality
                writer.write(null, IIOImage(image, null, null), parameters)
            }
            val encoded = output.toByteArray()
            assertTrue(encoded.size > 12)
            val decoded = ImageIO.read(ByteArrayInputStream(encoded))
            assertEquals(image.width, decoded.width)
            assertEquals(image.height, decoded.height)
            encoded
        } finally {
            writer.dispose()
        }
    }

    private fun animatedWebpHeader(): ByteArray {
        val bytes = ByteArray(30)
        "RIFF".toByteArray().copyInto(bytes, 0)
        writeLittleEndianInt(bytes, 4, bytes.size - 8)
        "WEBP".toByteArray().copyInto(bytes, 8)
        "VP8X".toByteArray().copyInto(bytes, 12)
        writeLittleEndianInt(bytes, 16, 10)
        bytes[20] = 0x02
        return bytes
    }

    private fun writeLittleEndianInt(bytes: ByteArray, offset: Int, value: Int) {
        repeat(4) { index -> bytes[offset + index] = (value ushr (index * 8)).toByte() }
    }
}
