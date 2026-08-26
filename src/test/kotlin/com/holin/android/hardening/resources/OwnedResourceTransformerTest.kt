package com.holin.android.hardening.resources

import java.awt.Color
import java.awt.image.BufferedImage
import java.io.ByteArrayOutputStream
import java.security.MessageDigest
import javax.imageio.ImageIO
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

class OwnedResourceTransformerTest {
    private val lineageSeed = MessageDigest.getInstance("SHA-256").digest("resource-lineage".toByteArray())

    @Test
    fun `renames every frozen non-style file family while preserving untransformed bytes`() {
        val fileEntries = listOf(
            resource(ResourceType.LAYOUT, "home", ".xml"),
            resource(ResourceType.DRAWABLE, "hero", ".xml"),
            resource(ResourceType.MIPMAP, "launcher", ".webp"),
            resource(ResourceType.FONT, "brand", ".ttf"),
            resource(ResourceType.RAW, "seed", ""),
            resource(ResourceType.ANIM, "fade_in", ".xml"),
            resource(ResourceType.ANIMATOR, "pulse", ".xml"),
            resource(ResourceType.XML, "provider_paths", ".xml"),
        )
        val entries = fileEntries + ResourceInventoryEntry(
            module = ":app",
            resourceId = 0x7f030001,
            type = ResourceType.STYLE,
            name = "Theme.Demo",
        )

        val result = OwnedResourceTransformer(lineageSeed, minimumImageCoverage = 1.0)
            .transform(entries, generation = 1, contentSalt = "salt".toByteArray())

        assertTrue(result.report.accepted)
        assertEquals(entries.map { it.type }.toSet(), result.report.renameReport.renames.map { it.type }.toSet())
        assertEquals(fileEntries.size, result.outputEntries.size)
        assertTrue(result.outputEntries.all { it.action == ResourceEntryTransformAction.RENAMED })
        assertTrue(result.outputEntries.all { output -> output.oldSha256 == output.newSha256 })
    }

    @Test
    fun `owned entry report is typed and names stay stable while PNG bytes vary by salt`() {
        val sourcePng = texturedPng(96, 80)
        val inventory = listOf(
            ResourceInventoryEntry(
                module = ":app",
                resourceId = 0x7f010001,
                type = ResourceType.LAYOUT,
                name = "home",
                aabPath = "base/res/layout/home.xml",
                bytes = "<layout/>".toByteArray(),
            ),
            ResourceInventoryEntry(
                module = ":core",
                resourceId = 0x7f020001,
                type = ResourceType.DRAWABLE,
                name = "hero",
                qualifier = "xhdpi",
                aabPath = "base/res/drawable-xhdpi/hero.png",
                bytes = sourcePng,
            ),
            ResourceInventoryEntry(
                module = ":ucrop",
                resourceId = 0x7f030001,
                type = ResourceType.STYLE,
                name = "crop_theme",
            ),
        )
        val transformer = OwnedResourceTransformer(lineageSeed, minimumImageCoverage = 1.0)

        val first = transformer.transform(inventory, generation = 1, contentSalt = "one".toByteArray())
        val second = transformer.transform(inventory, generation = 1, contentSalt = "two".toByteArray())

        assertTrue(first.report.accepted)
        assertEquals(1.0, first.report.imageCoverage)
        assertEquals(3, first.report.renameReport.renames.size)
        assertEquals(
            first.report.renameReport.renames.map { it.resourceId to it.newName },
            second.report.renameReport.renames.map { it.resourceId to it.newName },
        )
        val pngFirst = first.outputEntries.single { it.oldPath.endsWith("hero.png") }
        val pngSecond = second.outputEntries.single { it.oldPath.endsWith("hero.png") }
        assertEquals(ResourceEntryTransformAction.RENAMED_AND_TRANSFORMED, pngFirst.action)
        assertFalse(pngFirst.bytes.contentEquals(sourcePng))
        assertFalse(pngFirst.bytes.contentEquals(pngSecond.bytes))
        assertEquals(ImageTransformStatus.TRANSFORMED, first.report.images.single().status)
        assertEquals(pngFirst.resourceId, first.report.images.single().resourceId)
        assertTrue(pngFirst.oldSha256.matches(Regex("[0-9a-f]{64}")))
        assertTrue(pngFirst.newSha256.matches(Regex("[0-9a-f]{64}")))
        assertFalse(pngFirst.oldSha256 == pngFirst.newSha256)
        assertEquals(ResourceEntryTransformAction.RENAMED, first.outputEntries.single { it.oldPath.endsWith("home.xml") }.action)
    }

    @Test
    fun `unmet image coverage fails closed and emits no candidate entries`() {
        val impossible = ResourceInventoryEntry(
            module = ":compress",
            resourceId = 0x7f020002,
            type = ResourceType.DRAWABLE,
            name = "dot",
            aabPath = "base/res/drawable/dot.png",
            bytes = texturedPng(1, 1),
        )
        val layout = ResourceInventoryEntry(
            module = ":app",
            resourceId = 0x7f010001,
            type = ResourceType.LAYOUT,
            name = "home",
            aabPath = "base/res/layout/home.xml",
            bytes = "<layout/>".toByteArray(),
        )

        val result = OwnedResourceTransformer(lineageSeed, minimumImageCoverage = 1.0)
            .transform(listOf(impossible, layout), generation = 1, contentSalt = "salt".toByteArray())

        assertFalse(result.report.accepted)
        assertEquals(0.0, result.report.imageCoverage)
        assertEquals(1, result.report.imageCandidates)
        assertEquals(0, result.report.transformedImages)
        assertEquals(ImageIneligibilityReason.NO_SAFE_PERTURBATION, result.report.images.single().reason)
        assertTrue(result.outputEntries.isEmpty())
        assertEquals(ResourceTransformFailure.IMAGE_COVERAGE_NOT_MET, result.report.failure)
    }

    @Test
    fun `non-owned generated and externally named entries are excluded from rename allocation`() {
        val bytes = "<layout/>".toByteArray()
        val inventory = listOf(
            ResourceInventoryEntry(
                ":thirdparty",
                1,
                ResourceType.LAYOUT,
                "thirdparty_page",
                "",
                "feature/res/layout/thirdparty_page.xml",
                bytes,
                ResourceOrigin.DEPENDENCY,
            ),
            ResourceInventoryEntry(":app", 2, ResourceType.LAYOUT, "generated_page", aabPath = "base/res/layout/generated_page.xml", bytes = bytes, origin = ResourceOrigin.GENERATED),
            ResourceInventoryEntry(":app", 3, ResourceType.LAYOUT, "public_page", aabPath = "base/res/layout/public_page.xml", bytes = bytes, externallyNamed = true),
        )

        val result = OwnedResourceTransformer(lineageSeed, minimumImageCoverage = 1.0)
            .transform(inventory, generation = 1, contentSalt = "salt".toByteArray())

        assertTrue(result.report.accepted)
        assertTrue(result.report.renameReport.renames.isEmpty())
        assertTrue(result.outputEntries.isEmpty())
        assertEquals(3, result.report.exclusions.size)
        assertEquals(
            setOf(ResourceExclusionReason.DEPENDENCY, ResourceExclusionReason.GENERATED, ResourceExclusionReason.EXTERNALLY_NAMED),
            result.report.exclusions.map(ResourceExclusion::reason).toSet(),
        )
        assertNull(result.report.failure)
    }

    private fun texturedPng(width: Int, height: Int): ByteArray {
        val image = BufferedImage(width, height, BufferedImage.TYPE_INT_ARGB)
        for (y in 0 until height) {
            for (x in 0 until width) {
                val wave = (x * 11 + y * 7 + (x xor y) * 3) % 96
                image.setRGB(x, y, Color(72 + wave, 64 + wave * 3 / 4, 80 + wave / 2, 96 + ((x * 5 + y * 3) % 160)).rgb)
            }
        }
        return ByteArrayOutputStream().use { output ->
            assertTrue(ImageIO.write(image, "png", output))
            output.toByteArray()
        }
    }

    private fun resource(type: ResourceType, name: String, extension: String): ResourceInventoryEntry =
        ResourceInventoryEntry(
            module = ":app",
            resourceId = 0x7f000000 or ((type.ordinal + 1) shl 16) or (type.ordinal + 1),
            type = type,
            name = name,
            aabPath = "base/res/${type.directoryName}/$name$extension",
            bytes = "bytes-$name".toByteArray(),
        )
}
