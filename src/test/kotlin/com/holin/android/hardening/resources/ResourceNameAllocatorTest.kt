package com.holin.android.hardening.resources

import java.security.MessageDigest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

class ResourceNameAllocatorTest {
    private val lineageSeed = MessageDigest.getInstance("SHA-256")
        .digest("resource-name-lineage".toByteArray())

    @Test
    fun `qualifier variants share a stable alias and retain their resource ID`() {
        val entries = listOf(
            resource(
                resourceId = 0x7f010001,
                qualifier = "",
                aabPath = "base/res/layout/home.xml",
            ),
            resource(
                resourceId = 0x7f010001,
                qualifier = "land",
                aabPath = "base/res/layout-land/home.xml",
            ),
        )

        val allocation = ResourceNameAllocator(lineageSeed).reconcile(entries, generation = 1)
        val rename = allocation.report.renames.single()

        assertEquals(0x7f010001, rename.resourceId)
        assertEquals(ResourceType.LAYOUT, rename.type)
        assertEquals("home", rename.oldName)
        assertEquals(setOf("", "land"), rename.qualifiers.toSet())
        assertEquals(
            listOf("base/res/layout-land/${rename.newName}.xml", "base/res/layout/${rename.newName}.xml"),
            rename.entries.map(ResourceEntryRename::newPath).sorted(),
        )
        assertTrue(rename.newName.matches(Regex("sl_layout_[a-z0-9_]+")))
        assertTrue(allocation.state.assignments.single().key.resourceId == rename.resourceId)
    }

    @Test
    fun `allocation is input-order stable and independent of content salt`() {
        val entries = listOf(
            resource(0x7f010001, name = "home", aabPath = "base/res/layout/home.xml"),
            resource(0x7f010002, name = "profile", aabPath = "base/res/layout/profile.xml"),
        )

        val first = ResourceNameAllocator(lineageSeed).reconcile(entries, generation = 1)
        val second = ResourceNameAllocator(lineageSeed).reconcile(entries.reversed(), generation = 1)

        assertEquals(first.report.renames, second.report.renames)
        assertEquals(first.state, second.state)
    }

    @Test
    fun `collisions are probed within a resource type namespace`() {
        val allocator = ResourceNameAllocator(
            lineageSeed = lineageSeed,
            candidateFactory = { key, probe -> "sl_${key.type.directoryName}_${if (probe == 0) "same" else "different"}" },
        )
        val first = resource(0x7f010001, name = "home", aabPath = "base/res/layout/home.xml")
        val second = resource(0x7f010002, name = "profile", aabPath = "base/res/layout/profile.xml")

        val aliases = allocator.reconcile(listOf(first, second), generation = 1)
            .report.renames.map(ResourceRename::newName).toSet()

        assertEquals(setOf("sl_layout_same", "sl_layout_different"), aliases)
    }

    @Test
    fun `removed aliases become tombstones and are not reused after restoration`() {
        val candidates: (ResourceKey, Int) -> String = { key, probe ->
            "sl_${key.type.directoryName}_${if (probe == 0) "first" else "next"}"
        }
        val original = resource(0x7f010001, name = "home", aabPath = "base/res/layout/home.xml")
        val replacement = resource(0x7f010002, name = "profile", aabPath = "base/res/layout/profile.xml")
        val allocator = ResourceNameAllocator(lineageSeed, candidateFactory = candidates)
        val firstAlias = allocator.reconcile(listOf(original), generation = 1).report.renames.single().newName

        val retired = allocator.reconcile(emptyList(), generation = 2).state
        val restored = ResourceNameAllocator.restore(lineageSeed, retired, candidateFactory = candidates)
        val replacementAlias = restored.reconcile(listOf(replacement), generation = 3).report.renames.single().newName

        assertEquals(firstAlias, retired.tombstones.single().alias)
        assertNotEquals(firstAlias, replacementAlias)
    }

    @Test
    fun `qualifier group with conflicting IDs fails closed`() {
        val entries = listOf(
            resource(0x7f010001, qualifier = "", aabPath = "base/res/layout/home.xml"),
            resource(0x7f010002, qualifier = "land", aabPath = "base/res/layout-land/home.xml"),
        )

        assertFailsWith<IllegalArgumentException> {
            ResourceNameAllocator(lineageSeed).reconcile(entries, generation = 1)
        }
    }

    @Test
    fun `style table names support Android uppercase and dotted parent syntax`() {
        val style = ResourceInventoryEntry(
            module = ":app",
            resourceId = 0x7f030001,
            type = ResourceType.STYLE,
            name = "Theme.Demo.Dialog",
        )

        val rename = ResourceNameAllocator(lineageSeed).reconcile(listOf(style), generation = 1)
            .report.renames.single()

        assertEquals("Theme.Demo.Dialog", rename.oldName)
        assertTrue(rename.newName.matches(Regex("sl_style_[a-z0-9_]+")))
        assertTrue(rename.entries.isEmpty())
    }

    private fun resource(
        resourceId: Int,
        name: String = "home",
        qualifier: String = "",
        aabPath: String,
    ) = ResourceInventoryEntry(
        module = ":app",
        resourceId = resourceId,
        type = ResourceType.LAYOUT,
        name = name,
        qualifier = qualifier,
        aabPath = aabPath,
        bytes = "<layout/>".toByteArray(),
    )
}
