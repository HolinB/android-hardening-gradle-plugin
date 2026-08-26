package com.holin.android.hardening.resources

import com.holin.android.hardening.naming.AliasRequest
import com.holin.android.hardening.naming.PseudowordRegistry
import com.holin.android.hardening.naming.RegistryKey
import com.holin.android.hardening.naming.SymbolKind
import java.security.MessageDigest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class ResourcePseudowordAllocatorTest {
    private val seed = MessageDigest.getInstance("SHA-256").digest("resource-pseudowords".toByteArray())

    @Test
    fun `uses namespace type and original name while retaining current resource id only in the report`() {
        val first = resource(0x7f010001)
        val registry = PseudowordRegistry(seed)
        val initial = ResourcePseudowordAllocator("com.example", registry).allocate(listOf(first), 1)
        val changedId = ResourcePseudowordAllocator(
            "com.example",
            PseudowordRegistry.restore(seed, initial.registry),
        ).allocate(listOf(resource(0x7f010099)), 2)

        assertEquals(initial.report.renames.single().newName, changedId.report.renames.single().newName)
        assertEquals(0x7f010099, changedId.report.renames.single().resourceId)
        assertTrue(changedId.report.renames.single().newName.matches(Regex("sl_layout_[a-z]+_[a-z]+_[a-z]+")))
    }

    @Test
    fun `resource-only reconciliation retains non-resource registry assignments`() {
        val registry = PseudowordRegistry(seed)
        val classKey = RegistryKey("com.example.Type", SymbolKind.CLASS, "Lcom/example/Type;")
        registry.reconcile(listOf(AliasRequest(classKey, "classes")), 1)

        val allocated = ResourcePseudowordAllocator("com.example", registry).allocate(listOf(resource(1)), 2)

        assertTrue(allocated.registry.assignments.any { it.key == classKey })
    }

    @Test
    fun `notification qualifiers reuse one stable physical pseudoword without a logical rename`() {
        val variants = listOf(
            notification("", "base/res/drawable/icon_notification.png"),
            notification("land", "base/res/drawable-land/icon_notification.png"),
        )

        val first = ResourcePseudowordAllocator("com.example", PseudowordRegistry(seed)).allocate(variants, 1)
        val second = ResourcePseudowordAllocator(
            "com.example",
            PseudowordRegistry.restore(seed, first.registry),
        ).allocate(variants, 2)
        val rename = first.report.renames.single()

        assertEquals("icon_notification", rename.oldName)
        assertEquals("icon_notification", rename.newName)
        assertEquals(2, rename.entries.size)
        assertEquals(1, rename.entries.map { it.newPath.substringAfterLast('/').substringBefore('.') }.distinct().size)
        assertTrue(rename.entries.all { it.newPath.substringAfterLast('/').startsWith("sl_drawable_") })
        assertEquals(rename.entries.map { it.newPath }, second.report.renames.single().entries.map { it.newPath })
    }

    @Test
    fun `adding the notification physical assignment retains existing logical resource assignments`() {
        val registry = PseudowordRegistry(seed)
        val before = ResourcePseudowordAllocator("com.example", registry).allocate(listOf(resource(1)), 1)
        val homeKey = before.registry.assignments.single { it.key.originalIdentity.endsWith("/layout/home") }.key

        val after = ResourcePseudowordAllocator(
            "com.example",
            PseudowordRegistry.restore(seed, before.registry),
        ).allocate(
            listOf(
                resource(1),
                notification("", "base/res/drawable/icon_notification.png"),
            ),
            2,
        )

        assertEquals(
            before.registry.assignments.single { it.key == homeKey }.alias,
            after.registry.assignments.single { it.key == homeKey }.alias,
        )
        assertEquals(2, after.registry.assignments.count { it.key.kind == SymbolKind.RESOURCE })
    }

    @Test
    fun `extensionless raw resource keeps its physical representation while renaming`() {
        val raw = ResourceInventoryEntry(
            module = ":app",
            resourceId = 0x7f060001,
            type = ResourceType.RAW,
            name = "seed",
            aabPath = "base/res/raw/seed",
            bytes = byteArrayOf(1),
        )

        val rename = ResourcePseudowordAllocator("com.example", PseudowordRegistry(seed))
            .allocate(listOf(raw), 1)
            .report.renames.single()

        assertTrue(rename.newName.startsWith("sl_raw_"))
        assertEquals("base/res/raw/${rename.newName}", rename.entries.single().newPath)
    }

    private fun resource(id: Int) = ResourceInventoryEntry(
        module = ":app",
        resourceId = id,
        type = ResourceType.LAYOUT,
        name = "home",
        qualifier = "",
        aabPath = "base/res/layout/home.xml",
        bytes = byteArrayOf(1),
    )

    private fun notification(qualifier: String, path: String) = ResourceInventoryEntry(
        module = ":app",
        resourceId = 0x7f020007,
        type = ResourceType.DRAWABLE,
        name = "icon_notification",
        qualifier = qualifier,
        aabPath = path,
        bytes = byteArrayOf(7),
        notificationIcon = true,
    )
}
