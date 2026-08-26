package com.holin.android.hardening.resources

import com.android.aapt.ConfigurationOuterClass.Configuration
import com.android.aapt.Resources
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class ResourceTableTransformerTest {
    @Test
    fun `rewrites table names and physical paths for every frozen file family`() {
        val families = listOf(
            Triple(ResourceType.LAYOUT, "home", ".xml"),
            Triple(ResourceType.DRAWABLE, "hero", ".png"),
            Triple(ResourceType.MIPMAP, "launcher", ".webp"),
            Triple(ResourceType.FONT, "brand", ".ttf"),
            Triple(ResourceType.RAW, "seed", ".bin"),
            Triple(ResourceType.ANIM, "fade_in", ".xml"),
            Triple(ResourceType.ANIMATOR, "pulse", ".xml"),
            Triple(ResourceType.XML, "network_security_config", ".xml"),
        )
        val original = table(*families.mapIndexed { index, (resourceType, name, extension) ->
            type(index + 1, resourceType.directoryName, entry(index + 10, name, fileValue("res/${resourceType.directoryName}/$name$extension")))
        }.toTypedArray())
        val requests = families.mapIndexed { index, (resourceType, name, extension) ->
            val replacement = "sl_${resourceType.directoryName}_cedar_river"
            rename(
                resourceId = (0x7f shl 24) or ((index + 1) shl 16) or (index + 10),
                type = resourceType,
                oldName = name,
                newName = replacement,
                entries = listOf(
                    ResourceEntryRename(
                        qualifier = "",
                        oldPath = "base/res/${resourceType.directoryName}/$name$extension",
                        newPath = "base/res/${resourceType.directoryName}/$replacement$extension",
                    ),
                ),
            )
        }

        val result = ResourceTableTransformer().transform(
            original.toByteArray(),
            ResourceRenameReport(renames = requests),
        )
        val rewritten = Resources.ResourceTable.parseFrom(result.resourcesPb)

        assertEquals(requests.map { it.newName }, rewritten.getPackage(0).typeList.map { it.getEntry(0).name })
        assertEquals(
            requests.map { it.entries.single().newPath }.toSet(),
            result.zipPathRenames.values.toSet(),
        )
        assertEquals(families.size, result.report.renames.size)
    }

    @Test
    fun `rewrites notification icon physical paths without changing its logical resource contract`() {
        val landscape = Configuration.newBuilder()
            .setOrientation(Configuration.Orientation.ORIENTATION_LAND)
            .build()
        val original = table(
            type(
                id = 2,
                name = "drawable",
                entry(
                    id = 7,
                    name = "icon_notification",
                    fileValue("res/drawable/icon_notification.png"),
                    fileValue("res/drawable-land/icon_notification.png", landscape),
                ),
            ),
        )
        val request = rename(
            resourceId = 0x7f020007,
            type = ResourceType.DRAWABLE,
            oldName = "icon_notification",
            newName = "icon_notification",
            qualifiers = listOf("", "land"),
            entries = listOf(
                ResourceEntryRename(
                    "",
                    "base/res/drawable/icon_notification.png",
                    "base/res/drawable/sl_drawable_cedar_river_pearl.png",
                ),
                ResourceEntryRename(
                    "land",
                    "base/res/drawable-land/icon_notification.png",
                    "base/res/drawable-land/sl_drawable_cedar_river_pearl.png",
                ),
            ),
        )

        val result = ResourceTableTransformer().transform(
            original.toByteArray(),
            ResourceRenameReport(renames = listOf(request)),
        )
        val rewritten = Resources.ResourceTable.parseFrom(result.resourcesPb)
        val originalEntry = original.getPackage(0).getType(0).getEntry(0)
        val rewrittenEntry = rewritten.getPackage(0).getType(0).getEntry(0)

        assertEquals(0x7f, rewritten.getPackage(0).packageId.id)
        assertEquals(2, rewritten.getPackage(0).getType(0).typeId.id)
        assertEquals(7, rewrittenEntry.entryId.id)
        assertEquals("icon_notification", rewrittenEntry.name)
        assertEquals(
            originalEntry.configValueList.map { it.config },
            rewrittenEntry.configValueList.map { it.config },
        )
        assertEquals(
            listOf(
                "res/drawable/sl_drawable_cedar_river_pearl.png",
                "res/drawable-land/sl_drawable_cedar_river_pearl.png",
            ),
            rewrittenEntry.configValueList.map { it.value.item.file.path },
        )
        assertEquals(2, result.zipPathRenames.size)
        assertTrue(result.logicalZipPathRenames.isEmpty())
        assertTrue(result.report.renames.isEmpty(), "path-only rewrites are not logical entry renames")
    }

    @Test
    fun `notification path-only rewrites fail closed outside their exact contract`() {
        val original = table(
            type(
                2,
                "drawable",
                entry(
                    7,
                    "icon_notification",
                    fileValue("res/drawable/icon_notification.png"),
                    fileValue("res/drawable-land/icon_notification.png", Configuration.newBuilder().setOrientationValue(2).build()),
                ),
                entry(8, "occupied", fileValue("res/drawable/occupied.png")),
            ),
        )
        val valid = rename(
            resourceId = 0x7f020007,
            type = ResourceType.DRAWABLE,
            oldName = "icon_notification",
            newName = "icon_notification",
            qualifiers = listOf("", "land"),
            entries = listOf(
                ResourceEntryRename("", "base/res/drawable/icon_notification.png", "base/res/drawable/sl_drawable_cedar_river_pearl.png"),
                ResourceEntryRename("land", "base/res/drawable-land/icon_notification.png", "base/res/drawable-land/sl_drawable_cedar_river_pearl.png"),
            ),
        )
        val invalidRequests = listOf(
            valid.copy(resourceId = 0x7f020009),
            valid.copy(type = ResourceType.LAYOUT),
            valid.copy(oldName = "other", newName = "other"),
            valid.copy(newName = "renamed_notification"),
            valid.copy(qualifiers = listOf(""), entries = valid.entries.take(1)),
            valid.copy(qualifiers = listOf("", "")),
            valid.copy(entries = valid.entries + valid.entries.first()),
            valid.copy(entries = valid.entries.mapIndexed { index, entry ->
                if (index == 0) entry.copy(newPath = "base/res/drawable/sl_drawable_cedar_river_pearl.webp") else entry
            }),
            valid.copy(entries = valid.entries.mapIndexed { index, entry ->
                if (index == 0) entry.copy(newPath = "base/res/drawable-land/sl_drawable_cedar_river_pearl.png") else entry
            }),
            valid.copy(entries = valid.entries.mapIndexed { index, entry ->
                if (index == 0) entry.copy(newPath = "feature/res/drawable/sl_drawable_cedar_river_pearl.png") else entry
            }),
            valid.copy(entries = valid.entries.mapIndexed { index, entry ->
                if (index == 0) entry.copy(newPath = "base/res/drawable/occupied.png") else entry
            }),
            valid.copy(entries = valid.entries.mapIndexed { index, entry ->
                if (index == 0) entry.copy(oldPath = "base/res/drawable/missing.png") else entry
            }),
            valid.copy(entries = valid.entries.mapIndexed { index, entry ->
                if (index == 1) entry.copy(newPath = "base/res/drawable-land/sl_drawable_other_name.png") else entry
            }),
        )

        invalidRequests.forEach { invalid ->
            assertFailsWith<IllegalArgumentException>(invalid.toString()) {
                ResourceTableTransformer().transform(
                    original.toByteArray(),
                    ResourceRenameReport(renames = listOf(invalid)),
                )
            }
        }

        val shared = table(
            type(
                2,
                "drawable",
                entry(7, "icon_notification", fileValue("res/drawable/icon_notification.png")),
                entry(8, "other", fileValue("res/drawable/icon_notification.png")),
            ),
        )
        assertFailsWith<IllegalArgumentException> {
            ResourceTableTransformer().transform(
                shared.toByteArray(),
                ResourceRenameReport(renames = listOf(valid.copy(qualifiers = listOf(""), entries = valid.entries.take(1)))),
            )
        }

        val duplicateReference = table(
            type(
                2,
                "drawable",
                entry(
                    7,
                    "icon_notification",
                    fileValue("res/drawable/icon_notification.png"),
                    fileValue("res/drawable/icon_notification.png"),
                ),
            ),
        )
        assertFailsWith<IllegalArgumentException> {
            ResourceTableTransformer().transform(
                duplicateReference.toByteArray(),
                ResourceRenameReport(renames = listOf(valid.copy(qualifiers = listOf(""), entries = valid.entries.take(1)))),
            )
        }
    }

    @Test
    fun `notification path mappings reject duplicate qualifier values with unique paths`() {
        val original = table(
            type(
                2,
                "drawable",
                entry(
                    7,
                    "icon_notification",
                    fileValue("res/drawable/icon_notification.png"),
                    fileValue("res/drawable/icon_notification.webp"),
                ),
            ),
        )
        val duplicateQualifierMappings = rename(
            resourceId = 0x7f020007,
            type = ResourceType.DRAWABLE,
            oldName = "icon_notification",
            newName = "icon_notification",
            qualifiers = listOf(""),
            entries = listOf(
                ResourceEntryRename(
                    "",
                    "base/res/drawable/icon_notification.png",
                    "base/res/drawable/sl_drawable_cedar_river_pearl.png",
                ),
                ResourceEntryRename(
                    "",
                    "base/res/drawable/icon_notification.webp",
                    "base/res/drawable/sl_drawable_cedar_river_pearl.webp",
                ),
            ),
        )

        val failure = assertFailsWith<IllegalArgumentException> {
            ResourceTableTransformer().transform(
                original.toByteArray(),
                ResourceRenameReport(renames = listOf(duplicateQualifierMappings)),
            )
        }

        assertTrue(failure.message.orEmpty().contains("duplicate qualifier"))
    }

    @Test
    fun `renames an explicit layout entry and every file reference without changing IDs or unrelated entries`() {
        val original = table(
            type(
                id = 1,
                name = "layout",
                entry(
                    id = 1,
                    name = "home",
                    fileValue("res/layout/home.xml"),
                    fileValue("res/layout-land/home.xml", Configuration.newBuilder().setOrientationValue(2).build()),
                ),
                entry(id = 2, name = "untouched", fileValue("res/layout/untouched.xml")),
            ),
        )
        val rename = rename(
            resourceId = 0x7f010001,
            type = ResourceType.LAYOUT,
            oldName = "home",
            newName = "sl_layout_cedar",
            qualifiers = listOf("", "land"),
            entries = listOf(
                ResourceEntryRename("", "base/res/layout/home.xml", "base/res/layout/sl_layout_cedar.xml"),
                ResourceEntryRename("land", "base/res/layout-land/home.xml", "base/res/layout-land/sl_layout_cedar.xml"),
            ),
        )

        val result = ResourceTableTransformer().transform(
            original.toByteArray(),
            ResourceRenameReport(renames = listOf(rename)),
        )
        val rewritten = Resources.ResourceTable.parseFrom(result.resourcesPb)
        val rewrittenType = rewritten.getPackage(0).getType(0)
        val rewrittenHome = rewrittenType.getEntry(0)

        assertEquals(0x7f, rewritten.getPackage(0).packageId.id)
        assertEquals(1, rewrittenType.typeId.id)
        assertEquals(1, rewrittenHome.entryId.id)
        assertEquals("sl_layout_cedar", rewrittenHome.name)
        assertEquals(
            listOf("res/layout/sl_layout_cedar.xml", "res/layout-land/sl_layout_cedar.xml"),
            rewrittenHome.configValueList.map { it.value.item.file.path },
        )
        assertEquals(original.getPackage(0).getType(0).getEntry(1), rewrittenType.getEntry(1))
        assertEquals(
            mapOf(
                "base/res/layout/home.xml" to "base/res/layout/sl_layout_cedar.xml",
                "base/res/layout-land/home.xml" to "base/res/layout-land/sl_layout_cedar.xml",
            ),
            result.zipPathRenames,
        )
        assertEquals(0x7f010001, result.report.renames.single().resourceId)
        assertEquals(2, result.report.renames.single().fileReferencesChanged)
    }

    @Test
    fun `style rename changes only the entry name and preserves every value byte for byte`() {
        val styleValue = Resources.Value.newBuilder()
            .setComment("semantic style bag marker")
            .setCompoundValue(
                Resources.CompoundValue.newBuilder().setStyle(
                    Resources.Style.newBuilder().setParent(
                        Resources.Reference.newBuilder().setName("style/Parent"),
                    ),
                ),
            )
            .build()
        val original = table(type(3, "style", entry(7, "Theme.Demo", configValue(styleValue))))
        val rename = rename(
            resourceId = 0x7f030007,
            type = ResourceType.STYLE,
            oldName = "Theme.Demo",
            newName = "sl_style_meadow",
            qualifiers = listOf(""),
        )

        val result = ResourceTableTransformer().transform(
            original.toByteArray(),
            ResourceRenameReport(renames = listOf(rename)),
        )
        val rewritten = Resources.ResourceTable.parseFrom(result.resourcesPb)
        val rewrittenEntry = rewritten.getPackage(0).getType(0).getEntry(0)

        assertEquals("sl_style_meadow", rewrittenEntry.name)
        assertEquals(original.getPackage(0).getType(0).getEntry(0).configValueList, rewrittenEntry.configValueList)
        assertTrue(result.zipPathRenames.isEmpty())
        assertEquals(0, result.report.renames.single().fileReferencesChanged)
    }

    @Test
    fun `style qualifiers must exactly match their protobuf configurations`() {
        val landscape = Configuration.newBuilder()
            .setOrientation(Configuration.Orientation.ORIENTATION_LAND)
            .build()
        val original = table(
            type(3, "style", entry(7, "Theme.Demo", configValue(Resources.Value.getDefaultInstance(), landscape))),
        )
        val wrongQualifier = rename(
            resourceId = 0x7f030007,
            type = ResourceType.STYLE,
            oldName = "Theme.Demo",
            newName = "sl_style_meadow",
            qualifiers = listOf("port"),
        )

        val failure = assertFailsWith<IllegalArgumentException> {
            ResourceTableTransformer().transform(
                original.toByteArray(),
                ResourceRenameReport(renames = listOf(wrongQualifier)),
            )
        }

        assertTrue(failure.message.orEmpty().contains("qualifier"))
        assertTrue(failure.message.orEmpty().contains("resources.pb"))
    }

    @Test
    fun `serialization is deterministic for the same table and request`() {
        val original = table(type(2, "drawable", entry(1, "hero", fileValue("res/drawable/hero.png"))))
        val request = ResourceRenameReport(
            renames = listOf(
                rename(
                    resourceId = 0x7f020001,
                    type = ResourceType.DRAWABLE,
                    oldName = "hero",
                    newName = "sl_drawable_harbor",
                    entries = listOf(
                        ResourceEntryRename("", "base/res/drawable/hero.png", "base/res/drawable/sl_drawable_harbor.png"),
                    ),
                ),
            ),
        )

        val first = ResourceTableTransformer().transform(original.toByteArray(), request)
        val second = ResourceTableTransformer().transform(original.toByteArray(), request)

        assertContentEquals(first.resourcesPb, second.resourcesPb)
        assertEquals(first.zipPathRenames, second.zipPathRenames)
        assertEquals(first.report, second.report)
    }

    @Test
    fun `missing resource ID fails closed`() {
        val original = table(type(1, "layout", entry(1, "home", fileValue("res/layout/home.xml"))))
        val missing = rename(
            resourceId = 0x7f010009,
            type = ResourceType.LAYOUT,
            oldName = "home",
            newName = "sl_layout_cedar",
            entries = listOf(ResourceEntryRename("", "base/res/layout/home.xml", "base/res/layout/sl_layout_cedar.xml")),
        )

        val failure = assertFailsWith<IllegalArgumentException> {
            ResourceTableTransformer().transform(original.toByteArray(), ResourceRenameReport(renames = listOf(missing)))
        }

        assertTrue(failure.message.orEmpty().contains("0x7f010009"))
        assertTrue(failure.message.orEmpty().contains("not found"))
    }

    @Test
    fun `entry name and type mismatches fail closed`() {
        val original = table(type(1, "layout", entry(1, "home", fileValue("res/layout/home.xml"))))
        val wrongName = rename(
            resourceId = 0x7f010001,
            type = ResourceType.LAYOUT,
            oldName = "profile",
            newName = "sl_layout_cedar",
            entries = listOf(ResourceEntryRename("", "base/res/layout/profile.xml", "base/res/layout/sl_layout_cedar.xml")),
        )
        val wrongType = wrongName.copy(type = ResourceType.DRAWABLE, oldName = "home")

        assertFailsWith<IllegalArgumentException> {
            ResourceTableTransformer().transform(original.toByteArray(), ResourceRenameReport(renames = listOf(wrongName)))
        }
        assertFailsWith<IllegalArgumentException> {
            ResourceTableTransformer().transform(original.toByteArray(), ResourceRenameReport(renames = listOf(wrongType)))
        }
    }

    @Test
    fun `entry-name and file-path collisions fail closed before rewriting`() {
        val original = table(
            type(
                1,
                "layout",
                entry(1, "home", fileValue("res/layout/home.xml")),
                entry(2, "sl_layout_cedar", fileValue("res/layout/existing.xml")),
            ),
        )
        val nameCollision = rename(
            resourceId = 0x7f010001,
            type = ResourceType.LAYOUT,
            oldName = "home",
            newName = "sl_layout_cedar",
            entries = listOf(ResourceEntryRename("", "base/res/layout/home.xml", "base/res/layout/renamed.xml")),
        )
        val pathCollision = nameCollision.copy(
            newName = "sl_layout_other",
            entries = listOf(ResourceEntryRename("", "base/res/layout/home.xml", "base/res/layout/existing.xml")),
        )

        assertFailsWith<IllegalArgumentException> {
            ResourceTableTransformer().transform(original.toByteArray(), ResourceRenameReport(renames = listOf(nameCollision)))
        }
        assertFailsWith<IllegalArgumentException> {
            ResourceTableTransformer().transform(original.toByteArray(), ResourceRenameReport(renames = listOf(pathCollision)))
        }
    }

    @Test
    fun `replacement names must be unique within one package and resource type`() {
        val original = table(
            type(
                3,
                "style",
                entry(1, "Theme.One", configValue(Resources.Value.getDefaultInstance())),
                entry(2, "Theme.Two", configValue(Resources.Value.getDefaultInstance())),
            ),
        )
        val first = rename(0x7f030001, ResourceType.STYLE, "Theme.One", "sl_style_shared")
        val second = rename(0x7f030002, ResourceType.STYLE, "Theme.Two", "sl_style_shared")

        val failure = assertFailsWith<IllegalArgumentException> {
            ResourceTableTransformer().transform(
                original.toByteArray(),
                ResourceRenameReport(renames = listOf(first, second)),
            )
        }

        assertTrue(failure.message.orEmpty().contains("replacement name"))
        assertTrue(failure.message.orEmpty().contains("collides"))
    }

    @Test
    fun `replacement table paths must stay unique after bundle module prefixes are removed`() {
        val original = Resources.ResourceTable.newBuilder()
            .addPackage(resourcePackage(0x7f, type(1, "layout", entry(1, "one", fileValue("res/layout/one.xml")))))
            .addPackage(resourcePackage(0x80, type(1, "layout", entry(1, "two", fileValue("res/layout/two.xml")))))
            .build()
        val first = rename(
            0x7f010001,
            ResourceType.LAYOUT,
            "one",
            "sl_layout_same",
            entries = listOf(
                ResourceEntryRename("", "base/res/layout/one.xml", "base/res/layout/sl_layout_same.xml"),
            ),
        )
        val second = rename(
            0x80010001.toInt(),
            ResourceType.LAYOUT,
            "two",
            "sl_layout_same",
            entries = listOf(
                ResourceEntryRename("", "feature/res/layout/two.xml", "feature/res/layout/sl_layout_same.xml"),
            ),
        )

        val failure = assertFailsWith<IllegalArgumentException> {
            ResourceTableTransformer().transform(
                original.toByteArray(),
                ResourceRenameReport(renames = listOf(first, second)),
            )
        }

        assertTrue(failure.message.orEmpty().contains("replacement"))
        assertTrue(failure.message.orEmpty().contains("collides"))
    }

    @Test
    fun `missing and inconsistent qualifier mappings fail closed`() {
        val original = table(
            type(
                1,
                "layout",
                entry(
                    1,
                    "home",
                    fileValue("res/layout/home.xml"),
                    fileValue("res/layout-land/home.xml", Configuration.newBuilder().setOrientationValue(2).build()),
                ),
            ),
        )
        val missingLand = rename(
            resourceId = 0x7f010001,
            type = ResourceType.LAYOUT,
            oldName = "home",
            newName = "sl_layout_cedar",
            entries = listOf(ResourceEntryRename("", "base/res/layout/home.xml", "base/res/layout/sl_layout_cedar.xml")),
        )
        val inconsistent = rename(
            resourceId = 0x7f010001,
            type = ResourceType.LAYOUT,
            oldName = "home",
            newName = "sl_layout_cedar",
            qualifiers = listOf("", "port"),
            entries = listOf(
                ResourceEntryRename("", "base/res/layout/home.xml", "base/res/layout/sl_layout_cedar.xml"),
                ResourceEntryRename("port", "base/res/layout-land/home.xml", "base/res/layout-land/sl_layout_cedar.xml"),
            ),
        )

        assertFailsWith<IllegalArgumentException> {
            ResourceTableTransformer().transform(original.toByteArray(), ResourceRenameReport(renames = listOf(missingLand)))
        }
        assertFailsWith<IllegalArgumentException> {
            ResourceTableTransformer().transform(original.toByteArray(), ResourceRenameReport(renames = listOf(inconsistent)))
        }
    }

    @Test
    fun `file path qualifiers must match their protobuf configurations`() {
        val portrait = Configuration.newBuilder()
            .setOrientation(Configuration.Orientation.ORIENTATION_PORT)
            .build()
        val original = table(
            type(1, "layout", entry(1, "home", fileValue("res/layout-land/home.xml", portrait))),
        )
        val request = rename(
            resourceId = 0x7f010001,
            type = ResourceType.LAYOUT,
            oldName = "home",
            newName = "sl_layout_cedar",
            qualifiers = listOf("land"),
            entries = listOf(
                ResourceEntryRename(
                    "land",
                    "base/res/layout-land/home.xml",
                    "base/res/layout-land/sl_layout_cedar.xml",
                ),
            ),
        )

        val failure = assertFailsWith<IllegalArgumentException> {
            ResourceTableTransformer().transform(
                original.toByteArray(),
                ResourceRenameReport(renames = listOf(request)),
            )
        }

        assertTrue(failure.message.orEmpty().contains("qualifier"))
        assertTrue(failure.message.orEmpty().contains("resources.pb"))
    }

    @Test
    fun `compiled paths may retain only a redundant trailing SDK qualifier`() {
        val landscape = Configuration.newBuilder()
            .setOrientation(Configuration.Orientation.ORIENTATION_LAND)
            .build()
        val original = table(
            type(
                1,
                "layout",
                entry(
                    1,
                    "home",
                    fileValue("res/layout-v21/home.xml"),
                    fileValue("res/layout-land-v21/home.xml", landscape),
                ),
            ),
        )
        val request = rename(
            resourceId = 0x7f010001,
            type = ResourceType.LAYOUT,
            oldName = "home",
            newName = "sl_layout_cedar",
            qualifiers = listOf("v21", "land-v21"),
            entries = listOf(
                ResourceEntryRename(
                    "v21",
                    "base/res/layout-v21/home.xml",
                    "base/res/layout-v21/sl_layout_cedar.xml",
                ),
                ResourceEntryRename(
                    "land-v21",
                    "base/res/layout-land-v21/home.xml",
                    "base/res/layout-land-v21/sl_layout_cedar.xml",
                ),
            ),
        )

        val result = ResourceTableTransformer().transform(
            original.toByteArray(),
            ResourceRenameReport(renames = listOf(request)),
        )

        assertEquals(2, result.zipPathRenames.size)
        assertEquals(2, result.report.renames.single().fileReferencesChanged)
    }

    @Test
    fun `root-module requests preserve table validation and malformed inputs fail closed`() {
        val original = table(type(1, "layout", entry(1, "home", fileValue("res/layout/home.xml"))))
        val valid = rename(
            resourceId = 0x7f010001,
            type = ResourceType.LAYOUT,
            oldName = "home",
            newName = "sl_layout_cedar",
            entries = listOf(ResourceEntryRename("", "base/res/layout/home.xml", "base/res/layout/sl_layout_cedar.xml")),
        )

        val rootModuleResult = ResourceTableTransformer().transform(
            original.toByteArray(),
            ResourceRenameReport(renames = listOf(valid.copy(":"))),
        )
        assertEquals("sl_layout_cedar", Resources.ResourceTable.parseFrom(rootModuleResult.resourcesPb)
            .getPackage(0).getType(0).getEntry(0).name)
        assertFailsWith<IllegalArgumentException> {
            ResourceTableTransformer().transform(original.toByteArray(), ResourceRenameReport(renames = listOf(valid, valid)))
        }
        assertFailsWith<IllegalArgumentException> {
            ResourceTableTransformer().transform(byteArrayOf(0x7f, 0x7f), ResourceRenameReport(renames = listOf(valid)))
        }
        assertFailsWith<IllegalArgumentException> {
            ResourceTableTransformer().transform(
                original.toByteArray(),
                ResourceRenameReport(schemaVersion = 2, renames = listOf(valid)),
            )
        }
    }

    private fun rename(
        resourceId: Int,
        type: ResourceType,
        oldName: String,
        newName: String,
        qualifiers: List<String> = listOf(""),
        entries: List<ResourceEntryRename> = emptyList(),
    ) = ResourceRename(
        module = ":app",
        resourceId = resourceId,
        type = type,
        oldName = oldName,
        newName = newName,
        qualifiers = qualifiers,
        entries = entries,
    )

    private fun table(vararg types: Resources.Type): Resources.ResourceTable = Resources.ResourceTable.newBuilder()
        .addPackage(resourcePackage(0x7f, *types))
        .build()

    private fun resourcePackage(id: Int, vararg types: Resources.Type): Resources.Package = Resources.Package.newBuilder()
        .setPackageId(Resources.PackageId.newBuilder().setId(id))
        .setPackageName("com.example.demo.package$id")
        .addAllType(types.asList())
        .build()

    private fun type(id: Int, name: String, vararg entries: Resources.Entry): Resources.Type = Resources.Type.newBuilder()
        .setTypeId(Resources.TypeId.newBuilder().setId(id))
        .setName(name)
        .addAllEntry(entries.asList())
        .build()

    private fun entry(id: Int, name: String, vararg values: Resources.ConfigValue): Resources.Entry = Resources.Entry.newBuilder()
        .setEntryId(Resources.EntryId.newBuilder().setId(id))
        .setName(name)
        .addAllConfigValue(values.asList())
        .build()

    private fun fileValue(
        path: String,
        config: Configuration = Configuration.getDefaultInstance(),
    ): Resources.ConfigValue = configValue(
        Resources.Value.newBuilder()
            .setItem(
                Resources.Item.newBuilder().setFile(
                    Resources.FileReference.newBuilder()
                        .setPath(path)
                        .setType(if (path.endsWith(".png")) Resources.FileReference.Type.PNG else Resources.FileReference.Type.PROTO_XML),
                ),
            )
            .build(),
        config,
    )

    private fun configValue(
        value: Resources.Value,
        config: Configuration = Configuration.getDefaultInstance(),
    ): Resources.ConfigValue = Resources.ConfigValue.newBuilder()
        .setConfig(config)
        .setValue(value)
        .build()
}
