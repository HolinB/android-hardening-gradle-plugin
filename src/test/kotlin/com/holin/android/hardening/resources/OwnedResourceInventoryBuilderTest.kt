package com.holin.android.hardening.resources

import com.android.aapt.Resources
import com.holin.android.hardening.HardeningOwnership
import com.holin.android.hardening.testHardeningOwnership
import java.nio.file.Path
import kotlin.io.path.createDirectories
import kotlin.io.path.createSymbolicLinkPointingTo
import kotlin.io.path.writeBytes
import kotlin.io.path.writeText
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import org.junit.jupiter.api.io.TempDir

class OwnedResourceInventoryBuilderTest {
    @TempDir
    lateinit var repository: Path

    @Test
    fun `uses resolved custom resource roots and explicit selector WebP scope`() {
        gitInit()
        resource("selector/src/main/res-im/drawable/selected.webp", byteArrayOf(1))
        resource("selector/src/main/res-im/drawable/private/blocked.webp", byteArrayOf(2))
        resource("selector/src/main/res-im/drawable/default_none.webp", byteArrayOf(3))
        val customRoot = repository.resolve("selector/src/main/res-im")
        val roots = HardeningOwnership.ResolvedSourceRoots(emptySet(), emptySet(), setOf(customRoot), emptySet())
        val scoped = HardeningOwnership.OwnedModule(
            ":selector",
            repository.resolve("selector"),
            setOf("main"),
            roots,
            HardeningOwnership.WebpScope.resolve(
                setOf("src/main/res-im/drawable/**/*.webp"),
                setOf("src/main/res-im/drawable/private/**"),
            ),
        )
        val ownership = HardeningOwnership(listOf(scoped), emptySet(), emptySet())

        val names = OwnedResourceInventoryBuilder(repository, ownership).scanSourceNames()

        assertTrue(names.single { it.name == "selected" }.webpDiversificationEnabled)
        assertTrue(!names.single { it.name == "blocked" }.webpDiversificationEnabled)
        assertTrue(names.single { it.name == "default_none" }.webpDiversificationEnabled)

        val defaultNone = HardeningOwnership(
            listOf(HardeningOwnership.OwnedModule(":selector", repository.resolve("selector"), setOf("main"), roots)),
            emptySet(),
            emptySet(),
        )
        assertTrue(
            OwnedResourceInventoryBuilder(repository, defaultNone).scanSourceNames()
                .none(OwnedResourceSourceName::webpDiversificationEnabled),
        )
    }

    @Test
    fun `fails when a declared include matches no owned WebP`() {
        gitInit()
        resource("selector/src/main/res-im/drawable/actual.webp", byteArrayOf(1))
        val roots = HardeningOwnership.ResolvedSourceRoots(
            emptySet(),
            emptySet(),
            setOf(repository.resolve("selector/src/main/res-im")),
            emptySet(),
        )
        val module = HardeningOwnership.OwnedModule(
            ":selector",
            repository.resolve("selector"),
            setOf("main"),
            roots,
            HardeningOwnership.WebpScope.resolve(setOf("src/main/res-im/drawable/missing*.webp"), emptySet()),
        )

        val failure = assertFailsWith<IllegalArgumentException> {
            OwnedResourceInventoryBuilder(
                repository,
                HardeningOwnership(listOf(module), emptySet(), emptySet()),
            ).scanSourceNames()
        }

        assertTrue(failure.message.orEmpty().contains(":selector"))
        assertTrue(failure.message.orEmpty().contains("src/main/res-im/drawable/missing*.webp"))
    }

    @Test
    fun `keeps WebP scope decisions distinct across resource qualifiers`() {
        gitInit()
        resource("selector/src/main/res/drawable-xhdpi/panel.webp", byteArrayOf(1))
        resource("selector/src/main/res/drawable-xxhdpi/panel.webp", byteArrayOf(2))
        val root = repository.resolve("selector/src/main/res")
        val module = HardeningOwnership.OwnedModule(
            ":selector",
            repository.resolve("selector"),
            setOf("main"),
            HardeningOwnership.ResolvedSourceRoots(emptySet(), emptySet(), setOf(root), emptySet()),
            HardeningOwnership.WebpScope.resolve(
                setOf("src/main/res/drawable-*/**/*.webp"),
                setOf("src/main/res/drawable-xxhdpi/**"),
            ),
        )
        val fileValues = listOf("drawable-xhdpi", "drawable-xxhdpi").map { directory ->
            Resources.ConfigValue.newBuilder().setValue(
                Resources.Value.newBuilder().setItem(
                    Resources.Item.newBuilder().setFile(
                        Resources.FileReference.newBuilder().setPath("res/$directory/panel.webp"),
                    ),
                ),
            ).build()
        }
        val table = Resources.ResourceTable.newBuilder().addPackage(
            Resources.Package.newBuilder()
                .setPackageId(Resources.PackageId.newBuilder().setId(0x7f))
                .addType(
                    Resources.Type.newBuilder()
                        .setTypeId(Resources.TypeId.newBuilder().setId(1))
                        .setName("drawable")
                        .addEntry(
                            Resources.Entry.newBuilder()
                                .setEntryId(Resources.EntryId.newBuilder().setId(2))
                                .setName("panel")
                                .addAllConfigValue(fileValues),
                        ),
                ),
        ).build()

        val inventory = OwnedResourceInventoryBuilder(
            repository,
            HardeningOwnership(listOf(module), emptySet(), emptySet()),
        ).build(
            table.toByteArray(),
            mapOf(
                "base/res/drawable-xhdpi/panel.webp" to byteArrayOf(1),
                "base/res/drawable-xxhdpi/panel.webp" to byteArrayOf(2),
            ),
        )

        assertTrue(inventory.single { it.qualifier == "xhdpi" }.webpDiversificationEnabled)
        assertTrue(!inventory.single { it.qualifier == "xxhdpi" }.webpDiversificationEnabled)
    }

    @Test
    fun `later source roots win equal resources and provide their WebP scope`() {
        gitInit()
        resource("app/src/main/res/drawable/hero.webp", byteArrayOf(1))
        resource("app/src/flavor/res/drawable/hero.webp", byteArrayOf(2))
        val moduleDirectory = repository.resolve("app")
        val roots = HardeningOwnership.ResolvedSourceRoots(
            emptySet(),
            emptySet(),
            linkedSetOf(
                moduleDirectory.resolve("src/main/res"),
                moduleDirectory.resolve("src/flavor/res"),
            ),
            emptySet(),
        )
        val module = HardeningOwnership.OwnedModule(
            ":app",
            moduleDirectory,
            linkedSetOf("main", "flavor"),
            roots,
            HardeningOwnership.WebpScope.resolve(setOf("src/flavor/res/**/*.webp"), emptySet()),
        )

        val winner = OwnedResourceInventoryBuilder(
            repository,
            HardeningOwnership(listOf(module), emptySet(), emptySet()),
        ).scanSourceNames().single()

        assertEquals(moduleDirectory.resolve("src/flavor/res/drawable/hero.webp"), winner.source)
        assertTrue(winner.webpDiversificationEnabled)
    }

    @Test
    fun `uses declared arbitrary resource source sets and module priority`() {
        gitInit()
        resource("mobile/src/demo/res/layout/home.xml")
        resource("mobile/src/main/res/layout/not_selected.xml")
        resource("core/src/shared/res/layout/home.xml")
        resource("core/src/shared/res/drawable/core_badge.xml")
        resource("core/src/shared/res/drawable/ignored.xml")
        repository.resolve(".gitignore").writeText("core/src/shared/res/drawable/ignored.xml\n")
        val ownership = HardeningOwnership(
            listOf(
                HardeningOwnership.OwnedModule(":mobile", repository.resolve("mobile"), setOf("demo")),
                HardeningOwnership.OwnedModule(":core", repository.resolve("core"), setOf("shared")),
            ),
            emptySet(),
            emptySet(),
        )

        val names = OwnedResourceInventoryBuilder(repository, ownership).scanSourceNames()

        assertEquals(":mobile", names.single { it.type == ResourceType.LAYOUT && it.name == "home" }.module)
        assertEquals(":core", names.single { it.type == ResourceType.DRAWABLE && it.name == "core_badge" }.module)
        assertTrue(names.none { it.name == "not_selected" || it.name == "ignored" })
    }

    @Test
    fun `rejects symbolic source set roots`() {
        gitInit()
        val outside = repository.resolve("outside-source-set")
        outside.resolve("res/layout").createDirectories()
        outside.resolve("res/layout/home.xml").writeText("<resources/>")
        repository.resolve("app/src").createDirectories()
        repository.resolve("app/src/main").createSymbolicLinkPointingTo(outside)

        val failure = assertFailsWith<IllegalArgumentException> {
            OwnedResourceInventoryBuilder(repository, testHardeningOwnership(repository)).scanSourceNames()
        }

        assertTrue(failure.message.orEmpty().contains("symbolic link"))
    }

    @Test
    fun `rejects symbolic resource roots`() {
        gitInit()
        val outside = repository.resolve("outside-res")
        outside.resolve("layout").createDirectories()
        outside.resolve("layout/home.xml").writeText("<resources/>")
        repository.resolve("app/src/main").createDirectories()
        repository.resolve("app/src/main/res").createSymbolicLinkPointingTo(outside)

        val failure = assertFailsWith<IllegalArgumentException> {
            OwnedResourceInventoryBuilder(repository, testHardeningOwnership(repository)).scanSourceNames()
        }

        assertTrue(failure.message.orEmpty().contains("symbolic link"))
    }

    @Test
    fun `rejects symbolic directories while walking resource roots`() {
        gitInit()
        val outside = repository.resolve("outside-layout")
        outside.createDirectories()
        outside.resolve("home.xml").writeText("<resources/>")
        repository.resolve("app/src/main/res").createDirectories()
        repository.resolve("app/src/main/res/layout").createSymbolicLinkPointingTo(outside)

        val failure = assertFailsWith<IllegalArgumentException> {
            OwnedResourceInventoryBuilder(repository, testHardeningOwnership(repository)).scanSourceNames()
        }

        assertTrue(failure.message.orEmpty().contains("symbolic link"))
    }

    @Test
    fun `rejects symbolic resource files`() {
        gitInit()
        val outside = repository.resolve("outside.xml")
        outside.writeText("<resources/>")
        repository.resolve("app/src/main/res/layout").createDirectories()
        repository.resolve("app/src/main/res/layout/home.xml").createSymbolicLinkPointingTo(outside)

        val failure = assertFailsWith<IllegalArgumentException> {
            OwnedResourceInventoryBuilder(repository, testHardeningOwnership(repository)).scanSourceNames()
        }

        assertTrue(failure.message.orEmpty().contains("symbolic link"))
    }

    @Test
    fun `discovers and joins every frozen file resource family`() {
        gitInit()
        val families = listOf(
            Triple(ResourceType.MIPMAP, "launcher", ".png"),
            Triple(ResourceType.FONT, "brand", ".ttf"),
            Triple(ResourceType.RAW, "seed", ".bin"),
            Triple(ResourceType.ANIM, "fade_in", ".xml"),
            Triple(ResourceType.ANIMATOR, "pulse", ".xml"),
            Triple(ResourceType.XML, "network_security_config", ".xml"),
        )
        families.forEach { (type, name, extension) ->
            resource("app/src/main/res/${type.directoryName}/$name$extension", name.toByteArray())
        }
        val table = Resources.ResourceTable.newBuilder().addPackage(
            Resources.Package.newBuilder()
                .setPackageId(Resources.PackageId.newBuilder().setId(0x7f))
                .addAllType(families.mapIndexed { index, (type, name, extension) ->
                    Resources.Type.newBuilder()
                        .setTypeId(Resources.TypeId.newBuilder().setId(index + 1))
                        .setName(type.directoryName)
                        .addEntry(
                            Resources.Entry.newBuilder()
                                .setEntryId(Resources.EntryId.newBuilder().setId(index + 10))
                                .setName(name)
                                .addConfigValue(
                                    Resources.ConfigValue.newBuilder().setValue(
                                        Resources.Value.newBuilder().setItem(
                                            Resources.Item.newBuilder().setFile(
                                                Resources.FileReference.newBuilder()
                                                    .setPath("res/${type.directoryName}/$name$extension"),
                                            ),
                                        ),
                                    ),
                                ),
                        )
                        .build()
                }),
        ).build()
        val aabEntries = families.associate { (type, name, extension) ->
            "base/res/${type.directoryName}/$name$extension" to name.toByteArray()
        }

        val ownership = testHardeningOwnership(repository)
        val sourceNames = OwnedResourceInventoryBuilder(repository, ownership).scanSourceNames()
        val inventory = OwnedResourceInventoryBuilder(repository, ownership).build(table.toByteArray(), aabEntries)

        assertEquals(families.map { it.first }.toSet(), sourceNames.map { it.type }.toSet())
        assertEquals(families.map { it.first }.toSet(), inventory.map { it.type }.toSet())
        assertEquals(aabEntries.keys, inventory.mapNotNull { it.aabPath }.toSet())
    }

    @Test
    fun `finds five-module production winners including res-im and styles while honoring git ignore`() {
        gitInit()
        resource("app/src/main/res/layout/home.xml")
        resource("app/src/main/res-im/drawable/hero.png", byteArrayOf(1))
        resource("core/src/main/res/layout/home.xml")
        resource("ucrop/src/main/res/drawable/crop.xml")
        resource("compress/src/main/res/values/styles.xml", "<resources><style name=\"Theme.Media\"/></resources>".toByteArray())
        resource("selector/src/main/res/layout/selector_page.xml")
        resource("app/src/main/res/layout/ignored.xml")
        repository.resolve(".gitignore").writeText("app/src/main/res/layout/ignored.xml\n")

        val names = OwnedResourceInventoryBuilder(repository, testHardeningOwnership(repository)).scanSourceNames()

        assertEquals(":app", names.single { it.type == ResourceType.LAYOUT && it.name == "home" }.module)
        assertTrue(names.any { it.type == ResourceType.DRAWABLE && it.name == "hero" && it.module == ":app" })
        assertTrue(names.any { it.type == ResourceType.DRAWABLE && it.name == "crop" && it.module == ":ucrop" })
        assertTrue(names.any { it.type == ResourceType.STYLE && it.name == "Theme.Media" && it.module == ":compress" })
        assertTrue(names.any { it.type == ResourceType.LAYOUT && it.name == "selector_page" && it.module == ":selector" })
        assertTrue(names.none { it.name == "ignored" })
    }

    @Test
    fun `joins owned names to exact resource ids qualifiers paths and bytes`() {
        gitInit()
        resource("app/src/main/res/layout/home.xml")
        val fileValue = Resources.Value.newBuilder().setItem(
            Resources.Item.newBuilder().setFile(Resources.FileReference.newBuilder().setPath("res/layout/home.xml")),
        )
        val table = Resources.ResourceTable.newBuilder().addPackage(
            Resources.Package.newBuilder()
                .setPackageId(Resources.PackageId.newBuilder().setId(0x7f))
                .addType(
                    Resources.Type.newBuilder()
                        .setTypeId(Resources.TypeId.newBuilder().setId(1))
                        .setName("layout")
                        .addEntry(
                            Resources.Entry.newBuilder()
                                .setEntryId(Resources.EntryId.newBuilder().setId(2))
                                .setName("home")
                                .addConfigValue(Resources.ConfigValue.newBuilder().setValue(fileValue)),
                        ),
                ),
        ).build()

        val inventory = OwnedResourceInventoryBuilder(repository, testHardeningOwnership(repository)).build(
            table.toByteArray(),
            mapOf("base/res/layout/home.xml" to "compiled".toByteArray()),
        )

        val entry = inventory.single()
        assertEquals(0x7f010002, entry.resourceId)
        assertEquals(":app", entry.module)
        assertEquals("", entry.qualifier)
        assertEquals("base/res/layout/home.xml", entry.aabPath)
        assertEquals("compiled", entry.bytes!!.toString(Charsets.UTF_8))
    }

    @Test
    fun `marks statically resolved dynamic lookup names as externally named`() {
        gitInit()
        resource("app/src/main/res/xml/provider_paths.xml")
        val fileValue = Resources.Value.newBuilder().setItem(
            Resources.Item.newBuilder().setFile(Resources.FileReference.newBuilder().setPath("res/xml/provider_paths.xml")),
        )
        val table = Resources.ResourceTable.newBuilder().addPackage(
            Resources.Package.newBuilder()
                .setPackageId(Resources.PackageId.newBuilder().setId(0x7f))
                .addType(
                    Resources.Type.newBuilder()
                        .setTypeId(Resources.TypeId.newBuilder().setId(1))
                        .setName("xml")
                        .addEntry(
                            Resources.Entry.newBuilder()
                                .setEntryId(Resources.EntryId.newBuilder().setId(2))
                                .setName("provider_paths")
                                .addConfigValue(Resources.ConfigValue.newBuilder().setValue(fileValue)),
                        ),
                ),
        ).build()

        val entry = OwnedResourceInventoryBuilder(
            repository,
            testHardeningOwnership(repository),
            externallyNamedResources = setOf(ResourceType.XML to "provider_paths"),
        ).build(
            table.toByteArray(),
            mapOf("base/res/xml/provider_paths.xml" to "compiled".toByteArray()),
        ).single()

        assertTrue(entry.externallyNamed)
    }

    private fun resource(relative: String, bytes: ByteArray = "<resources/>".toByteArray()) {
        repository.resolve(relative).also { file ->
            file.parent.createDirectories()
            file.writeBytes(bytes)
        }
    }

    private fun gitInit() {
        val process = ProcessBuilder("git", "init", "-q", repository.toString()).start()
        check(process.waitFor() == 0)
    }
}
