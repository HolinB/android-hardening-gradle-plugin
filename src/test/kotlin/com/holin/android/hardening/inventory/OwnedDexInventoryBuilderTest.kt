package com.holin.android.hardening.inventory

import com.holin.android.hardening.HardeningOwnership
import com.holin.android.hardening.testHardeningOwnership
import java.nio.file.Files
import java.nio.file.Path
import kotlin.io.path.createDirectories
import kotlin.io.path.writeText
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import org.junit.jupiter.api.io.TempDir

class OwnedDexInventoryBuilderTest {
    @TempDir
    lateinit var repository: Path

    @Test
    fun `uses arbitrary declared source sets and excludes configured packages`() {
        gitInit()
        source("mobile/src/demo/java/com/example/mobile/Owned.kt", "package com.example.mobile\nclass Owned\n")
        source("mobile/src/main/java/com/example/mobile/NotSelected.kt", "package com.example.mobile\nclass NotSelected\n")
        source("core/src/shared/java/com/example/core/Core.java", "package com.example.core; public class Core {}\n")
        source("core/src/shared/java/com/example/generated/Junk.java", "package com.example.generated; class Junk {}\n")
        source("core/src/shared/java/com/example/excluded/Legacy.java", "package com.example.excluded; class Legacy {}\n")
        val ownership = HardeningOwnership(
            listOf(
                HardeningOwnership.OwnedModule(":mobile", repository.resolve("mobile"), setOf("demo")),
                HardeningOwnership.OwnedModule(":core", repository.resolve("core"), setOf("shared")),
            ),
            setOf("com.example.generated"),
            setOf("com.example.excluded"),
        )
        val mapping = """
            com.example.mobile.Owned -> a.a:
            com.example.mobile.NotSelected -> a.b:
            com.example.core.Core -> a.c:
            com.example.generated.Junk -> a.d:
            com.example.excluded.Legacy -> a.e:
        """.trimIndent()

        val inventory = OwnedDexInventoryBuilder(repository, ownership).build(mapping)

        assertEquals(setOf("La/a;", "La/c;"), inventory.acceptedDexDescriptors)
    }

    @Test
    fun `custom flavor source root overrides the same main descriptor`() {
        gitInit()
        val main = repository.resolve("mobile/custom/main-code/com/example/Overlay.kt")
        source(
            "mobile/custom/main-code/com/example/Overlay.kt",
            "package com.example\nclass Overlay\n",
        )
        val orchid = repository.resolve("mobile/custom/orchid-code/com/example/Overlay.kt")
        source(
            "mobile/custom/orchid-code/com/example/Overlay.kt",
            "package com.example\nclass Overlay\n",
        )
        val roots = HardeningOwnership.ResolvedSourceRoots.fromSourceSets(
            listOf(
                HardeningOwnership.ResolvedSourceSetRoots(
                    "main",
                    setOf(main.parent.parent.parent),
                    emptySet(),
                    emptySet(),
                    emptySet(),
                ),
                HardeningOwnership.ResolvedSourceSetRoots(
                    "orchid",
                    setOf(orchid.parent.parent.parent),
                    emptySet(),
                    emptySet(),
                    emptySet(),
                ),
            ),
        )
        val ownership = HardeningOwnership(
            listOf(
                HardeningOwnership.OwnedModule(
                    ":mobile",
                    repository.resolve("mobile"),
                    linkedSetOf("main", "orchid"),
                    roots,
                ),
            ),
            emptySet(),
            emptySet(),
        )

        val sources = OwnedDexInventoryBuilder(repository, ownership).sourceInventory()

        assertEquals(listOf(orchid), sources.filter { it.originalDescriptor == "Lcom/example/Overlay;" }.map { it.source })
    }

    @Test
    fun `proves every package level Java declaration from an eligible source`() {
        gitInit()
        source(
            "core/src/main/java/com/example/Owner.java",
            """
                package com.example;
                public class Owner { Object binding; }
                final class Secondary { void calculate() {} }
            """.trimIndent(),
        )

        val sources = OwnedDexInventoryBuilder(repository, testHardeningOwnership(repository, setOf(":core"))).sourceInventory()

        assertEquals(
            setOf("Lcom/example/Owner;", "Lcom/example/Secondary;"),
            sources.mapTo(sortedSetOf()) { it.originalDescriptor },
        )
    }

    @Test
    fun `does not prove an undeclared Java file stem`() {
        gitInit()
        source(
            "core/src/main/java/com/example/Unrelated.java",
            "package com.example; final class OnlyDeclared {}",
        )

        val sources = OwnedDexInventoryBuilder(repository, testHardeningOwnership(repository, setOf(":core"))).sourceInventory()

        assertEquals(setOf("Lcom/example/OnlyDeclared;"), sources.mapTo(sortedSetOf()) { it.originalDescriptor })
    }

    @Test
    fun `proves a Kotlin class immediately following KDoc`() {
        gitInit()
        source(
            "app/src/main/java/com/example/demo/match/common/activity/MyJsBridge.kt",
            """
                package com.example.demo.match.common.activity

                import android.webkit.JavascriptInterface

                /**
                 * Bridge methods exposed to JavaScript.
                 */
                class MyJsBridge {
                    @JavascriptInterface
                    fun a(value: String) = Unit
                }
            """.trimIndent(),
        )

        val sources = OwnedDexInventoryBuilder(repository, testHardeningOwnership(repository, setOf(":app"))).sourceInventory()

        assertTrue("Lcom/example/demo/match/common/activity/MyJsBridge;" in sources.map { it.originalDescriptor })
    }

    @Test
    fun `proves a Kotlin file facade for a top level declaration immediately following KDoc`() {
        gitInit()
        source(
            "app/src/main/java/com/example/KdocFacade.kt",
            """
                package com.example

                /**
                 * Entry point exposed from this file.
                 */
                fun topLevel() = Unit
            """.trimIndent(),
        )

        val sources = OwnedDexInventoryBuilder(repository, testHardeningOwnership(repository, setOf(":app"))).sourceInventory()

        assertTrue("Lcom/example/KdocFacadeKt;" in sources.map { it.originalDescriptor })
    }

    @Test
    fun `rejects a symlinked source leaf`() {
        gitInit()
        val external = repository.resolve("external/Escape.kt")
        external.parent.createDirectories()
        external.writeText("package com.example\nclass Escape")
        val link = repository.resolve("app/src/main/java/com/example/Escape.kt")
        link.parent.createDirectories()
        Files.createSymbolicLink(link, external)

        val failure = assertFailsWith<IllegalArgumentException> {
            OwnedDexInventoryBuilder(repository, testHardeningOwnership(repository, setOf(":app"))).sourceInventory()
        }

        assertTrue(failure.message.orEmpty().contains("symbolic link"))
    }

    @Test
    fun `rejects a symlink at an owned source root ancestor`() {
        gitInit()
        source("actual-main/java/com/example/Escape.kt", "package com.example\nclass Escape")
        repository.resolve("app/src").createDirectories()
        Files.createSymbolicLink(repository.resolve("app/src/main"), repository.resolve("actual-main"))

        val failure = assertFailsWith<IllegalArgumentException> {
            OwnedDexInventoryBuilder(repository, testHardeningOwnership(repository, setOf(":app"))).sourceInventory()
        }

        assertTrue(failure.message.orEmpty().contains("symbolic link"))
    }

    @Test
    fun `rejects a symbolic repository root before source discovery`() {
        val realRepository = repository.resolve("real-repository")
        realRepository.createDirectories()
        gitInit(realRepository)
        realRepository.resolve("app/src/main/java/com/example/App.kt").also { file ->
            file.parent.createDirectories()
            file.writeText("package com.example\nclass App")
        }
        val linkedRepository = repository.resolve("linked-repository")
        Files.createSymbolicLink(linkedRepository, realRepository.fileName)

        val failure = assertFailsWith<IllegalArgumentException> {
            OwnedDexInventoryBuilder(linkedRepository, testHardeningOwnership(linkedRepository, setOf(":app"))).sourceInventory()
        }

        assertTrue(failure.message.orEmpty().contains("symbolic link"))
    }

    @Test
    fun `prefers an exact Java top level dollar name over an outer prefix`() {
        gitInit()
        source(
            "core/src/main/java/com/example/Dollar.java",
            "package com.example; class Outer${'$'}Name {} class Outer${'$'}Name${'$'}Inner {}",
        )

        val inventory = OwnedDexInventoryBuilder(repository, testHardeningOwnership(repository, setOf(":core"))).build(
            "com.example.Outer${'$'}Name${'$'}Inner${'$'}Child -> a.b:\n",
        )

        assertEquals(setOf("La/b;"), inventory.acceptedDexDescriptors)
    }

    @Test
    fun `uses tracked production source and rejects junk generated tests and kts`() {
        gitInit()
        source("app/src/main/java/com/example/Owned.kt", "package com.example\nclass Owned\nfun top() = 1\n")
        source("core/src/main/java/com/example/Base.java", "package com.example; public class Base {}\n")
        source("selector/src/main/java/com/example/Selector.kt", "package com.example\nclass Selector\n")
        source("app/src/main/java/com/example/junkcode/Junk.kt", "package com.example.junkcode\nclass Junk\n")
        source("app/src/test/java/com/example/TestOnly.kt", "package com.example\nclass TestOnly\n")
        source("app/src/main/java/com/example/Script.kts", "package com.example\nclass Script\n")
        source("app/src/main/java/com/example/Ignored.kt", "package com.example\nclass Ignored\n")
        repository.resolve(".gitignore").writeText("app/src/main/java/com/example/Ignored.kt\n")
        val mapping = """
            com.example.Owned -> a.b:
            com.example.Owned${'$'}Nested -> a.c:
            com.example.OwnedKt -> a.d:
            com.example.Base -> a.e:
            com.example.Selector -> a.j:
            com.example.junkcode.Junk -> a.f:
            com.example.TestOnly -> a.g:
            com.example.Script -> a.h:
            com.example.Ignored -> a.i:
        """.trimIndent()

        val inventory = OwnedDexInventoryBuilder(
            repository,
            testHardeningOwnership(repository),
        ).build(mapping)

        assertEquals(setOf("La/b;", "La/c;", "La/d;", "La/e;", "La/j;"), inventory.acceptedDexDescriptors)
        assertFalse("La/f;" in inventory.acceptedDexDescriptors)
        assertTrue(inventory.sources.all { it.module in setOf(":app", ":core", ":selector") })
        assertEquals(inventory.acceptedDexDescriptors, inventory.descriptorProofs.mapTo(sortedSetOf()) { it.outputDescriptor })
        assertTrue(inventory.descriptorProofs.all { proof -> proof.sourceFiles.all(Files::isRegularFile) })
        assertEquals(
            setOf("Lcom/example/Owned;"),
            inventory.descriptorProofs.single { it.outputDescriptor == "La/c;" }.sourceOriginalDescriptors,
        )
    }

    @Test
    fun `excludes an R8 horizontal merge shared with unowned code`() {
        gitInit()
        source("app/src/main/java/com/example/Owned.kt", "package com.example\nclass Owned\n")
        val mapping = """
            com.example.Owned -> a.a:
            third.party.Library -> a.a:
        """.trimIndent()

        val inventory = OwnedDexInventoryBuilder(repository, testHardeningOwnership(repository, setOf(":app"))).build(mapping)

        assertTrue(inventory.acceptedDexDescriptors.isEmpty())
        assertEquals(setOf("La/a;"), inventory.mixedOrUnownedMergedDescriptors)
    }

    @Test
    fun `excludes an owned output class containing explicitly merged unowned members`() {
        gitInit()
        source("app/src/main/java/com/example/Owned.kt", "package com.example\nclass Owned\n")
        val mapping = """
            com.example.Owned -> com.example.Owned:
                1:2:void call():3:4 -> call
                5:6:void third.party.Library.merged():7:8 -> merged
        """.trimIndent()

        val inventory = OwnedDexInventoryBuilder(repository, testHardeningOwnership(repository, setOf(":app"))).build(mapping)

        assertTrue(inventory.acceptedDexDescriptors.isEmpty())
        assertEquals(setOf("Lcom/example/Owned;"), inventory.mixedOrUnownedMergedDescriptors)
        assertEquals(setOf("Lcom/example/Owned;"), inventory.accessCompatibilityDexDescriptors)
    }

    @Test
    fun `accepts an owned output class with an R8 synthesized member owner`() {
        gitInit()
        source("app/src/main/java/com/example/Owned.kt", "package com.example\nclass Owned\n")
        val mapping = """
            com.example.Owned -> a.a:
                int synthetic.Owned.${'$'}r8${'$'}classId -> a
                  # {"id":"com.android.tools.r8.synthesized"}
                1:2:void call():3:4 -> call
        """.trimIndent()

        val inventory = OwnedDexInventoryBuilder(repository, testHardeningOwnership(repository, setOf(":app"))).build(mapping)

        assertEquals(setOf("La/a;"), inventory.acceptedDexDescriptors)
        assertTrue(inventory.mixedOrUnownedMergedDescriptors.isEmpty())
        assertTrue(
            inventory.descriptorProofs.single().explicitMemberOwnerDescriptors.isEmpty(),
        )
    }

    @Test
    fun `fails closed when two production sources claim the same original descriptor`() {
        gitInit()
        source("app/src/main/java/com/example/Owned.kt", "package com.example\nclass Owned\n")
        source("app/src/main/kotlin/com/example/Alias.kt", "package com.example\nclass Owned\n")

        val failure = assertFailsWith<IllegalArgumentException> {
            OwnedDexInventoryBuilder(repository, testHardeningOwnership(repository, setOf(":app")))
                .build("com.example.Owned -> a.b:\n")
        }

        assertTrue(failure.message.orEmpty().contains("duplicate class descriptors"))
    }

    @Test
    fun `allows a shared Kotlin multifile facade from matching source parts`() {
        gitInit()
        source(
            "app/src/main/java/com/example/PartOne.kt",
            "@file:JvmName(\"Combined\")\n@file:JvmMultifileClass\npackage com.example\nfun first() = 1",
        )
        source(
            "app/src/main/java/com/example/PartTwo.kt",
            "@file:kotlin.jvm.JvmName(\"Combined\")\n@file:kotlin.jvm.JvmMultifileClass\npackage com.example\nval second = 2",
        )
        val mapping = """
            com.example.Combined -> a.a:
            com.example.Combined__PartOneKt -> a.b:
            com.example.Combined__PartTwoKt -> a.c:
        """.trimIndent()

        val inventory = OwnedDexInventoryBuilder(repository, testHardeningOwnership(repository, setOf(":app"))).build(mapping)

        assertEquals(setOf("La/a;", "La/b;", "La/c;"), inventory.acceptedDexDescriptors)
        assertEquals(
            setOf(
                repository.resolve("app/src/main/java/com/example/PartOne.kt"),
                repository.resolve("app/src/main/java/com/example/PartTwo.kt"),
            ),
            inventory.descriptorProofs.single { it.outputDescriptor == "La/a;" }.sourceFiles,
        )
    }

    @Test
    fun `rejects conflicting non multifile facade declarations`() {
        gitInit()
        source(
            "app/src/main/java/com/example/First.kt",
            "@file:JvmName(\"Conflict\")\npackage com.example\nfun first() = 1",
        )
        source(
            "app/src/main/java/com/example/Second.kt",
            "@file:JvmName(\"Conflict\")\npackage com.example\nfun second() = 2",
        )

        val failure = assertFailsWith<IllegalArgumentException> {
            OwnedDexInventoryBuilder(repository, testHardeningOwnership(repository, setOf(":app")))
                .build("com.example.Conflict -> a.a:\n")
        }

        assertTrue(failure.message.orEmpty().contains("duplicate class descriptors"))
    }

    @Test
    fun `same nested simple name in different owners does not create a duplicate top level descriptor`() {
        gitInit()
        source(
            "app/src/main/java/com/example/First.kt",
            """
                package com.example
                class First {
                    class ExchangeContent
                    val sample = "class NotADeclaration"
                }
            """.trimIndent(),
        )
        source(
            "app/src/main/java/com/example/Second.kt",
            "package com.example\nclass Second {\n" +
                "    class ExchangeContent\n" +
                "    val sample = \"\"\"\nclass AlsoNotADeclaration\n\"\"\"\n" +
                "}\n",
        )
        val mapping = """
            com.example.First -> a.a:
            com.example.First${'$'}ExchangeContent -> a.b:
            com.example.Second -> a.c:
            com.example.Second${'$'}ExchangeContent -> a.d:
        """.trimIndent()

        val inventory = OwnedDexInventoryBuilder(repository, testHardeningOwnership(repository, setOf(":app"))).build(mapping)

        assertEquals(setOf("La/a;", "La/b;", "La/c;", "La/d;"), inventory.acceptedDexDescriptors)
        assertFalse(inventory.sources.any { it.originalDescriptor == "Lcom/example/ExchangeContent;" })
        assertFalse(inventory.sources.any { it.originalDescriptor == "Lcom/example/NotADeclaration;" })
        assertFalse(inventory.sources.any { it.originalDescriptor == "Lcom/example/AlsoNotADeclaration;" })
    }

    @Test
    fun `filters previous mapping to app source classes and their members`() {
        gitInit()
        source("app/src/main/java/com/example/Owned.kt", "package com.example\nclass Owned\n")
        source("core/src/main/java/com/example/Base.kt", "package com.example\nclass Base\n")
        val mapping = """
            # compiler: R8
            # compiler_version: 8.13.2
            com.example.Owned -> a.b:
                1:2:void call(java.lang.String):3:4 -> c
            com.example.Owned${'$'}Nested -> a.d:
                int value -> e
            com.example.Base -> a.f:
                void ignored() -> g
            third.party.Library -> a.h:
                void ignored() -> i
        """.trimIndent() + "\n"

        val filtered = AppOnlyMappingFilter(repository, testHardeningOwnership(repository, setOf(":app"))).filter(mapping)

        assertTrue("com.example.Owned -> a.b:" in filtered)
        assertTrue("com.example.Owned${'$'}Nested -> a.d:" in filtered)
        assertTrue("void call(java.lang.String)" in filtered)
        assertFalse("com.example.Base" in filtered)
        assertFalse("third.party.Library" in filtered)
        assertTrue(filtered.endsWith('\n'))
    }

    @Test
    fun `empty previous mapping produces no applymapping payload`() {
        gitInit()
        source("app/src/main/java/com/example/Owned.kt", "package com.example\nclass Owned\n")

        assertEquals("", AppOnlyMappingFilter(repository, testHardeningOwnership(repository, setOf(":app"))).filter(""))
    }

    private fun source(relative: String, text: String) {
        repository.resolve(relative).also { file ->
            file.parent.createDirectories()
            file.writeText(text)
        }
    }

    private fun gitInit(path: Path = repository) {
        val process = ProcessBuilder("git", "init", "-q", path.toString()).start()
        check(process.waitFor() == 0)
    }
}
