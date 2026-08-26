package com.holin.android.hardening.code

import com.holin.android.hardening.testHardeningOwnership
import java.io.ByteArrayOutputStream
import java.nio.file.Files
import java.nio.file.Path
import java.util.zip.CRC32
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream
import kotlin.io.path.createDirectories
import kotlin.io.path.writeBytes
import kotlin.io.path.writeText
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import org.junit.jupiter.api.io.TempDir
import org.objectweb.asm.ClassWriter
import org.objectweb.asm.Opcodes

class OwnedBytecodeInventoryTest {
    @TempDir
    lateinit var repository: Path

    @Test
    fun `only source proven classes in exact owned modules are mutable`() {
        gitInit()
        writeSource(":core", "src/main/java/com/example/Owner.java", """
            package com.example;
            public class Owner { Object binding; }
            final class Secondary { void calculate() {} }
        """.trimIndent())
        writeSource(":app", "src/main/java/com/example/App.kt", "package com.example\nclass App")
        writeSource(":compress", "src/main/java/com/example/Compress.kt", "package com.example\nclass Compress")
        writeSource(":selector", "src/main/java/com/example/Selector.kt", "package com.example\nclass Selector")
        writeSource(":ucrop", "src/main/java/com/example/Ucrop.kt", "package com.example\nclass Ucrop")
        val ownedJar = classJar(
            "com/example/Owner" to classBytes("com/example/Owner", "Owner.java", fields = listOf("binding")),
            "com/example/Owner${'$'}Nested" to classBytes("com/example/Owner${'$'}Nested", "Owner.java"),
            "com/example/Secondary" to classBytes("com/example/Secondary", "Owner.java", methods = listOf("calculate")),
        )
        val result = OwnedBytecodeInventoryBuilder(repository, testHardeningOwnership(repository)).build(
            listOf(
                BytecodeInput(classJar("com/example/App" to classBytes("com/example/App", "App.kt")), ":app"),
                BytecodeInput(ownedJar, ":core"),
                BytecodeInput(classJar("com/example/Compress" to classBytes("com/example/Compress", "Compress.kt")), ":compress"),
                BytecodeInput(classJar("com/example/Selector" to classBytes("com/example/Selector", "Selector.kt")), ":selector"),
                BytecodeInput(classJar("com/example/Ucrop" to classBytes("com/example/Ucrop", "Ucrop.kt")), ":ucrop"),
                BytecodeInput(classJar("third/Party" to classBytes("third/Party", "Party.java")), null),
            ),
        )

        assertEquals(
            setOf(
                "com/example/App", "com/example/Compress", "com/example/Owner", "com/example/Owner${'$'}Nested",
                "com/example/Secondary", "com/example/Selector", "com/example/Ucrop",
            ),
            result.ownedClasses.keys,
        )
        assertEquals(listOf("binding"), result.ownedClasses.getValue("com/example/Owner").fields.map(BytecodeField::name))
        assertTrue("calculate" in result.ownedClasses.getValue("com/example/Secondary").methods.map(BytecodeMethod::name))
        assertTrue("third/Party" in result.hierarchyClasses)
    }

    @Test
    fun `excludes ignored generated and Junk Code sources`() {
        gitInit()
        writeAllModuleSources()
        writeSource(":app", "src/main/java/com/example/Ignored.kt", "package com.example\nclass Ignored\nfun ignored() = 1")
        writeSource(
            ":app",
            "src/main/java/com/example/generated/Generated.kt",
            "package com.example.generated\nclass Generated\nfun generated() = 1",
        )
        writeSource(":app", "src/main/java/com/example/BuildConfig.kt", "package com.example\nfun generatedName() = 1")
        writeSource(
            ":app",
            "src/main/java/com/example/junkcode/Junk.kt",
            "package com.example.junkcode\nclass Junk\nfun junkTopLevel() = 1",
        )
        writeSource(
            ":app",
            "src/main/java/com/example/junkcode/JunkPart.kt",
            "@file:JvmName(\"JunkCombined\")\n@file:JvmMultifileClass\n" +
                "package com.example.junkcode\nfun junk() = 1\nval junkValue = 2",
        )
        repository.resolve(".gitignore").writeText("app/src/main/java/com/example/Ignored.kt\n")

        val result = buildAll(
            ":app" to classJar(
                "com/example/App" to classBytes("com/example/App", "App.kt"),
                "com/example/Ignored" to classBytes("com/example/Ignored", "Ignored.kt"),
                "com/example/IgnoredKt" to classBytes("com/example/IgnoredKt", "Ignored.kt", metadataKind = 2),
                "com/example/generated/Generated" to classBytes("com/example/generated/Generated", "Generated.kt"),
                "com/example/generated/GeneratedKt" to classBytes(
                    "com/example/generated/GeneratedKt", "Generated.kt", metadataKind = 2,
                ),
                "com/example/BuildConfigKt" to classBytes(
                    "com/example/BuildConfigKt", "BuildConfig.kt", metadataKind = 2,
                ),
                "com/example/junkcode/Junk" to classBytes("com/example/junkcode/Junk", "Junk.kt"),
                "com/example/junkcode/JunkKt" to classBytes(
                    "com/example/junkcode/JunkKt", "Junk.kt", metadataKind = 2,
                ),
                "com/example/junkcode/JunkCombined" to classBytes(
                    "com/example/junkcode/JunkCombined", "JunkPart.kt", metadataKind = 4,
                ),
                "com/example/junkcode/JunkCombined__JunkPartKt" to classBytes(
                    "com/example/junkcode/JunkCombined__JunkPartKt", "JunkPart.kt", metadataKind = 5,
                    metadataExtraString = "com/example/junkcode/JunkCombined",
                ),
            ),
        )

        assertFalse("com/example/Ignored" in result.ownedClasses)
        assertFalse("com/example/IgnoredKt" in result.ownedClasses)
        assertFalse("com/example/generated/Generated" in result.ownedClasses)
        assertFalse("com/example/generated/GeneratedKt" in result.ownedClasses)
        assertFalse("com/example/BuildConfigKt" in result.ownedClasses)
        assertFalse("com/example/junkcode/Junk" in result.ownedClasses)
        assertFalse("com/example/junkcode/JunkKt" in result.ownedClasses)
        assertFalse("com/example/junkcode/JunkCombined" in result.ownedClasses)
        assertFalse("com/example/junkcode/JunkCombined__JunkPartKt" in result.ownedClasses)
    }

    @Test
    fun `rejects a hierarchy copy that conflicts with the owned definition`() {
        gitInit()
        writeAllModuleSources()

        val failure = assertFailsWith<IllegalArgumentException> {
            buildAll(
                ":app" to classJar("com/example/App" to classBytes("com/example/App", "App.kt")),
                null to classJar(
                    "com/example/App" to classBytes("com/example/App", "App.kt", methods = listOf("different")),
                ),
            )
        }

        assertTrue(failure.message.orEmpty().contains("conflicting owned bytecode classes"))
    }

    @Test
    fun `an identical hierarchy copy keeps the single owned definition`() {
        gitInit()
        writeAllModuleSources()
        val ownedBytes = classBytes("com/example/App", "App.kt", methods = listOf("render"))

        val result = buildAll(
            ":app" to classJar("com/example/App" to ownedBytes),
            null to classJar("com/example/App" to ownedBytes),
        )

        assertEquals(":app", result.ownedClasses.getValue("com/example/App").modulePath)
        assertEquals(":app", result.hierarchyClasses.getValue("com/example/App").modulePath)
        assertEquals(listOf("render"), result.ownedClasses.getValue("com/example/App").methods.map(BytecodeMethod::name))
    }

    @Test
    fun `ranked hierarchy duplicates select the lowest precedence`() {
        gitInit()
        writeAllModuleSources()
        val preferred = classJar(
            "java/lang/invoke/MethodHandles" to classBytes(
                "java/lang/invoke/MethodHandles",
                "MethodHandles.java",
                methods = listOf("preferred"),
            ),
        )
        val fallback = classJar(
            "java/lang/invoke/MethodHandles" to classBytes(
                "java/lang/invoke/MethodHandles",
                "MethodHandles.java",
                access = Opcodes.ACC_PUBLIC or Opcodes.ACC_FINAL,
                fields = listOf("fallback"),
            ),
        )

        val result = OwnedBytecodeInventoryBuilder(repository, testHardeningOwnership(repository)).build(
            defaultOwnedInputs() + listOf(
                BytecodeInput(fallback, null, hierarchyPrecedence = 1),
                BytecodeInput(preferred, null, hierarchyPrecedence = 0),
            ),
        )

        val selected = result.hierarchyClasses.getValue("java/lang/invoke/MethodHandles")
        assertEquals(Opcodes.ACC_PUBLIC, selected.access)
        assertEquals(listOf("preferred"), selected.methods.map(BytecodeMethod::name))
        assertTrue(selected.fields.isEmpty())
    }

    @Test
    fun `ranked hierarchy selection is independent of input collection order`() {
        gitInit()
        writeAllModuleSources()
        val preferred = BytecodeInput(
            classJar("java/lang/invoke/MethodHandles" to classBytes("java/lang/invoke/MethodHandles", null)),
            null,
            hierarchyPrecedence = 0,
        )
        val fallback = BytecodeInput(
            classJar(
                "java/lang/invoke/MethodHandles" to classBytes(
                    "java/lang/invoke/MethodHandles",
                    null,
                    access = Opcodes.ACC_PUBLIC or Opcodes.ACC_FINAL,
                ),
            ),
            null,
            hierarchyPrecedence = 1,
        )
        val owned = defaultOwnedInputs()
        val builder = OwnedBytecodeInventoryBuilder(repository, testHardeningOwnership(repository))

        val forward = builder.build(owned + listOf(preferred, fallback))
        val reversed = builder.build(owned + listOf(fallback, preferred))

        assertEquals(
            forward.hierarchyClasses.getValue("java/lang/invoke/MethodHandles"),
            reversed.hierarchyClasses.getValue("java/lang/invoke/MethodHandles"),
        )
        assertEquals(Opcodes.ACC_PUBLIC, reversed.hierarchyClasses.getValue("java/lang/invoke/MethodHandles").access)
    }

    @Test
    fun `program input provenance remains independent of source ownership`() {
        gitInit()
        writeAllModuleSources()
        val appProgram = classJar(
            "com/example/App" to classBytes("com/example/App", "App.kt"),
            "generated/GeneratedBinding" to classBytes("generated/GeneratedBinding", "GeneratedBinding.java"),
            "generated/UnusedBinding" to classBytes("generated/UnusedBinding", "UnusedBinding.java"),
        )
        val ownedPrograms = defaultOwnedInputs(mapOf(":app" to appProgram)).map { input ->
            BytecodeInput(input.path, input.modulePath, programInput = true)
        }
        val runtimeProgram = BytecodeInput(
            classJar("external/RuntimeType" to classBytes("external/RuntimeType", "RuntimeType.java")),
            modulePath = null,
            hierarchyPrecedence = 1,
            programInput = true,
        )
        val bootLibrary = BytecodeInput(
            classJar("platform/LibraryType" to classBytes("platform/LibraryType", "LibraryType.java")),
            modulePath = null,
            hierarchyPrecedence = 0,
        )
        val compileOnly = BytecodeInput(
            classJar("compile/LibraryType" to classBytes("compile/LibraryType", "LibraryType.java")),
            modulePath = null,
            hierarchyPrecedence = 2,
        )

        val result = OwnedBytecodeInventoryBuilder(repository, testHardeningOwnership(repository)).build(
            ownedPrograms + runtimeProgram + bootLibrary + compileOnly,
        )

        assertTrue("com/example/App" in result.ownedClasses)
        assertFalse("generated/GeneratedBinding" in result.ownedClasses)
        assertFalse("generated/UnusedBinding" in result.ownedClasses)
        assertEquals(
            setOf(
                "com/example/App",
                "com/example/Base",
                "com/example/Compress",
                "com/example/Selector",
                "com/example/Ucrop",
                "external/RuntimeType",
                "generated/GeneratedBinding",
                "generated/UnusedBinding",
            ),
            result.programClasses,
        )
        assertFalse("platform/LibraryType" in result.programClasses)
        assertFalse("compile/LibraryType" in result.programClasses)
    }

    @Test
    fun `owned definition wins over an identical ranked hierarchy copy`() {
        gitInit()
        writeAllModuleSources()
        val rankedOwned = defaultOwnedInputs().map { input ->
            if (input.modulePath == ":app") {
                BytecodeInput(input.path, input.modulePath, hierarchyPrecedence = 1)
            } else {
                input
            }
        }
        val rankedHierarchy = BytecodeInput(
            classJar("com/example/App" to classBytes("com/example/App", "App.kt")),
            null,
            hierarchyPrecedence = 0,
        )

        val result = OwnedBytecodeInventoryBuilder(repository, testHardeningOwnership(repository)).build(
            rankedOwned + rankedHierarchy,
        )

        assertEquals(":app", result.hierarchyClasses.getValue("com/example/App").modulePath)
    }

    @Test
    fun `multiple owned producers for one class remain fatal`() {
        gitInit()
        writeAllModuleSources()
        val duplicate = classJar("com/example/App" to classBytes("com/example/App", "App.kt"))

        val failure = assertFailsWith<IllegalArgumentException> {
            OwnedBytecodeInventoryBuilder(repository, testHardeningOwnership(repository)).build(
                defaultOwnedInputs() + BytecodeInput(duplicate, ":app"),
            )
        }

        assertTrue(failure.message.orEmpty().contains("multiple owned bytecode producers"))
    }

    @Test
    fun `generated Android resource classes are excluded from owned and hierarchy inputs`() {
        gitInit()
        writeAllModuleSources()
        val owned = classJar(
            "com/example/App" to classBytes("com/example/App", "App.kt"),
            "third/library/R" to classBytes("third/library/R", "R.java", fields = listOf("owned")),
            "third/library/R${'$'}id" to classBytes("third/library/R${'$'}id", "R.java", fields = listOf("owned")),
        )
        val hierarchy = classJar(
            "third/library/R" to classBytes("third/library/R", "R.java", fields = listOf("external")),
            "third/library/R${'$'}id" to classBytes("third/library/R${'$'}id", "R.java", fields = listOf("external")),
        )

        val result = buildAll(":app" to owned, null to hierarchy)

        assertFalse("third/library/R" in result.hierarchyClasses)
        assertFalse("third/library/R${'$'}id" in result.hierarchyClasses)
    }

    @Test
    fun `unranked hierarchy duplicate remains fatal`() {
        gitInit()
        writeAllModuleSources()
        val first = classJar("third/Party" to classBytes("third/Party", null))
        val second = classJar("third/Party" to classBytes("third/Party", null, methods = listOf("other")))

        val failure = assertFailsWith<IllegalArgumentException> {
            OwnedBytecodeInventoryBuilder(repository, testHardeningOwnership(repository)).build(
                defaultOwnedInputs() + listOf(BytecodeInput(first, null), BytecodeInput(second, null)),
            )
        }

        assertTrue(failure.message.orEmpty().contains("explicit unique precedence"))
    }

    @Test
    fun `equal hierarchy precedence fails closed`() {
        gitInit()
        writeAllModuleSources()
        val first = classJar("third/Party" to classBytes("third/Party", null))
        val second = classJar("third/Party" to classBytes("third/Party", null, fields = listOf("other")))

        val failure = assertFailsWith<IllegalArgumentException> {
            OwnedBytecodeInventoryBuilder(repository, testHardeningOwnership(repository)).build(
                defaultOwnedInputs() + listOf(
                    BytecodeInput(first, null, hierarchyPrecedence = 0),
                    BytecodeInput(second, null, hierarchyPrecedence = 0),
                ),
            )
        }

        assertTrue(failure.message.orEmpty().contains("explicit unique precedence"))
    }

    @Test
    fun `negative hierarchy precedence fails closed`() {
        gitInit()
        writeAllModuleSources()

        val failure = assertFailsWith<IllegalArgumentException> {
            OwnedBytecodeInventoryBuilder(repository, testHardeningOwnership(repository)).build(
                defaultOwnedInputs() + BytecodeInput(
                    classJar("third/Party" to classBytes("third/Party", null)),
                    null,
                    hierarchyPrecedence = -1,
                ),
            )
        }

        assertTrue(failure.message.orEmpty().contains("hierarchy precedence must be non-negative"))
    }

    @Test
    fun `rejects unsafe ZIP entries before reading bytecode`() {
        gitInit()
        writeAllModuleSources()
        val unsafe = repository.resolve("unsafe.jar")
        ZipOutputStream(Files.newOutputStream(unsafe)).use { zip ->
            zip.putNextEntry(ZipEntry("../com/example/App.class"))
            zip.write(classBytes("com/example/App", "App.kt"))
            zip.closeEntry()
        }

        val failure = assertFailsWith<IllegalArgumentException> { buildAll(":app" to unsafe) }

        assertTrue(failure.message.orEmpty().contains("unsafe bytecode ZIP entry"))
    }

    @Test
    fun `accepts safe ZIP directory entries`() {
        gitInit()
        writeAllModuleSources()
        val archive = Files.createTempFile(repository, "classes-with-directory", ".jar")
        ZipOutputStream(Files.newOutputStream(archive)).use { zip ->
            zip.putNextEntry(ZipEntry("META-INF/"))
            zip.closeEntry()
            zip.putNextEntry(ZipEntry("com/example/App.class"))
            zip.write(classBytes("com/example/App", "App.kt"))
            zip.closeEntry()
        }

        val result = buildAll(":app" to archive)

        assertTrue("com/example/App" in result.ownedClasses)
    }

    @Test
    fun `accepts special dependency classes and ignores versioned classes`() {
        gitInit()
        writeAllModuleSources()
        val dependency = Files.createTempFile(repository, "dependency", ".jar")
        ZipOutputStream(Files.newOutputStream(dependency)).use { zip ->
            zip.putNextEntry(ZipEntry("module-info.class")); zip.write(byteArrayOf(0)); zip.closeEntry()
            zip.putNextEntry(ZipEntry("third/package-info.class")); zip.write(byteArrayOf(0)); zip.closeEntry()
            zip.putNextEntry(ZipEntry("META-INF/versions/9/third/Party.class")); zip.write(classBytes("third/Party", "Party.java")); zip.closeEntry()
            zip.putNextEntry(ZipEntry("META-INF/versions/9/Legacy.class")); zip.write(byteArrayOf(0)); zip.closeEntry()
            zip.putNextEntry(ZipEntry("third/Party.class")); zip.write(classBytes("third/Party", "Party.java")); zip.closeEntry()
        }

        val result = buildAll(null to dependency)

        assertTrue("third/Party" in result.hierarchyClasses)
        assertFalse("module-info" in result.hierarchyClasses)
    }

    @Test
    fun `filters special classes consistently from directory inputs`() {
        gitInit()
        writeAllModuleSources()
        val directory = repository.resolve("dependency-classes")
        directory.resolve("module-info.class").also { it.parent.createDirectories(); it.writeBytes(byteArrayOf(0)) }
        directory.resolve("third/package-info.class").also { it.parent.createDirectories(); it.writeBytes(byteArrayOf(0)) }
        directory.resolve("META-INF/versions/9/third/Party.class").also {
            it.parent.createDirectories()
            it.writeBytes(classBytes("third/Party", "Party.java"))
        }
        directory.resolve("META-INF/versions/9/Legacy.class").also {
            it.parent.createDirectories()
            it.writeBytes(byteArrayOf(0))
        }
        directory.resolve("third/Party.class").also {
            it.parent.createDirectories()
            it.writeBytes(classBytes("third/Party", "Party.java"))
        }

        val result = buildAll(null to directory)

        assertEquals(setOf("third/Party"), result.hierarchyClasses.keys - result.ownedClasses.keys)
    }

    @Test
    fun `rejects malformed ZIP input`() {
        gitInit()
        writeAllModuleSources()
        val malformed = repository.resolve("malformed.jar")
        malformed.writeBytes(byteArrayOf(1, 2, 3))

        val failure = assertFailsWith<IllegalArgumentException> { buildAll(":app" to malformed) }

        assertTrue(failure.message.orEmpty().contains("invalid bytecode ZIP"))
    }

    @Test
    fun `reads directory input deterministically and rejects directory symlinks`() {
        gitInit()
        writeAllModuleSources()
        val directory = repository.resolve("classes")
        val classFile = directory.resolve("com/example/App.class")
        classFile.parent.createDirectories()
        classFile.writeBytes(classBytes("com/example/App", "App.kt", metadataKind = 1, metadataExtraString = "stable"))

        val inputs = testHardeningOwnership(repository).modulePaths.map { module ->
            BytecodeInput(if (module == ":app") directory else classJar(defaultClass(module)), module)
        }
        val first = OwnedBytecodeInventoryBuilder(repository, testHardeningOwnership(repository)).build(inputs)
        val second = OwnedBytecodeInventoryBuilder(repository, testHardeningOwnership(repository)).build(inputs.reversed())

        assertEquals(first, second)
        assertEquals(first.ownedClasses.keys.sorted(), first.ownedClasses.keys.toList())
        assertEquals(first.hierarchyClasses.keys.sorted(), first.hierarchyClasses.keys.toList())
        assertEquals("stable", first.ownedClasses.getValue("com/example/App").kotlinMetadataExtraString)
        val link = directory.resolve("linked.class")
        Files.createSymbolicLink(link, classFile)
        val failure = assertFailsWith<IllegalArgumentException> { buildAll(":app" to directory) }
        assertTrue(failure.message.orEmpty().contains("symbolic link"))
    }

    @Test
    fun `models and inventory do not expose mutable inputs`() {
        val interfaces = mutableListOf("java/io/Serializable")
        val annotations = mutableSetOf("Lsample/Annotation;")
        val fields = mutableListOf(BytecodeField("sample/Thing", "field", "I", 0, annotations))
        val value = BytecodeClass("sample/Thing", ":app", "Thing.java", null, 0, "java/lang/Object", interfaces, annotations, fields, emptyList())
        interfaces += "java/lang/Runnable"
        annotations.clear()
        fields.clear()
        val inventory = BytecodeInventory(mapOf("sample/Thing" to value), emptyMap())

        assertEquals(listOf("java/io/Serializable"), value.interfaces)
        assertEquals(setOf("Lsample/Annotation;"), value.annotations)
        assertFailsWith<UnsupportedOperationException> { (inventory.ownedClasses as MutableMap)["x"] = value }

        val firstMetadata = BytecodeClass(
            "sample/Metadata", ":app", "Metadata.kt", null, 0, "java/lang/Object",
            emptyList(), emptySet(), emptyList(), emptyList(), kotlinMetadataKind = 5,
            kotlinMetadataExtraString = "sample/Facade",
        )
        val secondMetadata = BytecodeClass(
            "sample/Metadata", ":app", "Metadata.kt", null, 0, "java/lang/Object",
            emptyList(), emptySet(), emptyList(), emptyList(), kotlinMetadataKind = 5,
            kotlinMetadataExtraString = "sample/OtherFacade",
        )
        assertFalse(firstMetadata == secondMetadata)
        assertFalse(firstMetadata.hashCode() == secondMetadata.hashCode())
    }

    @Test
    fun `proves ordinary Kotlin classes and exact file facades by metadata kind`() {
        gitInit()
        writeAllModuleSources()
        writeSource(":app", "src/main/java/com/example/ClassOnly.kt", "package com.example\nclass ClassOnly")
        writeSource(":app", "src/main/java/com/example/Facade.kt", "package com.example\nfun visible() = 1")
        writeSource(
            ":app",
            "src/main/java/com/example/Named.kt",
            "@file:kotlin.jvm.JvmName(\"NamedFacade\")\npackage com.example\nfun named() = 1",
        )
        writeSource(":app", "src/main/java/com/example/Foo.kt", "package com.example\nclass FooKt")

        val result = buildAll(":app" to classJar(
            "com/example/App" to classBytes("com/example/App", "App.kt"),
            "com/example/ClassOnlyKt" to classBytes("com/example/ClassOnlyKt", "ClassOnly.kt", metadataKind = 2),
            "com/example/FacadeKt" to classBytes("com/example/FacadeKt", "Facade.kt", metadataKind = 2),
            "com/example/NamedFacade" to classBytes("com/example/NamedFacade", "Named.kt", metadataKind = 2),
            "com/example/FooKt" to classBytes("com/example/FooKt", "Foo.kt", metadataKind = 1),
        ))

        assertFalse("com/example/ClassOnlyKt" in result.ownedClasses)
        assertTrue("com/example/FacadeKt" in result.ownedClasses)
        assertTrue("com/example/NamedFacade" in result.ownedClasses)
        assertTrue("com/example/FooKt" in result.ownedClasses)
    }

    @Test
    fun `proves a genuine two part Kotlin multifile facade and exact parts`() {
        gitInit()
        writeAllModuleSources()
        writeSource(
            ":app",
            "src/main/java/com/example/PartOne.kt",
            "@file:JvmName(\"Combined\")\n@file:JvmMultifileClass\npackage com.example\nfun first() = 1",
        )
        writeSource(
            ":app",
            "src/main/java/com/example/PartTwo.kt",
            "@file:kotlin.jvm.JvmName(\"Combined\")\n@file:kotlin.jvm.JvmMultifileClass\npackage com.example\nval second = 2",
        )

        val result = buildAll(":app" to classJar(
            "com/example/App" to classBytes("com/example/App", "App.kt"),
            "com/example/Combined" to classBytes("com/example/Combined", "PartOne.kt", metadataKind = 4),
            "com/example/Combined__PartOneKt" to classBytes(
                "com/example/Combined__PartOneKt", "PartOne.kt", metadataKind = 5,
                metadataExtraString = "com/example/Combined",
            ),
            "com/example/Combined__PartTwoKt" to classBytes(
                "com/example/Combined__PartTwoKt", "PartTwo.kt", metadataKind = 5,
                metadataExtraString = "com/example/Combined",
            ),
            "com/example/Combined__PartOneKt${'$'}lambda${'$'}1" to classBytes(
                "com/example/Combined__PartOneKt${'$'}lambda${'$'}1", "PartOne.kt", metadataKind = 3,
            ),
            "com/example/Combined__PartOneKt${'$'}anonymous${'$'}1" to classBytes(
                "com/example/Combined__PartOneKt${'$'}anonymous${'$'}1", "PartOne.kt", metadataKind = 1,
            ),
            "com/example/Combined${'$'}Shared${'$'}1" to classBytes(
                "com/example/Combined${'$'}Shared${'$'}1", "PartTwo.kt", metadataKind = 3,
            ),
        ))

        assertTrue("com/example/Combined" in result.ownedClasses)
        assertTrue("com/example/Combined__PartOneKt" in result.ownedClasses)
        assertTrue("com/example/Combined__PartTwoKt" in result.ownedClasses)
        assertTrue("com/example/Combined__PartOneKt${'$'}lambda${'$'}1" in result.ownedClasses)
        assertTrue("com/example/Combined__PartOneKt${'$'}anonymous${'$'}1" in result.ownedClasses)
        assertTrue("com/example/Combined${'$'}Shared${'$'}1" in result.ownedClasses)
    }

    @Test
    fun `owns nested production classes only below a verified Kotlin file facade root`() {
        gitInit()
        writeAllModuleSources()
        writeSource(":app", "src/main/java/com/example/Facade.kt", "package com.example\nfun visible() = 1")

        val result = buildAll(":app" to classJar(
            "com/example/App" to classBytes("com/example/App", "App.kt"),
            "com/example/FacadeKt" to classBytes("com/example/FacadeKt", "Facade.kt", metadataKind = 2),
            "com/example/FacadeKt${'$'}lambda${'$'}1" to classBytes(
                "com/example/FacadeKt${'$'}lambda${'$'}1", "Facade.kt", metadataKind = 3,
            ),
            "com/example/FacadeKt${'$'}coroutine${'$'}1" to classBytes(
                "com/example/FacadeKt${'$'}coroutine${'$'}1", "Facade.kt", metadataKind = 3,
            ),
            "com/example/FacadeKt${'$'}WhenMappings" to classBytes(
                "com/example/FacadeKt${'$'}WhenMappings", "Facade.kt", metadataKind = 3,
            ),
            "com/example/FacadeKt${'$'}anonymous${'$'}1" to classBytes(
                "com/example/FacadeKt${'$'}anonymous${'$'}1", "Facade.kt", metadataKind = 1,
            ),
        ))

        assertTrue("com/example/FacadeKt${'$'}lambda${'$'}1" in result.ownedClasses)
        assertTrue("com/example/FacadeKt${'$'}coroutine${'$'}1" in result.ownedClasses)
        assertTrue("com/example/FacadeKt${'$'}WhenMappings" in result.ownedClasses)
        assertTrue("com/example/FacadeKt${'$'}anonymous${'$'}1" in result.ownedClasses)
    }

    @Test
    fun `rejects a metadata-free dependent below a Kotlin declared root`() {
        gitInit()
        writeAllModuleSources()
        writeSource(":app", "src/main/java/com/example/Foo.kt", "package com.example\nclass Foo")

        val result = buildAll(":app" to classJar(
            "com/example/App" to classBytes("com/example/App", "App.kt"),
            "com/example/Foo" to classBytes("com/example/Foo", "Foo.kt", metadataKind = 1),
            "com/example/Foo${'$'}Injected" to classBytes("com/example/Foo${'$'}Injected", "Foo.kt"),
        ))

        assertFalse("com/example/Foo${'$'}Injected" in result.ownedClasses)
        assertTrue("com/example/Foo${'$'}Injected" in result.hierarchyClasses)
    }

    @Test
    fun `rejects dependent Kotlin classes without an exact verified root and source`() {
        gitInit()
        writeAllModuleSources()
        writeSource(":app", "src/main/java/com/example/Facade.kt", "package com.example\nfun visible() = 1")
        writeSource(":app", "src/main/java/com/example/Other.kt", "package com.example\nclass Other")
        writeSource(":app", "src/main/java/com/example/Orphan.kt", "package com.example\nfun orphan() = 1")
        writeSource(
            ":app",
            "src/main/java/com/example/WrongOne.kt",
            "@file:JvmName(\"WrongCombined\")\n@file:JvmMultifileClass\npackage com.example\nfun wrongOne() = 1",
        )
        writeSource(
            ":app",
            "src/main/java/com/example/WrongTwo.kt",
            "@file:JvmName(\"WrongCombined\")\n@file:JvmMultifileClass\npackage com.example\nfun wrongTwo() = 2",
        )

        val rejected = setOf(
            "com/example/FacadeKt${'$'}wrongSource${'$'}1",
            "other/FacadeKt${'$'}crossPackage${'$'}1",
            "com/example/Arbitrary${'$'}lambda${'$'}1",
            "com/example/FacadeKt${'$'}missingSource${'$'}1",
            "com/example/OrphanKt${'$'}lambda${'$'}1",
            "com/example/WrongCombined__WrongOneKt",
            "com/example/WrongCombined__WrongOneKt${'$'}lambda${'$'}1",
        )
        val result = buildAll(":app" to classJar(
            "com/example/App" to classBytes("com/example/App", "App.kt"),
            "com/example/FacadeKt" to classBytes("com/example/FacadeKt", "Facade.kt", metadataKind = 2),
            "com/example/FacadeKt${'$'}wrongSource${'$'}1" to classBytes(
                "com/example/FacadeKt${'$'}wrongSource${'$'}1", "Other.kt", metadataKind = 3,
            ),
            "other/FacadeKt${'$'}crossPackage${'$'}1" to classBytes(
                "other/FacadeKt${'$'}crossPackage${'$'}1", "Facade.kt", metadataKind = 3,
            ),
            "com/example/Arbitrary${'$'}lambda${'$'}1" to classBytes(
                "com/example/Arbitrary${'$'}lambda${'$'}1", "Facade.kt", metadataKind = 3,
            ),
            "com/example/FacadeKt${'$'}missingSource${'$'}1" to classBytes(
                "com/example/FacadeKt${'$'}missingSource${'$'}1", null, metadataKind = 3,
            ),
            "com/example/OrphanKt${'$'}lambda${'$'}1" to classBytes(
                "com/example/OrphanKt${'$'}lambda${'$'}1", "Orphan.kt", metadataKind = 3,
            ),
            "com/example/WrongCombined__WrongOneKt" to classBytes(
                "com/example/WrongCombined__WrongOneKt", "WrongOne.kt", metadataKind = 5,
                metadataExtraString = "com/example/OtherFacade",
            ),
            "com/example/WrongCombined__WrongOneKt${'$'}lambda${'$'}1" to classBytes(
                "com/example/WrongCombined__WrongOneKt${'$'}lambda${'$'}1", "WrongOne.kt", metadataKind = 3,
            ),
        ))

        assertTrue(rejected.none(result.ownedClasses::containsKey))
        assertTrue(rejected.all(result.hierarchyClasses::containsKey))
    }

    @Test
    fun `does not prove an exact shared Kotlin multifile facade without SourceFile`() {
        gitInit()
        writeAllModuleSources()
        writeSource(
            ":app",
            "src/main/java/com/example/MissingOne.kt",
            "@file:JvmName(\"Missing\")\n@file:JvmMultifileClass\npackage com.example\nfun first() = 1",
        )
        writeSource(
            ":app",
            "src/main/java/com/example/MissingTwo.kt",
            "@file:JvmName(\"Missing\")\n@file:JvmMultifileClass\npackage com.example\nfun second() = 2",
        )

        val result = buildAll(":app" to classJar(
            "com/example/App" to classBytes("com/example/App", "App.kt"),
            "com/example/Missing" to classBytes("com/example/Missing", null, metadataKind = 4),
        ))

        assertFalse("com/example/Missing" in result.ownedClasses)
        assertTrue("com/example/Missing" in result.hierarchyClasses)
    }

    @Test
    fun `rejects single part missing source and fabricated Kotlin metadata ownership`() {
        gitInit()
        writeAllModuleSources()
        writeSource(
            ":app",
            "src/main/java/com/example/Part.kt",
            "@file:JvmName(\"Combined\")\n@file:JvmMultifileClass\npackage com.example\nfun part() = 1",
        )
        writeSource(":app", "src/main/java/com/example/Facade.kt", "package com.example\nfun facade() = 1")

        val result = buildAll(":app" to classJar(
            "com/example/App" to classBytes("com/example/App", "App.kt"),
            "com/example/Combined" to classBytes("com/example/Combined", "Part.kt", metadataKind = 4),
            "com/example/CombinedMissingSource" to classBytes("com/example/CombinedMissingSource", null, metadataKind = 4),
            "com/example/Combined__PartKt" to classBytes(
                "com/example/Combined__PartKt", "Part.kt", metadataKind = 5,
                metadataExtraString = "com/example/Combined",
            ),
            "com/example/Combined__PartKt${'$'}lambda${'$'}1" to classBytes(
                "com/example/Combined__PartKt${'$'}lambda${'$'}1", "Part.kt", metadataKind = 3,
            ),
            "com/example/Arbitrary" to classBytes("com/example/Arbitrary", "Facade.kt", metadataKind = 2),
            "other/FacadeKt" to classBytes("other/FacadeKt", "Facade.kt", metadataKind = 2),
            "other/Combined__PartKt" to classBytes(
                "other/Combined__PartKt", "Part.kt", metadataKind = 5,
                metadataExtraString = "com/example/Combined",
            ),
        ))

        assertFalse("com/example/Combined" in result.ownedClasses)
        assertFalse("com/example/CombinedMissingSource" in result.ownedClasses)
        assertFalse("com/example/Combined__PartKt" in result.ownedClasses)
        assertFalse("com/example/Combined__PartKt${'$'}lambda${'$'}1" in result.ownedClasses)
        assertFalse("com/example/Arbitrary" in result.ownedClasses)
        assertFalse("other/FacadeKt" in result.ownedClasses)
        assertFalse("other/Combined__PartKt" in result.ownedClasses)
    }

    @Test
    fun `comments and strings cannot spoof Kotlin file annotations`() {
        gitInit()
        writeAllModuleSources()
        writeSource(
            ":app",
            "src/main/java/com/example/Spoof.kt",
            """
                /* @file:JvmName("CommentFacade") */
                package com.example
                val text = "@file:JvmName(\"StringFacade\")"
                fun real() = 1
            """.trimIndent(),
        )

        val result = buildAll(":app" to classJar(
            "com/example/App" to classBytes("com/example/App", "App.kt"),
            "com/example/SpoofKt" to classBytes("com/example/SpoofKt", "Spoof.kt", metadataKind = 2),
            "com/example/CommentFacade" to classBytes("com/example/CommentFacade", "Spoof.kt", metadataKind = 2),
            "com/example/StringFacade" to classBytes("com/example/StringFacade", "Spoof.kt", metadataKind = 2),
        ))

        assertTrue("com/example/SpoofKt" in result.ownedClasses)
        assertFalse("com/example/CommentFacade" in result.ownedClasses)
        assertFalse("com/example/StringFacade" in result.ownedClasses)
    }

    @Test
    fun `fun interfaces are ordinary declarations and do not synthesize file facades`() {
        gitInit()
        writeAllModuleSources()
        writeSource(":app", "src/main/java/com/example/Api.kt", "package com.example\nfun interface Api { fun call() }")

        val result = buildAll(":app" to classJar(
            "com/example/App" to classBytes("com/example/App", "App.kt"),
            "com/example/Api" to classBytes("com/example/Api", "Api.kt", metadataKind = 1),
            "com/example/ApiKt" to classBytes("com/example/ApiKt", "Api.kt", metadataKind = 2),
        ))

        assertTrue("com/example/Api" in result.ownedClasses)
        assertFalse("com/example/ApiKt" in result.ownedClasses)
    }

    @Test
    fun `backtick identifiers cannot promote nested Kotlin declarations to top level`() {
        gitInit()
        writeAllModuleSources()
        writeSource(
            ":app",
            "src/main/java/com/example/Outer.kt",
            """
                package com.example
                class Outer {
                    fun `}`() = Unit
                    class Nested
                }
            """.trimIndent(),
        )

        val result = buildAll(":app" to classJar(
            "com/example/App" to classBytes("com/example/App", "App.kt"),
            "com/example/Outer" to classBytes("com/example/Outer", "Outer.kt", metadataKind = 1),
            "com/example/Outer${'$'}Nested" to classBytes(
                "com/example/Outer${'$'}Nested", "Outer.kt", metadataKind = 1,
            ),
            "com/example/Nested" to classBytes("com/example/Nested", "Outer.kt", metadataKind = 1),
        ))

        assertTrue("com/example/Outer" in result.ownedClasses)
        assertTrue("com/example/Outer${'$'}Nested" in result.ownedClasses)
        assertFalse("com/example/Nested" in result.ownedClasses)
    }

    @Test
    fun `does not own a class without SourceFile`() {
        gitInit()
        writeAllModuleSources()
        writeSource(":app", "src/main/java/com/example/Other.kt", "package com.example\nclass Other")
        val result = buildAll(":app" to classJar(
            "com/example/App" to classBytes("com/example/App", null),
            "com/example/Other" to classBytes("com/example/Other", "Other.kt"),
        ))

        assertFalse("com/example/App" in result.ownedClasses)
        assertTrue("com/example/App" in result.hierarchyClasses)
    }

    @Test
    fun `captures ASM class and member metadata`() {
        gitInit()
        writeAllModuleSources()
        val result = buildAll(":app" to classJar(
            "com/example/App" to classBytes(
                internalName = "com/example/App",
                sourceFile = "App.kt",
                fields = listOf("value"),
                methods = listOf("call"),
                access = Opcodes.ACC_PUBLIC or Opcodes.ACC_FINAL,
                superName = "java/lang/Number",
                interfaces = listOf("java/io/Serializable"),
                annotations = listOf("Lsample/ClassMarker;"),
                memberAnnotations = listOf("Lsample/MemberMarker;"),
            ),
        ))

        val value = result.ownedClasses.getValue("com/example/App")
        assertEquals(Opcodes.ACC_PUBLIC or Opcodes.ACC_FINAL, value.access)
        assertEquals("java/lang/Number", value.superName)
        assertEquals(listOf("java/io/Serializable"), value.interfaces)
        assertEquals(setOf("Lsample/ClassMarker;"), value.annotations)
        assertEquals(Opcodes.ACC_PRIVATE, value.fields.single().access)
        assertEquals("com/example/App", value.fields.single().owner)
        assertEquals("Ljava/lang/Object;", value.fields.single().descriptor)
        assertEquals(setOf("Lsample/MemberMarker;"), value.fields.single().annotations)
        assertEquals(Opcodes.ACC_PUBLIC, value.methods.single().access)
        assertEquals("com/example/App", value.methods.single().owner)
        assertEquals("()V", value.methods.single().descriptor)
        assertEquals(setOf("Lsample/MemberMarker;"), value.methods.single().annotations)
    }

    @Test
    fun `rejects class entry whose header internal name differs`() {
        gitInit()
        writeAllModuleSources()

        val failure = assertFailsWith<IllegalArgumentException> {
            buildAll(":app" to classJar("com/example/App" to classBytes("com/example/Other", "App.kt")))
        }

        assertTrue(failure.message.orEmpty().contains("bytecode class name mismatch"))
    }

    @Test
    fun `accepts Kotlin generated JVM class names`() {
        gitInit()
        writeAllModuleSources()
        val internalName =
            "com/example/core/net/ServiceCreator\$httpClient_delegate\$lambda\$0\$0\$\$inlined\$-addInterceptor\$1"

        val result = buildAll(null to classJar(internalName to classBytes(internalName, null)))

        assertTrue(internalName in result.hierarchyClasses)
    }

    @Test
    fun `rejects JVM forbidden class name characters`() {
        gitInit()
        writeAllModuleSources()

        listOf('.', ';', '[').forEach { forbidden ->
            val internalName = "com/example/Invalid${forbidden}Name"
            val failure = assertFailsWith<IllegalArgumentException> {
                buildAll(null to classJar(internalName to classBytes(internalName, null)))
            }

            assertTrue(failure.message.orEmpty().contains("invalid bytecode class entry"))
        }
    }

    @Test
    fun `rejects symlinked bytecode inputs`() {
        gitInit()
        writeAllModuleSources()
        val target = classJar("com/example/App" to classBytes("com/example/App", "App.kt"))
        val link = repository.resolve("linked.jar")
        Files.createSymbolicLink(link, target.fileName)

        val failure = assertFailsWith<IllegalArgumentException> { buildAll(":app" to link) }

        assertTrue(failure.message.orEmpty().contains("symbolic link"))
    }

    @Test
    fun `rejects an owned bytecode input below a symlinked repository ancestor`() {
        gitInit()
        writeAllModuleSources()
        val target = repository.resolve("actual-bytecode")
        target.createDirectories()
        val archive = classJar("com/example/App" to classBytes("com/example/App", "App.kt"))
        Files.move(archive, target.resolve("classes.jar"))
        Files.createSymbolicLink(repository.resolve("linked-bytecode"), target.fileName)

        val failure = assertFailsWith<IllegalArgumentException> {
            buildAll(":app" to repository.resolve("linked-bytecode/classes.jar"))
        }

        assertTrue(failure.message.orEmpty().contains("symbolic link"))
    }

    @Test
    fun `rejects an external symlink alias targeting an owned repository bytecode input`() {
        gitInit()
        writeAllModuleSources()
        val archive = classJar("com/example/App" to classBytes("com/example/App", "App.kt"))
        val external = Files.createTempDirectory(repository.parent, "repository-alias")
        val alias = external.resolve("linked-repository")
        Files.createSymbolicLink(alias, repository)

        try {
            val failure = assertFailsWith<IllegalArgumentException> {
                buildAll(":app" to alias.resolve(archive.fileName))
            }
            assertTrue(failure.message.orEmpty().contains("symbolic link"))
        } finally {
            Files.deleteIfExists(alias)
            Files.deleteIfExists(external)
        }
    }

    @Test
    fun `accepts a normal external hierarchy cache and rejects its leaf symlink`() {
        gitInit()
        writeAllModuleSources()
        val external = Files.createTempDirectory(repository.parent, "hierarchy-cache")
        val dependency = external.resolve("dependency.jar")
        Files.move(classJar("third/Party" to classBytes("third/Party", "Party.java")), dependency)

        val result = buildAll(null to dependency)
        assertTrue("third/Party" in result.hierarchyClasses)

        val link = external.resolve("linked.jar")
        Files.createSymbolicLink(link, dependency.fileName)
        val failure = assertFailsWith<IllegalArgumentException> { buildAll(null to link) }
        assertTrue(failure.message.orEmpty().contains("symbolic link"))
    }

    @Test
    fun `proves exact legal Java dollar declarations before unique longest nested prefixes`() {
        gitInit()
        writeAllModuleSources()
        writeSource(
            ":core",
            "src/main/java/com/example/Dollar.java",
            "package com.example; class Outer${'$'}Name {} class Outer${'$'}Name${'$'}Inner {}",
        )

        val result = buildAll(":core" to classJar(
            "com/example/Base" to classBytes("com/example/Base", "Base.kt"),
            "com/example/Outer${'$'}Name" to classBytes("com/example/Outer${'$'}Name", "Dollar.java"),
            "com/example/Outer${'$'}Name${'$'}Inner${'$'}Child" to classBytes(
                "com/example/Outer${'$'}Name${'$'}Inner${'$'}Child", "Dollar.java",
            ),
        ))

        assertTrue("com/example/Outer${'$'}Name" in result.ownedClasses)
        assertTrue("com/example/Outer${'$'}Name${'$'}Inner${'$'}Child" in result.ownedClasses)
    }

    @Test
    fun `rejects raw duplicate ZIP entry names during archive validation`() {
        gitInit()
        writeAllModuleSources()
        val duplicate = repository.resolve("duplicate.jar")
        writeRawZip(
            duplicate,
            listOf(
                "com/example/App.class" to classBytes("com/example/App", "App.kt"),
                "com/example/App.class" to classBytes("com/example/App", "App.kt"),
            ),
        )

        val failure = assertFailsWith<IllegalArgumentException> { buildAll(":app" to duplicate) }

        assertTrue(failure.message.orEmpty().contains("duplicate bytecode ZIP entries"))
    }

    @Test
    fun `does not attribute a class to the wrong project component`() {
        gitInit()
        writeAllModuleSources()
        writeSource(":core", "src/main/java/com/example/BaseOnly.kt", "package com.example\nclass BaseOnly")

        val result = buildAll(
            ":app" to classJar(
                "com/example/App" to classBytes("com/example/App", "App.kt"),
                "com/example/BaseOnly" to classBytes("com/example/BaseOnly", "BaseOnly.kt"),
            ),
        )

        assertFalse("com/example/BaseOnly" in result.ownedClasses)
        assertTrue("com/example/BaseOnly" in result.hierarchyClasses)
    }

    private fun buildAll(vararg replacements: Pair<String?, Path>): BytecodeInventory {
        val overridden = replacements.toMap()
        val inputs = defaultOwnedInputs(overridden) + listOfNotNull(overridden[null]?.let { BytecodeInput(it, null) })
        return OwnedBytecodeInventoryBuilder(repository, testHardeningOwnership(repository)).build(inputs)
    }

    private fun defaultOwnedInputs(overridden: Map<String?, Path> = emptyMap()): List<BytecodeInput> =
        testHardeningOwnership(repository).modulePaths.sorted().map { module ->
            BytecodeInput(
                overridden[module] ?: classJar(defaultClass(module)),
                module,
            )
        }

    private fun writeAllModuleSources() {
        writeSource(":app", "src/main/java/com/example/App.kt", "package com.example\nclass App")
        writeSource(":core", "src/main/java/com/example/Base.kt", "package com.example\nclass Base")
        writeSource(":compress", "src/main/java/com/example/Compress.kt", "package com.example\nclass Compress")
        writeSource(":selector", "src/main/java/com/example/Selector.kt", "package com.example\nclass Selector")
        writeSource(":ucrop", "src/main/java/com/example/Ucrop.kt", "package com.example\nclass Ucrop")
    }

    private fun defaultClass(module: String): Pair<String, ByteArray> = when (module) {
        ":app" -> "com/example/App" to classBytes("com/example/App", "App.kt")
        ":core" -> "com/example/Base" to classBytes("com/example/Base", "Base.kt")
        ":compress" -> "com/example/Compress" to classBytes("com/example/Compress", "Compress.kt")
        ":selector" -> "com/example/Selector" to classBytes("com/example/Selector", "Selector.kt")
        ":ucrop" -> "com/example/Ucrop" to classBytes("com/example/Ucrop", "Ucrop.kt")
        else -> error("unexpected module $module")
    }

    private fun writeSource(module: String, relative: String, text: String) {
        repository.resolve(module.removePrefix(":")).resolve(relative).also { file ->
            file.parent.createDirectories()
            file.writeText(text)
        }
    }

    private fun classJar(vararg classes: Pair<String, ByteArray>): Path {
        val path = Files.createTempFile(repository, "classes", ".jar")
        ZipOutputStream(Files.newOutputStream(path)).use { zip ->
            classes.forEach { (internalName, bytes) ->
                zip.putNextEntry(ZipEntry("$internalName.class"))
                zip.write(bytes)
                zip.closeEntry()
            }
        }
        return path
    }

    private fun classBytes(
        internalName: String,
        sourceFile: String?,
        fields: List<String> = emptyList(),
        methods: List<String> = emptyList(),
        metadataKind: Int? = null,
        metadataExtraString: String? = null,
        access: Int = Opcodes.ACC_PUBLIC,
        superName: String = "java/lang/Object",
        interfaces: List<String> = emptyList(),
        annotations: List<String> = emptyList(),
        memberAnnotations: List<String> = emptyList(),
    ): ByteArray = ClassWriter(0).apply {
        visit(Opcodes.V17, access, internalName, null, superName, interfaces.toTypedArray())
        sourceFile?.let { visitSource(it, null) }
        metadataKind?.let { kind -> visitAnnotation("Lkotlin/Metadata;", false).apply {
            visit("k", kind)
            metadataExtraString?.let { visit("xs", it) }
            visitEnd()
        } }
        annotations.forEach { visitAnnotation(it, true).visitEnd() }
        fields.forEach { name -> visitField(Opcodes.ACC_PRIVATE, name, "Ljava/lang/Object;", null, null).apply {
            memberAnnotations.forEach { visitAnnotation(it, true).visitEnd() }; visitEnd()
        } }
        methods.forEach { name -> visitMethod(Opcodes.ACC_PUBLIC, name, "()V", null, null).apply {
            memberAnnotations.forEach { visitAnnotation(it, true).visitEnd() }; visitEnd()
        } }
        visitEnd()
    }.toByteArray()

    private fun writeRawZip(path: Path, entries: List<Pair<String, ByteArray>>) {
        data class CentralEntry(val name: ByteArray, val bytes: ByteArray, val crc: Long, val offset: Int)

        val output = ByteArrayOutputStream()
        val central = entries.map { (name, bytes) ->
            val encodedName = name.toByteArray(Charsets.UTF_8)
            val crc = CRC32().apply { update(bytes) }.value
            val offset = output.size()
            output.writeLeInt(0x04034b50)
            output.writeLeShort(20)
            output.writeLeShort(0)
            output.writeLeShort(0)
            output.writeLeShort(0)
            output.writeLeShort(0)
            output.writeLeInt(crc)
            output.writeLeInt(bytes.size.toLong())
            output.writeLeInt(bytes.size.toLong())
            output.writeLeShort(encodedName.size)
            output.writeLeShort(0)
            output.write(encodedName)
            output.write(bytes)
            CentralEntry(encodedName, bytes, crc, offset)
        }
        val centralOffset = output.size()
        central.forEach { entry ->
            output.writeLeInt(0x02014b50)
            output.writeLeShort(20)
            output.writeLeShort(20)
            repeat(4) { output.writeLeShort(0) }
            output.writeLeInt(entry.crc)
            output.writeLeInt(entry.bytes.size.toLong())
            output.writeLeInt(entry.bytes.size.toLong())
            output.writeLeShort(entry.name.size)
            output.writeLeShort(0)
            output.writeLeShort(0)
            output.writeLeShort(0)
            output.writeLeShort(0)
            output.writeLeInt(0)
            output.writeLeInt(entry.offset.toLong())
            output.write(entry.name)
        }
        val centralSize = output.size() - centralOffset
        output.writeLeInt(0x06054b50)
        output.writeLeShort(0)
        output.writeLeShort(0)
        output.writeLeShort(central.size)
        output.writeLeShort(central.size)
        output.writeLeInt(centralSize.toLong())
        output.writeLeInt(centralOffset.toLong())
        output.writeLeShort(0)
        path.writeBytes(output.toByteArray())
    }

    private fun ByteArrayOutputStream.writeLeShort(value: Int) {
        write(value and 0xff)
        write(value ushr 8 and 0xff)
    }

    private fun ByteArrayOutputStream.writeLeInt(value: Long) {
        repeat(4) { shift -> write((value ushr (shift * 8) and 0xff).toInt()) }
    }

    private fun gitInit() {
        val process = ProcessBuilder("git", "init", "-q", repository.toString()).start()
        check(process.waitFor() == 0)
    }
}
