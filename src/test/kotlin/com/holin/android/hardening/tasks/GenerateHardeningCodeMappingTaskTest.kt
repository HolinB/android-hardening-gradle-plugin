package com.holin.android.hardening.tasks

import com.android.tools.r8.CompilationMode
import com.android.tools.r8.OutputMode
import com.android.tools.r8.R8
import com.android.tools.r8.R8Command
import com.android.tools.r8.StringConsumer
import com.android.tools.r8.origin.Origin
import com.holin.android.hardening.HardeningOwnership
import com.holin.android.hardening.code.ClassArtifactInput
import com.holin.android.hardening.code.ClassArtifactInputCodec
import com.holin.android.hardening.code.CodeExclusionReason
import com.holin.android.hardening.code.CodeNamingManifestCodec
import com.holin.android.hardening.code.CodeSymbolKey
import com.holin.android.hardening.code.CodeSymbolKind
import com.holin.android.hardening.code.PotentialBeanFieldManifestCodec
import com.holin.android.hardening.code.fieldRegistryIdentity
import com.holin.android.hardening.naming.AliasRequest
import com.holin.android.hardening.naming.PseudowordRegistry
import com.holin.android.hardening.naming.RegistryCodec
import com.holin.android.hardening.naming.RegistryKey
import com.holin.android.hardening.naming.SymbolKind
import com.holin.android.hardening.state.EntropySource
import com.holin.android.hardening.state.InvocationSaltService
import com.holin.android.hardening.state.PrepareRequest
import com.holin.android.hardening.state.PreparedStateCodec
import com.holin.android.hardening.state.Sha256
import com.holin.android.hardening.state.StateCoordinates
import com.holin.android.hardening.state.StateStore
import com.holin.android.hardening.verification.MappingSymbolKey
import com.holin.android.hardening.verification.R8MappingParser
import com.holin.android.hardening.verification.SymbolKind as MappingSymbolKind
import java.nio.file.Files
import java.nio.file.Path
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream
import kotlin.io.path.createDirectories
import kotlin.io.path.readBytes
import kotlin.io.path.readText
import kotlin.io.path.writeBytes
import kotlin.io.path.writeText
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue
import org.gradle.api.Project
import org.gradle.api.tasks.Input
import org.gradle.testfixtures.ProjectBuilder
import org.junit.jupiter.api.io.TempDir
import org.objectweb.asm.ClassWriter
import org.objectweb.asm.Opcodes

class GenerateHardeningCodeMappingTaskTest {
    @TempDir
    lateinit var repository: Path

    @Test
    fun `task emits one authoritative Bean field manifest and exact rules`() {
        val fixture = fixture()
        val task = fixture.task
        val appInput = task.ownedArtifactMetadata.get().map(ClassArtifactInputCodec::decode)
            .single { input -> input.modulePath == ":app" }
        classJar(
            appInput.file,
            "com/example/App",
            "App.kt",
            methods = listOf("refresh"),
            fieldDescriptors = mapOf("id" to "J"),
            fieldAccess = Opcodes.ACC_PRIVATE,
        )

        task.generate()

        val fieldCodec = PotentialBeanFieldManifestCodec()
        val manifest = fieldCodec.decode(task.potentialBeanFieldsManifest.get().asFile.readText())
        val field = manifest.fields.single()
        val rules = task.applyMappingRules.get().asFile.readText()
        val naming = CodeNamingManifestCodec().decode(task.codeNamingManifest.get().asFile.readText())
        assertEquals(":app", field.modulePath)
        assertEquals(CodeSymbolKey(CodeSymbolKind.FIELD, "com/example/App", "id", "J"), field.key)
        assertEquals("a".repeat(64), manifest.configurationSha256)
        assertEquals(fieldCodec.inventorySha256(manifest.fields), manifest.inventorySha256)
        assertEquals(0, manifest.retiredLegacyFieldAssignmentCount)
        val ownerRule = "-keep,allowoptimization,allowobfuscation class com.example.App"
        val fieldRule = "-keepclassmembers class com.example.App {\n    long id;\n}"
        assertTrue(rules.contains(ownerRule))
        assertTrue(rules.contains(fieldRule))
        assertTrue(rules.indexOf("-applymapping ") < rules.indexOf(ownerRule))
        assertTrue(rules.indexOf(ownerRule) < rules.indexOf(fieldRule))
        assertTrue(rules.indexOf("-keepclassmembers class") < rules.indexOf("# Preserve the optimization shape"))
        assertFalse(naming.expectedSymbols.any { assignment -> assignment.key == field.key })
        assertTrue(naming.exclusions.any { exclusion ->
            exclusion.key == field.key && exclusion.reason == CodeExclusionReason.POTENTIAL_BEAN_INSTANCE_FIELD
        })
    }

    @Test
    fun `task retires a prepared legacy field assignment without resetting lineage`() {
        val fixture = fixture()
        val task = fixture.task
        val appInput = task.ownedArtifactMetadata.get().map(ClassArtifactInputCodec::decode)
            .single { input -> input.modulePath == ":app" }
        classJar(
            appInput.file,
            "com/example/App",
            "App.kt",
            methods = listOf("refresh"),
            fieldDescriptors = mapOf("id" to "J"),
            fieldAccess = Opcodes.ACC_PRIVATE,
        )
        val preparedDirectory = fixture.preparedRegistry.parent
        val preparedStatePath = preparedDirectory.resolve(PREPARED_STATE_FILE)
        val beforeState = PreparedStateCodec.read(preparedStatePath)
        val seedPath = preparedDirectory.resolve("seed.bin")
        val seedBefore = seedPath.readBytes()
        val registryCodec = RegistryCodec()
        val preparedSnapshot = registryCodec.decode(fixture.preparedRegistry.readText())
        val fieldKey = CodeSymbolKey(CodeSymbolKind.FIELD, "com/example/App", "id", "J")
        val registry = PseudowordRegistry.restore(seedBefore, preparedSnapshot)
        registry.reconcileScoped(
            listOf(
                AliasRequest(
                    RegistryKey(fieldRegistryIdentity(fieldKey), SymbolKind.MEMBER, fieldKey.descriptor),
                    "code-members-v2",
                ),
            ),
            preparedSnapshot.generation,
            setOf(SymbolKind.MEMBER),
        )
        val withLegacyField = registry.snapshot(preparedSnapshot.generation)
        val legacyAssignment = withLegacyField.assignments.single {
            it.key.originalIdentity == fieldRegistryIdentity(fieldKey)
        }
        fixture.preparedRegistry.writeText(registryCodec.encode(withLegacyField))
        PreparedStateCodec.write(
            preparedStatePath,
            beforeState.copy(
                identity = beforeState.identity.copy(
                    payloadHashes = beforeState.identity.payloadHashes +
                        ("registry.json" to Sha256.file(fixture.preparedRegistry)),
                ),
            ),
        )

        task.generate()

        val manifest = PotentialBeanFieldManifestCodec().decode(task.potentialBeanFieldsManifest.get().asFile.readText())
        val generatedRegistry = registryCodec.decode(task.codeRegistry.get().asFile.readText())
        val afterState = PreparedStateCodec.read(preparedStatePath)
        assertEquals(1, manifest.retiredLegacyFieldAssignmentCount)
        assertFalse(generatedRegistry.assignments.any { it.key == legacyAssignment.key })
        assertTrue(generatedRegistry.tombstones.any { it.keyHash == legacyAssignment.keyHash })
        assertContentEquals(seedBefore, seedPath.readBytes())
        assertEquals(beforeState.identity.lineageId, afterState.identity.lineageId)
        assertEquals(beforeState.identity.generation, afterState.identity.generation)
    }

    @Test
    fun `task preserves proven program descriptor packages required by applied member names`() {
        val program = externalDescriptorFixture()
        val mapping = runR8(program)

        assertEquals(setOf(program.methodAlias), mappedMethodNames(mapping))
        assertEquals(setOf(program.fieldAlias), mappedFieldNames(mapping))
        assertEquals(setOf(program.generatedMethodAlias), mappedGeneratedMethodNames(mapping))
        assertEquals(setOf(program.ownedMethodAlias), mappedOwnedMethodNames(mapping))
        assertEquals(
            listOf(
                "-keeppackagenames external.FieldType",
                "-keeppackagenames external.ReviewManager",
                "-keeppackagenames generated.GeneratedBinding",
            ),
            program.applyMappingRules.readText().lineSequence()
                .filter { line -> line.startsWith("-keeppackagenames ") }
                .toList(),
        )
        assertFalse(program.ownedOriginalOwners.contains("generated/GeneratedBinding"))
        assertFalse(program.ownedOriginalOwners.contains("generated/UnusedBinding"))
        assertTrue(program.ownedOriginalOwners.contains("com/example/Base"))
    }

    @Test
    fun `task emits sorted exact Serializable keep names without freezing generated subclasses`() {
        val fixture = fixture()
        val task = fixture.task
        val appInput = task.ownedArtifactMetadata.get().map(ClassArtifactInputCodec::decode)
            .single { input -> input.modulePath == ":app" }
        Files.delete(repository.resolve("app/src/main/java/com/example/App.kt"))
        repository.resolve("app/src/main/java/com/example/App.java").writeText(
            """
            package com.example;

            class App implements java.io.Serializable {}
            class Aardvark implements java.io.Serializable {}
            """.trimIndent(),
        )
        classJar(
            appInput.file,
            "com/example/App",
            "App.java",
            methods = listOf("save"),
            interfaces = listOf("java/io/Serializable"),
            additionalClasses = listOf(
                ClassSpec("com/example/Aardvark", "App.java", interfaces = listOf("java/io/Serializable")),
                ClassSpec("com/example/App\$SuspendState", "App.java", interfaces = listOf("java/io/Serializable")),
            ),
        )

        task.generate()

        val mapping = task.codeMapping.get().asFile.readText()
        val rules = task.applyMappingRules.get().asFile.readText()
        assertFalse(mapping.contains("com.example.App -> "))
        assertFalse(mapping.contains("com.example.Aardvark -> "))
        assertTrue(mapping.lineSequence().any { line ->
            line.startsWith("com.example.App\$SuspendState -> ") && !line.endsWith("com.example.App\$SuspendState:")
        })
        assertEquals(
            listOf(
                "-keepnames class com.example.Aardvark",
                "-keepnames class com.example.App",
            ),
            rules.lineSequence().filter { line -> line.startsWith("-keepnames class ") }.toList(),
        )
    }

    @Test
    fun `task emits code mapping without mutating prepared registry`() {
        val fixture = fixture()
        val before = fixture.preparedRegistry.readBytes()
        val task = fixture.task

        task.generate()

        assertContentEquals(before, fixture.preparedRegistry.readBytes())
        val mapping = task.codeMapping.get().asFile.toPath().readText()
        val codeRegistry = task.codeRegistry.get().asFile.toPath()
        val rules = task.applyMappingRules.get().asFile.toPath().readText()
        val manifest = CodeNamingManifestCodec().decode(task.codeNamingManifest.get().asFile.readText())
        assertTrue(mapping.contains("com.example.App -> "))
        assertTrue(
            rules.startsWith(
                "# hardening mapping sha256: ${Sha256.hex(mapping.toByteArray(Charsets.UTF_8))}\n" +
                    "-applymapping \"${task.codeMapping.get().asFile.toPath().toAbsolutePath().normalize()}\"\n",
            ),
        )
        assertTrue(rules.contains("# Preserve the optimization shape of app-owned symbols"))
        assertFalse(rules.contains("com.example.App ->"))
        assertEquals(1, manifest.schemaVersion)
        assertEquals(Sha256.file(task.codeMapping.get().asFile.toPath()), manifest.mappingSha256)
        assertEquals(Sha256.file(codeRegistry), manifest.registrySha256)
        assertEquals(5, manifest.expectedSymbols.count { it.key.kind.name == "CLASS" })
        assertEquals(
            setOf(SymbolKind.CLASS, SymbolKind.PACKAGE),
            RegistryCodec().decode(codeRegistry.readText()).assignments.mapTo(linkedSetOf()) { it.key.kind },
        )
    }

    @Test
    fun `apply mapping rules identify mapping content while preserving directive and owned rules`() {
        val fixture = fixture()
        val task = fixture.task
        val mappingPath = task.codeMapping.get().asFile.toPath().toAbsolutePath().normalize()
        val rulesPath = task.applyMappingRules.get().asFile.toPath()

        task.generate()

        val firstMapping = mappingPath.readBytes()
        val firstRules = rulesPath.readBytes()
        val expectedDirective = "# hardening mapping sha256: ${Sha256.hex(firstMapping)}\n" +
            "-applymapping \"$mappingPath\"\n"
        assertTrue(rulesPath.readText().startsWith(expectedDirective))
        assertTrue(rulesPath.readText().contains("# Preserve the optimization shape of app-owned symbols"))

        task.generate()

        assertContentEquals(firstRules, rulesPath.readBytes())
        val changedPrepared = prepareState(
            root = repository.resolve("changed-prepared-state"),
            contentSaltSha256 = "c".repeat(64),
            entropyStart = 2,
        )
        task.preparedRegistry.set(changedPrepared.resolve("registry.json").toFile())
        task.lineageSeed.set(changedPrepared.resolve("seed.bin").toFile())
        task.preparedState.set(changedPrepared.resolve(PREPARED_STATE_FILE).toFile())
        assertEquals(mappingPath, task.codeMapping.get().asFile.toPath().toAbsolutePath().normalize())
        assertEquals(rulesPath.toAbsolutePath().normalize(), task.applyMappingRules.get().asFile.toPath().toAbsolutePath().normalize())

        task.generate()

        val changedMapping = mappingPath.readBytes()
        val changedRules = rulesPath.readBytes()
        assertFalse(firstMapping.contentEquals(changedMapping))
        assertFalse(firstRules.contentEquals(changedRules))
        assertTrue(
            rulesPath.readText().startsWith(
                "# hardening mapping sha256: ${Sha256.hex(changedMapping)}\n-applymapping \"$mappingPath\"\n",
            ),
        )
        assertTrue(rulesPath.readText().contains("# Preserve the optimization shape of app-owned symbols"))
    }

    @Test
    fun `task boot order changes emitted contract for duplicate definition while validating every file`() {
        val fixture = fixture()
        val task = fixture.task
        val contractName = "java/lang/invoke/BootContract"
        val appInput = task.ownedArtifactMetadata.get()
            .map(ClassArtifactInputCodec::decode)
            .single { input -> input.modulePath == ":app" }
        classJar(
            appInput.file,
            "com/example/App",
            "App.kt",
            methods = listOf("dispatch"),
            interfaces = listOf(contractName),
        )
        val bootInputs = listOf(
            ClassArtifactInput(
                "Android boot classpath",
                null,
                classJar(
                    repository.resolve("boot/first.jar"),
                    contractName,
                    "BootContract.java",
                    access = Opcodes.ACC_PUBLIC or Opcodes.ACC_INTERFACE or Opcodes.ACC_ABSTRACT,
                    methods = listOf("dispatch"),
                    methodAccess = Opcodes.ACC_PUBLIC or Opcodes.ACC_ABSTRACT,
                ),
            ),
            ClassArtifactInput(
                "Android boot classpath",
                null,
                classJar(
                    repository.resolve("boot/second.jar"),
                    contractName,
                    "BootContract.java",
                    access = Opcodes.ACC_PUBLIC or Opcodes.ACC_INTERFACE or Opcodes.ACC_ABSTRACT,
                ),
            ),
        )
        task.hierarchyArtifactMetadata.set(bootInputs.reversed().map(ClassArtifactInputCodec::encode))
        task.bootClasspath.setFrom(bootInputs.map { it.file.toFile() })

        task.generate()

        val preferredManifest = CodeNamingManifestCodec().decode(task.codeNamingManifest.get().asFile.readText())
        val preferredMapping = task.codeMapping.get().asFile.readText()
        assertTrue(preferredManifest.exclusions.any { exclusion ->
            exclusion.key.owner == "com/example/App" && exclusion.key.name == "dispatch" &&
                exclusion.reason == CodeExclusionReason.EXTERNAL_OVERRIDE
        })
        assertFalse(preferredMapping.contains("void dispatch() ->"))
        assertEquals(
            bootInputs.map { it.file.toAbsolutePath().normalize() },
            task.bootClasspath.files.map { it.toPath().toAbsolutePath().normalize() },
        )
        assertEquals(
            bootInputs.mapTo(linkedSetOf()) { it.file.toAbsolutePath().normalize() },
            task.hierarchyArtifactMetadata.get().mapTo(linkedSetOf()) { encoded ->
                ClassArtifactInputCodec.decode(encoded).file.toAbsolutePath().normalize()
            },
        )

        task.bootClasspath.setFrom(bootInputs.reversed().map { it.file.toFile() })
        task.generate()

        val fallbackManifest = CodeNamingManifestCodec().decode(task.codeNamingManifest.get().asFile.readText())
        val fallbackMapping = task.codeMapping.get().asFile.readText()
        assertTrue(fallbackManifest.expectedSymbols.any { assignment ->
            assignment.key.owner == "com/example/App" && assignment.key.name == "dispatch"
        })
        assertFalse(fallbackManifest.exclusions.any { exclusion ->
            exclusion.key.owner == "com/example/App" && exclusion.key.name == "dispatch"
        })
        assertTrue(fallbackMapping.contains("void dispatch() ->"))
    }

    @Test
    fun `task emits exact CoordinatorLayout Behavior construction rules without freezing ordinary members`() {
        val fixture = fixture()
        val task = fixture.task
        val behaviorName = "com/example/DirectBehavior"
        val coordinatorBehavior = "androidx/coordinatorlayout/widget/CoordinatorLayout\$Behavior"
        val appInput = task.ownedArtifactMetadata.get().map(ClassArtifactInputCodec::decode)
            .single { input -> input.modulePath == ":app" }
        repository.resolve("app/src/main/java/com/example/DirectBehavior.kt").also { source ->
            source.parent.createDirectories()
            source.writeText("package com.example\nclass DirectBehavior")
        }
        classJar(
            appInput.file,
            behaviorName,
            "DirectBehavior.kt",
            Opcodes.ACC_PUBLIC,
            listOf("ordinary"),
            Opcodes.ACC_PUBLIC,
            emptyMap(),
            mapOf("state" to "I"),
            Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC,
            emptyList(),
            emptyList(),
            coordinatorBehavior,
        )
        val hierarchyJar = classJar(
            repository.resolve("hierarchy/coordinator-layout.jar"),
            coordinatorBehavior,
            "CoordinatorLayout.java",
        )
        val hierarchyInput = ClassArtifactInput(
            "demoDebug runtime classpath",
            null,
            hierarchyJar,
            1,
        )
        task.hierarchyArtifactMetadata.set(listOf(ClassArtifactInputCodec.encode(hierarchyInput)))
        task.runtimeClasspath.setFrom(hierarchyJar.toFile())

        task.generate()

        val rules = task.applyMappingRules.get().asFile.readText()
        val mapping = task.codeMapping.get().asFile.readText()
        assertTrue(
            rules.contains(
                "-keep,allowoptimization public class com.example.DirectBehavior {\n" +
                    "    public <init>(android.content.Context, android.util.AttributeSet);\n" +
                    "}",
            ),
        )
        assertFalse(rules.contains("class * extends androidx.coordinatorlayout.widget.CoordinatorLayout\$Behavior"))
        assertTrue(mapping.contains("int state ->"))
        assertTrue(mapping.contains("void ordinary() ->"))
    }

    @Test
    fun `task excludes only class names preserved by external hierarchy keep rules`() {
        val fixture = fixture()
        val task = fixture.task
        val ownedAdapter = "com/example/OwnedAdapter"
        val externalAdapter = "external/adapter/BaseAdapter"
        val appInput = task.ownedArtifactMetadata.get().map(ClassArtifactInputCodec::decode)
            .single { input -> input.modulePath == ":app" }
        repository.resolve("app/src/main/java/com/example/OwnedAdapter.kt").writeText(
            "package com.example\nclass OwnedAdapter",
        )
        classJar(
            appInput.file,
            "com/example/App",
            "App.kt",
            Opcodes.ACC_PUBLIC,
            emptyList(),
            Opcodes.ACC_PUBLIC,
            emptyMap(),
            emptyMap(),
            Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC,
            emptyList(),
            listOf(
                ClassSpec(
                    ownedAdapter,
                    "OwnedAdapter.kt",
                    Opcodes.ACC_PUBLIC,
                    listOf("bind"),
                    Opcodes.ACC_PUBLIC,
                    emptyMap(),
                    emptyMap(),
                    Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC,
                    emptyList(),
                    externalAdapter,
                ),
            ),
            "java/lang/Object",
        )
        val hierarchyJar = classJar(
            repository.resolve("hierarchy/external-adapter.jar"),
            externalAdapter,
            "BaseAdapter.java",
        )
        val hierarchyInput = ClassArtifactInput(
            "demoDebug runtime classpath",
            null,
            hierarchyJar,
            1,
        )
        task.hierarchyArtifactMetadata.set(listOf(ClassArtifactInputCodec.encode(hierarchyInput)))
        task.runtimeClasspath.setFrom(hierarchyJar.toFile())
        task.effectiveR8Rules.get().asFile.writeText(
            "-keep public class * extends external.adapter.*\n",
        )

        task.generate()

        val manifest = CodeNamingManifestCodec().decode(task.codeNamingManifest.get().asFile.readText())
        val classKey = CodeSymbolKey(CodeSymbolKind.CLASS, ownedAdapter, "OwnedAdapter", "L$ownedAdapter;")
        assertFalse(manifest.expectedSymbols.any { assignment -> assignment.key == classKey })
        assertTrue(manifest.exclusions.any { exclusion ->
            exclusion.key == classKey &&
                exclusion.reason == CodeExclusionReason.R8_HIERARCHY_KEEP_RULE &&
                exclusion.evidence.contains("-keep public class * extends external.adapter.*")
        })
        assertTrue(manifest.expectedSymbols.any { assignment ->
            assignment.key.owner == ownedAdapter &&
                assignment.key.kind == CodeSymbolKind.METHOD &&
                assignment.key.name == "bind" &&
                assignment.outputOwner == ownedAdapter
        })
        val mapping = task.codeMapping.get().asFile.readText()
        assertTrue(mapping.contains("com.example.OwnedAdapter -> com.example.OwnedAdapter:"))
        assertTrue(mapping.contains("void bind() ->"))
    }

    @Test
    fun `runtime hierarchy definition wins over the compile fallback`() {
        val fixture = fixture()
        val task = fixture.task
        val contractName = "external/Contract"
        val appInput = task.ownedArtifactMetadata.get()
            .map(ClassArtifactInputCodec::decode)
            .single { input -> input.modulePath == ":app" }
        classJar(
            appInput.file,
            "com/example/App",
            "App.kt",
            methods = listOf("dispatch"),
            interfaces = listOf(contractName),
        )
        val compileFallback = ClassArtifactInput(
            "demoDebug compile classpath",
            null,
            classJar(
                repository.resolve("hierarchy/compile.jar"),
                contractName,
                "Contract.java",
                access = Opcodes.ACC_PUBLIC or Opcodes.ACC_INTERFACE or Opcodes.ACC_ABSTRACT,
            ),
            hierarchyPrecedence = 2,
        )
        val runtimeDefinition = ClassArtifactInput(
            "demoDebug runtime classpath",
            null,
            classJar(
                repository.resolve("hierarchy/runtime.jar"),
                contractName,
                "Contract.java",
                access = Opcodes.ACC_PUBLIC or Opcodes.ACC_INTERFACE or Opcodes.ACC_ABSTRACT,
                methods = listOf("dispatch"),
                methodAccess = Opcodes.ACC_PUBLIC or Opcodes.ACC_ABSTRACT,
            ),
            hierarchyPrecedence = 1,
        )
        task.hierarchyArtifactMetadata.set(
            listOf(compileFallback, runtimeDefinition).map(ClassArtifactInputCodec::encode),
        )
        task.runtimeClasspath.setFrom(compileFallback.file.toFile(), runtimeDefinition.file.toFile())

        task.generate()

        val manifest = CodeNamingManifestCodec().decode(task.codeNamingManifest.get().asFile.readText())
        assertTrue(manifest.exclusions.any { exclusion ->
            exclusion.key.owner == "com/example/App" && exclusion.key.name == "dispatch" &&
                exclusion.reason == CodeExclusionReason.EXTERNAL_OVERRIDE
        })
    }

    @Test
    fun `ordered boot classpath identity is an order sensitive Gradle input`() {
        val fixture = fixture()
        val task = fixture.task
        val bootFiles = listOf(
            classJar(repository.resolve("boot/first.jar"), "boot/First", "First.java"),
            classJar(repository.resolve("boot/second.jar"), "boot/Second", "Second.java"),
        )
        task.bootClasspath.setFrom(bootFiles.map(Path::toFile))

        val forward = task.orderedBootClasspathIdentity
        task.bootClasspath.setFrom(bootFiles.reversed().map(Path::toFile))
        val reversed = task.orderedBootClasspathIdentity

        assertEquals(bootFiles.map(Sha256::canonicalNode), forward)
        assertEquals(bootFiles.reversed().map(Sha256::canonicalNode), reversed)
        assertNotEquals(forward, reversed)
        assertTrue(
            GenerateHardeningCodeMappingTask::class.java
                .getMethod("getOrderedBootClasspathIdentity")
                .isAnnotationPresent(Input::class.java),
        )
    }

    @Test
    fun `application module path is an explicit Gradle input`() {
        val task = fixture().task
        val getter = GenerateHardeningCodeMappingTask::class.java.getMethod("getApplicationModulePath")

        assertTrue(getter.isAnnotationPresent(Input::class.java))
        val property = getter.invoke(task) as org.gradle.api.provider.Property<*>
        assertEquals(":app", property.get())
    }

    @Test
    fun `task rejects metadata that does not equal the normalized Gradle file collections`() {
        val fixture = fixture()
        fixture.task.projectClassJars.set(fixture.task.projectClassJars.get().dropLast(1))

        val failure = assertFailsWith<IllegalArgumentException> { fixture.task.generate() }

        assertTrue(failure.message.orEmpty().contains("metadata"))
    }

    @Test
    fun `task requires artifacts for the exact configured ownership scope`() {
        val fixture = fixture()
        fixture.task.ownedArtifactMetadata.set(
            fixture.task.ownedArtifactMetadata.get().filterNot { encoded ->
                ClassArtifactInputCodec.decode(encoded).modulePath == ":ucrop"
            },
        )
        fixture.task.projectClassJars.set(fixture.task.projectClassJars.get().dropLast(1))

        val failure = assertFailsWith<IllegalArgumentException> { fixture.task.generate() }

        assertTrue(failure.message.orEmpty().contains("configured ownership"))
    }

    @Test
    fun `cache identity includes contract sources ignore rules and mapping output path`() {
        val fixture = fixture()
        val task = fixture.task
        val root = task.repositoryRoot.get().asFile.toPath()
        val appModule = task.ownership.get().modules.single { it.path == ":app" }
        val customJava = root.resolve("app/custom/java/com/example/Contract.java").also { file ->
            file.parent.createDirectories()
            file.writeText("package com.example; final class Contract {}")
        }
        val customKotlin = root.resolve("app/custom/kotlin/com/example/Contract.kt").also { file ->
            file.parent.createDirectories()
            file.writeText("package com.example\nclass KotlinContract")
        }
        val customResource = root.resolve("app/custom/res/layout/contract.xml").also { file ->
            file.parent.createDirectories()
            file.writeText("<FrameLayout />")
        }
        val customManifest = root.resolve("app/custom/manifest/OwnedManifest.xml").also { file ->
            file.parent.createDirectories()
            file.writeText("<manifest package=\"com.example\"/>")
        }
        val customRoots = HardeningOwnership.ResolvedSourceRoots(
            setOf(customJava.parent.parent.parent),
            setOf(customKotlin.parent.parent.parent),
            setOf(customResource.parent.parent),
            setOf(customManifest),
        )
        task.ownership.set(
            HardeningOwnership(
                task.ownership.get().modules.map { module ->
                    if (module.path == ":app") {
                        HardeningOwnership.OwnedModule(
                            module.path,
                            module.directory,
                            module.sourceSets,
                            customRoots,
                            module.webp,
                        )
                    } else {
                        module
                    }
                },
                task.ownership.get().generatedPackagePrefixes,
                task.ownership.get().excludedPackagePrefixes,
                task.ownership.get().hardcodedReferences,
            ),
        )
        val gitIgnore = root.resolve(".gitignore").also { it.writeText("ignored.kt\n") }
        val globalIgnore = root.resolve("fixture-global-ignore").also { it.writeText("global.kt\n") }
        check(
            ProcessBuilder("git", "-C", root.toString(), "config", "core.excludesFile", globalIgnore.toString())
                .start().waitFor() == 0,
        )

        val declaredInputs = task.sourceContractInputs.files.mapTo(linkedSetOf()) { it.toPath().toAbsolutePath().normalize() }
        val ignoreControls = task.gitIgnoreControlPaths.map(Path::of).mapTo(linkedSetOf()) { it.toAbsolutePath().normalize() }

        assertTrue(customJava.toAbsolutePath().normalize() in declaredInputs)
        assertTrue(customKotlin.toAbsolutePath().normalize() in declaredInputs)
        assertTrue(customResource.toAbsolutePath().normalize() in declaredInputs)
        assertTrue(customManifest.toAbsolutePath().normalize() in declaredInputs)
        assertFalse(root.resolve("app/src/main/java/com/example/App.kt").toAbsolutePath().normalize() in declaredInputs)
        assertFalse(appModule.sourceRoots.manifestFiles.any { it in declaredInputs })
        assertTrue(gitIgnore.toAbsolutePath().normalize() in declaredInputs)
        assertTrue(root.resolve(".git/info/exclude").toAbsolutePath().normalize() in ignoreControls)
        assertTrue(globalIgnore.toAbsolutePath().normalize() in ignoreControls)
        val defaultGlobalIgnore = System.getenv("XDG_CONFIG_HOME")?.takeIf(String::isNotBlank)?.let(Path::of)
            ?.resolve("git/ignore")
            ?: Path.of(System.getProperty("user.home"), ".config", "git", "ignore")
        assertTrue(defaultGlobalIgnore.toAbsolutePath().normalize() in ignoreControls)
        assertTrue(ignoreControls.filter(Files::exists).all(declaredInputs::contains))
        val beforeManifestHash = Sha256.file(customManifest)
        customManifest.writeText("<manifest package=\"com.changed\"/>")
        assertNotEquals(beforeManifestHash, Sha256.file(customManifest))
        assertTrue(customManifest.toAbsolutePath().normalize() in task.inputs.files.files.map { it.toPath().toAbsolutePath().normalize() })
        assertEquals(
            task.codeMapping.get().asFile.toPath().toAbsolutePath().normalize().toString(),
            task.codeMappingOutputPath,
        )
    }

    @Test
    fun `rewrite consumes generated code registry and leaves prepared registry unchanged on failure`() {
        gitInit()
        val project = ProjectBuilder.builder().withProjectDir(repository.toFile()).build()
        val root = project.projectDir.toPath()
        val salt = project.gradle.sharedServices.registerIfAbsent(
            "task4RewriteSalt",
            InvocationSaltService::class.java,
        ) {}
        val prepared = prepareState(root, salt.get().sha256())
        val before = prepared.resolve("registry.json").readBytes()
        val build = root.resolve("build")
        val ordinary = build.resolve("ordinary.aab").also { it.writeBytes(byteArrayOf(1)) }
        val mapping = build.resolve("mapping.txt").also { it.writeText("com.example.App -> a.b:\n") }
        val generatedRegistry = build.resolve("hardening/code/code-registry.json").also { file ->
            file.parent.createDirectories()
            file.writeText("not-json")
        }
        val expected = assertFailsWith<IllegalArgumentException> { RegistryCodec().decode(generatedRegistry.readText()) }
        val task = project.tasks.register("rewriteWithCodeRegistry", RewriteHardeningBundleTask::class.java).get().apply {
            inputBundle.set(ordinary.toFile())
            r8Mapping.set(mapping.toFile())
            codeRegistry.set(generatedRegistry.toFile())
            namespace.set("com.example")
            minimumCodeCoverage.set(0.50)
            minimumCodeSimHashDistance.set(4)
            maximumDexGrowth.set(1.0)
            enforceMaximumDexGrowth.set(true)
            minimumImageCoverage.set(0.90)
            minimumImageSsim.set(0.995)
            minimumImagePHashDistance.set(11)
            unsignedBundle.set(build.resolve("hardening/unsigned.aab").toFile())
            rewriteManifest.set(build.resolve("hardening/rewrite.json").toFile())
            semanticResults.set(build.resolve("hardening/semantic.json").toFile())
            planReport.set(build.resolve("hardening/plan.json").toFile())
            ownedArtifactInventory.set(build.resolve("hardening/inventory.json").toFile())
            ownedArtifactAnalysisInventory.set(build.resolve("hardening/analysis-inventory.json").toFile())
            artifactBoundary.set(project.layout.buildDirectory)
            repositoryRoot.set(project.layout.projectDirectory)
            preparedDirectory.set(prepared.toFile())
            saltService.set(salt)
        }

        val failure = assertFailsWith<IllegalArgumentException> { task.rewrite() }

        assertEquals(expected.message, failure.message)
        assertContentEquals(before, prepared.resolve("registry.json").readBytes())
    }

    @Test
    fun `rewrite rejects a same-seed code registry from another generation before planning`() {
        gitInit()
        val project = ProjectBuilder.builder().withProjectDir(repository.toFile()).build()
        val root = project.projectDir.toPath()
        val salt = project.gradle.sharedServices.registerIfAbsent(
            "task4WrongGenerationRewriteSalt",
            InvocationSaltService::class.java,
        ) {}
        val prepared = prepareState(root, salt.get().sha256())
        val preparedRegistry = prepared.resolve("registry.json")
        val before = preparedRegistry.readBytes()
        val registryCodec = RegistryCodec()
        val preparedSnapshot = registryCodec.decode(preparedRegistry.readText())
        val build = root.resolve("build")
        val ordinary = build.resolve("ordinary.aab").also { it.writeBytes(byteArrayOf(1)) }
        val mapping = build.resolve("mapping.txt").also { it.writeText("com.example.App -> a.b:\n") }
        val generatedRegistry = build.resolve("hardening/code/code-registry.json").also { file ->
            file.parent.createDirectories()
            file.writeText(registryCodec.encode(preparedSnapshot.copy(generation = preparedSnapshot.generation + 1)))
        }
        val task = project.tasks.register("rewriteWithWrongGenerationCodeRegistry", RewriteHardeningBundleTask::class.java)
            .get().apply {
                inputBundle.set(ordinary.toFile())
                r8Mapping.set(mapping.toFile())
                codeRegistry.set(generatedRegistry.toFile())
                namespace.set("com.example")
                minimumCodeCoverage.set(0.50)
                minimumCodeSimHashDistance.set(4)
                maximumDexGrowth.set(1.0)
                enforceMaximumDexGrowth.set(true)
                minimumImageCoverage.set(0.90)
                minimumImageSsim.set(0.995)
                minimumImagePHashDistance.set(11)
                unsignedBundle.set(build.resolve("hardening/unsigned.aab").toFile())
                rewriteManifest.set(build.resolve("hardening/rewrite.json").toFile())
                semanticResults.set(build.resolve("hardening/semantic.json").toFile())
                planReport.set(build.resolve("hardening/plan.json").toFile())
                ownedArtifactInventory.set(build.resolve("hardening/inventory.json").toFile())
                ownedArtifactAnalysisInventory.set(build.resolve("hardening/analysis-inventory.json").toFile())
                artifactBoundary.set(project.layout.buildDirectory)
                repositoryRoot.set(project.layout.projectDirectory)
                preparedDirectory.set(prepared.toFile())
                saltService.set(salt)
            }

        val failure = assertFailsWith<IllegalArgumentException> { task.rewrite() }

        assertEquals("code registry generation differs from prepared state", failure.message)
        assertContentEquals(before, preparedRegistry.readBytes())
    }

    @Test
    fun `prepared registry commit happens only after late semantic verification succeeds`() {
        val registry = repository.resolve("registry.json").also { it.writeText("prepared") }
        val before = registry.readBytes()

        assertFailsWith<LateVerificationFailure> {
            commitRegistryAfterVerification(registry, "updated".toByteArray()) {
                throw LateVerificationFailure()
            }
        }

        assertContentEquals(before, registry.readBytes())
    }

    private fun fixture(): Fixture {
        gitInit()
        val project = ProjectBuilder.builder().withProjectDir(repository.toFile()).build()
        val projectRoot = project.projectDir.toPath()
        val owned = OWNED_CLASSES.map { (module, internalName) ->
            val simpleName = internalName.substringAfterLast('/')
            projectRoot.resolve(module.removePrefix(":"))
                .resolve("src/main/java/com/example/$simpleName.kt")
                .also { source ->
                    source.parent.createDirectories()
                    source.writeText("package com.example\nclass $simpleName")
                }
            val jar = projectRoot.resolve(module.removePrefix(":"))
                .resolve("build/intermediates/classes/$simpleName.jar")
            classJar(jar, internalName, "$simpleName.kt")
            ClassArtifactInput("project $module", module, jar)
        }
        val prepared = prepareState()
        val task = project.tasks.register("generateCodeMapping", GenerateHardeningCodeMappingTask::class.java).get()
        configureTask(project, task, owned, prepared)
        return Fixture(task, prepared.resolve("registry.json"))
    }

    private fun externalDescriptorFixture(): ExternalDescriptorFixture {
        val fixture = fixture()
        val task = fixture.task
        val ownedInputs = task.ownedArtifactMetadata.get().map(ClassArtifactInputCodec::decode)
        val appInput = ownedInputs.single { input -> input.modulePath == ":app" }
        val baseInput = ownedInputs.single { input -> input.modulePath == ":core" }
        classJar(
            appInput.file,
            "com/example/App",
            "App.kt",
            methods = listOf("dispatch", "generatedDispatch", "ownedDispatch", "platformDispatch", "compileDispatch"),
            methodAccess = Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC,
            methodDescriptors = mapOf(
                "dispatch" to "(Lexternal/ReviewManager;)V",
                "generatedDispatch" to "(Lgenerated/GeneratedBinding;)V",
                "ownedDispatch" to "(Lcom/example/Base;)V",
                "platformDispatch" to "(Lplatform/LibraryType;)V",
                "compileDispatch" to "(Lcompile/LibraryType;)V",
            ),
            fieldDescriptors = mapOf("reviewField" to "Lexternal/FieldType;"),
            additionalClasses = listOf(
                ClassSpec("generated/GeneratedBinding", "GeneratedBinding.java"),
                ClassSpec("generated/UnusedBinding", "UnusedBinding.java"),
            ),
        )
        val externalJar = classJar(
            repository.resolve("external/review.jar"),
            "external/ReviewManager",
            "ReviewManager.java",
            access = Opcodes.ACC_PUBLIC or Opcodes.ACC_INTERFACE or Opcodes.ACC_ABSTRACT,
            methods = listOf("requestReview"),
            methodAccess = Opcodes.ACC_PUBLIC or Opcodes.ACC_ABSTRACT,
            additionalClasses = listOf(
                ClassSpec(
                    "external/FieldType",
                    "FieldType.java",
                    access = Opcodes.ACC_PUBLIC or Opcodes.ACC_INTERFACE or Opcodes.ACC_ABSTRACT,
                ),
            ),
        )
        val external = ClassArtifactInput(
            component = "demoDebug runtime classpath",
            modulePath = null,
            file = externalJar,
            hierarchyPrecedence = 1,
        )
        val platformJar = classJar(
            repository.resolve("boot/platform.jar"),
            "platform/LibraryType",
            "LibraryType.java",
        )
        val platform = ClassArtifactInput(
            component = "Android boot classpath",
            modulePath = null,
            file = platformJar,
        )
        val compileJar = classJar(
            repository.resolve("compile/library.jar"),
            "compile/LibraryType",
            "LibraryType.java",
        )
        val compile = ClassArtifactInput(
            component = "demoDebug compile classpath",
            modulePath = null,
            file = compileJar,
            hierarchyPrecedence = 2,
        )
        task.hierarchyArtifactMetadata.set(listOf(external, compile, platform).map(ClassArtifactInputCodec::encode))
        task.runtimeClasspath.setFrom(externalJar.toFile(), compileJar.toFile())
        task.bootClasspath.setFrom(platformJar.toFile())
        task.generate()
        val manifest = CodeNamingManifestCodec().decode(task.codeNamingManifest.get().asFile.readText())
        val methodAssignment = manifest.expectedSymbols.single { candidate ->
            candidate.key.owner == "com/example/App" && candidate.key.name == "dispatch"
        }
        val fieldAssignment = manifest.expectedSymbols.single { candidate ->
            candidate.key.owner == "com/example/App" && candidate.key.name == "reviewField"
        }
        val generatedMethodAssignment = manifest.expectedSymbols.single { candidate ->
            candidate.key.owner == "com/example/App" && candidate.key.name == "generatedDispatch"
        }
        val ownedMethodAssignment = manifest.expectedSymbols.single { candidate ->
            candidate.key.owner == "com/example/App" && candidate.key.name == "ownedDispatch"
        }
        return ExternalDescriptorFixture(
            programFiles = listOf(appInput.file, baseInput.file, externalJar),
            applyMappingRules = task.applyMappingRules.get().asFile.toPath(),
            methodAlias = methodAssignment.alias,
            fieldAlias = fieldAssignment.alias,
            generatedMethodAlias = generatedMethodAssignment.alias,
            ownedMethodAlias = ownedMethodAssignment.alias,
            ownedOriginalOwners = manifest.expectedSymbols.mapTo(linkedSetOf()) { assignment -> assignment.key.owner },
        )
    }

    private fun runR8(fixture: ExternalDescriptorFixture): String {
        val mapping = StringBuilder()
        val output = repository.resolve("r8-output.jar")
        val rules = listOf(
            "-keep,allowrepackage,allowobfuscation class com.example.App {",
            "    public static void dispatch(external.ReviewManager);",
            "    public static void generatedDispatch(generated.GeneratedBinding);",
            "    public static void ownedDispatch(com.example.Base);",
            "    public static external.FieldType reviewField;",
            "}",
            "-repackageclasses 'r'",
            "-dontwarn **",
        )
        val command = R8Command.builder()
            .addProgramFiles(fixture.programFiles)
            .addLibraryFiles(androidJar())
            .addProguardConfigurationFiles(fixture.applyMappingRules)
            .addProguardConfiguration(rules, Origin.unknown())
            .setMode(CompilationMode.RELEASE)
            .setOutput(output, OutputMode.ClassFile)
            .setProguardMapConsumer(StringConsumer { content, _ -> mapping.append(content) })
            .build()
        R8.run(command)
        return mapping.toString()
    }

    private fun androidJar(): Path {
        val sdk = System.getenv("ANDROID_HOME") ?: System.getenv("ANDROID_SDK_ROOT")
        require(!sdk.isNullOrBlank()) { "ANDROID_HOME or ANDROID_SDK_ROOT is required for the R8 fixture" }
        return Path.of(sdk, "platforms", "android-35", "android.jar")
    }

    private fun mappedMethodNames(mapping: String): Set<String>? = R8MappingParser().parse(mapping, null).symbols[
        MappingSymbolKey(
            kind = MappingSymbolKind.METHOD,
            originalOwner = "com.example.App",
            originalName = "dispatch",
            jvmDescriptor = "(Lexternal/ReviewManager;)V",
        ),
    ]

    private fun mappedFieldNames(mapping: String): Set<String>? = R8MappingParser().parse(mapping, null).symbols[
        MappingSymbolKey(
            kind = MappingSymbolKind.FIELD,
            originalOwner = "com.example.App",
            originalName = "reviewField",
            jvmDescriptor = "Lexternal/FieldType;",
        ),
    ]

    private fun mappedGeneratedMethodNames(mapping: String): Set<String>? = R8MappingParser().parse(mapping, null).symbols[
        MappingSymbolKey(
            kind = MappingSymbolKind.METHOD,
            originalOwner = "com.example.App",
            originalName = "generatedDispatch",
            jvmDescriptor = "(Lgenerated/GeneratedBinding;)V",
        ),
    ]

    private fun mappedOwnedMethodNames(mapping: String): Set<String>? = R8MappingParser().parse(mapping, null).symbols[
        MappingSymbolKey(
            kind = MappingSymbolKind.METHOD,
            originalOwner = "com.example.App",
            originalName = "ownedDispatch",
            jvmDescriptor = "(Lcom/example/Base;)V",
        ),
    ]

    private fun configureTask(
        project: Project,
        task: GenerateHardeningCodeMappingTask,
        owned: List<ClassArtifactInput>,
        prepared: Path,
    ) {
        task.variantName.set("demoDebug")
        task.namespace.set("com.example")
        task.applicationModulePath.set(":app")
        task.unresolvedAppReflectionPolicy.set("FAIL_BUILD")
        task.externalNamesPolicy.set("PRESERVE_AND_REPORT")
        task.repositoryRoot.set(project.layout.projectDirectory)
        task.ownership.set(
            HardeningOwnership(
                owned.mapNotNull { input ->
                    input.modulePath?.let { module ->
                        HardeningOwnership.OwnedModule(
                            module,
                            project.projectDir.toPath().resolve(module.removePrefix(":")),
                            setOf("main"),
                        )
                    }
                },
                emptySet(),
                emptySet(),
            ),
        )
        task.ownedArtifactMetadata.set(owned.map(ClassArtifactInputCodec::encode))
        task.hierarchyArtifactMetadata.set(emptyList())
        task.projectClassJars.set(owned.map { input ->
            project.layout.file(project.provider { input.file.toFile() }).get()
        })
        task.projectClassDirectories.set(emptyList())
        task.runtimeClasspath.setFrom(emptyList<Any>())
        task.bootClasspath.setFrom(emptyList<Any>())
        task.preparedRegistry.set(prepared.resolve("registry.json").toFile())
        task.lineageSeed.set(prepared.resolve("seed.bin").toFile())
        task.preparedState.set(prepared.resolve(PREPARED_STATE_FILE).toFile())
        task.effectiveR8Rules.set(
            prepared.resolve("effective-rules.pro").also { rules -> rules.writeText("") }.toFile(),
        )
        val output = project.layout.buildDirectory.dir("hardening/code")
        task.codeRegistry.set(output.map { it.file("code-registry.json") })
        task.codeMapping.set(output.map { it.file("code-mapping.txt") })
        task.applyMappingRules.set(output.map { it.file("applymapping.pro") })
        task.codeNamingManifest.set(output.map { it.file("code-naming.json") })
        task.potentialBeanFieldsManifest.set(output.map { it.file("potential-bean-fields.json") })
    }

    private fun prepareState(
        root: Path = repository,
        contentSaltSha256: String = "b".repeat(64),
        entropyStart: Int = 1,
    ): Path {
        val prepared = root.resolve("build/prepared")
        val state = StateStore(
            entropy = EntropySource { _, size -> ByteArray(size) { index -> (entropyStart + index).toByte() } },
        ).prepare(
            PrepareRequest(
                root = root.resolve("state"),
                coordinates = StateCoordinates(
                    projectKey = "demo",
                    variant = "demoDebug",
                    namespace = "com.example",
                    applicationId = "com.example",
                    configurationSha256 = "a".repeat(64),
                ),
                outputDirectory = prepared,
                contentSaltSha256 = contentSaltSha256,
                reusePrevious = true,
                keepHistory = true,
                quarantineInvalid = true,
            ),
        )
        PreparedStateCodec.write(prepared.resolve(PREPARED_STATE_FILE), state)
        return prepared
    }

    private fun classJar(
        path: Path,
        internalName: String,
        sourceFile: String,
        access: Int = Opcodes.ACC_PUBLIC,
        methods: List<String> = emptyList(),
        methodAccess: Int = Opcodes.ACC_PUBLIC,
        methodDescriptors: Map<String, String> = emptyMap(),
        fieldDescriptors: Map<String, String> = emptyMap(),
        fieldAccess: Int = Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC,
        interfaces: List<String> = emptyList(),
        additionalClasses: List<ClassSpec> = emptyList(),
        superName: String = "java/lang/Object",
    ): Path {
        path.parent.createDirectories()
        fun classBytes(spec: ClassSpec): ByteArray = ClassWriter(ClassWriter.COMPUTE_MAXS).apply {
            visit(Opcodes.V17, spec.access, spec.internalName, null, spec.superName, spec.interfaces.toTypedArray())
            visitSource(spec.sourceFile, null)
            spec.fieldDescriptors.forEach { (name, descriptor) ->
                visitField(spec.fieldAccess, name, descriptor, null, null).visitEnd()
            }
            spec.methods.forEach { name ->
                val descriptor = spec.methodDescriptors[name] ?: "()V"
                visitMethod(spec.methodAccess, name, descriptor, null, null).apply {
                    if (spec.methodAccess and (Opcodes.ACC_ABSTRACT or Opcodes.ACC_NATIVE) == 0) {
                        visitCode()
                        if (name == "dispatch" && descriptor == "(Lexternal/ReviewManager;)V") {
                            visitVarInsn(Opcodes.ALOAD, 0)
                            visitMethodInsn(
                                Opcodes.INVOKEINTERFACE,
                                "external/ReviewManager",
                                "requestReview",
                                "()V",
                                true,
                            )
                        }
                        visitInsn(Opcodes.RETURN)
                        visitMaxs(0, 0)
                    }
                    visitEnd()
                }
            }
            visitEnd()
        }.toByteArray()
        ZipOutputStream(Files.newOutputStream(path)).use { zip ->
            (
                listOf(
                    ClassSpec(
                        internalName,
                        sourceFile,
                        access,
                        methods,
                        methodAccess,
                        methodDescriptors,
                        fieldDescriptors,
                        fieldAccess,
                        interfaces,
                        superName,
                    ),
                ) +
                    additionalClasses
                ).forEach { spec ->
                zip.putNextEntry(ZipEntry("${spec.internalName}.class"))
                zip.write(classBytes(spec))
                zip.closeEntry()
            }
        }
        return path
    }

    private fun gitInit() {
        check(ProcessBuilder("git", "init", "-q", repository.toString()).start().waitFor() == 0)
    }

    private data class Fixture(
        val task: GenerateHardeningCodeMappingTask,
        val preparedRegistry: Path,
    )

    private data class ExternalDescriptorFixture(
        val programFiles: List<Path>,
        val applyMappingRules: Path,
        val methodAlias: String,
        val fieldAlias: String,
        val generatedMethodAlias: String,
        val ownedMethodAlias: String,
        val ownedOriginalOwners: Set<String>,
    )

    private data class ClassSpec(
        val internalName: String,
        val sourceFile: String,
        val access: Int = Opcodes.ACC_PUBLIC,
        val methods: List<String> = emptyList(),
        val methodAccess: Int = Opcodes.ACC_PUBLIC,
        val methodDescriptors: Map<String, String> = emptyMap(),
        val fieldDescriptors: Map<String, String> = emptyMap(),
        val fieldAccess: Int = Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC,
        val interfaces: List<String> = emptyList(),
        val superName: String = "java/lang/Object",
    )

    private class LateVerificationFailure : RuntimeException()

    private companion object {
        val OWNED_CLASSES = listOf(
            ":app" to "com/example/App",
            ":core" to "com/example/Base",
            ":compress" to "com/example/Compress",
            ":selector" to "com/example/Selector",
            ":ucrop" to "com/example/Ucrop",
        )
    }
}
