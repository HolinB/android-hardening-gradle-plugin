package com.holin.android.hardening

import com.android.tools.smali.dexlib2.dexbacked.DexBackedDexFile
import com.android.tools.smali.dexlib2.iface.instruction.ReferenceInstruction
import com.android.tools.smali.dexlib2.iface.reference.StringReference
import com.holin.android.hardening.code.ClassArtifactInput
import com.holin.android.hardening.code.ClassArtifactInputCodec
import com.holin.android.hardening.naming.RegistryCodec
import com.holin.android.hardening.naming.RegistrySnapshot
import com.holin.android.hardening.state.LineageReason
import com.holin.android.hardening.state.PreparedState
import com.holin.android.hardening.state.PreparedStateCodec
import com.holin.android.hardening.state.Sha256
import com.holin.android.hardening.state.StateCoordinates
import com.holin.android.hardening.state.StateIdentity
import com.holin.android.hardening.tasks.GenerateHardeningCodeMappingTask
import com.holin.android.hardening.tasks.GenerateHardeningR8RulesTask
import com.holin.android.hardening.verification.MappingSymbolKey
import com.holin.android.hardening.verification.R8MappingParser
import com.holin.android.hardening.verification.SymbolKind
import java.nio.file.Files
import java.nio.file.Path
import java.util.jar.JarEntry
import java.util.jar.JarOutputStream
import java.util.zip.ZipFile
import javax.tools.ToolProvider
import kotlin.io.path.createDirectories
import kotlin.io.path.readText
import kotlin.io.path.writeText
import kotlin.test.Test
import kotlin.test.assertContains
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import org.gradle.api.Project
import org.gradle.testkit.runner.GradleRunner
import org.gradle.testfixtures.ProjectBuilder
import org.junit.jupiter.api.io.TempDir

class R8HardcodedReferenceFunctionalTest {
    @TempDir
    lateinit var projectDirectory: Path

    @Test
    fun `real R8 rewrites owned class literals and exact rules preserve only proven reflected members`() {
        val aliases = writeFixture()

        assertContains(projectDirectory.resolve("rules.pro").readText(), "# hardening mapping sha256:")

        runner("assembleRelease").build()

        val mapping = projectDirectory.resolve("build/outputs/mapping/release/mapping.txt").readText()
        assertContains(mapping, "fixture.ProtectedTarget -> ${aliases.protectedClass}:")
        assertContains(mapping, "fixture.UnprotectedTarget -> ${aliases.unprotectedClass}:")
        assertTrue(Regex("java\\.lang\\.String probe\\(\\).* -> ${Regex.escape(aliases.probeMethod)}").containsMatchIn(mapping))
        assertTrue(
            Regex("java\\.lang\\.String unrelated\\(\\).* -> ${Regex.escape(aliases.unrelatedMethod)}")
                .containsMatchIn(mapping),
        )

        val apk = Files.walk(projectDirectory.resolve("build/outputs/apk/release")).use { paths ->
            paths.filter { path -> path.fileName.toString().endsWith(".apk") }.findFirst().orElseThrow()
        }
        val dexBytes = ZipFile(apk.toFile()).use { archive ->
            archive.getInputStream(archive.getEntry("classes.dex")).use { it.readBytes() }
        }
        val dex = DexBackedDexFile.fromInputStream(null, dexBytes.inputStream())
        val protectedTarget = dex.classes.single { it.type == aliases.protectedDescriptor }
        val unprotectedTarget = dex.classes.single { it.type == aliases.unprotectedDescriptor }
        assertTrue(protectedTarget.methods.any { it.name == "reflected" })
        assertTrue(protectedTarget.fields.any { it.name == "token" })
        assertTrue(protectedTarget.methods.any { it.name == aliases.unrelatedMethod })
        assertTrue(unprotectedTarget.methods.any { it.name == aliases.probeMethod })
        val entryStrings = dex.classes.single { it.type == "Lfixture/Entry;" }.methods.asSequence()
            .flatMap { method -> method.implementation?.instructions?.asSequence() ?: emptySequence() }
            .filterIsInstance<ReferenceInstruction>()
            .mapNotNull { instruction -> (instruction.reference as? StringReference)?.string }
            .toSet()
        assertFalse("fixture.ProtectedTarget" in entryStrings)
        assertFalse("fixture.UnprotectedTarget" in entryStrings)

        val runtimeOutput = runClassfileR8()
        assertContains(runtimeOutput, "CLASS_AND_MEMBER_OK")
    }

    private fun writeFixture(): GeneratedAliases {
        val sdk = System.getenv("ANDROID_HOME") ?: System.getenv("ANDROID_SDK_ROOT")
        require(!sdk.isNullOrBlank()) { "ANDROID_HOME or ANDROID_SDK_ROOT is required for the AGP fixture" }
        projectDirectory.resolve("settings.gradle.kts").writeText(
            """
            pluginManagement {
                repositories {
                    google()
                    mavenCentral()
                    gradlePluginPortal()
                }
            }
            dependencyResolutionManagement {
                repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
                repositories {
                    google()
                    mavenCentral()
                }
            }
            rootProject.name = "hardcoded-reference-r8-fixture"
            """.trimIndent() + "\n",
        )
        projectDirectory.resolve("local.properties").writeText("sdk.dir=${sdk.replace("\\", "\\\\")}\n")
        projectDirectory.resolve("build.gradle.kts").writeText(
            """
            plugins {
                id("com.android.application") version "8.13.2"
            }

            android {
                namespace = "fixture"
                compileSdk = 35
                defaultConfig {
                    applicationId = "fixture.hardcoded"
                    minSdk = 26
                    targetSdk = 35
                    versionCode = 1
                    versionName = "1.0"
                }
                compileOptions {
                    sourceCompatibility = JavaVersion.VERSION_17
                    targetCompatibility = JavaVersion.VERSION_17
                }
                lint {
                    checkReleaseBuilds = false
                }
                buildTypes {
                    release {
                        isMinifyEnabled = true
                        proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "rules.pro")
                    }
                }
            }
            """.trimIndent() + "\n",
        )
        val main = projectDirectory.resolve("src/main").createDirectories()
        main.resolve("AndroidManifest.xml").writeText("<manifest><application /></manifest>\n")
        val java = main.resolve("java/fixture").createDirectories()
        java.resolve("ProtectedTarget.java").writeText(
            """
            package fixture;

            public final class ProtectedTarget {
                public String token = "token";
                public String reflected(String value) { return value + token; }
                public String unrelated() { return "unrelated"; }
            }
            """.trimIndent() + "\n",
        )
        java.resolve("UnprotectedTarget.java").writeText(
            """
            package fixture;

            public final class UnprotectedTarget {
                public String probe() { return "probe"; }
            }
            """.trimIndent() + "\n",
        )
        java.resolve("Entry.java").writeText(
            """
            package fixture;

            public final class Entry {
                public static String run() throws Exception {
                    ProtectedTarget direct = new ProtectedTarget();
                    direct.reflected("direct");
                    direct.unrelated();
                    new UnprotectedTarget().probe();

                    Class<?> first = Class.forName("fixture.ProtectedTarget");
                    Class<?> second = Entry.class.getClassLoader().loadClass("fixture.ProtectedTarget");
                    Object instance = first.getDeclaredConstructor().newInstance();
                    Object value = ProtectedTarget.class.getDeclaredMethod("reflected", String.class).invoke(instance, "value");
                    Object token = ProtectedTarget.class.getDeclaredField("token").get(instance);

                    boolean classesResolve = first == second;
                    return classesResolve && value.equals("valuetoken") && token.equals("token")
                        ? "CLASS_AND_MEMBER_OK"
                        : "FAILED";
                }

                public static void main(String[] args) throws Exception {
                    System.out.println(run());
                }
            }
            """.trimIndent() + "\n",
        )
        projectDirectory.resolve("source-rules.pro").writeText(sourceRules())
        check(ProcessBuilder("git", "init", "-q", projectDirectory.toString()).start().waitFor() == 0)
        return generateHardeningRules()
    }

    private fun sourceRules(): String = buildString {
        appendLine("-keep,allowoptimization class fixture.Entry { public static void main(java.lang.String[]); public static java.lang.String run(); }")
        appendLine("-keep,allowobfuscation,allowoptimization class fixture.ProtectedTarget { public <init>(); }")
        appendLine("-keep,allowobfuscation,allowoptimization class fixture.UnprotectedTarget { public <init>(); }")
        appendLine("-keepclassmembers,allowoptimization,allowobfuscation class fixture.ProtectedTarget { java.lang.String unrelated(); }")
        appendLine("-keepclassmembers,allowoptimization,allowobfuscation class fixture.UnprotectedTarget { java.lang.String probe(); }")
        appendLine("-dontwarn **")
    }

    private fun generateHardeningRules(): GeneratedAliases {
        val repositoryRoot = projectDirectory.toRealPath()
        val compiledClasses = compileFixtureSources(repositoryRoot.resolve("generated-hardening/classes"))
        val project = ProjectBuilder.builder().withProjectDir(repositoryRoot.toFile()).build()
        val ownership = hardeningOwnership(
            listOf(HardeningOwnership.OwnedModule(":", repositoryRoot, setOf("main"))),
        )
        val prepared = prepareState(repositoryRoot)
        val input = ClassArtifactInput("release fixture classes", ":", compiledClasses)
        val mappingTask = project.tasks.register(
            "generateFixtureHardeningCodeMapping",
            GenerateHardeningCodeMappingTask::class.java,
        ).get()
        configureMappingTask(project, mappingTask, ownership, input, prepared)
        mappingTask.generate()

        val rulesTask = project.tasks.register(
            "generateFixtureHardeningR8Rules",
            GenerateHardeningR8RulesTask::class.java,
        ).get()
        rulesTask.variantName.set("release")
        rulesTask.sourceOccurrenceCount.set(1)
        rulesTask.sourceRules.from(repositoryRoot.resolve("source-rules.pro"))
        rulesTask.preserveExactRules.setFrom(emptyList<Any>())
        rulesTask.additionalRules.from(mappingTask.applyMappingRules)
        rulesTask.repositoryRoot.set(project.layout.projectDirectory)
        rulesTask.ownership.set(ownership)
        rulesTask.filteredRules.set(repositoryRoot.resolve("rules.pro").toFile())
        rulesTask.decisionManifest.set(repositoryRoot.resolve("generated-hardening/rules-manifest.json").toFile())
        rulesTask.generate()

        return generatedAliases(mappingTask.codeMapping.get().asFile.toPath())
    }

    private fun configureMappingTask(
        project: Project,
        task: GenerateHardeningCodeMappingTask,
        ownership: HardeningOwnership,
        input: ClassArtifactInput,
        prepared: Path,
    ) {
        val repositoryRoot = project.projectDir.toPath()
        task.variantName.set("release")
        task.namespace.set("fixture")
        task.applicationModulePath.set(":")
        task.unresolvedAppReflectionPolicy.set("FAIL_BUILD")
        task.externalNamesPolicy.set("PRESERVE_AND_REPORT")
        task.repositoryRoot.set(project.layout.projectDirectory)
        task.ownership.set(ownership)
        task.ownedArtifactMetadata.set(listOf(ClassArtifactInputCodec.encode(input)))
        task.hierarchyArtifactMetadata.set(emptyList())
        task.projectClassJars.set(emptyList())
        task.projectClassDirectories.set(
            listOf(project.layout.dir(project.provider { input.file.toFile() }).get()),
        )
        task.runtimeClasspath.setFrom(emptyList<Any>())
        task.bootClasspath.setFrom(emptyList<Any>())
        task.preparedRegistry.set(prepared.resolve("registry.json").toFile())
        task.lineageSeed.set(prepared.resolve("seed.bin").toFile())
        task.preparedState.set(prepared.resolve(PREPARED_STATE_FILE_NAME).toFile())
        task.effectiveR8Rules.set(repositoryRoot.resolve("source-rules.pro").toFile())
        task.codeRegistry.set(repositoryRoot.resolve("generated-hardening/code-registry.json").toFile())
        task.codeMapping.set(repositoryRoot.resolve("generated-hardening/code-mapping.txt").toFile())
        task.applyMappingRules.set(repositoryRoot.resolve("generated-hardening/applymapping.pro").toFile())
        task.codeNamingManifest.set(repositoryRoot.resolve("generated-hardening/code-naming.json").toFile())
        task.potentialBeanFieldsManifest.set(
            repositoryRoot.resolve("generated-hardening/potential-bean-fields.json").toFile(),
        )
    }

    private fun prepareState(repositoryRoot: Path): Path {
        val prepared = repositoryRoot.resolve("generated-hardening/prepared")
        prepared.createDirectories()
        val seed = ByteArray(32) { index -> (index + 1).toByte() }
        val seedPath = prepared.resolve("seed.bin")
        val mappingPath = prepared.resolve("mapping.txt")
        val registryPath = prepared.resolve("registry.json")
        Files.write(seedPath, seed)
        mappingPath.writeText("")
        registryPath.writeText(
            RegistryCodec().encode(RegistrySnapshot(1, Sha256.hex(seed), 1, emptyList(), emptyList())),
        )
        val coordinates = StateCoordinates("fixture", "release", "fixture", "fixture.hardcoded", "a".repeat(64))
        val hashes = linkedMapOf(
            "mapping.txt" to Sha256.file(mappingPath),
            "registry.json" to Sha256.file(registryPath),
            "seed.bin" to Sha256.file(seedPath),
        )
        val identity = StateIdentity(
            1,
            coordinates.projectKey,
            coordinates.variant,
            coordinates.namespace,
            coordinates.applicationId,
            coordinates.configurationSha256,
            "fixture-lineage",
            1,
            hashes.getValue("seed.bin"),
            hashes,
            false,
        )
        val state = PreparedState(
            repositoryRoot.resolve("generated-hardening/state"),
            coordinates,
            prepared,
            identity,
            LineageReason.FIRST_BUILD,
            1,
            null,
            "b".repeat(64),
            null,
            true,
        )
        PreparedStateCodec.write(prepared.resolve(PREPARED_STATE_FILE_NAME), state)
        return prepared
    }

    private fun hardeningOwnership(modules: List<HardeningOwnership.OwnedModule>): HardeningOwnership {
        val constructor = HardeningOwnership::class.java.getDeclaredConstructor(
            List::class.java,
            Set::class.java,
            Set::class.java,
            HardeningOwnership.HardcodedReferenceScope::class.java,
        )
        constructor.isAccessible = true
        return constructor.newInstance(
            modules,
            emptySet<String>(),
            emptySet<String>(),
            HardeningOwnership.HardcodedReferenceScope.defaults(),
        )
    }

    private fun generatedAliases(mapping: Path): GeneratedAliases {
        val symbols = R8MappingParser().parse(mapping, null).symbols
        fun alias(kind: SymbolKind, owner: String, name: String, descriptor: String): String =
            requireNotNull(symbols[MappingSymbolKey(kind, owner, name, descriptor)]) {
                "generated mapping is missing $kind $owner#$name$descriptor"
            }.single()
        return GeneratedAliases(
            alias(SymbolKind.CLASS, "fixture.ProtectedTarget", "fixture.ProtectedTarget", "Lfixture/ProtectedTarget;"),
            alias(SymbolKind.CLASS, "fixture.UnprotectedTarget", "fixture.UnprotectedTarget", "Lfixture/UnprotectedTarget;"),
            alias(SymbolKind.METHOD, "fixture.ProtectedTarget", "unrelated", "()Ljava/lang/String;"),
            alias(SymbolKind.METHOD, "fixture.UnprotectedTarget", "probe", "()Ljava/lang/String;"),
        )
    }

    private fun runClassfileR8(): String {
        Class.forName("com.android.tools.r8.R8")
        val classDirectory = compileFixtureSources(projectDirectory.resolve("runtime/classes"))
        val inputJar = projectDirectory.resolve("runtime/input.jar")
        JarOutputStream(Files.newOutputStream(inputJar)).use { output ->
            Files.walk(classDirectory).use { paths ->
                paths.filter(Files::isRegularFile).forEach { path ->
                    val name = classDirectory.relativize(path).toString().replace('\\', '/')
                    output.putNextEntry(JarEntry(name))
                    Files.copy(path, output)
                    output.closeEntry()
                }
            }
        }
        val outputJar = projectDirectory.resolve("runtime/output.jar")
        val java = Path.of(System.getProperty("java.home"), "bin", "java").toString()
        val javaBase = javaBaseLibrary().toString()
        val r8 = ProcessBuilder(
            java,
            "-cp",
            System.getProperty("java.class.path"),
            "com.android.tools.r8.R8",
            "--classfile",
            "--release",
            "--output",
            outputJar.toString(),
            "--pg-conf",
            projectDirectory.resolve("rules.pro").toString(),
            "--lib",
            javaBase,
            inputJar.toString(),
        ).directory(projectDirectory.toFile()).redirectErrorStream(true).start()
        val r8Output = r8.inputStream.bufferedReader().readText()
        check(r8.waitFor() == 0) { "classfile R8 failed:\n$r8Output" }
        val runtime = ProcessBuilder(java, "-cp", outputJar.toString(), "fixture.Entry")
            .redirectErrorStream(true)
            .start()
        val runtimeOutput = runtime.inputStream.bufferedReader().readText()
        check(runtime.waitFor() == 0) { "R8 runtime failed:\n$runtimeOutput" }
        return runtimeOutput
    }

    private fun compileFixtureSources(classDirectory: Path): Path {
        classDirectory.createDirectories()
        val sourceFiles = Files.walk(projectDirectory.resolve("src/main/java")).use { paths ->
            paths.filter { it.fileName.toString().endsWith(".java") }.map(Path::toString).toList()
        }
        val compiler = requireNotNull(ToolProvider.getSystemJavaCompiler())
        check(compiler.run(null, null, null, "-d", classDirectory.toString(), *sourceFiles.toTypedArray()) == 0)
        return classDirectory
    }

    private fun javaBaseLibrary(): Path {
        val jmod = Path.of(System.getProperty("java.home"), "jmods", "java.base.jmod")
        val library = projectDirectory.resolve("runtime/java-base.jar")
        ZipFile(jmod.toFile()).use { archive ->
            JarOutputStream(Files.newOutputStream(library)).use { output ->
                archive.entries().asSequence()
                    .filter { entry -> !entry.isDirectory && entry.name.startsWith("classes/") }
                    .forEach { entry ->
                        output.putNextEntry(JarEntry(entry.name.removePrefix("classes/")))
                        archive.getInputStream(entry).use { input -> input.copyTo(output) }
                        output.closeEntry()
                    }
            }
        }
        return library
    }

    private fun runner(vararg arguments: String): GradleRunner = GradleRunner.create()
        .withProjectDir(projectDirectory.toFile())
        .withTestKitDir(sharedGradleUserHome().toFile())
        .withArguments("--offline", "--stacktrace", *arguments)

    private fun sharedGradleUserHome(): Path = Path.of(
        System.getenv("GRADLE_USER_HOME") ?: "${System.getProperty("user.home")}/.gradle",
    )

    private data class GeneratedAliases(
        val protectedClass: String,
        val unprotectedClass: String,
        val unrelatedMethod: String,
        val probeMethod: String,
    ) {
        val protectedDescriptor: String = "L${protectedClass.replace('.', '/')};"
        val unprotectedDescriptor: String = "L${unprotectedClass.replace('.', '/')};"
    }

    private companion object {
        const val PREPARED_STATE_FILE_NAME = "prepared-state.properties"
    }
}
