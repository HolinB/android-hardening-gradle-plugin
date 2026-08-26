package com.holin.android.hardening

import com.android.tools.smali.dexlib2.AccessFlags
import com.android.tools.smali.dexlib2.dexbacked.DexBackedDexFile
import com.android.tools.smali.dexlib2.iface.instruction.ReferenceInstruction
import com.android.tools.smali.dexlib2.iface.reference.MethodReference
import com.holin.android.hardening.dex.DexClassAccessCompatibility
import com.holin.android.hardening.dex.DexTransformRequest
import com.holin.android.hardening.dex.SafeDexTransformer
import com.holin.android.hardening.r8.HardeningRulesFilter
import java.nio.file.Files
import java.nio.file.Path
import java.util.zip.ZipFile
import kotlin.io.path.createDirectories
import kotlin.io.path.writeText
import kotlin.test.Test
import kotlin.test.assertTrue
import org.gradle.testkit.runner.GradleRunner
import org.junit.jupiter.api.io.TempDir

class R8SuspendLambdaAccessFunctionalTest {
    @TempDir
    lateinit var projectDirectory: Path

    @Test
    fun `portable pipeline repairs Kotlin synthetic lambda bridge class access after applymapping`() {
        writeFixture()

        runner("assembleRelease").build()

        val apk = Files.walk(projectDirectory.resolve("build/outputs/apk/release")).use { paths ->
            paths.filter { path -> Files.isRegularFile(path) && path.fileName.toString().endsWith(".apk") }
                .toList()
                .single()
        }
        val dexFiles = ZipFile(apk.toFile()).use { zip ->
            zip.entries().asSequence()
                .filterNot { entry -> entry.isDirectory }
                .filter { entry -> entry.name.matches(Regex("classes(?:[2-9][0-9]*)?\\.dex")) }
                .map { entry -> zip.getInputStream(entry).use { input -> input.readBytes() } }
                .toList()
        }
        val continuation = "Lrenamed/ContinuationAlias;"
        val requiredPublicClasses = DexClassAccessCompatibility.requiredPublicClassDescriptors(
            dexFiles,
            setOf(continuation),
        )
        assertTrue(
            requiredPublicClasses == setOf(continuation),
            "fixture did not reproduce the package-private continuation owner: $requiredPublicClasses",
        )
        val dexClasses = dexFiles.flatMap { bytes ->
            val descriptors = DexBackedDexFile.fromInputStream(null, bytes.inputStream()).classes
                .mapTo(linkedSetOf()) { clazz -> clazz.type }
            if (continuation !in descriptors) {
                DexBackedDexFile.fromInputStream(null, bytes.inputStream()).classes.toList()
            } else {
                val transformed = SafeDexTransformer().transform(
                    bytes,
                    DexTransformRequest(
                        ownedDescriptorPrefixes = emptySet(),
                        ownedDescriptors = setOf(continuation),
                        salt = "suspend-lambda-access-fixture".encodeToByteArray(),
                        enforceMaximumGrowth = false,
                        selectionRate = 0.0,
                        publicClassDescriptors = setOf(continuation),
                    ),
                )
                DexBackedDexFile.fromInputStream(null, transformed.dexBytes.inputStream()).classes.toList()
            }
        }
        val classesByType = dexClasses.associateBy { clazz -> clazz.type }
        assertTrue(continuation in classesByType, "applymapping did not move the continuation")
        val callsIntoContinuation = dexClasses.flatMap { caller ->
            caller.methods.flatMap methodLoop@{ method ->
                val implementation = method.implementation ?: return@methodLoop emptyList<ObservedCall>()
                implementation.instructions.mapNotNull { instruction ->
                    val reference = (instruction as? ReferenceInstruction)?.reference as? MethodReference
                        ?: return@mapNotNull null
                    if (reference.definingClass != continuation) return@mapNotNull null
                    val target = classesByType.getValue(reference.definingClass).methods.singleOrNull { candidate ->
                        candidate.name == reference.name &&
                            candidate.parameterTypes == reference.parameterTypes &&
                            candidate.returnType == reference.returnType
                    } ?: return@mapNotNull null
                    ObservedCall(
                        caller.type,
                        method.name,
                        target.definingClass,
                        target.name,
                        classesByType.getValue(reference.definingClass).accessFlags,
                        target.accessFlags,
                    )
                }
            }
        }
        val syntheticCalls = callsIntoContinuation.filter { call ->
            call.caller != continuation
        }
        assertTrue(syntheticCalls.isNotEmpty(), "fixture did not emit a separate synthetic lambda caller")
        val illegalCalls = syntheticCalls.filter { call ->
            call.caller.substringBeforeLast('/', "") != call.target.substringBeforeLast('/', "") &&
                (!AccessFlags.PUBLIC.isSet(call.targetClassAccess) ||
                    !AccessFlags.PUBLIC.isSet(call.targetAccess))
        }
        assertTrue(illegalCalls.isEmpty(), "R8 emitted inaccessible cross-package calls: $illegalCalls")
    }

    private fun writeFixture() {
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
            rootProject.name = "suspend-lambda-access-fixture"
            """.trimIndent() + "\n",
        )
        projectDirectory.resolve("local.properties").writeText("sdk.dir=${sdk.replace("\\", "\\\\")}\n")
        projectDirectory.resolve("build.gradle.kts").writeText(
            """
            plugins {
                id("com.android.application") version "8.13.2"
                id("org.jetbrains.kotlin.android") version "2.3.0"
            }

            android {
                namespace = "fixture.app"
                compileSdk = 35
                defaultConfig {
                    applicationId = "fixture.app"
                    minSdk = 26
                    targetSdk = 35
                    versionCode = 1
                    versionName = "1.0"
                }
                compileOptions {
                    sourceCompatibility = JavaVersion.VERSION_17
                    targetCompatibility = JavaVersion.VERSION_17
                }
                buildTypes {
                    release {
                        isMinifyEnabled = true
                        proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "rules.pro")
                    }
                }
            }

            kotlin {
                compilerOptions {
                    freeCompilerArgs.add("-Xlambdas=indy")
                }
            }
            """.trimIndent() + "\n",
        )
        projectDirectory.resolve("rules.pro").writeText(
            buildString {
                appendLine("-keep class fixture.Entry { public static kotlin.jvm.functions.Function2 make(); }")
                appendLine("-keep class fixture.Sink { *; }")
                appendLine("-keep,allowoptimization,allowobfuscation class fixture.Entry${'$'}make${'$'}1")
                appendLine("-keepclassmembers class fixture.Entry${'$'}make${'$'}1 { int label; }")
                appendLine("-keepclassmembers class fixture.Entry${'$'}make${'$'}1 { *** invoke(...); *** invokeSuspend(...); }")
                appendLine("-allowaccessmodification")
                appendLine("-applymapping mapping.txt")
                appendLine("-dontwarn **")
                append(HardeningRulesFilter.filter("").effectiveRules)
            },
        )
        projectDirectory.resolve("mapping.txt").writeText(
            """
            fixture.Entry${'$'}make${'$'}1 -> renamed.ContinuationAlias:
                kotlin.Unit invokeSuspend${'$'}lambda${'$'}0(java.util.List) -> helperAlias
            """.trimIndent() + "\n",
        )
        val main = projectDirectory.resolve("src/main").createDirectories()
        main.resolve("AndroidManifest.xml").writeText("<manifest><application /></manifest>\n")
        main.resolve("java/fixture").createDirectories().resolve("Fixture.kt").writeText(
            """
            package fixture

            object Entry {
                @JvmStatic
                fun make(): suspend (List<String>) -> Unit = { values ->
                    java.util.concurrent.ForkJoinPool.commonPool().execute {
                        val copy = values.toMutableList()
                        Sink.accept(copy)
                    }
                }
            }

            object Sink {
                @JvmStatic
                fun accept(values: List<String>) {
                    values.size
                }
            }
            """.trimIndent() + "\n",
        )
    }

    private fun runner(vararg arguments: String): GradleRunner = GradleRunner.create()
        .withProjectDir(projectDirectory.toFile())
        .withTestKitDir(sharedGradleUserHome().toFile())
        .withArguments("--offline", "--stacktrace", *arguments)

    private fun sharedGradleUserHome(): Path = Path.of(
        System.getenv("GRADLE_USER_HOME") ?: "${System.getProperty("user.home")}/.gradle",
    )

    private data class ObservedCall(
        val caller: String,
        val callerMethod: String,
        val target: String,
        val targetMethod: String,
        val targetClassAccess: Int,
        val targetAccess: Int,
    )
}
