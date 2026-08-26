package com.holin.android.hardening.audit

import com.holin.android.hardening.HardeningOwnership
import com.holin.android.hardening.testHardeningOwnership
import java.nio.file.Files
import java.nio.file.Path
import kotlin.io.path.createDirectories
import kotlin.io.path.writeText
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import org.junit.jupiter.api.io.TempDir

class HardeningSourceAuditScannerTest {
    @TempDir
    lateinit var repository: Path

    @Test
    fun `scans only declared arbitrary module source sets and package scope`() {
        gitInit()
        source("mobile/src/demo/java/com/example/mobile/Owned.kt", "package com.example.mobile\nclass Owned\n")
        source("mobile/src/main/java/com/example/mobile/NotSelected.kt", "package com.example.mobile\nclass NotSelected\n")
        source("core/src/shared/kotlin/com/example/core/Core.kt", "package com.example.core\nclass Core\n")
        source("core/src/shared/java/com/example/generated/Junk.java", "package com.example.generated; class Junk {}\n")
        source("core/src/shared/java/com/example/excluded/Legacy.java", "package com.example.excluded; class Legacy {}\n")
        source("core/src/shared/kotlin/com/example/core/Script.kts", "package com.example.core\nclass Script\n")
        source("core/src/shared/kotlin/com/example/core/Ignored.kt", "package com.example.core\nclass Ignored\n")
        repository.resolve(".gitignore").writeText("core/src/shared/kotlin/com/example/core/Ignored.kt\n")
        val ownership = HardeningOwnership(
            listOf(
                HardeningOwnership.OwnedModule(":mobile", repository.resolve("mobile"), setOf("demo")),
                HardeningOwnership.OwnedModule(":core", repository.resolve("core"), setOf("shared")),
            ),
            setOf("com.example.generated"),
            setOf("com.example.excluded"),
        )

        val audit = HardeningSourceAuditScanner(
            repositoryRoot = repository,
            appDirectory = repository.resolve("mobile"),
            namespace = "com.example.mobile",
            ownership = ownership,
        ).scan()

        assertEquals(
            listOf(
                "core/src/shared/kotlin/com/example/core/Core.kt",
                "mobile/src/demo/java/com/example/mobile/Owned.kt",
            ),
            audit.productionSourceFiles,
        )
    }

    @Test
    fun `custom flavor source root overrides main source audit evidence`() {
        gitInit()
        val main = repository.resolve("mobile/custom/main-code/com/example/Contract.kt")
        source(
            "mobile/custom/main-code/com/example/Contract.kt",
            """
                package com.example
                val gson = GsonBuilder().setFieldNamingStrategy(CustomStrategy()).create()
            """.trimIndent(),
        )
        val orchid = repository.resolve("mobile/custom/orchid-code/com/example/Contract.kt")
        source(
            "mobile/custom/orchid-code/com/example/Contract.kt",
            """
                package com.example
                val gson = GsonBuilder().setFieldNamingStrategy(FieldNamingPolicy.IDENTITY).create()
            """.trimIndent(),
        )
        val roots = HardeningOwnership.ResolvedSourceRoots.fromSourceSets(
            listOf(
                HardeningOwnership.ResolvedSourceSetRoots(
                    "main",
                    emptySet(),
                    setOf(main.parent.parent.parent),
                    emptySet(),
                    emptySet(),
                ),
                HardeningOwnership.ResolvedSourceSetRoots(
                    "orchid",
                    emptySet(),
                    setOf(orchid.parent.parent.parent),
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

        val audit = HardeningSourceAuditScanner(
            repository,
            repository.resolve("mobile"),
            "com.example",
            null,
            ownership,
        ).scan()

        assertEquals(listOf("mobile/custom/orchid-code/com/example/Contract.kt"), audit.productionSourceFiles)
        assertTrue(audit.unresolvedContracts.none { it.kind == UnresolvedContractKind.GSON_FIELD_NAMING_STRATEGY })
    }

    @Test
    fun `allows built in Gson field naming policies and rejects a custom strategy`() {
        gitInit()
        source(
            "app/src/main/java/com/example/GsonNaming.kt",
            """
            package com.example

            val builtIn = GsonBuilder().setFieldNamingStrategy(FieldNamingPolicy.IDENTITY).create()
            val fullyQualified = GsonBuilder().setFieldNamingStrategy(com.google.gson.FieldNamingPolicy.LOWER_CASE_WITH_UNDERSCORES).create()
            val custom = GsonBuilder().setFieldNamingStrategy(ServerNamingStrategy()).create()
            val text = "GsonBuilder().setFieldNamingStrategy(RemoteNamingStrategy()).create()"
            // GsonBuilder().setFieldNamingStrategy(CommentNamingStrategy()).create()
            """.trimIndent(),
        )

        val violations = scanner().scan().unresolvedContracts
            .filter { it.kind == UnresolvedContractKind.GSON_FIELD_NAMING_STRATEGY }

        assertEquals(1, violations.size)
        assertEquals(5, violations.single().line)
        assertEquals(
            ".setFieldNamingStrategy(ServerNamingStrategy())",
            violations.single().expression,
        )
        assertEquals(
            "custom Gson FieldNamingStrategy can derive JSON keys from renamed metadata",
            violations.single().reason,
        )
    }

    @Test
    fun `resolves literal and compile time constant reflection and resource contracts`() {
        gitInit()
        source(
            "app/src/main/java/com/example/Contracts.kt",
            """
            package com.example

            private const val MODEL = "com.example.Model"
            private const val METHOD = "ren" + "der"

            fun contracts(loader: ClassLoader, resources: android.content.res.Resources) {
                Class.forName(MODEL)
                loader.loadClass("com.example.Other")
                Model::class.java.getDeclaredMethod(METHOD, String::class.java)
                Model::class.java.getDeclaredField("token")
                resources.getIdentifier("hero", "drawable", "com.example")
            }
            """.trimIndent(),
        )

        val audit = scanner().scan()

        assertTrue(audit.unresolvedContracts.isEmpty(), audit.unresolvedContracts.joinToString())
        assertEquals(
            setOf(
                ResolvedContractKind.CLASS_FOR_NAME to "com.example.Model",
                ResolvedContractKind.CLASS_LOADER to "com.example.Other",
                ResolvedContractKind.METHOD to "render(java.lang.String)",
                ResolvedContractKind.FIELD to "token",
                ResolvedContractKind.RESOURCE_IDENTIFIER to "com.example:drawable/hero",
            ),
            audit.resolvedContracts.map { it.kind to it.resolvedName }.toSet(),
        )
    }

    @Test
    fun `fails closed for variables interpolation concatenation and unknown method descriptors`() {
        gitInit()
        source(
            "app/src/main/java/com/example/Dynamic.kt",
            """
            package com.example

            fun dynamic(
                loader: ClassLoader,
                resources: android.content.res.Resources,
                remote: String,
                parameterTypes: Array<Class<*>>,
            ) {
                Class.forName(remote)
                loader.loadClass("com.example." + remote)
                Model::class.java.getMethod("render", *parameterTypes)
                resources.getIdentifier("hero_${'$'}remote", "drawable", "com.example")
            }
            """.trimIndent(),
        )

        val audit = scanner().scan()

        assertEquals(4, audit.unresolvedContracts.size)
        assertEquals(
            setOf(
                UnresolvedContractKind.APP_REFLECTION,
                UnresolvedContractKind.RESOURCE_LOOKUP,
            ),
            audit.unresolvedContracts.map { it.kind }.toSet(),
        )
        assertTrue(audit.unresolvedContracts.all { it.reason.isNotBlank() })
    }

    @Test
    fun `ignores comments strings generated tests kts junk and git ignored sources`() {
        gitInit()
        repository.resolve(".gitignore").writeText("app/src/main/java/ignored/\n")
        source(
            "app/src/main/java/com/example/Real.kt",
            """
            package com.example
            // Class.forName(remote)
            val text = "resources.getIdentifier(remote, type, packageName)"
            fun ok() = Class.forName("com.example.Real")
            """.trimIndent(),
        )
        source("app/src/main/java/ignored/Ignored.kt", "fun bad() = Class.forName(remote)")
        source("app/src/main/java/com/example/Script.kts", "Class.forName(remote)")
        source("app/src/main/generated/com/example/Generated.kt", "Class.forName(remote)")
        source("app/src/test/java/com/example/Test.kt", "Class.forName(remote)")
        source("app/src/main/java/com/example/junkcode/Junk.kt", "package com.example.junkcode\nClass.forName(remote)")

        val audit = scanner().scan()

        assertTrue(audit.unresolvedContracts.isEmpty())
        assertEquals(listOf("app/src/main/java/com/example/Real.kt"), audit.productionSourceFiles)
        assertEquals(1, audit.resolvedContracts.size)
    }

    @Test
    fun `reports preserve candidates for external name contracts and exported components`() {
        gitInit()
        source(
            "app/src/main/java/com/example/model/Profile.kt",
            """
            package com.example.model

            import android.webkit.JavascriptInterface
            import io.objectbox.annotation.Entity
            import java.io.Serializable

            @Entity
            data class Profile(
                val displayName: String,
                @com.google.gson.annotations.SerializedName("user_id") val userId: String,
            ) : Serializable {
                @JavascriptInterface fun send(value: String) = Unit
                external fun nativeToken(): String
            }
            """.trimIndent(),
        )
        source(
            "app/src/main/AndroidManifest.xml",
            """
            <manifest xmlns:android="http://schemas.android.com/apk/res/android">
              <application>
                <activity android:name="com.example.PublicActivity" android:exported="true" />
                <service android:name="com.example.PrivateService" android:exported="false" />
              </application>
            </manifest>
            """.trimIndent(),
        )

        val audit = scanner().scan()
        val byKind = audit.externalNameCandidates.groupBy { it.kind }

        assertTrue(ExternalNameContractKind.GSON_UNEXPLICIT_FIELD in byKind)
        assertTrue(byKind.getValue(ExternalNameContractKind.GSON_UNEXPLICIT_FIELD).any { it.symbol == "displayName" })
        assertTrue(byKind.getValue(ExternalNameContractKind.GSON_UNEXPLICIT_FIELD).none { it.symbol == "userId" })
        assertTrue(ExternalNameContractKind.SERIALIZABLE in byKind)
        assertTrue(ExternalNameContractKind.OBJECTBOX_ENTITY in byKind)
        assertTrue(ExternalNameContractKind.JAVASCRIPT_INTERFACE in byKind)
        assertTrue(ExternalNameContractKind.JNI_NATIVE in byKind)
        assertTrue(byKind.getValue(ExternalNameContractKind.EXPORTED_COMPONENT).any { it.symbol == "com.example.PublicActivity" })
        assertTrue(byKind.getValue(ExternalNameContractKind.EXPORTED_COMPONENT).none { it.symbol.contains("PrivateService") })
        assertTrue(audit.externalNameCandidates.all { it.action == ExternalNameAction.PRESERVE_AND_REPORT })
    }

    @Test
    fun `reports manifest declared classes and winning layout custom views with exact evidence`() {
        gitInit()
        source(
            "app/src/main/AndroidManifest.xml",
            """
            <manifest xmlns:android="http://schemas.android.com/apk/res/android">
              <application android:name=".App">
                <activity android:name=".PublicActivity" android:exported="true" />
                <service android:name="PrivateService" android:exported="false" />
                <receiver android:name="com.example.Receiver" />
                <provider android:name=".Provider" />
                <activity-alias android:name=".LauncherAlias" android:targetActivity=".TargetActivity" />
              </application>
              <instrumentation android:name=".Instrumentation" />
            </manifest>
            """.trimIndent(),
        )
        source(
            "core/src/main/AndroidManifest.xml",
            """
            <manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.example.library">
              <application>
                <activity android:name=".LibraryActivity" />
                <service android:name="LibraryService" />
              </application>
            </manifest>
            """.trimIndent(),
        )
        source(
            "app/src/main/res/layout/main.xml",
            """
            <layout>
              <data />
              <com.example.MainView />
              <view class="com.example.SharedView" />
              <com.vendor.ExternalView />
              <com.example.MainView />
            </layout>
            """.trimIndent(),
        )
        source(
            "app/src/main/res/layout-land/main.xml",
            """
            <com.example.LandView />
            """.trimIndent(),
        )
        source("app/src/main/res/xml/ignored.xml", "<com.example.IgnoredView />")
        source("app/src/main/res/layout/ignored.json", "{ \"class\": \"com.example.IgnoredJson\" }")

        val candidates = scanner().scan().externalNameCandidates
        val manifest = candidates.filter { it.kind == ExternalNameContractKind.MANIFEST_DECLARED_CLASS }
        val views = candidates.filter { it.kind == ExternalNameContractKind.LAYOUT_CUSTOM_VIEW }

        assertEquals(
            setOf(
                "com.example.App",
                "com.example.PublicActivity",
                "com.example.PrivateService",
                "com.example.Receiver",
                "com.example.Provider",
                "com.example.TargetActivity",
                "com.example.Instrumentation",
                "com.example.library.LibraryActivity",
                "com.example.library.LibraryService",
            ),
            manifest.map(ExternalNameCandidate::symbol).toSet(),
        )
        assertTrue(manifest.none { it.symbol.contains("LauncherAlias") })
        assertTrue(manifest.all { it.line > 1 })
        assertTrue(candidates.any { it.kind == ExternalNameContractKind.EXPORTED_COMPONENT && it.symbol == "com.example.PublicActivity" })
        assertEquals(
            listOf(
                "com.example.LandView",
                "com.example.MainView",
                "com.example.SharedView",
                "com.vendor.ExternalView",
                "com.example.MainView",
            ),
            views.map(ExternalNameCandidate::symbol),
        )
        assertEquals(listOf(1, 3, 4, 5, 6), views.map(ExternalNameCandidate::line))
        assertTrue(candidates.none { it.symbol.contains("Ignored") })
    }

    @Test
    fun `scans selected app static resource layers with AGP winner and ambiguity semantics`() {
        gitInit()
        source("app/src/main/res/layout/profile.xml", "<com.example.MainProfileView />")
        source("app/src/dsl-res/layout/profile.xml", "<com.example.DslProfileView />")

        val winning = HardeningSourceAuditScanner(
            repository,
            repository.resolve("app"),
            "com.example",
            listOf(
                listOf(repository.resolve("app/src/dsl-res")),
                listOf(repository.resolve("app/src/main/res")),
            ),
            testHardeningOwnership(repository),
        ).scan()

        assertEquals(
            listOf("com.example.DslProfileView"),
            winning.externalNameCandidates
                .filter { it.kind == ExternalNameContractKind.LAYOUT_CUSTOM_VIEW }
                .map(ExternalNameCandidate::symbol),
        )
        assertEquals(
            listOf("app/src/dsl-res/layout/profile.xml"),
            winning.productionSourceFiles.filter { it.endsWith("profile.xml") },
        )

        source("app/src/also-dsl-res/layout/profile.xml", "<com.example.AmbiguousProfileView />")
        val failure = assertFailsWith<IllegalArgumentException> {
            HardeningSourceAuditScanner(
                repository,
                repository.resolve("app"),
                "com.example",
                listOf(
                    listOf(
                        repository.resolve("app/src/dsl-res"),
                        repository.resolve("app/src/also-dsl-res"),
                    ),
                    listOf(repository.resolve("app/src/main/res")),
                ),
                testHardeningOwnership(repository),
            ).scan()
        }

        assertTrue(failure.message.orEmpty().contains("ambiguous static app resource winner for layout/profile.xml"))
    }

    @Test
    fun `rejects static resource directory below an app symlink to outside the repository`() {
        gitInit()
        val outside = repository.resolveSibling("outside-resources")
        outside.resolve("res/layout").createDirectories()
        outside.resolve("res/layout/escaped.xml").writeText("<com.example.EscapedView />")
        val link = repository.resolve("app/src/linked")
        link.parent.createDirectories()
        Files.createSymbolicLink(link, outside)
        val escapedRoot = link.resolve("res")

        val audit = HardeningSourceAuditScanner(
            repository,
            repository.resolve("app"),
            "com.example",
            listOf(listOf(escapedRoot)),
            testHardeningOwnership(repository),
        ).scan()

        assertTrue(audit.productionSourceFiles.none { it.endsWith("escaped.xml") })
        assertTrue(audit.externalNameCandidates.none { it.symbol == "com.example.EscapedView" })
    }

    @Test
    fun `reports production shaped local Gson candidates for bytecode resolution`() {
        gitInit()
        source(
            "app/src/main/java/com/example/MyJsBridge.kt",
            """
            package com.example

            import android.app.Activity
            import android.webkit.JavascriptInterface
            import com.example.json.GsonUtils

            class MyJsBridge(
                private val constructorField: String,
            ) : Activity() {
                private val classBodyField = constructorField

                @JavascriptInterface
                fun a(content: String) {
                    val commonJsBridgeBean = GsonUtils.fromJson(content, CommonJsBridgeBean::class.java)
                }
            }
            """.trimIndent(),
        )

        val candidates = scanner().scan().externalNameCandidates
            .filter { it.kind == ExternalNameContractKind.GSON_UNEXPLICIT_FIELD }

        assertEquals(
            listOf(
                "constructorField" to 8,
                "classBodyField" to 10,
                "commonJsBridgeBean" to 14,
            ),
            candidates.map { it.symbol to it.line },
        )
    }

    @Test
    fun `scans production sources from every owned module`() {
        gitInit()
        source("app/src/main/java/com/example/AppOwned.kt", "fun appOwned() = Class.forName(\"com.example.AppOwned\")")
        source("core/src/main/java/com/example/BaseOwned.kt", "fun baseOwned() = Class.forName(\"com.example.BaseOwned\")")
        source("compress/src/main/java/com/example/CompressOwned.kt", "fun compressOwned() = Class.forName(\"com.example.CompressOwned\")")
        source("selector/src/main/java/com/example/SelectorOwned.kt", "fun selectorOwned() = Class.forName(\"com.example.SelectorOwned\")")
        source("ucrop/src/main/java/com/example/UcropOwned.kt", "fun ucropOwned() = Class.forName(\"com.example.UcropOwned\")")

        val audit = scanner().scan()

        assertEquals(
            setOf(
                "app/src/main/java/com/example/AppOwned.kt",
                "core/src/main/java/com/example/BaseOwned.kt",
                "compress/src/main/java/com/example/CompressOwned.kt",
                "selector/src/main/java/com/example/SelectorOwned.kt",
                "ucrop/src/main/java/com/example/UcropOwned.kt",
            ),
            audit.productionSourceFiles.toSet(),
        )
        assertEquals(5, audit.resolvedContracts.size)
    }

    @Test
    fun `reports generated binding and Android platform reflection as external contracts`() {
        gitInit()
        source(
            "core/src/main/java/com/example/PlatformContracts.kt",
            """
            package com.example

            import android.view.LayoutInflater
            import android.view.inputmethod.InputMethodManager
            import androidx.viewbinding.ViewBinding

            fun binding(cls: Class<*>, fieldName: String) {
                if (ViewBinding::class.java.isAssignableFrom(cls)) {
                    cls.getDeclaredMethod("inflate", LayoutInflater::class.java)
                }
                InputMethodManager::class.java.getDeclaredField(fieldName)
                val statusBar = Class.forName("android.app.StatusBarManager")
                statusBar.getMethod(fieldName)
                android.content.res.Resources.getSystem().getIdentifier(fieldName, "dimen", "android")
            }
            """.trimIndent(),
        )
        source(
            "selector/src/main/java/com/example/PlatformNested.java",
            """
            package com.example;
            final class PlatformNested {
                void reflect() throws Exception {
                    Class<?> params = Class.forName("android.view.MiuiWindowManager${'$'}LayoutParams");
                    params.getField("EXTRA_FLAG_STATUS_BAR_DARK_MODE");
                }
            }
            """.trimIndent(),
        )

        val audit = scanner().scan()

        assertTrue(audit.unresolvedContracts.isEmpty(), audit.unresolvedContracts.joinToString())
        assertTrue(
            audit.externalNameCandidates.any { it.kind == ExternalNameContractKind.GENERATED_VIEW_BINDING_REFLECTION },
        )
        assertTrue(
            audit.externalNameCandidates.any { it.kind == ExternalNameContractKind.PLATFORM_REFLECTION },
        )
        assertTrue(
            audit.externalNameCandidates.any { it.kind == ExternalNameContractKind.PLATFORM_RESOURCE_LOOKUP },
        )
        assertTrue(audit.externalNameCandidates.all { it.action == ExternalNameAction.PRESERVE_AND_REPORT })
    }

    private fun scanner() = HardeningSourceAuditScanner(
        repositoryRoot = repository,
        appDirectory = repository.resolve("app"),
        namespace = "com.example",
        ownership = testHardeningOwnership(repository),
    )

    private fun gitInit() {
        check(ProcessBuilder("git", "init", "-q", repository.toString()).start().waitFor() == 0)
    }

    private fun source(relative: String, content: String) {
        repository.resolve(relative).also { path ->
            path.parent?.createDirectories()
            path.writeText(content)
        }
    }
}
