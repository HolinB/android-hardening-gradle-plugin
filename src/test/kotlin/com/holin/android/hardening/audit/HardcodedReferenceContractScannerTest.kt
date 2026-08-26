package com.holin.android.hardening.audit

import com.holin.android.hardening.HardcodedReferenceKind
import com.holin.android.hardening.HardeningOwnership
import java.nio.file.Path
import kotlin.io.path.createDirectories
import kotlin.io.path.writeText
import kotlin.test.Test
import kotlin.test.assertEquals
import org.junit.jupiter.api.io.TempDir

class HardcodedReferenceContractScannerTest {
    @TempDir
    lateinit var repository: Path

    @Test
    fun `reports static references and external literals without expanding naming contracts`() {
        gitInit()
        source(
            "app/src/main/kotlin/com/example/Contracts.kt",
            """
            package com.example

            import com.example.model.Model
            import com.example.model.Other

            fun contracts(
                loader: ClassLoader,
                resources: android.content.res.Resources,
                receiver: Class<Model>,
                parameterType: Class<*>,
            ) {
                Class.forName("com.example.model.Model")
                loader.loadClass("com.example.model.Other")
                Model::class.java.getMethod("render", String::class.java)
                Model::class.java.getDeclaredField("token")
                receiver.getMethod("ambiguous", String::class.java)
                Model::class.java.getMethod("unknown", parameterType)
                resources.getIdentifier("hero", "drawable", "com.example")
                val route = "route:profile"
                val uri = "demo://profile"
                val url = "https://api.example.test/profile"
                val file = "profile.json"
                // val commentedUrl = "https://comment.example.test/private?token=secret"
                /* val commentedRoute = "route:commented" */
            }
            """.trimIndent(),
        )
        source(
            "app/src/owned/AndroidManifest.xml",
            """
            <manifest xmlns:android="http://schemas.android.com/apk/res/android">
              <!-- <meta-data android:value="https://comment.example.test/private?token=secret" /> -->
              <application><meta-data android:value="https://api.example.test/manifest" /></application>
            </manifest>
            """.trimIndent(),
        )

        val audit = scanner().scan()

        assertEquals(
            setOf(
                HardcodedReferenceKind.CLASS_NAME to "com.example.model.Model",
                HardcodedReferenceKind.CLASS_NAME to "com.example.model.Other",
                HardcodedReferenceKind.MEMBER_NAME to "render(java.lang.String)",
                HardcodedReferenceKind.MEMBER_NAME to "token",
                HardcodedReferenceKind.RESOURCE_NAME to "com.example:drawable/hero",
                HardcodedReferenceKind.ROUTE to "route:profile",
                HardcodedReferenceKind.URI to "demo://profile",
                HardcodedReferenceKind.URL to "https://api.example.test/profile",
                HardcodedReferenceKind.URL to "https://api.example.test/manifest",
                HardcodedReferenceKind.FILE_NAME to "profile.json",
            ),
            audit.hardcodedReferenceFindings.map { it.kind to it.value }.toSet(),
        )
        assertEquals(0, audit.externalNameCandidates.size)
        assertEquals(
            setOf(
                Triple(
                    "com/example/model/Model",
                    "Lcom/example/model/Model;",
                    "com.example.model.Model",
                ),
                Triple(
                    "com/example/model/Other",
                    "Lcom/example/model/Other;",
                    "com.example.model.Other",
                ),
            ),
            audit.hardcodedReferenceFindings
                .filter { it.kind == HardcodedReferenceKind.CLASS_NAME }
                .map { Triple(it.ownerInternalName, it.jvmDescriptor, it.value) }
                .toSet(),
        )
        assertEquals(
            setOf(
                Triple("com/example/model/Model", "(Ljava/lang/String;)", "render(java.lang.String)"),
                Triple("com/example/model/Model", null, "token"),
            ),
            audit.hardcodedReferenceFindings
                .filter { it.kind == HardcodedReferenceKind.MEMBER_NAME }
                .map { Triple(it.ownerInternalName, it.jvmDescriptor, it.value) }
                .toSet(),
        )
        assertEquals(
            setOf(".getMethod(\"ambiguous\", String::class.java)", ".getMethod(\"unknown\", parameterType)"),
            audit.unresolvedHardcodedReferences
                .filter { it.kind == HardcodedReferenceKind.MEMBER_NAME }
                .map { it.expression }
                .toSet(),
        )
    }

    private fun scanner(): HardeningSourceAuditScanner {
        val module = repository.resolve("app")
        val ownership = HardeningOwnership(
            listOf(
                HardeningOwnership.OwnedModule(
                    ":app",
                    module,
                    setOf("main"),
                    HardeningOwnership.ResolvedSourceRoots.fromSourceSets(
                        listOf(
                            HardeningOwnership.ResolvedSourceSetRoots(
                                "main",
                                emptySet(),
                                setOf(module.resolve("src/main/kotlin")),
                                emptySet(),
                                setOf(module.resolve("src/owned/AndroidManifest.xml")),
                            ),
                        ),
                    ),
                ),
            ),
            emptySet(),
            emptySet(),
        )
        return HardeningSourceAuditScanner(repository, module, "com.example", null, ownership)
    }

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
