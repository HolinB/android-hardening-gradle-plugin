package com.holin.android.hardening.audit

import com.holin.android.hardening.HardcodedReferenceKind
import com.holin.android.hardening.HardeningOwnership
import java.nio.file.Path
import kotlin.io.path.createDirectories
import kotlin.io.path.writeText
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import org.junit.jupiter.api.io.TempDir

class HardcodedReferenceScopeScannerTest {
    @TempDir
    lateinit var repository: Path

    @Test
    fun `collects only included owned production sources and explicit custom manifests`() {
        gitInit()
        source("app/src/main/java/com/example/NotIncluded.java", "package com.example; final class NotIncluded {}")
        source("app/src/main/kotlin/com/example/Public.kt", "package com.example\nclass Public")
        source("app/src/main/kotlin/com/example/private/Excluded.kt", "package com.example.private\nclass Excluded")
        source("app/src/owned/AndroidManifest.xml", "<manifest package=\"com.example\" />")

        val scope = HardeningOwnership.HardcodedReferenceScope.resolve(
            setOf(HardcodedReferenceKind.URL),
            setOf("src/main/kotlin/**/*.kt", "src/owned/**/*.xml"),
            setOf("**/private/**"),
            true,
            true,
        )
        val ownership = HardeningOwnership(
            listOf(
                HardeningOwnership.OwnedModule(
                    ":app",
                    repository.resolve("app"),
                    setOf("main"),
                    HardeningOwnership.ResolvedSourceRoots.fromSourceSets(
                        listOf(
                            HardeningOwnership.ResolvedSourceSetRoots(
                                "main",
                                setOf(repository.resolve("app/src/main/java")),
                                setOf(repository.resolve("app/src/main/kotlin")),
                                emptySet(),
                                setOf(repository.resolve("app/src/owned/AndroidManifest.xml")),
                            ),
                        ),
                    ),
                ),
            ),
            emptySet(),
            emptySet(),
            scope,
        )

        val audit = HardeningSourceAuditScanner(
            repository,
            repository.resolve("app"),
            "com.example",
            null,
            ownership,
        ).scan()

        assertEquals(
            listOf(
                "app/src/main/kotlin/com/example/Public.kt",
                "app/src/owned/AndroidManifest.xml",
            ),
            audit.hardcodedReferenceSourceFiles,
        )
    }

    @Test
    fun `explicit default looking includes fail when an extension has no eligible match`() {
        gitInit()
        source("app/src/main/kotlin/com/example/Public.kt", "package com.example\nclass Public")
        val scope = HardeningOwnership.HardcodedReferenceScope.resolve(
            HardcodedReferenceKind.values().toSet(),
            listOf("**/*.kt", "**/*.java", "**/*.xml"),
            listOf("**/test/**", "**/androidTest/**"),
            true,
            true,
        )
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
                                emptySet(),
                            ),
                        ),
                    ),
                ),
            ),
            emptySet(),
            emptySet(),
            scope,
        )

        val failure = assertFailsWith<IllegalArgumentException> {
            HardeningSourceAuditScanner(repository, module, "com.example", null, ownership).scan()
        }

        assertTrue(failure.message.orEmpty().contains("**/*.java"))
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
