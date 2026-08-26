package com.holin.android.hardening.audit

import com.holin.android.hardening.HardcodedReferenceKind
import com.holin.android.hardening.HardeningOwnership
import java.nio.file.Path
import kotlin.io.path.createDirectories
import kotlin.io.path.writeText
import kotlin.test.Test
import kotlin.test.assertEquals
import org.junit.jupiter.api.io.TempDir

class HardcodedReferenceUnresolvedTest {
    @TempDir
    lateinit var repository: Path

    @Test
    fun `reports unresolved dynamic references only for enabled scoped kinds`() {
        gitInit()
        source(
            "app/src/main/kotlin/com/example/Dynamic.kt",
            """
            package com.example

            fun dynamic(loader: ClassLoader, resources: android.content.res.Resources, remote: String, types: Array<Class<*>>) {
                Class.forName(remote)
                loader.loadClass("com.example." + remote)
                Model::class.java.getMethod("render", *types)
                resources.getIdentifier(remote, "drawable", "com.example")
            }
            """.trimIndent(),
        )

        val audit = scanner(
            setOf(
                HardcodedReferenceKind.CLASS_NAME,
                HardcodedReferenceKind.MEMBER_NAME,
                HardcodedReferenceKind.RESOURCE_NAME,
            ),
        ).scan()

        assertEquals(
            setOf(
                HardcodedReferenceKind.CLASS_NAME,
                HardcodedReferenceKind.MEMBER_NAME,
                HardcodedReferenceKind.RESOURCE_NAME,
            ),
            audit.unresolvedHardcodedReferences.map { it.kind }.toSet(),
        )
        assertEquals(4, audit.unresolvedHardcodedReferences.size)
    }

    private fun scanner(kinds: Set<HardcodedReferenceKind>): HardeningSourceAuditScanner {
        val module = repository.resolve("app")
        val scope = HardeningOwnership.HardcodedReferenceScope.resolve(
            kinds,
            setOf("**/*.kt"),
            emptySet(),
            true,
            true,
        )
        val ownership = HardeningOwnership(
            listOf(HardeningOwnership.OwnedModule(":app", module, setOf("main"))),
            emptySet(),
            emptySet(),
            scope,
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
