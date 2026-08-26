package com.holin.android.hardening.inventory

import java.nio.file.Files
import java.nio.file.Path
import kotlin.io.path.createDirectories
import kotlin.io.path.writeText
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import org.junit.jupiter.api.io.TempDir

class GitIgnoreMatcherTest {
    @TempDir
    lateinit var repository: Path

    @Test
    fun `matches Git nesting negation escaped spaces and directory rules exactly`() {
        gitInit()
        repository.resolve(".gitignore").writeText(
            """
            ignored.kt
            escaped\ name.kt
            generated/
            *.tmp
            !keep.tmp
            """.trimIndent() + "\n",
        )
        repository.resolve("nested/.gitignore").write(
            """
            *.kt
            !Keep.kt
            """.trimIndent() + "\n",
        )
        val candidates = listOf(
            file("ignored.kt"),
            file("visible.kt"),
            file("escaped name.kt"),
            file("generated/Child.java"),
            file("drop.tmp"),
            file("keep.tmp"),
            file("nested/Drop.kt"),
            file("nested/Keep.kt"),
            file("nested/Visible.java"),
        )

        val ignored = GitIgnoreMatcher(repository).ignored(candidates)

        assertEquals(
            setOf("ignored.kt", "escaped name.kt", "generated/Child.java", "drop.tmp", "nested/Drop.kt"),
            ignored.map { repository.relativize(it).toString().replace('\\', '/') }.toSet(),
        )
    }

    @Test
    fun `rejects candidates outside the configured repository`() {
        gitInit()
        val outside = repository.resolveSibling("outside.kt")

        assertFailsWith<IllegalArgumentException> {
            GitIgnoreMatcher(repository).ignored(listOf(outside))
        }
    }

    private fun gitInit() {
        val process = ProcessBuilder("git", "init", "-q", repository.toString()).start()
        check(process.waitFor() == 0) { process.errorStream.bufferedReader().readText() }
    }

    private fun file(relative: String): Path = repository.resolve(relative).also { path ->
        path.parent?.createDirectories()
        path.writeText(relative)
    }

    private fun Path.write(content: String) {
        parent?.createDirectories()
        writeText(content)
    }
}
