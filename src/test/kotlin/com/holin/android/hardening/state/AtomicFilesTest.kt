package com.holin.android.hardening.state

import java.io.IOException
import java.nio.file.AtomicMoveNotSupportedException
import java.nio.file.Files
import java.nio.file.Path
import kotlin.io.path.createDirectory
import kotlin.io.path.exists
import kotlin.io.path.writeText
import kotlin.test.Test
import kotlin.test.assertFailsWith
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import org.junit.jupiter.api.io.TempDir

class AtomicFilesTest {
    @TempDir
    lateinit var root: Path

    @Test
    fun `unsupported atomic directory move fails without fallback copy or delete`() {
        val source = root.resolve("source").createDirectory()
        source.resolve("payload.txt").writeText("payload")
        val target = root.resolve("target")
        val atomicFiles = AtomicFiles(moveOperation = { from, to, _ ->
            throw AtomicMoveNotSupportedException(from.toString(), to.toString(), "test filesystem")
        })

        assertFailsWith<IllegalStateException> { atomicFiles.publishDirectory(source, target) }
        assertTrue(source.resolve("payload.txt").exists())
        assertFalse(target.exists())
    }

    @Test
    fun `checked replace failure preserves old target and removes temporary file`() {
        val target = root.resolve("active.json").also { it.writeText("old-pointer") }
        val atomicFiles = AtomicFiles(moveOperation = { _, _, _ -> throw IOException("injected move failure") })

        assertFailsWith<IOException> { atomicFiles.replace(target, "new-pointer".toByteArray()) }

        assertEquals("old-pointer", target.toFile().readText())
        val leftovers = Files.list(root).use { entries ->
            entries.filter { it.fileName.toString().startsWith(".active.json.tmp-") }.toList()
        }
        assertTrue(leftovers.isEmpty())
    }

    @Test
    fun `write or force failure removes partial temporary file`() {
        val target = root.resolve("active.json").also { it.writeText("old-pointer") }
        val atomicFiles = AtomicFiles(writeOperation = { temporary, _ ->
            Files.writeString(temporary, "partial-pointer")
            throw IOException("injected write or force failure")
        })

        assertFailsWith<IOException> { atomicFiles.replace(target, "new-pointer".toByteArray()) }

        assertEquals("old-pointer", target.toFile().readText())
        val leftovers = Files.list(root).use { entries ->
            entries.filter { it.fileName.toString().startsWith(".active.json.tmp-") }.toList()
        }
        assertTrue(leftovers.isEmpty())
    }
}
