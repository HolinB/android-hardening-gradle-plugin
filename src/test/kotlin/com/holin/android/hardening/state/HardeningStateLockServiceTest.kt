package com.holin.android.hardening.state

import java.nio.channels.FileChannel
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardOpenOption.CREATE
import java.nio.file.StandardOpenOption.READ
import java.nio.file.StandardOpenOption.WRITE
import java.time.Duration
import kotlin.io.path.exists
import kotlin.io.path.readText
import kotlin.io.path.writeText
import kotlin.test.Test
import kotlin.test.assertContains
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import org.junit.jupiter.api.io.TempDir

class HardeningStateLockServiceTest {
    @TempDir
    lateinit var temporary: Path

    @Test
    fun `same thread may reenter and only outer release removes its owner sidecar`() {
        val lock = StateLock(lockFile(), ":app", "demoRelease", Duration.ofSeconds(1))

        val outer = lock.acquire()
        val inner = lock.acquire()

        assertTrue(lock.ownerFile.exists())
        inner.close()
        assertTrue(lock.ownerFile.exists())
        outer.close()
        assertFalse(lock.ownerFile.exists())
    }

    @Test
    fun `timeout reports both lock path and current owner diagnostics`() {
        val holder = StateLock(lockFile(), ":app", "demoRelease", Duration.ofSeconds(1))
        holder.acquire().use {
            val contender = StateLock(lockFile(), ":other", "demoRelease", Duration.ZERO)

            val failure = assertFailsWith<StateLockTimeoutException> { contender.acquire() }

            assertContains(failure.message!!, lockFile().toString())
            assertContains(failure.message!!, "demoRelease")
            assertContains(failure.message!!, "owner=")
        }
    }

    @Test
    fun `release preserves an owner sidecar whose nonce no longer belongs to it`() {
        val lock = StateLock(lockFile(), ":app", "demoRelease", Duration.ofSeconds(1))
        val handle = lock.acquire()
        val original = lock.ownerFile.readText()
        lock.ownerFile.writeText(original.replace(lock.owner.nonce, "replacement-nonce"))

        handle.close()

        assertTrue(lock.ownerFile.exists())
        assertContains(lock.ownerFile.readText(), "replacement-nonce")
    }

    @Test
    fun `owner sidecar records required diagnostics atomically`() {
        val lock = StateLock(lockFile(), ":app", "demoRelease", Duration.ofSeconds(1))
        lock.acquire().use {
            val owner = lock.ownerFile.readText()
            assertContains(owner, "\"schemaVersion\":1")
            assertContains(owner, "\"pid\":")
            assertContains(owner, "\"host\":")
            assertContains(owner, "\"projectPath\":\":app\"")
            assertContains(owner, "\"variant\":\"demoRelease\"")
            assertContains(owner, "\"startedAtUtc\":")
            assertContains(owner, "\"nonce\":")
            assertFalse(Files.exists(lock.ownerFile.resolveSibling("${lock.ownerFile.fileName}.tmp")))
        }
    }

    @Test
    fun `symlinked lock ancestor is rejected before writing outside state`() {
        val outside = temporary.resolve("outside").also(Files::createDirectories)
        val locks = temporary.resolve("state/locks")
        Files.createDirectories(locks.parent)
        Files.createSymbolicLink(locks, outside)
        val lock = StateLock(locks.resolve("state.lock"), ":app", "demoRelease", Duration.ofSeconds(1))

        assertFailsWith<IllegalArgumentException> { lock.acquire() }

        assertFalse(outside.resolve("state.lock").exists())
        assertFalse(outside.resolve("state.lock.owner.json").exists())
    }

    @Test
    fun `configured state boundary symlink five ancestors above lock is rejected`() {
        val outside = temporary.resolve("deep-outside").also(Files::createDirectories)
        val boundary = temporary.resolve("boundary")
        Files.createSymbolicLink(boundary, outside)
        val path = boundary.resolve("mapping/project/variant/locks/state.lock")
        val lock = StateLock(
            path,
            ":app",
            "demoRelease",
            Duration.ofSeconds(1),
            stateBoundary = boundary,
        )

        assertFailsWith<IllegalArgumentException> { lock.acquire() }

        assertFalse(outside.resolve("mapping/project/variant/locks/state.lock").exists())
        assertFalse(outside.resolve("mapping/project/variant/locks/state.lock.owner.json").exists())
    }

    @Test
    fun `build end fallback releases a leaked process lock and its owner sidecar`() {
        val lock = StateLock(lockFile(), ":app", "demoRelease", Duration.ofSeconds(1))
        val leaked = lock.acquire()

        lock.close()

        assertFalse(lock.ownerFile.exists())
        StateLock(lockFile(), ":next", "demoRelease", Duration.ofSeconds(1)).acquire().use { }
        leaked.close()
    }

    @Test
    fun `negative nanoTime origin still waits and retries a contended lock`() {
        val path = lockFile()
        Files.createDirectories(path.parent)
        var slept = false
        val contender = StateLock(
            path,
            ":app",
            "demoRelease",
            Duration.ofSeconds(60),
            nanoTime = { -1L },
            sleep = {
                slept = true
                throw RetryObserved()
            },
        )

        FileChannel.open(path, CREATE, READ, WRITE).use { channel ->
            channel.lock().use {
                assertFailsWith<RetryObserved> { contender.acquire() }
            }
        }

        assertTrue(slept)
    }

    @Test
    fun `timeout diagnostics never follow a swapped owner symlink`() {
        val path = lockFile()
        Files.createDirectories(path.parent)
        val secret = temporary.resolve("secret.txt").also { it.writeText("TOP-SECRET-CONTENT") }
        val contender = StateLock(path, ":app", "demoRelease", Duration.ZERO)
        Files.createSymbolicLink(contender.ownerFile, secret)

        val failure = FileChannel.open(path, CREATE, READ, WRITE).use { channel ->
            channel.lock().use {
                assertFailsWith<StateLockTimeoutException> { contender.acquire() }
            }
        }

        assertFalse(failure.message!!.contains("TOP-SECRET-CONTENT"))
        assertEquals("TOP-SECRET-CONTENT", secret.readText())
        assertTrue(Files.isSymbolicLink(contender.ownerFile))
    }

    @Test
    fun `release never follows or deletes a swapped owner symlink`() {
        val lock = StateLock(lockFile(), ":app", "demoRelease", Duration.ofSeconds(1))
        val handle = lock.acquire()
        val nonce = lock.owner.nonce
        val secret = temporary.resolve("release-secret.txt")
            .also { it.writeText("{\"nonce\":\"$nonce\"}") }
        Files.delete(lock.ownerFile)
        Files.createSymbolicLink(lock.ownerFile, secret)

        handle.close()

        assertTrue(Files.isSymbolicLink(lock.ownerFile))
        assertContains(secret.readText(), nonce)
    }

    @Test
    fun `sidecar cleanup failure still releases native and JVM locks`() {
        val lock = StateLock(
            lockFile(),
            ":app",
            "demoRelease",
            Duration.ofSeconds(1),
            deleteOwner = { _, _, _ -> throw CleanupFailure() },
        )
        val handle = lock.acquire()

        assertFailsWith<CleanupFailure> { handle.close() }

        StateLock(lockFile(), ":next", "demoRelease", Duration.ofSeconds(1)).acquire().use { }
    }

    private class RetryObserved : RuntimeException()
    private class CleanupFailure : RuntimeException()

    private fun lockFile(): Path = temporary.resolve("locks/state.lock")
}
