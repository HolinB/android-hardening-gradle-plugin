package com.holin.android.hardening.state

import java.io.Closeable
import java.net.InetAddress
import java.nio.channels.FileChannel
import java.nio.channels.FileLock
import java.nio.channels.OverlappingFileLockException
import java.nio.ByteBuffer
import java.nio.charset.StandardCharsets.UTF_8
import java.nio.file.AtomicMoveNotSupportedException
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.StandardCopyOption.ATOMIC_MOVE
import java.nio.file.StandardCopyOption.REPLACE_EXISTING
import java.nio.file.StandardOpenOption.CREATE
import java.nio.file.StandardOpenOption.READ
import java.nio.file.StandardOpenOption.WRITE
import java.nio.file.attribute.BasicFileAttributes
import java.time.Duration
import java.time.Instant
import java.util.UUID
import java.util.concurrent.TimeUnit
import java.util.concurrent.locks.ReentrantLock
import java.lang.management.ManagementFactory
import org.gradle.api.file.DirectoryProperty
import org.gradle.api.file.RegularFileProperty
import org.gradle.api.provider.Property
import org.gradle.api.services.BuildService
import org.gradle.api.services.BuildServiceParameters

abstract class HardeningStateLockService : BuildService<HardeningStateLockService.Parameters>, AutoCloseable {
    interface Parameters : BuildServiceParameters {
        val lockFile: RegularFileProperty
        val projectPath: Property<String>
        val variant: Property<String>
        val timeoutSeconds: Property<Int>
        val stateBoundary: DirectoryProperty
    }

    private val stateLockDelegate = lazy(LazyThreadSafetyMode.SYNCHRONIZED) {
        StateLock(
            lockFile = parameters.lockFile.get().asFile.toPath(),
            projectPath = parameters.projectPath.get(),
            variant = parameters.variant.get(),
            timeout = Duration.ofSeconds(parameters.timeoutSeconds.get().toLong()),
            stateBoundary = parameters.stateBoundary.get().asFile.toPath(),
        )
    }
    private val stateLock: StateLock by stateLockDelegate

    fun acquire(): Closeable = stateLock.acquire()

    fun <T> withLock(action: () -> T): T = stateLock.withLock(action)

    override fun close() {
        if (stateLockDelegate.isInitialized()) stateLock.close()
    }
}

internal class StateLock(
    val lockFile: Path,
    private val projectPath: String,
    private val variant: String,
    private val timeout: Duration,
    private val stateBoundary: Path = lockFile.parent,
    private val nanoTime: () -> Long = System::nanoTime,
    private val sleep: (Duration) -> Unit = ::sleepFor,
    private val openChannel: (Path) -> FileChannel = ::openLockChannel,
    private val ownerFactory: () -> LockOwner = { LockOwner.create(projectPath, variant) },
    private val deleteOwner: (Path, Path, String) -> Unit = ::deleteOwnerIfMatching,
) {
    private val jvmLock = ReentrantLock(true)
    private var channel: FileChannel? = null
    private var fileLock: FileLock? = null
    private var heldOwner: LockOwner? = null

    val ownerFile: Path = lockFile.resolveSibling("${lockFile.fileName}.owner.json")
    val owner: LockOwner get() = heldOwner ?: error("state lock is not held")

    fun acquire(): Closeable {
        val startedAt = nanoTime()
        if (!jvmLock.tryLock(remaining(startedAt), TimeUnit.NANOSECONDS)) throw timeoutFailure()
        if (jvmLock.holdCount > 1) return Handle(this)

        var opened: FileChannel? = null
        try {
            requireSafeLockPath(lockFile, stateBoundary)
            lockFile.parent?.let(Files::createDirectories)
            requireSafeLockPath(lockFile, stateBoundary)
            opened = openChannel(lockFile)
            while (true) {
                val acquired = try {
                    opened.tryLock()
                } catch (_: OverlappingFileLockException) {
                    null
                }
                if (acquired != null) {
                    channel = opened
                    fileLock = acquired
                    heldOwner = ownerFactory()
                    requireSafeLockPath(ownerFile, stateBoundary)
                    writeOwnerAtomically(ownerFile, heldOwner!!)
                    return Handle(this)
                }
                val wait = remaining(startedAt)
                if (wait <= 0) throw timeoutFailure()
                sleep(Duration.ofNanos(minOf(RETRY_NANOS, wait)))
            }
        } catch (failure: Throwable) {
            runCatching { opened?.close() }
            jvmLock.unlock()
            throw failure
        }
    }

    fun <T> withLock(action: () -> T): T = acquire().use { action() }

    @Synchronized
    fun close() {
        var cleanupFailure: Throwable? = null
        try {
            heldOwner?.let {
                deleteOwner(ownerFile, stateBoundary, it.nonce)
            }
        } catch (failure: Throwable) {
            cleanupFailure = failure
        } finally {
            runCatching { fileLock?.release() }
            runCatching { channel?.close() }
            fileLock = null
            channel = null
            heldOwner = null
        }
        cleanupFailure?.let { throw it }
    }

    private fun release() {
        check(jvmLock.isHeldByCurrentThread) { "state lock must be released by the acquiring thread" }
        var cleanupFailure: Throwable? = null
        try {
            if (jvmLock.holdCount == 1) {
                try {
                    heldOwner?.let {
                        deleteOwner(ownerFile, stateBoundary, it.nonce)
                    }
                } catch (failure: Throwable) {
                    cleanupFailure = failure
                } finally {
                    runCatching { fileLock?.release() }
                    runCatching { channel?.close() }
                    fileLock = null
                    channel = null
                    heldOwner = null
                }
            }
        } finally {
            jvmLock.unlock()
        }
        cleanupFailure?.let { throw it }
    }

    private fun remaining(startedAt: Long): Long {
        val timeoutNanos = runCatching { timeout.toNanos() }.getOrDefault(Long.MAX_VALUE)
        val elapsed = (nanoTime() - startedAt).coerceAtLeast(0)
        return (timeoutNanos - elapsed).coerceAtLeast(0)
    }

    private fun timeoutFailure(): StateLockTimeoutException = StateLockTimeoutException(
        "timed out acquiring hardening state lock $lockFile; owner=${readOwnerDiagnostic(ownerFile, stateBoundary)}",
    )

    private class Handle(private val lock: StateLock) : Closeable {
        private var closed = false

        override fun close() {
            if (!closed) {
                closed = true
                lock.release()
            }
        }
    }

    private companion object {
        const val RETRY_NANOS = 50_000_000L
    }
}

internal data class LockOwner(
    val pid: String,
    val host: String,
    val projectPath: String,
    val variant: String,
    val startedAtUtc: Instant,
    val nonce: String,
) {
    fun encode(): String = buildString {
        append('{')
        append("\"schemaVersion\":1")
        append(",\"pid\":\"").append(json(pid)).append('\"')
        append(",\"host\":\"").append(json(host)).append('\"')
        append(",\"projectPath\":\"").append(json(projectPath)).append('\"')
        append(",\"variant\":\"").append(json(variant)).append('\"')
        append(",\"startedAtUtc\":\"").append(startedAtUtc).append('\"')
        append(",\"nonce\":\"").append(json(nonce)).append("\"}\n")
    }

    companion object {
        fun create(projectPath: String, variant: String): LockOwner = LockOwner(
            pid = ManagementFactory.getRuntimeMXBean().name.substringBefore('@'),
            host = runCatching { InetAddress.getLocalHost().hostName }.getOrDefault("unknown"),
            projectPath = projectPath,
            variant = variant,
            startedAtUtc = Instant.now(),
            nonce = UUID.randomUUID().toString(),
        )

        private fun json(value: String): String = value
            .replace("\\", "\\\\")
            .replace("\"", "\\\"")
            .replace("\n", "\\n")
            .replace("\r", "\\r")
            .replace("\t", "\\t")
    }
}

class StateLockTimeoutException(message: String) : IllegalStateException(message)

private fun openLockChannel(path: Path): FileChannel = FileChannel.open(path, CREATE, READ, WRITE, LinkOption.NOFOLLOW_LINKS)

private fun requireSafeLockPath(path: Path, stateBoundary: Path) {
    val absolute = path.toAbsolutePath().normalize()
    val boundary = stateBoundary.toAbsolutePath().normalize()
    require(absolute.startsWith(boundary) && absolute != boundary) {
        "hardening lock path must stay under configured state boundary: $absolute"
    }
    var current = boundary
    val ancestors = buildList {
        add(boundary)
        boundary.relativize(requireNotNull(absolute.parent)).forEach { component ->
            current = current.resolve(component)
            add(current)
        }
    }
    ancestors.forEach { ancestor ->
        current = ancestor
        if (Files.exists(current, LinkOption.NOFOLLOW_LINKS)) {
            require(!Files.isSymbolicLink(current)) { "symlink is not allowed in hardening lock path: $current" }
            require(Files.isDirectory(current, LinkOption.NOFOLLOW_LINKS)) {
                "hardening lock ancestor is not a directory: $current"
            }
        }
    }
    if (Files.exists(absolute, LinkOption.NOFOLLOW_LINKS)) {
        require(!Files.isSymbolicLink(absolute)) { "symlink is not allowed in hardening lock path: $absolute" }
        require(Files.isRegularFile(absolute, LinkOption.NOFOLLOW_LINKS)) { "hardening lock path is not a regular file: $absolute" }
    }
}

private fun sleepFor(duration: Duration) {
    if (!duration.isZero && !duration.isNegative) {
        val milliseconds = duration.toMillis()
        val nanoseconds = duration.minusMillis(milliseconds).toNanos().toInt()
        Thread.sleep(milliseconds, nanoseconds)
    }
}

private fun writeOwnerAtomically(ownerFile: Path, owner: LockOwner) {
    ownerFile.parent?.let(Files::createDirectories)
    val temporary = ownerFile.resolveSibling("${ownerFile.fileName}.tmp-${UUID.randomUUID()}")
    try {
        Files.writeString(temporary, owner.encode(), UTF_8, CREATE, WRITE)
        FileChannel.open(temporary, READ).use { it.force(true) }
        Files.move(temporary, ownerFile, ATOMIC_MOVE, REPLACE_EXISTING)
    } catch (failure: AtomicMoveNotSupportedException) {
        throw IllegalStateException("atomic owner sidecar move is not supported for $ownerFile", failure)
    } finally {
        Files.deleteIfExists(temporary)
    }
}

private fun deleteOwnerIfMatching(ownerFile: Path, stateBoundary: Path, nonce: String) {
    if (runCatching { requireSafeLockPath(ownerFile, stateBoundary) }.isFailure) return
    val owner = runCatching { readSafeOwner(ownerFile) }.getOrNull() ?: return
    val escapedNonce = nonce.replace("\\", "\\\\").replace("\"", "\\\"")
    if (!owner.text.contains("\"nonce\":\"$escapedNonce\"")) return
    val current = runCatching { Files.readAttributes(ownerFile, BasicFileAttributes::class.java, LinkOption.NOFOLLOW_LINKS) }
        .getOrNull()
        ?: return
    if (owner.fileKey != null && current.isRegularFile && current.fileKey() == owner.fileKey) Files.deleteIfExists(ownerFile)
}

private fun readOwnerDiagnostic(ownerFile: Path, stateBoundary: Path): String =
    runCatching {
        requireSafeLockPath(ownerFile, stateBoundary)
        readSafeOwner(ownerFile)?.text?.trim() ?: "unavailable (unsafe owner sidecar)"
    }
        .getOrElse { "unavailable (${it.javaClass.simpleName})" }

private fun readSafeOwner(ownerFile: Path): SafeOwner? {
    val before = Files.readAttributes(ownerFile, BasicFileAttributes::class.java, LinkOption.NOFOLLOW_LINKS)
    if (!before.isRegularFile || before.size() > MAX_OWNER_BYTES) return null
    return FileChannel.open(ownerFile, READ, LinkOption.NOFOLLOW_LINKS).use { channel ->
        val size = channel.size()
        if (size > MAX_OWNER_BYTES) return null
        val buffer = ByteBuffer.allocate(size.toInt())
        while (buffer.hasRemaining()) {
            if (channel.read(buffer) < 0) break
        }
        val after = Files.readAttributes(ownerFile, BasicFileAttributes::class.java, LinkOption.NOFOLLOW_LINKS)
        if (!after.isRegularFile || before.fileKey() != after.fileKey()) return null
        SafeOwner(String(buffer.array(), 0, buffer.position(), UTF_8), after.fileKey())
    }
}

private data class SafeOwner(val text: String, val fileKey: Any?)

private const val MAX_OWNER_BYTES = 16 * 1024L
