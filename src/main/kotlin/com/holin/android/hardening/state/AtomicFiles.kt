package com.holin.android.hardening.state

import java.io.IOException
import java.nio.ByteBuffer
import java.nio.channels.FileChannel
import java.nio.file.AtomicMoveNotSupportedException
import java.nio.file.CopyOption
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardCopyOption.ATOMIC_MOVE
import java.nio.file.StandardCopyOption.REPLACE_EXISTING
import java.nio.file.StandardOpenOption.CREATE_NEW
import java.nio.file.StandardOpenOption.READ
import java.nio.file.StandardOpenOption.WRITE
import java.util.UUID

class AtomicFiles internal constructor(
    private val moveOperation: (Path, Path, Array<CopyOption>) -> Path = { source, target, options ->
        Files.move(source, target, *options)
    },
    private val writeOperation: (Path, ByteArray) -> Unit = ::writeForced,
) {
    fun replace(target: Path, bytes: ByteArray) {
        Files.createDirectories(target.parent)
        val temporary = target.parent.resolve(".${target.fileName}.tmp-${UUID.randomUUID()}")
        try {
            writeOperation(temporary, bytes)
            atomicMove(temporary, target, replaceExisting = true)
            forceDirectory(target.parent)
        } finally {
            Files.deleteIfExists(temporary)
        }
    }

    fun publishDirectory(source: Path, target: Path) {
        require(Files.isDirectory(source)) { "atomic publish source is not a directory: $source" }
        require(source.fileSystem == target.fileSystem) { "atomic publish requires the same filesystem: $source -> $target" }
        Files.createDirectories(target.parent)
        atomicMove(source, target, replaceExisting = false)
        forceDirectory(target.parent)
    }

    private fun atomicMove(source: Path, target: Path, replaceExisting: Boolean) {
        val options = if (replaceExisting) arrayOf<CopyOption>(ATOMIC_MOVE, REPLACE_EXISTING) else arrayOf<CopyOption>(ATOMIC_MOVE)
        try {
            moveOperation(source, target, options)
        } catch (unsupported: AtomicMoveNotSupportedException) {
            throw IllegalStateException(
                "atomic move is not supported for $source -> $target on ${source.fileSystem}",
                unsupported,
            )
        }
    }

    private fun forceDirectory(directory: Path) {
        try {
            FileChannel.open(directory, READ).use { it.force(true) }
        } catch (_: UnsupportedOperationException) {
            // Some providers do not expose directories as forceable channels.
        } catch (_: IOException) {
            // The atomic move already succeeded; directory forcing is provider-specific.
        }
    }
}

private fun writeForced(path: Path, bytes: ByteArray) {
    FileChannel.open(path, CREATE_NEW, WRITE).use { channel ->
        val buffer = ByteBuffer.wrap(bytes)
        while (buffer.hasRemaining()) channel.write(buffer)
        channel.force(true)
    }
}
