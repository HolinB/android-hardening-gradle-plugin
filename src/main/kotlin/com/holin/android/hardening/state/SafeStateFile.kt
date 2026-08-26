package com.holin.android.hardening.state

import java.nio.ByteBuffer
import java.nio.channels.FileChannel
import java.nio.charset.StandardCharsets.UTF_8
import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import java.nio.file.StandardOpenOption.READ
import java.nio.file.attribute.BasicFileAttributes

internal object SafeStateFile {
    fun readUtf8(path: Path, maxBytes: Long): String {
        require(maxBytes in 1..Int.MAX_VALUE) { "maxBytes must fit a positive buffer size" }
        val before = Files.readAttributes(path, BasicFileAttributes::class.java, NOFOLLOW_LINKS)
        require(before.isRegularFile) { "state metadata is not a regular file: $path" }
        require(before.size() <= maxBytes) { "state metadata exceeds $maxBytes bytes: $path" }
        val expectedFileKey = requireNotNull(before.fileKey()) { "state metadata file identity is unavailable: $path" }
        return FileChannel.open(path, READ, NOFOLLOW_LINKS).use { channel ->
            val size = channel.size()
            require(size <= maxBytes) { "state metadata exceeds $maxBytes bytes: $path" }
            val buffer = ByteBuffer.allocate(size.toInt())
            while (buffer.hasRemaining()) {
                if (channel.read(buffer) < 0) break
            }
            val after = Files.readAttributes(path, BasicFileAttributes::class.java, NOFOLLOW_LINKS)
            require(
                after.isRegularFile &&
                    after.fileKey() == expectedFileKey &&
                    after.size() == size &&
                    before.size() == size &&
                    buffer.position().toLong() == size,
            ) { "state metadata changed while reading: $path" }
            String(buffer.array(), 0, buffer.position(), UTF_8)
        }
    }
}
