package com.holin.android.hardening.state

import java.nio.ByteBuffer
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.security.MessageDigest
import java.util.Comparator
import java.util.Base64

enum class CanonicalContentDomain(
    val id: String,
    val payloadMagic: ByteArray,
    val fileMagic: ByteArray,
) {
    LEGACY_V1(
        "legacy-v1",
        Base64.getDecoder().decode("U2luZ2xlTGlua0hhcmRlbmluZ0Nhbm9uaWNhbFBheWxvYWQAdjE="),
        Base64.getDecoder().decode("U2luZ2xlTGlua0hhcmRlbmluZ0Nhbm9uaWNhbEZpbGUAdjE="),
    ),
    HOLIN_1_2(
        "com.holin.android.hardening/1.2.0",
        "com.holin.android.hardening/1.2.0/canonical-payload/v1\u0000".toByteArray(Charsets.UTF_8),
        "com.holin.android.hardening/1.2.0/canonical-file/v1\u0000".toByteArray(Charsets.UTF_8),
    ),
    ;

    companion object {
        fun require(id: String): CanonicalContentDomain = values().singleOrNull { it.id == id }
            ?: throw IllegalArgumentException("unsupported canonical content domain: $id")
    }
}

object Sha256 {
    fun hex(bytes: ByteArray): String = digest(bytes).toHex()

    fun file(path: Path): String {
        require(Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS)) { "not a regular file: $path" }
        require(!Files.isSymbolicLink(path)) { "symlink is not allowed: $path" }
        return Files.newInputStream(path).use { input ->
            val digest = MessageDigest.getInstance("SHA-256")
            val buffer = ByteArray(DEFAULT_BUFFER_SIZE)
            while (true) {
                val count = input.read(buffer)
                if (count < 0) break
                digest.update(buffer, 0, count)
            }
            digest.digest().toHex()
        }
    }

    fun canonicalPayload(root: Path): String = canonicalPayload(root, CanonicalContentDomain.HOLIN_1_2)

    fun canonicalPayload(root: Path, domain: CanonicalContentDomain): String {
        require(Files.isDirectory(root, LinkOption.NOFOLLOW_LINKS)) { "payload root is not a directory: $root" }
        require(!Files.isSymbolicLink(root)) { "symlink is not allowed: $root" }
        val entries = Files.walk(root).use { stream ->
            stream.filter { it != root }
                .sorted(Comparator.comparing { root.relativize(it).toString().replace('\\', '/') })
                .toList()
        }
        val digest = MessageDigest.getInstance("SHA-256")
        digest.update(domain.payloadMagic)
        updateLength(digest, entries.size.toLong())
        entries.forEach { entry ->
            require(!Files.isSymbolicLink(entry)) { "symlink is not allowed: $entry" }
            val isDirectory = Files.isDirectory(entry, LinkOption.NOFOLLOW_LINKS)
            require(isDirectory || Files.isRegularFile(entry, LinkOption.NOFOLLOW_LINKS)) { "unsupported payload entry: $entry" }
            digest.update(if (isDirectory) DIRECTORY_ENTRY else FILE_ENTRY)
            val relative = root.relativize(entry).normalize()
            require(!relative.startsWith("..")) { "payload path escapes root: $entry" }
            val pathBytes = relative.toString().replace('\\', '/').toByteArray(Charsets.UTF_8)
            updateLength(digest, pathBytes.size.toLong())
            digest.update(pathBytes)
            if (isDirectory) return@forEach
            updateLength(digest, Files.size(entry))
            Files.newInputStream(entry).use { input ->
                val buffer = ByteArray(DEFAULT_BUFFER_SIZE)
                while (true) {
                    val count = input.read(buffer)
                    if (count < 0) break
                    digest.update(buffer, 0, count)
                }
            }
        }
        return digest.digest().toHex()
    }

    fun canonicalNode(path: Path): String = canonicalNode(path, CanonicalContentDomain.HOLIN_1_2)

    fun canonicalNode(path: Path, domain: CanonicalContentDomain): String {
        if (Files.isDirectory(path, LinkOption.NOFOLLOW_LINKS)) return canonicalPayload(path, domain)
        require(Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS)) { "unsupported payload node: $path" }
        require(!Files.isSymbolicLink(path)) { "symlink is not allowed: $path" }
        val digest = MessageDigest.getInstance("SHA-256")
        digest.update(domain.fileMagic)
        updateLength(digest, Files.size(path))
        Files.newInputStream(path).use { input ->
            val buffer = ByteArray(DEFAULT_BUFFER_SIZE)
            while (true) {
                val count = input.read(buffer)
                if (count < 0) break
                digest.update(buffer, 0, count)
            }
        }
        return digest.digest().toHex()
    }

    internal fun digest(bytes: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(bytes)

    private fun updateLength(digest: MessageDigest, value: Long) {
        digest.update(ByteBuffer.allocate(Long.SIZE_BYTES).putLong(value).array())
    }

    private fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }

    private const val DIRECTORY_ENTRY: Byte = 1
    private const val FILE_ENTRY: Byte = 2
}
