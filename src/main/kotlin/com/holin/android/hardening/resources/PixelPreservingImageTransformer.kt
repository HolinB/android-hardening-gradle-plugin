package com.holin.android.hardening.resources

import com.holin.android.hardening.state.Sha256
import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.MessageDigest
import java.util.zip.CRC32
import javax.imageio.ImageIO

enum class BitmapMode { LEGACY_PERCEPTUAL, PIXEL_EXACT }

data class PixelExactVerification(val width: Int, val height: Int, val backgrounds: List<Int>)

/** Changes container representation while retaining every encoded image sample and rendering field. */
object PixelPreservingImageTransformer {
    fun transform(before: ByteArray, path: String, salt: ByteArray): ByteArray = transformWithVerification(before, path, salt).first

    fun transformWithVerification(before: ByteArray, path: String, salt: ByteArray): Pair<ByteArray, PixelExactVerification> {
        require(salt.isNotEmpty())
        val marker = MessageDigest.getInstance("SHA-256").digest(salt + path.toByteArray() + before)
        val result = when (path.substringAfterLast('.').lowercase()) {
            "png" -> {
                val chunks = pngChunks(before)
                val data = chunks.filter { it.type == "IDAT" }.fold(ByteArray(0)) { bytes, chunk -> bytes + chunk.data }
                require(data.size > 1 && chunks.none { it.type == "acTL" }) { "unsupported PNG image data" }
                var split = 1 + ((marker[0].toInt() and 255) % (data.size - 1))
                if (chunks.count { it.type == "IDAT" } == 2 && chunks.first { it.type == "IDAT" }.data.size == split) {
                    split = if (split == data.size - 1) 1 else split + 1
                }
                val out = ByteArrayOutputStream()
                out.write(PNG_SIGNATURE)
                var emitted = false
                chunks.forEach { chunk ->
                    if (chunk.type != "IDAT") out.write(chunk.raw)
                    else if (!emitted) {
                        out.write(pngChunk("IDAT", data.copyOfRange(0, split)))
                        out.write(pngChunk("IDAT", data.copyOfRange(split, data.size)))
                        emitted = true
                    }
                }
                out.toByteArray()
            }
            "webp" -> {
                val chunks = webpChunks(before)
                require(chunks.none { it.type in setOf("ANIM", "ANMF", "HRDN") }) { "unsupported WebP container" }
                val result = before + "HRDN".toByteArray(Charsets.US_ASCII) +
                    ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(marker.size).array() + marker
                ByteBuffer.wrap(result).order(ByteOrder.LITTLE_ENDIAN).putInt(4, result.size - 8)
                result
            }
            "jpg", "jpeg" -> {
                require(before.size > 4 && before[0] == (-1).toByte() && before[1] == 0xd8.toByte())
                val payload = "HARDENING\u0000".toByteArray(Charsets.US_ASCII) + marker
                before.copyOfRange(0, 2) + byteArrayOf(-1, 0xef.toByte()) +
                    ByteBuffer.allocate(2).putShort((payload.size + 2).toShort()).array() + payload + before.copyOfRange(2, before.size)
            }
            else -> throw IllegalArgumentException("unsupported pixel-exact image format")
        }
        require(!before.contentEquals(result)) { "container transformation was ineffective" }
        return result to verify(before, result, path)
    }

    fun verify(before: ByteArray, after: ByteArray, path: String): PixelExactVerification {
        require(!before.contentEquals(after)) { "pixel-exact output must change the file fingerprint" }
        val extension = path.substringAfterLast('.').lowercase()
        when (extension) {
            "png" -> {
                val a = pngChunks(before); val b = pngChunks(after)
                require(a.filter { it.type != "IDAT" }.map { Sha256.hex(it.raw) } == b.filter { it.type != "IDAT" }.map { Sha256.hex(it.raw) }) {
                    "PNG rendering chunks or metadata changed"
                }
                fun data(chunks: List<Chunk>) = chunks.filter { it.type == "IDAT" }.fold(ByteArray(0)) { out, chunk -> out + chunk.data }
                require(data(a).contentEquals(data(b))) { "PNG compressed sample stream changed" }
            }
            "webp" -> {
                val a = webpChunks(before); val b = webpChunks(after)
                require(a.none { it.type == "HRDN" } && b.count { it.type == "HRDN" } == 1)
                require(b.last().type == "HRDN" && b.last().data.size == 32)
                require(a.map { Sha256.hex(it.raw) } == b.filterNot { it.type == "HRDN" }.map { Sha256.hex(it.raw) }) {
                    "WebP encoded samples or rendering metadata changed"
                }
            }
            "jpg", "jpeg" -> {
                require(after.size >= 6 && after[2] == (-1).toByte() && after[3] == 0xef.toByte())
                val length = ByteBuffer.wrap(after).getShort(4).toInt() and 0xffff
                require(length == 44 && after.copyOfRange(6, 16).contentEquals("HARDENING\u0000".toByteArray()))
                require((after.copyOfRange(0, 2) + after.copyOfRange(length + 4, after.size)).contentEquals(before)) {
                    "JPEG changed outside the private APP15 segment"
                }
            }
            else -> throw IllegalArgumentException("unsupported pixel-exact image format")
        }
        fun decode(bytes: ByteArray) = when (extension) {
            "webp" -> VerifiedWebp.read(bytes)
            "png" -> VerifiedPng.read(bytes)?.image
            else -> ImageIO.read(bytes.inputStream())
        }
        val a = requireNotNull(decode(before)) { "original image could not be decoded" }
        val b = requireNotNull(decode(after)) { "transformed image could not be decoded" }
        require(a.width == b.width && a.height == b.height)
        require(a.width.toLong() * a.height <= 16_777_216)
        val backgrounds = listOf(0x000000, 0xffffff, 0x808080, 0xff0000, 0x00ff00, 0x0000ff)
        val leftPixels = IntArray(a.width)
        val rightPixels = IntArray(b.width)
        for (y in 0 until a.height) {
            a.getRGB(0, y, a.width, 1, leftPixels, 0, a.width)
            b.getRGB(0, y, b.width, 1, rightPixels, 0, b.width)
            require(leftPixels.contentEquals(rightPixels)) { "RGBA pixels changed on row $y" }
            for (background in backgrounds) {
                for (x in leftPixels.indices) {
                    val left = leftPixels[x]
                    val right = rightPixels[x]
                    val leftAlpha = left ushr 24
                    val rightAlpha = right ushr 24
                    var shift = 0
                    while (shift <= 16) {
                        val channel = background ushr shift and 255
                        val leftComposite = ((left ushr shift and 255) * leftAlpha + channel * (255 - leftAlpha) + 127) / 255
                        val rightComposite = ((right ushr shift and 255) * rightAlpha + channel * (255 - rightAlpha) + 127) / 255
                        require(leftComposite == rightComposite) { "background composite changed" }
                        shift += 8
                    }
                }
            }
        }
        return PixelExactVerification(a.width, a.height, backgrounds)
    }

    private data class Chunk(val type: String, val data: ByteArray, val raw: ByteArray)

    private fun pngChunks(bytes: ByteArray): List<Chunk> {
        require(bytes.size >= 8 && bytes.copyOfRange(0, 8).contentEquals(PNG_SIGNATURE))
        val result = mutableListOf<Chunk>()
        var offset = 8
        while (offset < bytes.size) {
            require(bytes.size - offset >= 12)
            val length = ByteBuffer.wrap(bytes, offset, 4).int
            require(length >= 0 && length <= bytes.size - offset - 12)
            val raw = bytes.copyOfRange(offset, offset + 12 + length)
            require(CRC32().apply { update(raw, 4, length + 4) }.value == (ByteBuffer.wrap(raw, length + 8, 4).int.toLong() and 0xffffffffL))
            result.add(Chunk(String(raw, 4, 4, Charsets.US_ASCII), raw.copyOfRange(8, 8 + length), raw))
            offset += 12 + length
        }
        require(result.firstOrNull()?.type == "IHDR" && result.lastOrNull()?.type == "IEND")
        val idat = result.indices.filter { result[it].type == "IDAT" }
        require(idat.isNotEmpty() && idat == (idat.first()..idat.last()).toList())
        return result
    }

    private fun pngChunk(type: String, data: ByteArray): ByteArray {
        val body = type.toByteArray(Charsets.US_ASCII) + data
        return ByteBuffer.allocate(4).putInt(data.size).array() + body +
            ByteBuffer.allocate(4).putInt(CRC32().apply { update(body) }.value.toInt()).array()
    }

    private fun webpChunks(bytes: ByteArray): List<Chunk> {
        require(bytes.size >= 12 && String(bytes, 0, 4, Charsets.US_ASCII) == "RIFF" && String(bytes, 8, 4, Charsets.US_ASCII) == "WEBP")
        require(ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN).getInt(4) == bytes.size - 8)
        val result = mutableListOf<Chunk>()
        var offset = 12
        while (offset < bytes.size) {
            require(bytes.size - offset >= 8)
            val length = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN).getInt(offset + 4)
            require(length >= 0 && length.toLong() + (length and 1) <= bytes.size - offset - 8)
            val end = offset + 8 + length + (length and 1)
            result.add(Chunk(String(bytes, offset, 4, Charsets.US_ASCII), bytes.copyOfRange(offset + 8, offset + 8 + length), bytes.copyOfRange(offset, end)))
            offset = end
        }
        return result
    }

    private val PNG_SIGNATURE = byteArrayOf(-119, 80, 78, 71, 13, 10, 26, 10)
}
