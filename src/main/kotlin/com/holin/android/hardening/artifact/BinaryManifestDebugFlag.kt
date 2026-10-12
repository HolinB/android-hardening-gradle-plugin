package com.holin.android.hardening.artifact

import java.nio.ByteBuffer
import java.nio.ByteOrder

/** Adds the default-false flag without re-encoding existing manifest strings or nodes. */
internal object BinaryManifestDebugFlag {
    private const val DEBUGGABLE = 0x0101000f
    private fun buffer(bytes: ByteArray) = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN)
    private fun short(bytes: ByteArray, offset: Int) = buffer(bytes).getShort(offset).toInt() and 65535

    fun addAbsent(input: ByteArray, strings: List<String>, resources: List<Int>): ByteArray {
        val chunks = chunks(input)
        require(chunks.count { short(it, 0) == 1 } == 1 && chunks.count { short(it, 0) == 0x180 } <= 1)
        val namespace = strings.indexOf("http://schemas.android.com/apk/res/android")
        require(namespace >= 0) { "manifest has no Android namespace" }
        val existing = resources.indexOf(DEBUGGABLE)
        require(existing < 0 || strings.getOrNull(existing) == "debuggable")
        val nameIndex = if (existing < 0) strings.size else existing
        var applications = 0
        var insertedMap = false
        val changed = mutableListOf<ByteArray>()
        val resourceChunk = ByteBuffer.allocate(8 + 4 * maxOf(resources.size, nameIndex + 1)).order(ByteOrder.LITTLE_ENDIAN)
        resourceChunk.putShort(0x180).putShort(8).putInt(resourceChunk.capacity())
        repeat(maxOf(resources.size, nameIndex + 1)) { resourceChunk.putInt(if (it == nameIndex) DEBUGGABLE else resources.getOrElse(it) { 0 }) }
        chunks.forEach { chunk ->
            when (short(chunk, 0)) {
                1 -> {
                    changed += if (existing < 0) appendName(chunk) else chunk
                    if (chunks.none { short(it, 0) == 0x180 }) { changed += resourceChunk.array(); insertedMap = true }
                }
                0x180 -> { changed += resourceChunk.array(); insertedMap = true }
                0x102 -> {
                    val b = buffer(chunk)
                    val header = short(chunk, 2)
                    val tag = b.getInt(header + 4)
                    if (strings.getOrNull(tag) != "application") changed += chunk else {
                        applications++
                        val attrStart = header + short(chunk, header + 8)
                        val count = short(chunk, header + 12)
                        require(short(chunk, header + 10) == 20 && count < 65535)
                        val attributes = (0 until count).map { chunk.copyOfRange(attrStart + it * 20, attrStart + (it + 1) * 20) }
                        require(attributes.none { resources.getOrNull(buffer(it).getInt(4)) == DEBUGGABLE })
                        val insertion = attributes.indexOfFirst { (resources.getOrNull(buffer(it).getInt(4)) ?: 0) > DEBUGGABLE }.let { if (it < 0) count else it }
                        val attribute = ByteBuffer.allocate(20).order(ByteOrder.LITTLE_ENDIAN)
                        attribute.putInt(namespace).putInt(nameIndex).putInt(-1).putShort(8).put(0).put(0x12).putInt(-1)
                        val position = attrStart + insertion * 20
                        val output = chunk.copyOfRange(0, position) + attribute.array() + chunk.copyOfRange(position, chunk.size)
                        val out = buffer(output)
                        out.putInt(4, output.size).putShort(header + 12, (count + 1).toShort())
                        listOf(14, 16, 18).forEach { delta ->
                            val index = short(chunk, header + delta)
                            if (index > insertion) out.putShort(header + delta, (index + 1).toShort())
                        }
                        changed += output
                    }
                }
                else -> changed += chunk
            }
        }
        require(applications == 1 && insertedMap) { "manifest requires exactly one application" }
        val result = input.copyOfRange(0, short(input, 2)) + changed.fold(ByteArray(0)) { output, chunk -> output + chunk }
        buffer(result).putInt(4, result.size)
        verifyAddition(input, result, strings, resources, nameIndex)
        return result
    }

    private fun appendName(original: ByteArray): ByteArray {
        val b = buffer(original)
        val header = short(original, 2)
        val count = b.getInt(8)
        val start = b.getInt(20)
        require(header == 28 && b.getInt(12) == 0 && b.getInt(24) == 0)
        val utf8 = b.getInt(16) and 0x100 != 0
        val encoded = if (utf8) byteArrayOf(10, 10) + "debuggable".toByteArray(Charsets.UTF_8) + byteArrayOf(0)
            else byteArrayOf(10, 0) + "debuggable".toByteArray(Charsets.UTF_16LE) + byteArrayOf(0, 0)
        val newOffset = buffer(ByteArray(4)).putInt(original.size - start).array()
        val split = header + count * 4
        val raw = original.copyOfRange(0, split) + newOffset + original.copyOfRange(split, original.size) + encoded
        val output = raw.copyOf((raw.size + 3) / 4 * 4)
        buffer(output).putInt(4, output.size).putInt(8, count + 1).putInt(16, b.getInt(16) and 1.inv()).putInt(20, start + 4)
        return output
    }

    /** Inverse structural proof: existing string bytes, IDs, attributes, and every other chunk are exact. */
    private fun verifyAddition(before: ByteArray, after: ByteArray, strings: List<String>, resources: List<Int>, nameIndex: Int) {
        val a = chunks(before)
        val b = chunks(after)
        val ap = a.single { short(it, 0) == 1 }
        val bp = b.single { short(it, 0) == 1 }
        if (nameIndex < strings.size) require(ap.contentEquals(bp)) else {
            val old = buffer(ap); val new = buffer(bp)
            val startA = old.getInt(20); val startB = new.getInt(20)
            require(new.getInt(8) == old.getInt(8) + 1 && startB == startA + 4)
            require(bp.copyOfRange(startB, startB + ap.size - startA).contentEquals(ap.copyOfRange(startA, ap.size)))
            require(bp.copyOfRange(28, 28 + strings.size * 4).contentEquals(ap.copyOfRange(28, 28 + strings.size * 4)))
            val restoredHeader = bp.copyOfRange(0, 28)
            buffer(restoredHeader).putInt(4, ap.size).putInt(8, strings.size).putInt(16, old.getInt(16)).putInt(20, startA)
            require(restoredHeader.contentEquals(ap.copyOfRange(0, 28)))
        }
        val map = b.single { short(it, 0) == 0x180 }
        resources.forEachIndexed { index, id -> require(buffer(map).getInt(8 + index * 4) == id) }
        require(buffer(map).getInt(8 + nameIndex * 4) == DEBUGGABLE)
        val nodesA = a.filterNot { short(it, 0) in setOf(1, 0x180) }
        val nodesB = b.filterNot { short(it, 0) in setOf(1, 0x180) }
        require(nodesA.size == nodesB.size)
        nodesA.zip(nodesB).forEach { (old, new) ->
            if (short(old, 0) != 0x102 || strings.getOrNull(buffer(old).getInt(short(old, 2) + 4)) != "application") {
                require(old.contentEquals(new)) { "unrelated manifest node changed" }
            } else {
                val header = short(new, 2)
                val start = header + short(new, header + 8)
                val count = short(new, header + 12)
                val added = (0 until count).single { buffer(new).getInt(start + it * 20 + 4) == nameIndex }
                val position = start + added * 20
                val attr = buffer(new.copyOfRange(position, position + 20))
                require(strings[attr.getInt(0)] == "http://schemas.android.com/apk/res/android" && attr.getInt(8) == -1)
                require(attr.getShort(12).toInt() == 8 && attr.get(14).toInt() == 0 && attr.get(15).toInt() == 0x12 && attr.getInt(16) == -1)
                val restored = new.copyOfRange(0, position) + new.copyOfRange(position + 20, new.size)
                val out = buffer(restored)
                out.putInt(4, old.size).putShort(header + 12, (count - 1).toShort())
                listOf(14, 16, 18).forEach { delta ->
                    val index = short(new, header + delta)
                    if (index > added + 1) out.putShort(header + delta, (index - 1).toShort())
                }
                require(old.contentEquals(restored)) { "existing application attributes changed" }
            }
        }
    }

    private fun chunks(input: ByteArray): List<ByteArray> {
        require(input.size >= 8 && short(input, 0) == 3 && buffer(input).getInt(4) == input.size)
        var offset = short(input, 2)
        val result = mutableListOf<ByteArray>()
        while (offset < input.size) {
            require(offset + 8 <= input.size)
            val size = buffer(input).getInt(offset + 4)
            require(size >= 8 && size <= input.size - offset)
            result += input.copyOfRange(offset, offset + size)
            offset += size
        }
        require(offset == input.size)
        return result
    }
}
