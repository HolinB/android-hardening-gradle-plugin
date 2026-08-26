package com.holin.android.hardening.artifact

import java.nio.ByteBuffer
import java.nio.ByteOrder
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals

class BinaryXmlLineNumberDiversifierTest {
    @Test
    fun `diversifies every binary XML node line number deterministically`() {
        val original = binaryXml(
            stringPool(),
            node(0x0100, lineNumber = 7),
            node(0x0102, lineNumber = 11),
            node(0x0104, lineNumber = 19),
            node(0x0103, lineNumber = 13),
            node(0x0101, lineNumber = 17),
        )
        val diversifier = BinaryXmlLineNumberDiversifier()

        val first = diversifier.diversify(original, "a".repeat(64), "res/layout/screen.xml")
        val repeated = diversifier.diversify(original, "a".repeat(64), "res/layout/screen.xml")
        val differentSalt = diversifier.diversify(original, "b".repeat(64), "res/layout/screen.xml")

        assertEquals(original.size, first.size)
        assertContentEquals(first, repeated)
        assertFalse(first.contentEquals(differentSalt))
        val originalLines = nodeLineNumbers(original)
        val diversifiedLines = nodeLineNumbers(first)
        assertEquals(originalLines.size, diversifiedLines.size)
        originalLines.zip(diversifiedLines).forEach { (before, after) ->
            assertNotEquals(before, after)
            assert(after > 0)
        }
        assertEquals(
            originalLines.size,
            BinaryXmlLineNumberDiversificationVerifier().verify(original, first).changedNodeCount,
        )
    }

    @Test
    fun `parser accepts canonical one two and three byte UTF-8 sequences`() {
        val original = binaryXml(
            utf8StringPool(
                utf16Length = 3,
                data = byteArrayOf(
                    0x41,
                    0xc2.toByte(), 0xa2.toByte(),
                    0xe2.toByte(), 0x82.toByte(), 0xac.toByte(),
                ),
            ),
            node(0x0102, lineNumber = 7),
        )

        val diversified = BinaryXmlLineNumberDiversifier().diversify(
            original,
            "a".repeat(64),
            "res/layout/screen.xml",
        )

        assertEquals(
            1,
            BinaryXmlLineNumberDiversificationVerifier().verify(original, diversified).changedNodeCount,
        )
    }

    @Test
    fun `parser accepts AAPT modified UTF-8 supplementary characters`() {
        val original = binaryXml(
            utf8StringPool(
                utf16Length = 2,
                data = byteArrayOf(
                    0xed.toByte(), 0xa0.toByte(), 0xbd.toByte(),
                    0xed.toByte(), 0xb8.toByte(), 0x80.toByte(),
                ),
            ),
            node(0x0102, lineNumber = 7),
        )

        val diversified = BinaryXmlLineNumberDiversifier().diversify(
            original,
            "a".repeat(64),
            "res/layout/screen.xml",
        )

        assertEquals(
            1,
            BinaryXmlLineNumberDiversificationVerifier().verify(original, diversified).changedNodeCount,
        )
    }

    @Test
    fun `parser accepts AAPT CDATA with an absent typed value`() {
        val aaptCdata = node(0x0104, lineNumber = 7).also { node ->
            node.fill(0, fromIndex = 20, toIndex = 28)
        }
        val original = binaryXml(stringPool(), aaptCdata)

        val diversified = BinaryXmlLineNumberDiversifier().diversify(
            original,
            "a".repeat(64),
            "res/xml/network_security_config.xml",
        )

        assertEquals(
            1,
            BinaryXmlLineNumberDiversificationVerifier().verify(original, diversified).changedNodeCount,
        )
    }

    @Test
    fun `parser rejects malformed AAPT modified UTF-8 sequences`() {
        val malformed = listOf(
            "invalid two-byte continuation" to (1 to byteArrayOf(0xc2.toByte(), 0x20)),
            "overlong three-byte sequence" to
                (1 to byteArrayOf(0xe0.toByte(), 0x80.toByte(), 0x80.toByte())),
            "unpaired high surrogate" to
                (1 to byteArrayOf(0xed.toByte(), 0xa0.toByte(), 0xbd.toByte())),
            "unpaired low surrogate" to
                (1 to byteArrayOf(0xed.toByte(), 0xb8.toByte(), 0x80.toByte())),
            "high surrogate followed by another high surrogate" to
                (2 to byteArrayOf(
                    0xed.toByte(), 0xa0.toByte(), 0xbd.toByte(),
                    0xed.toByte(), 0xa0.toByte(), 0x80.toByte(),
                )),
            "four-byte standard UTF-8 sequence" to
                (2 to byteArrayOf(0xf0.toByte(), 0x9f.toByte(), 0x98.toByte(), 0x80.toByte())),
        )

        malformed.forEach { (description, encoded) ->
            val (utf16Length, data) = encoded
            assertFailsWith<IllegalArgumentException>(description) {
                BinaryXmlLineNumberDiversifier().diversify(
                    binaryXml(utf8StringPool(utf16Length, data), node(0x0102, 1)),
                    "a".repeat(64),
                    "res/layout/screen.xml",
                )
            }
        }
    }

    @Test
    fun `parser rejects duplicate and missing binary XML structural chunks`() {
        assertFailsWith<IllegalArgumentException> {
            BinaryXmlLineNumberDiversifier().diversify(
                binaryXml(stringPool(), stringPool(), node(0x0102, 1)),
                "a".repeat(64),
                "res/layout/screen.xml",
            )
        }
        assertFailsWith<IllegalArgumentException> {
            BinaryXmlLineNumberDiversifier().diversify(
                binaryXml(node(0x0102, 1)),
                "a".repeat(64),
                "res/layout/screen.xml",
            )
        }
        assertFailsWith<IllegalArgumentException> {
            BinaryXmlLineNumberDiversifier().diversify(
                binaryXml(stringPool(), node(0x0102, 1), chunk(0x0180, 8)),
                "a".repeat(64),
                "res/layout/screen.xml",
            )
        }
    }

    @Test
    fun `parser rejects placeholder and malformed string pools`() {
        val invalidStringsStart = stringPool().also { writeInt(it, 20, it.size + 4) }
        val invalidStringOffset = stringPool().also { writeInt(it, 28, 4) }
        val truncatedUtf8String = stringPool().also { it[33] = 8 }

        listOf(
            chunk(0x0001, 8),
            invalidStringsStart,
            invalidStringOffset,
            truncatedUtf8String,
        ).forEach { malformedPool ->
            assertFailsWith<IllegalArgumentException> {
                BinaryXmlLineNumberDiversifier().diversify(
                    binaryXml(malformedPool, node(0x0102, 1)),
                    "a".repeat(64),
                    "res/layout/screen.xml",
                )
            }
        }
    }

    @Test
    fun `parser rejects string pools containing styles`() {
        assertFailsWith<IllegalArgumentException> {
            BinaryXmlLineNumberDiversifier().diversify(
                binaryXml(stringPoolWithStyles(), node(0x0102, 1)),
                "a".repeat(64),
                "res/layout/screen.xml",
            )
        }
    }

    @Test
    fun `parser rejects payload-less chunks for every supported node type`() {
        (0x0100..0x0104).forEach { type ->
            assertFailsWith<IllegalArgumentException> {
                BinaryXmlLineNumberDiversifier().diversify(
                    binaryXml(stringPool(), payloadlessNode(type, 1)),
                    "a".repeat(64),
                    "res/layout/screen.xml",
                )
            }
        }
    }

    @Test
    fun `parser rejects malformed typed values in CDATA and attributes`() {
        val cdataSize = node(0x0104, 1).also { writeShort(it, 20, 7) }
        val cdataReserved = node(0x0104, 1).also { it[22] = 1 }
        val absentCdataWithType = node(0x0104, 1).also { node ->
            node.fill(0, fromIndex = 20, toIndex = 28)
            node[23] = 3
        }
        val attributeReserved = startElementWithAttribute(1).also { it[50] = 1 }

        listOf(cdataSize, cdataReserved, absentCdataWithType, attributeReserved).forEach { malformedNode ->
            assertFailsWith<IllegalArgumentException> {
                BinaryXmlLineNumberDiversifier().diversify(
                    binaryXml(stringPool(), malformedNode),
                    "a".repeat(64),
                    "res/layout/screen.xml",
                )
            }
        }
    }

    @Test
    fun `parser rejects malformed truncated overlapping wrong-root and no-node inputs`() {
        val valid = binaryXml(stringPool(), node(0x0102, 1))
        val wrongRoot = valid.copyOf().also { it[0] = 0x04 }
        val overlapping = valid.copyOf().also { writeInt(it, 8 + 4, valid.size) }
        val undersizedHeader = valid.copyOf().also { writeShort(it, 8 + 2, 4) }
        val noNodes = binaryXml(stringPool())
        val textXml = "<LinearLayout />".encodeToByteArray()

        listOf(valid.copyOf(valid.size - 1), wrongRoot, overlapping, undersizedHeader, noNodes, textXml)
            .forEach { malformed ->
                assertFailsWith<IllegalArgumentException> {
                    BinaryXmlLineNumberDiversifier().diversify(
                        malformed,
                        "a".repeat(64),
                        "res/layout/screen.xml",
                    )
                }
            }
    }

    @Test
    fun `independent verification rejects unchanged invalid and collateral candidates`() {
        val pool = stringPool()
        val original = binaryXml(pool, node(0x0102, 9), node(0x0103, 10))
        val diversified = BinaryXmlLineNumberDiversifier().diversify(
            original,
            "a".repeat(64),
            "res/layout/screen.xml",
        )
        val collateral = diversified.copyOf().also { candidate ->
            candidate[8 + 7] = (candidate[8 + 7].toInt() xor 0x40).toByte()
        }
        val invalidLine = diversified.copyOf().also { candidate -> writeInt(candidate, 8 + pool.size + 8, -1) }

        listOf(original, collateral, invalidLine, diversified.copyOf(diversified.size + 1)).forEach { candidate ->
            assertFailsWith<IllegalArgumentException> {
                BinaryXmlLineNumberDiversificationVerifier().verify(original, candidate)
            }
        }
    }

    private fun binaryXml(vararg children: ByteArray): ByteArray {
        val size = 8 + children.sumOf(ByteArray::size)
        return ByteBuffer.allocate(size).order(ByteOrder.LITTLE_ENDIAN).apply {
            putShort(0x0003)
            putShort(8)
            putInt(size)
            children.forEach(::put)
        }.array()
    }

    private fun chunk(type: Int, headerSize: Int): ByteArray =
        ByteBuffer.allocate(headerSize).order(ByteOrder.LITTLE_ENDIAN).apply {
            putShort(type.toShort())
            putShort(headerSize.toShort())
            putInt(headerSize)
        }.array()

    private fun stringPool(): ByteArray =
        ByteBuffer.allocate(36).order(ByteOrder.LITTLE_ENDIAN).apply {
            putShort(0x0001)
            putShort(28)
            putInt(36)
            putInt(1)
            putInt(0)
            putInt(0x00000100)
            putInt(32)
            putInt(0)
            putInt(0)
            put(1)
            put(1)
            put('x'.code.toByte())
            put(0)
        }.array()

    private fun utf8StringPool(utf16Length: Int, data: ByteArray): ByteArray {
        require(utf16Length in 0..0x7f && data.size <= 0x7f)
        val unalignedSize = 32 + 2 + data.size + 1
        val size = (unalignedSize + 3) and -4
        return ByteBuffer.allocate(size).order(ByteOrder.LITTLE_ENDIAN).apply {
            putShort(0x0001)
            putShort(28)
            putInt(size)
            putInt(1)
            putInt(0)
            putInt(0x00000100)
            putInt(32)
            putInt(0)
            putInt(0)
            put(utf16Length.toByte())
            put(data.size.toByte())
            put(data)
            put(0)
        }.array()
    }

    private fun stringPoolWithStyles(): ByteArray =
        ByteBuffer.allocate(44).order(ByteOrder.LITTLE_ENDIAN).apply {
            putShort(0x0001)
            putShort(28)
            putInt(44)
            putInt(1)
            putInt(1)
            putInt(0x00000100)
            putInt(36)
            putInt(40)
            putInt(0)
            putInt(-1)
            put(1)
            put(1)
            put('x'.code.toByte())
            put(0)
            putInt(-1)
        }.array()

    private fun node(type: Int, lineNumber: Int): ByteArray {
        val payloadSize = when (type) {
            0x0100, 0x0101, 0x0103 -> 8
            0x0102 -> 20
            0x0104 -> 12
            else -> error("unsupported fixture node type")
        }
        return ByteBuffer.allocate(16 + payloadSize).order(ByteOrder.LITTLE_ENDIAN).apply {
            putShort(type.toShort())
            putShort(16)
            putInt(16 + payloadSize)
            putInt(lineNumber)
            putInt(-1)
            when (type) {
                0x0100, 0x0101, 0x0103 -> {
                    putInt(0)
                    putInt(0)
                }
                0x0102 -> {
                    putInt(0)
                    putInt(0)
                    putShort(20)
                    putShort(20)
                    putShort(0)
                    putShort(0)
                    putShort(0)
                    putShort(0)
                }
                0x0104 -> {
                    putInt(0)
                    putShort(8)
                    put(0)
                    put(3)
                    putInt(0)
                }
            }
        }.array()
    }

    private fun payloadlessNode(type: Int, lineNumber: Int): ByteArray =
        ByteBuffer.allocate(16).order(ByteOrder.LITTLE_ENDIAN).apply {
            putShort(type.toShort())
            putShort(16)
            putInt(16)
            putInt(lineNumber)
            putInt(-1)
        }.array()

    private fun startElementWithAttribute(lineNumber: Int): ByteArray =
        ByteBuffer.allocate(56).order(ByteOrder.LITTLE_ENDIAN).apply {
            putShort(0x0102)
            putShort(16)
            putInt(56)
            putInt(lineNumber)
            putInt(-1)
            putInt(0)
            putInt(0)
            putShort(20)
            putShort(20)
            putShort(1)
            putShort(0)
            putShort(0)
            putShort(0)
            putInt(0)
            putInt(0)
            putInt(-1)
            putShort(8)
            put(0)
            put(3)
            putInt(0)
        }.array()

    private fun nodeLineNumbers(bytes: ByteArray): List<Int> {
        val buffer = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN)
        val lines = mutableListOf<Int>()
        var offset = 8
        while (offset < bytes.size) {
            val type = buffer.getShort(offset).toInt() and 0xffff
            val size = buffer.getInt(offset + 4)
            if (type in 0x0100..0x0104) lines += buffer.getInt(offset + 8)
            offset += size
        }
        return lines
    }

    private fun writeShort(bytes: ByteArray, offset: Int, value: Int) {
        bytes[offset] = value.toByte()
        bytes[offset + 1] = (value ushr 8).toByte()
    }

    private fun writeInt(bytes: ByteArray, offset: Int, value: Int) {
        bytes[offset] = value.toByte()
        bytes[offset + 1] = (value ushr 8).toByte()
        bytes[offset + 2] = (value ushr 16).toByte()
        bytes[offset + 3] = (value ushr 24).toByte()
    }
}
