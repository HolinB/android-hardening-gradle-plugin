package com.holin.android.hardening.dex

import com.android.tools.smali.dexlib2.AccessFlags
import com.android.tools.smali.dexlib2.Opcode
import com.android.tools.smali.dexlib2.Opcodes
import com.android.tools.smali.dexlib2.immutable.ImmutableClassDef
import com.android.tools.smali.dexlib2.immutable.ImmutableDexFile
import com.android.tools.smali.dexlib2.immutable.ImmutableMethod
import com.android.tools.smali.dexlib2.immutable.ImmutableMethodImplementation
import com.android.tools.smali.dexlib2.immutable.instruction.ImmutableInstruction10x
import com.android.tools.smali.dexlib2.writer.io.MemoryDataStore
import com.android.tools.smali.dexlib2.writer.pool.DexPool
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.MessageDigest
import java.util.zip.Adler32
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class DexIdTableValidatorTest {
    @Test
    fun `valid method id table is accepted`() {
        DexIdTableValidator.requireValid(validDex(), "valid.dex")
    }

    @Test
    fun `truncated method id section is rejected before reading entries`() {
        val bytes = validDex()
        val methodIdsOffset = littleEndianInt(bytes, METHOD_IDS_OFFSET_FIELD)
        val methodIdsSize = littleEndianInt(bytes, METHOD_IDS_SIZE_FIELD)
        assertEquals(2, methodIdsSize)
        val truncated = bytes.copyOf(methodIdsOffset + methodIdsSize * METHOD_ID_ITEM_SIZE - 1)

        val failure = assertFailsWith<IllegalArgumentException> {
            DexIdTableValidator.requireValid(truncated, "truncated.dex")
        }

        assertTrue(failure.message!!.contains("truncated.dex method_ids section is out of bounds"))
    }

    @Test
    fun `descending adjacent method id reports both indices and keys`() {
        val bytes = validDex()
        val methodIdsOffset = littleEndianInt(bytes, METHOD_IDS_OFFSET_FIELD)
        val first = bytes.copyOfRange(methodIdsOffset, methodIdsOffset + METHOD_ID_ITEM_SIZE)
        val second = bytes.copyOfRange(
            methodIdsOffset + METHOD_ID_ITEM_SIZE,
            methodIdsOffset + 2 * METHOD_ID_ITEM_SIZE,
        )
        second.copyInto(bytes, methodIdsOffset)
        first.copyInto(bytes, methodIdsOffset + METHOD_ID_ITEM_SIZE)
        rebuildDexHashes(bytes)

        val failure = assertFailsWith<IllegalArgumentException> {
            DexIdTableValidator.requireValid(bytes, "descending.dex")
        }

        assertTrue(failure.message!!.contains("out-of-order method_id at indices 0 and 1"))
        assertTrue(failure.message!!.contains(MethodIdKey.read(second, 0).toString()))
        assertTrue(failure.message!!.contains(MethodIdKey.read(first, 0).toString()))
    }

    @Test
    fun `duplicate adjacent method id reports both indices and key`() {
        val bytes = validDex()
        val methodIdsOffset = littleEndianInt(bytes, METHOD_IDS_OFFSET_FIELD)
        val duplicateKey = MethodIdKey.read(bytes, methodIdsOffset)
        bytes.copyInto(
            destination = bytes,
            destinationOffset = methodIdsOffset + METHOD_ID_ITEM_SIZE,
            startIndex = methodIdsOffset,
            endIndex = methodIdsOffset + METHOD_ID_ITEM_SIZE,
        )
        rebuildDexHashes(bytes)

        val failure = assertFailsWith<IllegalArgumentException> {
            DexIdTableValidator.requireValid(bytes, "duplicate.dex")
        }

        assertTrue(failure.message!!.contains("duplicate method_id at indices 0 and 1"))
        assertTrue(failure.message!!.contains(duplicateKey.toString()))
    }

    private fun validDex(): ByteArray {
        val methods = listOf("alpha", "beta").map { name ->
            ImmutableMethod(
                TEST_CLASS,
                name,
                emptyList(),
                "V",
                AccessFlags.PUBLIC.value or AccessFlags.STATIC.value,
                emptySet(),
                emptySet(),
                ImmutableMethodImplementation(
                    0,
                    listOf(ImmutableInstruction10x(Opcode.RETURN_VOID)),
                    emptyList(),
                    emptyList(),
                ),
            )
        }
        val clazz = ImmutableClassDef(
            TEST_CLASS,
            AccessFlags.PUBLIC.value,
            "Ljava/lang/Object;",
            emptyList(),
            null,
            emptySet(),
            emptyList(),
            methods,
        )
        val store = MemoryDataStore()
        DexPool.writeTo(store, ImmutableDexFile(Opcodes.getDefault(), listOf(clazz)))
        return store.data
    }

    private fun rebuildDexHashes(bytes: ByteArray) {
        MessageDigest.getInstance("SHA-1")
            .digest(bytes.copyOfRange(SIGNATURE_CONTENT_OFFSET, bytes.size))
            .copyInto(bytes, SIGNATURE_OFFSET)
        ByteBuffer.wrap(bytes, CHECKSUM_OFFSET, Int.SIZE_BYTES)
            .order(ByteOrder.LITTLE_ENDIAN)
            .putInt(Adler32().apply {
                update(bytes, SIGNATURE_OFFSET, bytes.size - SIGNATURE_OFFSET)
            }.value.toInt())
    }

    private fun littleEndianInt(bytes: ByteArray, offset: Int): Int =
        ByteBuffer.wrap(bytes, offset, Int.SIZE_BYTES).order(ByteOrder.LITTLE_ENDIAN).int

    private data class MethodIdKey(
        val classIndex: Int,
        val nameIndex: Long,
        val protoIndex: Int,
    ) {
        override fun toString(): String =
            "[class_idx=$classIndex, name_idx=$nameIndex, proto_idx=$protoIndex]"

        companion object {
            fun read(bytes: ByteArray, offset: Int): MethodIdKey {
                val buffer = ByteBuffer.wrap(bytes, offset, METHOD_ID_ITEM_SIZE)
                    .order(ByteOrder.LITTLE_ENDIAN)
                return MethodIdKey(
                    classIndex = buffer.short.toInt() and 0xffff,
                    protoIndex = buffer.short.toInt() and 0xffff,
                    nameIndex = buffer.int.toLong() and 0xffff_ffffL,
                )
            }
        }
    }

    private companion object {
        const val TEST_CLASS = "Lcom/example/demo/match/ValidatorFixture;"
        const val CHECKSUM_OFFSET = 8
        const val SIGNATURE_OFFSET = 12
        const val SIGNATURE_CONTENT_OFFSET = 32
        const val METHOD_IDS_SIZE_FIELD = 0x58
        const val METHOD_IDS_OFFSET_FIELD = 0x5c
        const val METHOD_ID_ITEM_SIZE = 8
    }
}
