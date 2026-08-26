package com.holin.android.hardening.resources

import com.android.aapt.Resources
import com.google.protobuf.ByteString
import com.google.protobuf.UnknownFieldSet
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

class ProtoResourceDiversifierTest {
    private val diversifier = ProtoResourceDiversifier()

    @Test
    fun `resource table diversification changes only one root unknown field`() {
        val preexistingUnknown = UnknownFieldSet.Field.newBuilder()
            .addLengthDelimited(ByteString.copyFromUtf8("preserve-me"))
            .build()
        val original = Resources.ResourceTable.newBuilder()
            .addPackage(
                Resources.Package.newBuilder()
                    .setPackageId(Resources.PackageId.newBuilder().setId(0x7f))
                    .setPackageName("com.example.demo.test"),
            )
            .setUnknownFields(
                UnknownFieldSet.newBuilder()
                    .addField(PREEXISTING_UNKNOWN_FIELD_NUMBER, preexistingUnknown)
                    .build(),
            )
            .build()
        val salt = "resource-table-secret-salt".encodeToByteArray()

        val first = diversifier.diversifyResourceTable(original.toByteArray(), salt)
        val repeated = diversifier.diversifyResourceTable(original.toByteArray(), salt)
        val different = diversifier.diversifyResourceTable(original.toByteArray(), "different-salt".encodeToByteArray())
        val parsed = Resources.ResourceTable.parseFrom(first)
        val marker = requireNotNull(parsed.unknownFields.asMap()[PROTO_DIVERSIFICATION_FIELD_NUMBER])

        assertContentEquals(first, repeated)
        assertFalse(first.contentEquals(different))
        assertNotEquals(sha256(original.toByteArray()), sha256(first))
        assertEquals(preexistingUnknown, parsed.unknownFields.asMap()[PREEXISTING_UNKNOWN_FIELD_NUMBER])
        assertEquals(1, marker.lengthDelimitedList.size)
        val markerText = marker.lengthDelimitedList.single().toStringUtf8()
        assertTrue(markerText.matches(Regex("hardening_marker_v1_[A-Za-z0-9_-]{43}")))
        assertTrue(marker.varintList.isEmpty())
        assertTrue(marker.fixed32List.isEmpty())
        assertTrue(marker.fixed64List.isEmpty())
        assertTrue(marker.groupList.isEmpty())
        assertEquals(clearRootUnknowns(original), clearRootUnknowns(parsed))
        assertFalse(first.containsSubsequence(salt))
    }

    @Test
    fun `xml diversification is path scoped deterministic and idempotently replaces its marker`() {
        val original = Resources.XmlNode.newBuilder()
            .setText("demo")
            .build()
        val salt = "xml-secret-salt".encodeToByteArray()

        val first = diversifier.diversifyXml(original.toByteArray(), salt, "base/res/layout/home.xml")
        val repeated = diversifier.diversifyXml(original.toByteArray(), salt, "base/res/layout/home.xml")
        val otherPath = diversifier.diversifyXml(original.toByteArray(), salt, "base/res/layout/profile.xml")
        val resalted = diversifier.diversifyXml(first, "next-salt".encodeToByteArray(), "base/res/layout/home.xml")
        val parsed = Resources.XmlNode.parseFrom(first)
        val resaltedParsed = Resources.XmlNode.parseFrom(resalted)

        assertContentEquals(first, repeated)
        assertFalse(first.contentEquals(otherPath))
        assertNotEquals(sha256(original.toByteArray()), sha256(first))
        assertEquals(clearRootUnknowns(original), clearRootUnknowns(parsed))
        assertEquals(clearRootUnknowns(original), clearRootUnknowns(resaltedParsed))
        assertEquals(
            1,
            requireNotNull(resaltedParsed.unknownFields.asMap()[PROTO_DIVERSIFICATION_FIELD_NUMBER])
                .lengthDelimitedList.size,
        )
        assertFalse(first.containsSubsequence(salt))
    }

    @Test
    fun `empty salt invalid protobuf and blank logical path fail closed`() {
        val table = Resources.ResourceTable.getDefaultInstance().toByteArray()
        val xml = Resources.XmlNode.getDefaultInstance().toByteArray()
        val malformed = byteArrayOf(0x0a, 0x7f)

        assertFailsWith<IllegalArgumentException> {
            diversifier.diversifyResourceTable(table, byteArrayOf())
        }
        assertFailsWith<IllegalArgumentException> {
            diversifier.diversifyXml(xml, byteArrayOf(), "base/res/layout/home.xml")
        }
        assertFailsWith<IllegalArgumentException> {
            diversifier.diversifyResourceTable(malformed, byteArrayOf(1))
        }
        assertFailsWith<IllegalArgumentException> {
            diversifier.diversifyXml(malformed, byteArrayOf(1), "base/res/layout/home.xml")
        }
        assertFailsWith<IllegalArgumentException> {
            diversifier.diversifyXml(xml, byteArrayOf(1), " ")
        }
    }

    private fun clearRootUnknowns(table: Resources.ResourceTable): Resources.ResourceTable =
        table.toBuilder().setUnknownFields(UnknownFieldSet.getDefaultInstance()).build()

    private fun clearRootUnknowns(xml: Resources.XmlNode): Resources.XmlNode =
        xml.toBuilder().setUnknownFields(UnknownFieldSet.getDefaultInstance()).build()

    private fun sha256(bytes: ByteArray): String = java.security.MessageDigest.getInstance("SHA-256")
        .digest(bytes)
        .joinToString("") { "%02x".format(it) }

    private fun ByteArray.containsSubsequence(candidate: ByteArray): Boolean {
        if (candidate.isEmpty() || candidate.size > size) return false
        return indices.take(size - candidate.size + 1).any { start ->
            candidate.indices.all { offset -> this[start + offset] == candidate[offset] }
        }
    }

    private companion object {
        const val PREEXISTING_UNKNOWN_FIELD_NUMBER = 51_000
    }
}
