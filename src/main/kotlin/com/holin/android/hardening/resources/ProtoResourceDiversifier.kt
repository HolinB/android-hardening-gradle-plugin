package com.holin.android.hardening.resources

import com.android.aapt.Resources
import com.google.protobuf.ByteString
import com.google.protobuf.InvalidProtocolBufferException
import com.google.protobuf.UnknownFieldSet
import java.nio.ByteBuffer
import java.security.MessageDigest
import java.util.Base64

internal const val PROTO_DIVERSIFICATION_FIELD_NUMBER = 51_001

/**
 * Adds a build-specific marker to the root unknown fields of compiled AAPT2 protobuf messages.
 * Known fields, including unknown fields nested below the root message, remain byte-for-byte
 * equivalent after parsing.
 */
class ProtoResourceDiversifier {
    fun diversifyResourceTable(
        bytes: ByteArray,
        salt: ByteArray,
    ): ByteArray {
        requireSalt(salt)
        checkFieldNumberIsUnused(Resources.ResourceTable.getDescriptor().findFieldByNumber(PROTO_DIVERSIFICATION_FIELD_NUMBER))

        val original = parseResourceTable(bytes)
        val knownOriginal = original.withoutRootUnknownFields()
        val payload = markerPayload(
            RESOURCE_TABLE_DOMAIN,
            salt,
            sha256(knownOriginal.toByteArray()),
        )
        val diversified = original.toBuilder()
            .setUnknownFields(original.unknownFields.withMarker(payload))
            .build()
            .toByteArray()
        val reparsed = parseResourceTable(diversified)

        check(reparsed.withoutRootUnknownFields() == knownOriginal) {
            "resource table diversification changed known protobuf fields"
        }
        return diversified
    }

    fun diversifyXml(
        bytes: ByteArray,
        salt: ByteArray,
        logicalPath: String,
    ): ByteArray {
        requireSalt(salt)
        require(logicalPath.isNotBlank()) { "logical path must not be blank" }
        checkFieldNumberIsUnused(Resources.XmlNode.getDescriptor().findFieldByNumber(PROTO_DIVERSIFICATION_FIELD_NUMBER))

        val original = parseXml(bytes, logicalPath)
        val knownOriginal = original.withoutRootUnknownFields()
        val payload = markerPayload(
            XML_DOMAIN,
            salt,
            logicalPath.encodeToByteArray(),
            sha256(knownOriginal.toByteArray()),
        )
        val diversified = original.toBuilder()
            .setUnknownFields(original.unknownFields.withMarker(payload))
            .build()
            .toByteArray()
        val reparsed = parseXml(diversified, logicalPath)

        check(reparsed.withoutRootUnknownFields() == knownOriginal) {
            "compiled XML diversification changed known protobuf fields for $logicalPath"
        }
        return diversified
    }

    private fun parseResourceTable(bytes: ByteArray): Resources.ResourceTable = try {
        Resources.ResourceTable.parseFrom(bytes)
    } catch (failure: InvalidProtocolBufferException) {
        throw IllegalArgumentException("resources.pb is not a valid AAPT2 ResourceTable protobuf", failure)
    }

    private fun parseXml(bytes: ByteArray, logicalPath: String): Resources.XmlNode = try {
        Resources.XmlNode.parseFrom(bytes)
    } catch (failure: InvalidProtocolBufferException) {
        throw IllegalArgumentException("$logicalPath is not a valid AAPT2 XmlNode protobuf", failure)
    }

    private fun Resources.ResourceTable.withoutRootUnknownFields(): Resources.ResourceTable =
        toBuilder().setUnknownFields(UnknownFieldSet.getDefaultInstance()).build()

    private fun Resources.XmlNode.withoutRootUnknownFields(): Resources.XmlNode =
        toBuilder().setUnknownFields(UnknownFieldSet.getDefaultInstance()).build()

    private fun UnknownFieldSet.withMarker(payload: ByteArray): UnknownFieldSet = toBuilder()
        .clearField(PROTO_DIVERSIFICATION_FIELD_NUMBER)
        .addField(
            PROTO_DIVERSIFICATION_FIELD_NUMBER,
            UnknownFieldSet.Field.newBuilder()
                .addLengthDelimited(ByteString.copyFrom(payload))
                .build(),
        )
        .build()

    private fun markerPayload(
        domain: String,
        salt: ByteArray,
        vararg context: ByteArray,
    ): ByteArray {
        val digest = MessageDigest.getInstance("SHA-256")
        digest.updateFramed(domain.encodeToByteArray())
        digest.updateFramed(salt)
        context.forEach { digest.updateFramed(it) }
        val encoded = Base64.getUrlEncoder().withoutPadding().encodeToString(digest.digest())
        return "hardening_marker_v1_$encoded".encodeToByteArray()
    }

    private fun sha256(bytes: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(bytes)

    private fun MessageDigest.updateFramed(value: ByteArray) {
        update(ByteBuffer.allocate(Int.SIZE_BYTES).putInt(value.size).array())
        update(value)
    }

    private fun requireSalt(salt: ByteArray) {
        require(salt.isNotEmpty()) { "content salt must not be empty" }
    }

    private fun checkFieldNumberIsUnused(field: Any?) {
        check(field == null) {
            "protobuf field $PROTO_DIVERSIFICATION_FIELD_NUMBER is now a known AAPT2 field"
        }
    }

    private companion object {
        const val RESOURCE_TABLE_DOMAIN = "com.holin.android.hardening/1.3.0/aapt2-resource-table/v1"
        const val XML_DOMAIN = "com.holin.android.hardening/1.3.0/aapt2-xml-node/v1"
    }
}
