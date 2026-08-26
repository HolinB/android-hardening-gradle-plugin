package com.holin.android.hardening.resources

import com.android.aapt.Resources
import com.android.aapt.ConfigurationOuterClass.Configuration
import com.google.protobuf.Descriptors
import com.google.protobuf.MessageOrBuilder

/** Accesses optional AAPT2 proto fields without linking version-specific generated methods. */
internal object AaptResourceEntryCompat {
    fun sdkVersionMinor(configuration: Configuration): Int =
        optionalInt32(configuration, SDK_VERSION_MINOR_FIELD)

    fun flagDisabledConfigValues(entry: Resources.Entry): List<Resources.ConfigValue> =
        repeatedConfigValues(entry, FLAG_DISABLED_CONFIG_FIELD, "flag-disabled")

    fun readwriteConfigValues(entry: Resources.Entry): List<Resources.ConfigValue> =
        repeatedConfigValues(entry, READWRITE_CONFIG_FIELD, "read/write flag")

    fun updateFlagDisabledConfigValues(
        entry: Resources.Entry.Builder,
        update: (Resources.ConfigValue.Builder) -> Boolean,
    ): Int = updateRepeatedConfigValues(entry, FLAG_DISABLED_CONFIG_FIELD, "flag-disabled", update)

    fun updateReadwriteConfigValues(
        entry: Resources.Entry.Builder,
        update: (Resources.ConfigValue.Builder) -> Boolean,
    ): Int = updateRepeatedConfigValues(entry, READWRITE_CONFIG_FIELD, "read/write flag", update)

    private fun repeatedConfigValues(
        entry: Resources.Entry,
        fieldName: String,
        label: String,
    ): List<Resources.ConfigValue> {
        val field = repeatedConfigField(entry.descriptorForType, fieldName, label) ?: return emptyList()
        return (0 until entry.getRepeatedFieldCount(field)).map { index ->
            requireNotNull(entry.getRepeatedField(field, index) as? Resources.ConfigValue) {
                "AAPT2 $label config field contains an unexpected message type"
            }
        }
    }

    private fun updateRepeatedConfigValues(
        entry: Resources.Entry.Builder,
        fieldName: String,
        label: String,
        update: (Resources.ConfigValue.Builder) -> Boolean,
    ): Int {
        val field = repeatedConfigField(entry.descriptorForType, fieldName, label) ?: return 0
        var changed = 0
        repeat(entry.getRepeatedFieldCount(field)) { index ->
            val current = requireNotNull(entry.getRepeatedField(field, index) as? Resources.ConfigValue) {
                "AAPT2 $label config field contains an unexpected message type"
            }
            val builder = current.toBuilder()
            if (update(builder)) {
                entry.setRepeatedField(field, index, builder.build())
                changed++
            }
        }
        return changed
    }

    private fun repeatedConfigField(
        descriptor: Descriptors.Descriptor,
        fieldName: String,
        label: String,
    ): Descriptors.FieldDescriptor? {
        val field = descriptor.findFieldByName(fieldName) ?: return null
        require(
            field.isRepeated &&
                field.javaType == Descriptors.FieldDescriptor.JavaType.MESSAGE &&
                field.messageType.fullName == Resources.ConfigValue.getDescriptor().fullName,
        ) { "AAPT2 $label config field has an incompatible schema" }
        return field
    }

    internal fun optionalInt32(message: MessageOrBuilder, fieldName: String): Int {
        val field = message.descriptorForType.findFieldByName(fieldName) ?: return 0
        require(
            !field.isRepeated && field.javaType == Descriptors.FieldDescriptor.JavaType.INT,
        ) { "AAPT2 optional integer field $fieldName has an incompatible schema" }
        return requireNotNull(message.getField(field) as? Int) {
            "AAPT2 optional integer field $fieldName contains an unexpected value"
        }
    }

    private const val FLAG_DISABLED_CONFIG_FIELD = "flag_disabled_config_value"
    private const val READWRITE_CONFIG_FIELD = "readwrite_flag_config_value"
    private const val SDK_VERSION_MINOR_FIELD = "sdk_version_minor"
}
