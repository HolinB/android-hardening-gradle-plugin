package com.holin.android.hardening.resources

import com.android.aapt.Resources
import com.android.aapt.ConfigurationOuterClass.Configuration
import kotlin.test.Test
import kotlin.test.assertEquals

class AaptResourceEntryCompatTest {
    @Test
    fun `reads and updates the optional readwrite config field when present`() {
        val original = configValue("res/layout/original.xml")
        val entry = Resources.Entry.newBuilder()
            .addReadwriteFlagConfigValue(original)
            .build()

        assertEquals(listOf(original), AaptResourceEntryCompat.readwriteConfigValues(entry))

        val builder = entry.toBuilder()
        val changed = AaptResourceEntryCompat.updateReadwriteConfigValues(builder) { config ->
            config.valueBuilder.itemBuilder.fileBuilder.path = "res/layout/replaced.xml"
            true
        }

        assertEquals(1, changed)
        assertEquals(
            "res/layout/replaced.xml",
            AaptResourceEntryCompat.readwriteConfigValues(builder.build()).single().value.item.file.path,
        )
    }

    @Test
    fun `reads and updates the optional flag disabled config field when present`() {
        val original = configValue("res/layout/original.xml")
        val entry = Resources.Entry.newBuilder()
            .addFlagDisabledConfigValue(original)
            .build()

        assertEquals(listOf(original), AaptResourceEntryCompat.flagDisabledConfigValues(entry))

        val builder = entry.toBuilder()
        val changed = AaptResourceEntryCompat.updateFlagDisabledConfigValues(builder) { config ->
            config.valueBuilder.itemBuilder.fileBuilder.path = "res/layout/replaced.xml"
            true
        }

        assertEquals(1, changed)
        assertEquals(
            "res/layout/replaced.xml",
            AaptResourceEntryCompat.flagDisabledConfigValues(builder.build()).single().value.item.file.path,
        )
    }

    @Test
    fun `reads an optional integer when present and uses protobuf zero when absent`() {
        val configuration = Configuration.newBuilder().setSdkVersionMinor(7).build()

        assertEquals(7, AaptResourceEntryCompat.sdkVersionMinor(configuration))
        assertEquals(0, AaptResourceEntryCompat.optionalInt32(configuration, "sdk_version_patch"))
    }

    private fun configValue(path: String): Resources.ConfigValue = Resources.ConfigValue.newBuilder()
        .setValue(
            Resources.Value.newBuilder().setItem(
                Resources.Item.newBuilder().setFile(
                    Resources.FileReference.newBuilder().setPath(path),
                ),
            ),
        )
        .build()

}
