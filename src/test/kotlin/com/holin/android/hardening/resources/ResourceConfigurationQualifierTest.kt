package com.holin.android.hardening.resources

import com.android.aapt.ConfigurationOuterClass.Configuration
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class ResourceConfigurationQualifierTest {
    @Test
    fun `default and common compiled qualifiers use Android directory order`() {
        assertEquals("", Configuration.getDefaultInstance().toResourceQualifier())
        assertEquals(
            "land-xhdpi-v4",
            Configuration.newBuilder()
                .setOrientation(Configuration.Orientation.ORIENTATION_LAND)
                .setDensity(320)
                .setSdkVersion(4)
                .build()
                .toResourceQualifier(),
        )
    }

    @Test
    fun `legacy and modified BCP47 locales become canonical resource qualifiers`() {
        assertEquals(
            "en-rUS",
            Configuration.newBuilder().setLocale("en-US").build().toResourceQualifier(),
        )
        assertEquals(
            "b+zh+Hant+TW",
            Configuration.newBuilder().setLocale("zh-Hant-TW").build().toResourceQualifier(),
        )
    }

    @Test
    fun `unrepresentable configuration fields fail closed`() {
        assertFailsWith<IllegalArgumentException> {
            Configuration.newBuilder()
                .setUiModeType(Configuration.UiModeType.UI_MODE_TYPE_NORMAL)
                .build()
                .toResourceQualifier()
        }
        assertFailsWith<IllegalArgumentException> {
            Configuration.newBuilder().setProduct("remote-overlay").build().toResourceQualifier()
        }
    }
}
