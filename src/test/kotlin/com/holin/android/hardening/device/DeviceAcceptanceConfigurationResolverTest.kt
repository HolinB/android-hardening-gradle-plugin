package com.holin.android.hardening.device

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class DeviceAcceptanceConfigurationResolverTest {
    @Test
    fun `variant application id is used unless a nonblank explicit override exists`() {
        assertEquals(
            "com.example.variant",
            DeviceAcceptanceConfigurationResolver.applicationId(null, true, "com.example.variant"),
        )
        assertEquals(
            "com.example.override",
            DeviceAcceptanceConfigurationResolver.applicationId(
                "com.example.override",
                true,
                "com.example.variant",
            ),
        )
    }

    @Test
    fun `application id resolution fails when both sources are disabled or blank`() {
        val disabled = assertFailsWith<IllegalArgumentException> {
            DeviceAcceptanceConfigurationResolver.applicationId(null, false, "com.example.variant")
        }
        val blank = assertFailsWith<IllegalArgumentException> {
            DeviceAcceptanceConfigurationResolver.applicationId(" ", true, "com.example.variant")
        }

        assertTrue(disabled.message.orEmpty().contains("applicationId"), disabled.message)
        assertTrue(blank.message.orEmpty().contains("nonblank"), blank.message)
    }

    @Test
    fun `manifest launcher names normalize relative package relative and fully qualified forms`() {
        listOf(
            ".RelativeActivity" to "com.example.app.RelativeActivity",
            "PackageRelativeActivity" to "com.example.app.PackageRelativeActivity",
            "org.example.FullActivity" to "org.example.FullActivity",
        ).forEach { (declared, expected) ->
            assertEquals(
                expected,
                DeviceAcceptanceConfigurationResolver.launchActivity(
                    null,
                    true,
                    manifest(declared),
                    "com.example.app",
                ),
            )
        }
    }

    @Test
    fun `explicit launcher override is normalized without consulting manifest`() {
        assertEquals(
            "com.example.app.OverrideActivity",
            DeviceAcceptanceConfigurationResolver.launchActivity(
                ".OverrideActivity",
                false,
                null,
                "com.example.app",
            ),
        )
    }

    @Test
    fun `missing and ambiguous manifest launchers fail closed`() {
        val missing = assertFailsWith<IllegalArgumentException> {
            DeviceAcceptanceConfigurationResolver.launchActivity(
                null,
                true,
                "<manifest xmlns:android=\"http://schemas.android.com/apk/res/android\"><application /></manifest>",
                "com.example.app",
            )
        }
        val ambiguous = assertFailsWith<IllegalArgumentException> {
            DeviceAcceptanceConfigurationResolver.launchActivity(
                null,
                true,
                """
                <manifest xmlns:android="http://schemas.android.com/apk/res/android">
                    <application>
                        ${launcher(".OneActivity")}
                        ${launcher(".TwoActivity")}
                    </application>
                </manifest>
                """.trimIndent(),
                "com.example.app",
            )
        }

        assertTrue(missing.message.orEmpty().contains("launcher"), missing.message)
        assertTrue(ambiguous.message.orEmpty().contains("ambiguous"), ambiguous.message)
    }

    private fun manifest(activity: String): String =
        """
        <manifest xmlns:android="http://schemas.android.com/apk/res/android">
            <application>${launcher(activity)}</application>
        </manifest>
        """.trimIndent()

    private fun launcher(activity: String): String =
        """
        <activity android:name="$activity">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>
        """.trimIndent()
}
