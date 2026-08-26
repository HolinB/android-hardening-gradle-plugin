package com.holin.android.hardening

import kotlin.test.Test
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class PortableToolchainCompatibilityTest {
    @Test
    fun `accepts exact floors and higher stable versions`() {
        listOf(
            ToolchainVersions("8.10", 17, "8.8.0", "2.3.0"),
            ToolchainVersions("8.13", 21, "8.13.2", "2.4.0"),
        ).forEach(PortableToolchainCompatibility::verify)
    }

    @Test
    fun `rejects each below floor component with actual and minimum versions`() {
        listOf(
            Triple("Gradle", ToolchainVersions("8.9", 17, "8.8.0", "2.3.0"), "8.10"),
            Triple("JDK", ToolchainVersions("8.10", 16, "8.8.0", "2.3.0"), "17"),
            Triple("Android Gradle Plugin", ToolchainVersions("8.10", 17, "8.7.2", "2.3.0"), "8.8.0"),
            Triple("Kotlin Android plugin", ToolchainVersions("8.10", 17, "8.8.0", "2.2.21"), "2.3.0"),
        ).forEach { (component, versions, minimum) ->
            val failure = assertFailsWith<IllegalArgumentException> {
                PortableToolchainCompatibility.verify(versions)
            }

            assertTrue(failure.message.orEmpty().contains(component), failure.message)
            assertTrue(failure.message.orEmpty().contains("actual="), failure.message)
            assertTrue(failure.message.orEmpty().contains("minimum=$minimum"), failure.message)
        }
    }

    @Test
    fun `rejects prerelease versions below a floor`() {
        listOf(
            ToolchainVersions("8.10-rc-1", 17, "8.8.0", "2.3.0"),
            ToolchainVersions("8.10", 17, "8.8.0-rc01", "2.3.0"),
            ToolchainVersions("8.10", 17, "8.8.0", "2.3.0-RC"),
        ).forEach { versions ->
            assertFailsWith<IllegalArgumentException> {
                PortableToolchainCompatibility.verify(versions)
            }
        }
    }
}
