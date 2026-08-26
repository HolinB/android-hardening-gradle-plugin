package com.holin.android.hardening

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class HardeningNamesTest {
    @Test
    fun `valid project and variant names produce stable paths and task suffixes`() {
        assertEquals("demo", HardeningNames.requireProjectKey("demo"))
        assertEquals("DemoRelease", HardeningNames.taskSuffix("demoRelease"))
    }

    @Test
    fun `path traversal and malformed variants are rejected`() {
        assertFailsWith<IllegalArgumentException> { HardeningNames.requireProjectKey("../demo") }
        assertFailsWith<IllegalArgumentException> { HardeningNames.taskSuffix("demo/release") }
    }
}
