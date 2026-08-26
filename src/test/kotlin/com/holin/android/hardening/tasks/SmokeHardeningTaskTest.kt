package com.holin.android.hardening.tasks

import kotlin.test.Test
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import org.gradle.testfixtures.ProjectBuilder

class SmokeHardeningTaskTest {
    @Test
    fun `direct task construction is not authorized to execute a device run`() {
        val task = ProjectBuilder.builder().build().tasks.register("smoke", SmokeHardeningTask::class.java).get()
        task.stabilitySeconds.set(30)

        val failure = assertFailsWith<IllegalStateException> { task.smoke() }

        assertTrue(failure.message.orEmpty().contains("hardeningRun"))
    }

    @Test
    fun `task boundary requires exactly thirty production stability seconds`() {
        val task = ProjectBuilder.builder().build().tasks.register("smoke", SmokeHardeningTask::class.java).get()
        task.deviceExecutionAuthorized.set(true)
        task.stabilitySeconds.set(29)

        val failure = assertFailsWith<IllegalArgumentException> { task.smoke() }

        assertTrue(failure.message.orEmpty().contains("must be 30"))
    }
}
