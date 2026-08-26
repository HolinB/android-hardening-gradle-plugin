package com.holin.android.hardening.device

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class AdbDeviceSelectorTest {
    @Test
    fun `auto selects the only online device`() {
        assertEquals(
            "SERIAL-1",
            AdbDeviceSelector.select(
                null,
                true,
                "List of devices attached\nSERIAL-1\tdevice product:x\n",
            ),
        )
    }

    @Test
    fun `explicit online serial wins when other devices are present`() {
        assertEquals(
            "SERIAL-2",
            AdbDeviceSelector.select(
                "SERIAL-2",
                true,
                "List of devices attached\nSERIAL-1\tdevice\nSERIAL-2\tdevice\n",
            ),
        )
    }

    @Test
    fun `auto selection rejects zero multiple offline and unauthorized inventories`() {
        listOf(
            "List of devices attached\n",
            "List of devices attached\nA\tdevice\nB\tdevice\n",
            "List of devices attached\nA\toffline\n",
            "List of devices attached\nA\tunauthorized\n",
            "List of devices attached\nA\tdevice\nB\tunauthorized\n",
        ).forEach { output ->
            val failure = assertFailsWith<IllegalStateException> {
                AdbDeviceSelector.select(null, true, output)
            }

            assertTrue(failure.message.orEmpty().contains("discovered="), failure.message)
            assertTrue(
                failure.message.orEmpty().contains("-PandroidHardeningDeviceSerial=<serial>"),
                failure.message,
            )
        }
    }

    @Test
    fun `explicit serial must identify an online device`() {
        val failure = assertFailsWith<IllegalStateException> {
            AdbDeviceSelector.select(
                "SERIAL-1",
                false,
                "List of devices attached\nSERIAL-1\tunauthorized\n",
            )
        }

        assertTrue(failure.message.orEmpty().contains("SERIAL-1(unauthorized)"), failure.message)
    }

    @Test
    fun `disabled auto selection without an explicit serial fails with remedy`() {
        val failure = assertFailsWith<IllegalStateException> {
            AdbDeviceSelector.select(null, false, "List of devices attached\nSERIAL-1\tdevice\n")
        }

        assertTrue(failure.message.orEmpty().contains("-PandroidHardeningDeviceSerial=<serial>"), failure.message)
    }
}
