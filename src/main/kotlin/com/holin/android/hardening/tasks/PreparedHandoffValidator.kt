package com.holin.android.hardening.tasks

import com.holin.android.hardening.state.PreparedState
import com.holin.android.hardening.state.StateCoordinates
import java.nio.file.Path

internal object PreparedHandoffValidator {
    fun validate(
        prepared: PreparedState,
        expectedRoot: Path,
        expectedPreparedDirectory: Path,
        expectedCoordinates: StateCoordinates,
    ) {
        val normalizedRoot = expectedRoot.toAbsolutePath().normalize()
        require(prepared.root.toAbsolutePath().normalize() == normalizedRoot) {
            "prepared state root does not match configured mapping store"
        }
        require(prepared.preparedDirectory.toAbsolutePath().normalize() == expectedPreparedDirectory.toAbsolutePath().normalize()) {
            "prepared state directory does not match configured task handoff"
        }
        require(prepared.coordinates == expectedCoordinates) {
            "prepared state identity does not match the selected Android variant"
        }
        prepared.quarantinedDirectory?.let { quarantined ->
            require(quarantined.toAbsolutePath().normalize().startsWith(normalizedRoot.resolve("quarantine"))) {
                "prepared quarantine path escapes configured mapping store"
            }
        }
    }
}
