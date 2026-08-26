package com.holin.android.hardening.dex

import com.android.tools.smali.dexlib2.Opcode
import com.android.tools.smali.dexlib2.builder.BuilderInstruction
import com.android.tools.smali.dexlib2.builder.BuilderOffsetInstruction
import com.android.tools.smali.dexlib2.builder.MutableMethodImplementation
import com.android.tools.smali.dexlib2.builder.instruction.BuilderInstruction21t
import com.android.tools.smali.dexlib2.builder.instruction.BuilderInstruction22t
import com.android.tools.smali.dexlib2.builder.instruction.BuilderInstruction30t
import com.android.tools.smali.dexlib2.iface.MethodImplementation
import com.android.tools.smali.dexlib2.immutable.ImmutableMethodImplementation

internal object ConditionalBranchExpander {
    fun expand(implementation: MethodImplementation): ImmutableMethodImplementation? {
        val mutable = MutableMethodImplementation(implementation)
        val original = mutable.instructions.toList()
        val plans = original.mapIndexedNotNull { index, instruction ->
            if (index + 1 >= mutable.instructions.size || inverse(instruction.opcode) == null) {
                null
            } else {
                ExpansionPlan(index, instruction, (instruction as BuilderOffsetInstruction).target)
            }
        }
        plans.asReversed().forEach { plan ->
            // Capture the existing location before insertion so the inverse target remains
            // owned by the original fallthrough instruction, including when it is also a true target.
            val fallthrough = mutable.newLabelForIndex(plan.index + 1)
            val replacement = inverseInstruction(plan.instruction, fallthrough)
            mutable.replaceInstruction(plan.index, replacement)
            mutable.addInstruction(plan.index + 1, BuilderInstruction30t(Opcode.GOTO_32, plan.trueTarget))
        }
        val expanded = requireNotNull(ImmutableMethodImplementation.of(mutable))
        val expectedOpcodes = original.flatMapIndexed { index, instruction ->
            inverse(instruction.opcode)?.takeIf { index + 1 < original.size }?.let { inverse ->
                listOf(inverse, Opcode.GOTO_32)
            } ?: listOf(instruction.opcode)
        }
        return expanded.takeIf { candidate -> candidate.instructions.map { it.opcode } == expectedOpcodes }
    }

    private fun inverseInstruction(
        instruction: BuilderInstruction,
        fallthrough: com.android.tools.smali.dexlib2.builder.Label,
    ): BuilderInstruction = when (instruction) {
        is BuilderInstruction22t -> BuilderInstruction22t(
            requireNotNull(inverse(instruction.opcode)),
            instruction.registerA,
            instruction.registerB,
            fallthrough,
        )
        is BuilderInstruction21t -> BuilderInstruction21t(
            requireNotNull(inverse(instruction.opcode)),
            instruction.registerA,
            fallthrough,
        )
        else -> error("supported conditional has an unexpected format: ${instruction.opcode}")
    }

    private fun inverse(opcode: Opcode): Opcode? = when (opcode) {
        Opcode.IF_EQ -> Opcode.IF_NE
        Opcode.IF_NE -> Opcode.IF_EQ
        Opcode.IF_LT -> Opcode.IF_GE
        Opcode.IF_GE -> Opcode.IF_LT
        Opcode.IF_GT -> Opcode.IF_LE
        Opcode.IF_LE -> Opcode.IF_GT
        Opcode.IF_EQZ -> Opcode.IF_NEZ
        Opcode.IF_NEZ -> Opcode.IF_EQZ
        Opcode.IF_LTZ -> Opcode.IF_GEZ
        Opcode.IF_GEZ -> Opcode.IF_LTZ
        Opcode.IF_GTZ -> Opcode.IF_LEZ
        Opcode.IF_LEZ -> Opcode.IF_GTZ
        else -> null
    }

    private data class ExpansionPlan(
        val index: Int,
        val instruction: BuilderInstruction,
        val trueTarget: com.android.tools.smali.dexlib2.builder.Label,
    )
}
