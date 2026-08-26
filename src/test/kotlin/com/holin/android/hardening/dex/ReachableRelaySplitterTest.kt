package com.holin.android.hardening.dex

import com.android.tools.smali.dexlib2.Opcode
import com.android.tools.smali.dexlib2.iface.MethodImplementation
import com.android.tools.smali.dexlib2.iface.instruction.Instruction
import com.android.tools.smali.dexlib2.iface.instruction.OffsetInstruction
import com.android.tools.smali.dexlib2.iface.instruction.OneRegisterInstruction
import com.android.tools.smali.dexlib2.iface.instruction.ReferenceInstruction
import com.android.tools.smali.dexlib2.immutable.ImmutableExceptionHandler
import com.android.tools.smali.dexlib2.immutable.ImmutableMethodImplementation
import com.android.tools.smali.dexlib2.immutable.ImmutableTryBlock
import com.android.tools.smali.dexlib2.immutable.debug.ImmutableLineNumber
import com.android.tools.smali.dexlib2.immutable.instruction.ImmutableInstruction10t
import com.android.tools.smali.dexlib2.immutable.instruction.ImmutableInstruction10x
import com.android.tools.smali.dexlib2.immutable.instruction.ImmutableInstruction11n
import com.android.tools.smali.dexlib2.immutable.instruction.ImmutableInstruction11x
import com.android.tools.smali.dexlib2.immutable.instruction.ImmutableInstruction12x
import com.android.tools.smali.dexlib2.immutable.instruction.ImmutableInstruction21t
import com.android.tools.smali.dexlib2.immutable.instruction.ImmutableInstruction31t
import com.android.tools.smali.dexlib2.immutable.instruction.ImmutableInstruction35c
import com.android.tools.smali.dexlib2.immutable.instruction.ImmutablePackedSwitchPayload
import com.android.tools.smali.dexlib2.immutable.instruction.ImmutableSwitchElement
import com.android.tools.smali.dexlib2.immutable.reference.ImmutableMethodReference
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

class ReachableRelaySplitterTest {
    @Test
    fun `one and multiple relay pairs split every safe five opcode window`() {
        val short = split(
            implementation(
                ImmutableInstruction11n(Opcode.CONST_4, 0, 0),
                ImmutableInstruction10x(Opcode.RETURN_VOID),
            ),
            salt = "one-relay",
        )
        val longOriginal = buildList {
            repeat(24) { add(ImmutableInstruction11n(Opcode.CONST_4, 0, it and 0x7)) }
            add(ImmutableInstruction10x(Opcode.RETURN_VOID))
        }
        val multiple = split(implementation(*longOriginal.toTypedArray()), salt = "many-relays")
        val boundaries = relayPairs(multiple).mapTo(linkedSetOf(), RelayPair::boundaryOrdinal)

        assertEquals(1, short.pairCount)
        assertTrue(multiple.pairCount > 1)
        for (windowStart in 0..longOriginal.size - SHINGLE_WIDTH) {
            assertTrue(
                ((windowStart + 1)..(windowStart + SHINGLE_WIDTH - 1)).any(boundaries::contains),
                "safe window $windowStart has no reachable split in boundaries=$boundaries",
            )
        }
    }

    @Test
    fun `same salt is byte structural identical while another salt changes boundaries or relay order`() {
        val original = buildList {
            repeat(64) { add(ImmutableInstruction11n(Opcode.CONST_4, 0, it and 0x7)) }
            add(ImmutableInstruction10x(Opcode.RETURN_VOID))
        }.let { implementation(*it.toTypedArray()) }

        val first = split(original, "stable-relay-salt")
        val repeated = split(original, "stable-relay-salt")
        val changed = split(original, "changed-relay-salt")

        assertEquals(canonical(first.implementation), canonical(repeated.implementation))
        assertEquals(topology(first), topology(repeated))
        assertNotEquals(topology(first), topology(changed))
    }

    @Test
    fun `each source and physical tail relay has one exact continuation edge and no data behavior`() {
        val original = buildList {
            repeat(20) { add(ImmutableInstruction12x(Opcode.NEG_INT, 0, 0)) }
            add(ImmutableInstruction10x(Opcode.RETURN_VOID))
        }.let { implementation(*it.toTypedArray()) }
        val split = split(original, "exact-relay-edges")
        val pairs = relayPairs(split)
        val incoming = incomingEdges(split.implementation)

        assertEquals(split.pairCount, pairs.size)
        pairs.forEach { pair ->
            val source = split.implementation.instructions.elementAt(pair.sourceIndex)
            val relay = split.implementation.instructions.elementAt(pair.relayIndex)
            assertEquals(Opcode.GOTO_32, source.opcode)
            assertEquals(Opcode.GOTO_32, relay.opcode)
            assertTrue(incoming[pair.sourceIndex].isNullOrEmpty())
            assertEquals(listOf(pair.sourceIndex), incoming[pair.relayIndex])
            assertEquals(listOf(pair.relayIndex), incoming[pair.continuationIndex])
            assertEquals(pair.sourceIndex + 1, pair.continuationIndex)
            listOf(source, relay).forEach { inserted ->
                assertFalse(inserted is OneRegisterInstruction)
                assertFalse(inserted is ReferenceInstruction)
                assertNotEquals(Opcode.THROW, inserted.opcode)
            }
        }
    }

    @Test
    fun `forward backward and conditional control flow excludes targets and following boundaries`() {
        val original = implementation(
            ImmutableInstruction11n(Opcode.CONST_4, 0, 2),
            ImmutableInstruction21t(Opcode.IF_EQZ, 0, 12),
            ImmutableInstruction11n(Opcode.CONST_4, 0, 1),
            ImmutableInstruction12x(Opcode.NEG_INT, 0, 0),
            ImmutableInstruction12x(Opcode.NEG_INT, 0, 0),
            ImmutableInstruction12x(Opcode.NEG_INT, 0, 0),
            ImmutableInstruction12x(Opcode.NEG_INT, 0, 0),
            ImmutableInstruction12x(Opcode.NEG_INT, 0, 0),
            ImmutableInstruction12x(Opcode.NEG_INT, 0, 0),
            ImmutableInstruction12x(Opcode.NEG_INT, 0, 0),
            ImmutableInstruction21t(Opcode.IF_NEZ, 0, -8),
            ImmutableInstruction10x(Opcode.RETURN_VOID),
        )
        val expanded = requireNotNull(ConditionalBranchExpander.expand(original))
        val split = split(expanded, "branch-safe-relays")
        val instructions = split.implementation.instructions.toList()
        val incoming = incomingEdges(split.implementation)

        assertTrue(split.pairCount > 0)
        relayPairs(split).forEach { pair ->
            assertTrue(incoming[pair.sourceIndex].isNullOrEmpty())
            assertFalse(instructions[pair.sourceIndex - 1] is OffsetInstruction)
        }
    }

    @Test
    fun `return throw and terminal goto all protect the physical relay suffix`() {
        val cases = listOf(
            "return" to implementation(
                ImmutableInstruction11n(Opcode.CONST_4, 0, 0),
                ImmutableInstruction10x(Opcode.RETURN_VOID),
            ),
            "throw" to implementation(
                ImmutableInstruction11n(Opcode.CONST_4, 0, 0),
                ImmutableInstruction11x(Opcode.THROW, 0),
            ),
            "goto" to implementation(
                ImmutableInstruction11n(Opcode.CONST_4, 0, 0),
                ImmutableInstruction12x(Opcode.NEG_INT, 0, 0),
                ImmutableInstruction10t(Opcode.GOTO, -1),
            ),
        )

        cases.forEach { (name, original) ->
            val split = split(original, "terminal-$name")
            val instructions = split.implementation.instructions.toList()
            val firstRelay = instructions.size - split.pairCount
            assertTrue(split.pairCount > 0, name)
            assertTrue(instructions.subList(firstRelay, instructions.size).all { it.opcode == Opcode.GOTO_32 }, name)
            assertTrue(
                instructions[firstRelay - 1].opcode in TERMINAL_OPCODES,
                "$name opcodes=${instructions.map(Instruction::getOpcode)} firstRelay=$firstRelay",
            )
        }
    }

    @Test
    fun `try switch no safe move result and move exception shapes receive no unsafe source`() {
        val tryImplementation = ImmutableMethodImplementation(
            1,
            listOf(
                ImmutableInstruction11n(Opcode.CONST_4, 0, 0),
                ImmutableInstruction10x(Opcode.RETURN_VOID),
                ImmutableInstruction11x(Opcode.MOVE_EXCEPTION, 0),
                ImmutableInstruction10x(Opcode.RETURN_VOID),
            ),
            listOf(ImmutableTryBlock(0, 1, listOf(ImmutableExceptionHandler(null, 2)))),
            emptyList(),
        )
        val switchImplementation = implementation(
            ImmutableInstruction31t(Opcode.PACKED_SWITCH, 0, 4),
            ImmutableInstruction10x(Opcode.RETURN_VOID),
            ImmutablePackedSwitchPayload(listOf(ImmutableSwitchElement(0, 3))),
        )
        val noSafe = implementation(ImmutableInstruction10t(Opcode.GOTO, 0))
        val moveResult = implementation(
            ImmutableInstruction35c(
                Opcode.INVOKE_STATIC,
                0,
                0,
                0,
                0,
                0,
                0,
                ImmutableMethodReference("Lcom/example/demo/match/RelayFixture;", "value", emptyList<String>(), "I"),
            ),
            ImmutableInstruction11x(Opcode.MOVE_RESULT, 0),
            ImmutableInstruction11n(Opcode.CONST_4, 0, 0),
            ImmutableInstruction10x(Opcode.RETURN_VOID),
        )
        val moveException = implementation(
            ImmutableInstruction11n(Opcode.CONST_4, 0, 0),
            ImmutableInstruction11x(Opcode.MOVE_EXCEPTION, 0),
            ImmutableInstruction11n(Opcode.CONST_4, 0, 1),
            ImmutableInstruction10x(Opcode.RETURN_VOID),
        )

        assertEquals(0, split(tryImplementation, "try").pairCount)
        assertEquals(0, split(switchImplementation, "switch").pairCount)
        assertEquals(0, split(noSafe, "no-safe").pairCount)
        val moveResultBoundaries = relayPairs(split(moveResult, "move-result")).map(RelayPair::boundaryOrdinal)
        val moveExceptionBoundaries = relayPairs(split(moveException, "move-exception")).map(RelayPair::boundaryOrdinal)
        assertTrue(1 !in moveResultBoundaries)
        assertTrue(1 !in moveExceptionBoundaries)
    }

    @Test
    fun `relay planning stops at the finite dex safety cap`() {
        val original = buildList {
            repeat(2_000) { add(ImmutableInstruction11n(Opcode.CONST_4, 0, it and 0x7)) }
            add(ImmutableInstruction10x(Opcode.RETURN_VOID))
        }.let { implementation(*it.toTypedArray()) }

        val split = split(original, "relay-cap")

        assertEquals(MAX_REACHABLE_RELAY_PAIRS_PER_METHOD, split.pairCount)
        assertEquals(split.pairCount, relayPairs(split).size)
    }

    @Test
    fun `debug item at original method end prevents a relay suffix`() {
        val original = ImmutableMethodImplementation(
            1,
            listOf(
                ImmutableInstruction11n(Opcode.CONST_4, 0, 0),
                ImmutableInstruction10x(Opcode.RETURN_VOID),
            ),
            emptyList(),
            listOf(ImmutableLineNumber(2, 42)),
        )

        assertEquals(0, split(original, "end-debug-boundary").pairCount)
    }

    private fun split(implementation: MethodImplementation, salt: String): ReachableRelaySplit =
        requireNotNull(
            ReachableRelaySplitter().split(
                implementation,
                salt.encodeToByteArray(),
                "Lcom/example/demo/match/RelayFixture;->run()V",
            ),
        )

    private fun implementation(vararg instructions: Instruction) =
        ImmutableMethodImplementation(1, instructions.toList(), emptyList(), emptyList())

    private fun relayPairs(split: ReachableRelaySplit): List<RelayPair> {
        val instructions = split.implementation.instructions.toList()
        val addresses = addresses(instructions)
        val indexByAddress = addresses.withIndex().associate { it.value to it.index }
        val relayIndexes = (instructions.size - split.pairCount until instructions.size).toSet()
        val sourceIndexes = instructions.mapIndexedNotNullTo(linkedSetOf()) { index, instruction ->
            val opcode = instruction.opcode
            val branch = instruction as? OffsetInstruction ?: return@mapIndexedNotNullTo null
            index.takeIf {
                opcode == Opcode.GOTO_32 &&
                    indexByAddress[addresses[index] + branch.codeOffset] in relayIndexes
            }
        }
        return relayIndexes.sorted().map { relayIndex ->
            val sourceIndex = sourceIndexes.single { sourceIndex ->
                val source = instructions[sourceIndex] as OffsetInstruction
                indexByAddress[addresses[sourceIndex] + source.codeOffset] == relayIndex
            }
            val relay = instructions[relayIndex] as OffsetInstruction
            val continuationIndex = requireNotNull(indexByAddress[addresses[relayIndex] + relay.codeOffset])
            val boundaryOrdinal = (0 until sourceIndex).count { it !in sourceIndexes }
            RelayPair(sourceIndex, relayIndex, continuationIndex, boundaryOrdinal)
        }
    }

    private fun incomingEdges(implementation: MethodImplementation): Map<Int, List<Int>> {
        val instructions = implementation.instructions.toList()
        val addresses = addresses(instructions)
        val indexByAddress = addresses.withIndex().associate { it.value to it.index }
        return instructions.mapIndexedNotNull { sourceIndex, instruction ->
            val branch = instruction as? OffsetInstruction ?: return@mapIndexedNotNull null
            indexByAddress[addresses[sourceIndex] + branch.codeOffset]?.let { it to sourceIndex }
        }.groupBy({ it.first }, { it.second })
    }

    private fun topology(split: ReachableRelaySplit): Pair<List<Int>, List<Int>> {
        val pairs = relayPairs(split)
        return pairs.map(RelayPair::boundaryOrdinal).sorted() to
            pairs.sortedBy(RelayPair::relayIndex).map(RelayPair::boundaryOrdinal)
    }

    private fun canonical(implementation: MethodImplementation): List<String> {
        val instructions = implementation.instructions.toList()
        val addresses = addresses(instructions)
        val indexByAddress = addresses.withIndex().associate { it.value to it.index }
        return instructions.mapIndexed { index, instruction ->
            val target = (instruction as? OffsetInstruction)?.let { branch ->
                indexByAddress[addresses[index] + branch.codeOffset]
            }
            "${instruction.opcode.name}:${target ?: "-"}"
        }
    }

    private fun addresses(instructions: List<Instruction>): IntArray {
        val addresses = IntArray(instructions.size)
        var address = 0
        instructions.forEachIndexed { index, instruction ->
            addresses[index] = address
            address += instruction.codeUnits
        }
        return addresses
    }

    private data class RelayPair(
        val sourceIndex: Int,
        val relayIndex: Int,
        val continuationIndex: Int,
        val boundaryOrdinal: Int,
    )

    private companion object {
        const val SHINGLE_WIDTH = 5
        val GOTO_OPCODES = setOf(Opcode.GOTO, Opcode.GOTO_16, Opcode.GOTO_32)
        val TERMINAL_OPCODES = GOTO_OPCODES + setOf(
            Opcode.RETURN_VOID,
            Opcode.RETURN,
            Opcode.RETURN_WIDE,
            Opcode.RETURN_OBJECT,
            Opcode.THROW,
        )
    }
}
