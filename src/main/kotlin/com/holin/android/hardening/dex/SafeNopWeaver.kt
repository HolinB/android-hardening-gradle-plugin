package com.holin.android.hardening.dex

import com.android.tools.smali.dexlib2.Opcode
import com.android.tools.smali.dexlib2.builder.BuilderInstruction
import com.android.tools.smali.dexlib2.builder.MutableMethodImplementation
import com.android.tools.smali.dexlib2.builder.instruction.BuilderInstruction10x
import com.android.tools.smali.dexlib2.builder.instruction.BuilderInstruction11n
import com.android.tools.smali.dexlib2.builder.instruction.BuilderInstruction12x
import com.android.tools.smali.dexlib2.builder.instruction.BuilderInstruction21t
import com.android.tools.smali.dexlib2.builder.instruction.BuilderInstruction30t
import com.android.tools.smali.dexlib2.builder.instruction.BuilderInstruction31c
import com.android.tools.smali.dexlib2.iface.MethodImplementation
import com.android.tools.smali.dexlib2.iface.instruction.Instruction
import com.android.tools.smali.dexlib2.immutable.ImmutableMethodImplementation
import com.android.tools.smali.dexlib2.immutable.reference.ImmutableStringReference
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.charset.StandardCharsets
import java.security.MessageDigest

internal class SafeNopWeaver {
    fun weave(
        implementation: MethodImplementation,
        salt: ByteArray,
        methodId: String,
        detourPaddingNopCount: Int,
        expandConditionals: Boolean,
        receiverRegister: Int? = null,
        opaqueDiamondCount: Int = 0,
    ): NopWeaveResult {
        require(detourPaddingNopCount > 0) { "detour payload must contain at least one unreachable instruction" }
        require(opaqueDiamondCount >= 0) { "opaque diamond count must not be negative" }
        require((receiverRegister == null) == (opaqueDiamondCount == 0)) {
            "opaque diamonds require exactly one representable receiver register"
        }
        require(receiverRegister == null || receiverRegister in 0..UByte.MAX_VALUE.toInt()) {
            "opaque diamond receiver must fit DEX format 21t"
        }
        val payloadInstructionCount = maxOf(
            detourPaddingNopCount,
            opaqueDiamondCount,
            if (implementation.registerCount > 0) MIN_MARKER_PAYLOAD_INSTRUCTIONS else 0,
        )
        val original = implementation.instructions.toList()
        val conditionallyExpanded = if (expandConditionals) {
            ConditionalBranchExpander.expand(implementation)
                ?: return NopWeaveResult.UnstableInstructionEncoding
        } else {
            requireNotNull(ImmutableMethodImplementation.of(implementation))
        }
        val expanded = conditionallyExpanded
        val expandedInstructions = expanded.instructions.toList()
        val prepared = chooseBoundaryVariants(expandedInstructions, salt, methodId).firstNotNullOfOrNull { boundaries ->
            val mutable = MutableMethodImplementation(expanded)
            boundaries.sorted().forEachIndexed { inserted, originalBoundary ->
                mutable.addInstruction(originalBoundary + inserted, BuilderInstruction10x(Opcode.NOP))
            }
            paddingInstructions(
                original = original,
                wovenEntryPrefix = CommonOpcodeShingles.tokens(mutable.instructions).take(SHINGLE_WIDTH - 1),
                registerCount = implementation.registerCount,
                salt = salt,
                methodId = methodId,
                count = payloadInstructionCount,
            )?.let { payload -> PreparedWeave(mutable, boundaries, payload) }
        } ?: return NopWeaveResult.NoSafeBoundary
        val mutable = prepared.implementation
        val boundaries = prepared.boundaries
        val integerPayloadChunks = if (opaqueDiamondCount == 0) {
            listOf(prepared.payload)
        } else {
            payloadChunkSizes(payloadInstructionCount, opaqueDiamondCount).mapIndexed { index, size ->
                paddingInstructions(
                    original = original,
                    wovenEntryPrefix = CommonOpcodeShingles.tokens(mutable.instructions).take(SHINGLE_WIDTH - 1),
                    registerCount = implementation.registerCount,
                    salt = salt,
                    methodId = "$methodId\u0000opaque-chunk-$index",
                    count = size,
                ) ?: return NopWeaveResult.NoSafeBoundary
            }
        }
        val payloadChunks = if (implementation.registerCount == 0) {
            integerPayloadChunks
        } else {
            withStringMarkers(
                chunks = integerPayloadChunks,
                salt = salt,
                methodId = methodId,
                opaqueDiamondCount = opaqueDiamondCount,
                wovenInstructions = mutable.instructions,
                oldShingles = CommonOpcodeShingles.shingles(CommonOpcodeShingles.tokens(original)),
            )
        }
        check(SafeUnreachablePayloadContract.isValidPayloadChunks(payloadChunks, implementation.registerCount))
        val payload = payloadChunks.flatten()
        val payloadNopCount = payload.count { it.opcode == Opcode.NOP }
        val originalEntry = mutable.newLabelForIndex(0)
        if (opaqueDiamondCount == 0) {
            payload.asReversed().forEach { instruction -> mutable.addInstruction(0, instruction) }
            mutable.addInstruction(0, BuilderInstruction30t(Opcode.GOTO_32, originalEntry))
        } else {
            var continuation = originalEntry
            payloadChunks.asReversed().forEachIndexed { reversedIndex, chunk ->
                chunk.asReversed().forEach { instruction -> mutable.addInstruction(0, instruction) }
                mutable.addInstruction(0, BuilderInstruction30t(Opcode.GOTO_32, continuation))
                val trueGoto = mutable.newLabelForIndex(0)
                mutable.addInstruction(0, BuilderInstruction30t(Opcode.GOTO_32, continuation))
                val diamondIndex = opaqueDiamondCount - reversedIndex - 1
                val conditionalOpcode = if (saltedIndex(salt, "$methodId\u0000opaque-branch", diamondIndex, 2) == 0) {
                    Opcode.IF_EQZ
                } else {
                    Opcode.IF_NEZ
                }
                mutable.addInstruction(
                    0,
                    BuilderInstruction21t(conditionalOpcode, requireNotNull(receiverRegister), trueGoto),
                )
                continuation = mutable.newLabelForIndex(0)
            }
        }
        val rewritten = requireNotNull(ImmutableMethodImplementation.of(mutable))
        val entryPrefixInstructionCount = payload.size + if (opaqueDiamondCount == 0) 1 else opaqueDiamondCount * 3
        val rewrittenOpcodes = rewritten.instructions
            .drop(entryPrefixInstructionCount)
            .filterNot { it.opcode == Opcode.NOP }
            .map(Instruction::getOpcode)
        val expandedOpcodes = expandedInstructions.filterNot { it.opcode == Opcode.NOP }.map(Instruction::getOpcode)
        if (rewrittenOpcodes != expandedOpcodes) return NopWeaveResult.UnstableInstructionEncoding
        val oldTokens = CommonOpcodeShingles.tokens(original)
        val newTokens = CommonOpcodeShingles.tokens(rewritten.instructions)
        return NopWeaveResult.Candidate(
            implementation = rewritten,
            insertedNopCount = boundaries.size + payloadNopCount,
            insertedPayloadInstructionCount = payloadInstructionCount,
            insertedRelayInstructionCount = 0,
            insertedOpaqueDiamondCount = opaqueDiamondCount,
            opcodeShingleSimilarity = CommonOpcodeShingles.similarity(oldTokens, newTokens),
            shingleEffectiveness = CommonOpcodeShingles.effectiveness(oldTokens, newTokens),
            simHashDistance = NormalizedOpcodeSimHash.distance(oldTokens, newTokens),
        )
    }

    private fun payloadChunkSizes(
        payloadInstructionCount: Int,
        opaqueDiamondCount: Int,
    ): List<Int> {
        require(payloadInstructionCount >= opaqueDiamondCount) {
            "each opaque diamond requires an independently valid payload"
        }
        val chunks = ArrayList<Int>(opaqueDiamondCount)
        var allocated = 0
        repeat(opaqueDiamondCount) { index ->
            val remainingChunks = opaqueDiamondCount - index
            val size = (payloadInstructionCount - allocated) / remainingChunks
            chunks += size
            allocated += size
        }
        return chunks
    }

    private fun withStringMarkers(
        chunks: List<List<BuilderInstruction>>,
        salt: ByteArray,
        methodId: String,
        opaqueDiamondCount: Int,
        wovenInstructions: List<BuilderInstruction>,
        oldShingles: Set<String>,
    ): List<List<BuilderInstruction>> {
        val markers = SafeUnreachablePayloadContract.markerValues(salt, methodId).map { value ->
            BuilderInstruction31c(Opcode.CONST_STRING_JUMBO, 0, ImmutableStringReference(value))
        }
        val layoutTokens = arrayListOf<String>()
        val slotTokenIndexes = linkedMapOf<Pair<Int, Int>, Int>()
        chunks.forEachIndexed { chunkIndex, chunk ->
            if (opaqueDiamondCount == 0) {
                layoutTokens += "goto"
            } else {
                layoutTokens += listOf("if", "goto", "goto")
            }
            chunk.forEachIndexed { instructionIndex, instruction ->
                slotTokenIndexes[chunkIndex to instructionIndex] = layoutTokens.size
                layoutTokens += token(instruction)
            }
        }
        layoutTokens += CommonOpcodeShingles.tokens(wovenInstructions)
        val opcodeCounts = chunks.flatten().groupingBy(BuilderInstruction::getOpcode).eachCount()
        val allAvailableSlots = slotTokenIndexes.keys.filter { (_, instructionIndex) -> instructionIndex > 0 }
        val duplicateOpcodeSlots = allAvailableSlots.filter { (chunkIndex, instructionIndex) ->
            opcodeCounts.getValue(chunks[chunkIndex][instructionIndex].opcode) > 1
        }
        check(allAvailableSlots.size >= markers.size) { "bounded unreachable payload has no room for exact string markers" }
        fun selectSlots(candidates: List<Pair<Int, Int>>): List<Pair<Int, Int>>? {
            if (candidates.size < markers.size) return null
            val rotation = saltedIndex(salt, "$methodId\u0000marker-slots", 0, candidates.size)
            val orderedSlots = candidates.drop(rotation) + candidates.take(rotation)
            val selectedSlots = ArrayList<Pair<Int, Int>>(markers.size)
            var visitedStates = 0

            fun remainingSlotsCanRepairViolations(start: Int): Boolean {
                val remainingTokenIndexes = orderedSlots.subList(start, orderedSlots.size)
                    .mapTo(hashSetOf()) { slotTokenIndexes.getValue(it) }
                val violationStarts = if (layoutTokens.size < SHINGLE_WIDTH) {
                    listOf(0).takeIf { layoutTokens.joinToString("\u001f") in oldShingles }.orEmpty()
                } else {
                    (0..layoutTokens.size - SHINGLE_WIDTH).filter { index ->
                        layoutTokens.subList(index, index + SHINGLE_WIDTH).joinToString("\u001f") in oldShingles
                    }
                }
                return violationStarts.all { violationStart ->
                    (violationStart until violationStart + SHINGLE_WIDTH).any(remainingTokenIndexes::contains)
                }
            }

            fun choose(start: Int): Boolean {
                if (++visitedStates > MAX_MARKER_SLOT_SEARCH_STATES) return false
                if (selectedSlots.size == markers.size) {
                    return CommonOpcodeShingles.shingles(layoutTokens).none(oldShingles::contains)
                }
                val remainingNeeded = markers.size - selectedSlots.size
                for (candidateIndex in start..orderedSlots.size - remainingNeeded) {
                    if (visitedStates >= MAX_MARKER_SLOT_SEARCH_STATES) return false
                    val slot = orderedSlots[candidateIndex]
                    val tokenIndex = slotTokenIndexes.getValue(slot)
                    val previous = layoutTokens[tokenIndex]
                    layoutTokens[tokenIndex] = "const"
                    selectedSlots += slot
                    if (remainingSlotsCanRepairViolations(candidateIndex + 1) && choose(candidateIndex + 1)) {
                        return true
                    }
                    selectedSlots.removeAt(selectedSlots.lastIndex)
                    layoutTokens[tokenIndex] = previous
                }
                return false
            }
            return if (choose(0)) selectedSlots.toList() else null
        }
        val selectedSlots = selectSlots(duplicateOpcodeSlots) ?: selectSlots(allAvailableSlots) ?: allAvailableSlots.take(markers.size)
        val markerBySlot = selectedSlots.zip(markers).toMap()
        return chunks.mapIndexed { chunkIndex, chunk ->
            chunk.mapIndexed { instructionIndex, instruction ->
                markerBySlot[chunkIndex to instructionIndex] ?: instruction
            }
        }
    }

    private fun paddingInstructions(
        original: List<Instruction>,
        wovenEntryPrefix: List<String>,
        registerCount: Int,
        salt: ByteArray,
        methodId: String,
        count: Int,
    ): List<BuilderInstruction>? {
        if (registerCount == 0) return List(count) { BuilderInstruction10x(Opcode.NOP) }
        val originalTokens = CommonOpcodeShingles.tokens(original)
        val oldShingles = CommonOpcodeShingles.shingles(originalTokens)
        for (repairSize in 1..minOf(MAX_PAYLOAD_REPAIR_INSTRUCTIONS, count)) {
            val baseCount = count - repairSize
            val selected = ArrayList<BuilderInstruction>(count)
            val selectedTokens = arrayListOf("goto")
            var baseValid = true
            repeat(baseCount) { index ->
                val chosen = payloadCandidates(salt, methodId, index).firstOrNull { candidate ->
                    safeAppend(selectedTokens, token(candidate), oldShingles)
                }
                if (chosen == null) {
                    baseValid = false
                } else {
                    selected += chosen
                    selectedTokens += token(chosen)
                }
            }
            if (!baseValid) continue
            val repaired = repairPayloadSuffix(
                index = baseCount,
                count = count,
                salt = salt,
                methodId = methodId,
                selectedTokens = selectedTokens,
                wovenEntryPrefix = wovenEntryPrefix,
                oldShingles = oldShingles,
            ) ?: continue
            return selected + repaired
        }
        return null
    }

    private fun repairPayloadSuffix(
        index: Int,
        count: Int,
        salt: ByteArray,
        methodId: String,
        selectedTokens: List<String>,
        wovenEntryPrefix: List<String>,
        oldShingles: Set<String>,
    ): List<BuilderInstruction>? {
        if (index == count) {
            val closureTokens = selectedTokens.toMutableList()
            return emptyList<BuilderInstruction>().takeIf {
                wovenEntryPrefix.all { wovenToken ->
                    safeAppend(closureTokens, wovenToken, oldShingles).also { safe ->
                        if (safe) closureTokens += wovenToken
                    }
                }
            }
        }
        payloadCandidates(salt, methodId, index).forEach { candidate ->
            val candidateToken = token(candidate)
            if (!safeAppend(selectedTokens, candidateToken, oldShingles)) return@forEach
            val tail = repairPayloadSuffix(
                index = index + 1,
                count = count,
                salt = salt,
                methodId = methodId,
                selectedTokens = selectedTokens + candidateToken,
                wovenEntryPrefix = wovenEntryPrefix,
                oldShingles = oldShingles,
            )
            if (tail != null) return listOf(candidate) + tail
        }
        return null
    }

    private fun safeAppend(
        tokens: List<String>,
        token: String,
        oldShingles: Set<String>,
    ): Boolean {
        val suffix = tokens.takeLast(SHINGLE_WIDTH - 1) + token
        return suffix.size < SHINGLE_WIDTH || CommonOpcodeShingles.shingles(suffix).single() !in oldShingles
    }

    private fun token(instruction: BuilderInstruction): String =
        CommonOpcodeShingles.tokens(listOf(instruction)).single()

    private fun payloadCandidates(
        salt: ByteArray,
        methodId: String,
        index: Int,
    ): List<BuilderInstruction> {
        if (index == 0) return listOf(saltedConstInstruction(salt, methodId, index))
        val candidates = SafeUnreachablePayloadContract.REGISTER_BEARING_OPCODES.map { opcode ->
            if (opcode == Opcode.CONST_4) {
                saltedConstInstruction(salt, methodId, index)
            } else {
                BuilderInstruction12x(opcode, 0, 0)
            }
        }
        val rotation = saltedIndex(salt, "$methodId\u0000payload", index, candidates.size)
        return candidates.drop(rotation) + candidates.take(rotation)
    }

    private fun saltedConstInstruction(
        salt: ByteArray,
        methodId: String,
        index: Int,
    ) = BuilderInstruction11n(
        Opcode.CONST_4,
        0,
        saltedIndex(salt, "$methodId\u0000literal", index, 16) - 8,
    )

    private fun chooseBoundaryVariants(
        instructions: List<Instruction>,
        salt: ByteArray,
        methodId: String,
    ): List<Set<Int>> {
        if (instructions.isEmpty()) return emptyList()
        val safe = (0..instructions.size).filterTo(linkedSetOf()) { boundary ->
            isSafeBoundary(instructions, boundary)
        }
        val firstCandidates = if (instructions.size < SHINGLE_WIDTH) {
            safe.filter { it > 0 }
        } else {
            (1 until SHINGLE_WIDTH).filter(safe::contains)
        }
        if (firstCandidates.isEmpty()) return emptyList()
        val primaryCandidates = firstCandidates.takeLast(minOf(2, firstCandidates.size))
        val primary = primaryCandidates[saltedIndex(salt, methodId, 0, primaryCandidates.size)]
        return (listOf(primary) + firstCandidates.filterNot { it == primary }).mapNotNull { firstBoundary ->
            chooseBoundaries(instructions, safe, salt, methodId, firstBoundary)
        }.distinct()
    }

    private fun chooseBoundaries(
        instructions: List<Instruction>,
        safe: Set<Int>,
        salt: ByteArray,
        methodId: String,
        firstBoundary: Int,
    ): Set<Int>? {
        if (instructions.size < SHINGLE_WIDTH) return setOf(firstBoundary)

        val selected = linkedSetOf(firstBoundary)
        for (start in 0..instructions.size - SHINGLE_WIDTH) {
            val windowBoundaries = (start + 1)..(start + SHINGLE_WIDTH - 1)
            if (windowBoundaries.any(selected::contains)) continue
            val candidates = windowBoundaries.filter(safe::contains)
            if (candidates.isEmpty()) return null
            val rightmost = candidates.takeLast(minOf(2, candidates.size))
            selected += rightmost[saltedIndex(salt, methodId, start, rightmost.size)]
        }
        return selected
    }

    private fun isSafeBoundary(instructions: List<Instruction>, boundary: Int): Boolean {
        val next = instructions.getOrNull(boundary)?.opcode
        if (next == Opcode.MOVE_EXCEPTION) return false
        if (boundary == 0 || boundary == instructions.size) return true
        val previous = instructions[boundary - 1].opcode
        if (next in MOVE_RESULT_OPCODES && previous.setsResult()) return false
        return true
    }

    private fun saltedIndex(
        salt: ByteArray,
        methodId: String,
        windowStart: Int,
        size: Int,
    ): Int {
        if (size == 1) return 0
        val digest = MessageDigest.getInstance("SHA-256").apply {
            update(DOMAIN)
            updateInt(salt.size)
            update(salt)
            val method = methodId.toByteArray(StandardCharsets.UTF_8)
            updateInt(method.size)
            update(method)
            updateInt(windowStart)
        }.digest()
        val value = ByteBuffer.wrap(digest, 0, Int.SIZE_BYTES).order(ByteOrder.BIG_ENDIAN).int and Int.MAX_VALUE
        return value % size
    }

    private fun MessageDigest.updateInt(value: Int) {
        update(ByteBuffer.allocate(Int.SIZE_BYTES).order(ByteOrder.BIG_ENDIAN).putInt(value).array())
    }

    private companion object {
        const val SHINGLE_WIDTH = 5
        const val MAX_PAYLOAD_REPAIR_INSTRUCTIONS = 8
        const val MAX_MARKER_SLOT_SEARCH_STATES = 250_000
        const val MIN_MARKER_PAYLOAD_INSTRUCTIONS = 8
        val DOMAIN = "com.holin.android.hardening/1.2.0/safe-nop-weave/v1\u0000".toByteArray(StandardCharsets.UTF_8)
        val MOVE_RESULT_OPCODES = setOf(
            Opcode.MOVE_RESULT,
            Opcode.MOVE_RESULT_WIDE,
            Opcode.MOVE_RESULT_OBJECT,
        )
    }

    private data class PreparedWeave(
        val implementation: MutableMethodImplementation,
        val boundaries: Set<Int>,
        val payload: List<BuilderInstruction>,
    )
}

internal sealed interface NopWeaveResult {
    object NoSafeBoundary : NopWeaveResult

    object UnstableInstructionEncoding : NopWeaveResult

    data class Candidate(
        val implementation: ImmutableMethodImplementation,
        val insertedNopCount: Int,
        val insertedPayloadInstructionCount: Int,
        val insertedRelayInstructionCount: Int,
        val insertedOpaqueDiamondCount: Int,
        val opcodeShingleSimilarity: Double,
        val shingleEffectiveness: Double,
        val simHashDistance: Int,
    ) : NopWeaveResult
}
