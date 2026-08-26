package com.holin.android.hardening.dex

import com.android.tools.smali.dexlib2.AccessFlags
import com.android.tools.smali.dexlib2.Opcode
import com.android.tools.smali.dexlib2.Opcodes
import com.android.tools.smali.dexlib2.builder.BuilderInstruction
import com.android.tools.smali.dexlib2.builder.instruction.BuilderInstruction11n
import com.android.tools.smali.dexlib2.builder.instruction.BuilderInstruction12x
import com.android.tools.smali.dexlib2.dexbacked.DexBackedDexFile
import com.android.tools.smali.dexlib2.iface.Method
import com.android.tools.smali.dexlib2.iface.MethodImplementation
import com.android.tools.smali.dexlib2.iface.instruction.Instruction
import com.android.tools.smali.dexlib2.iface.instruction.OffsetInstruction
import com.android.tools.smali.dexlib2.iface.instruction.OneRegisterInstruction
import com.android.tools.smali.dexlib2.iface.instruction.ReferenceInstruction
import com.android.tools.smali.dexlib2.iface.instruction.TwoRegisterInstruction
import com.android.tools.smali.dexlib2.iface.reference.StringReference
import com.android.tools.smali.dexlib2.immutable.ImmutableClassDef
import com.android.tools.smali.dexlib2.immutable.ImmutableDexFile
import com.android.tools.smali.dexlib2.immutable.ImmutableMethod
import com.android.tools.smali.dexlib2.immutable.ImmutableMethodImplementation
import com.android.tools.smali.dexlib2.immutable.debug.ImmutableLineNumber
import com.android.tools.smali.dexlib2.immutable.instruction.ImmutableInstruction10x
import com.android.tools.smali.dexlib2.immutable.instruction.ImmutableInstruction11n
import com.android.tools.smali.dexlib2.immutable.instruction.ImmutableInstruction12x
import com.android.tools.smali.dexlib2.immutable.instruction.ImmutableInstruction31c
import com.android.tools.smali.dexlib2.immutable.reference.ImmutableStringReference
import com.android.tools.smali.dexlib2.writer.io.MemoryDataStore
import com.android.tools.smali.dexlib2.writer.pool.DexPool
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.MessageDigest
import java.util.zip.Adler32
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

class SafeUnreachablePayloadTest {
    @Test
    fun `marker slot search evaluates complete combinations when partial replacements remain unsafe`() {
        val blockOpcodes = listOf(
            Opcode.MOVE,
            Opcode.NEG_INT,
            Opcode.NOT_INT,
            Opcode.ADD_INT_2ADDR,
            Opcode.XOR_INT_2ADDR,
        )
        val chunk = buildList<BuilderInstruction> {
            add(BuilderInstruction11n(Opcode.CONST_4, 0, 0))
            repeat(5) { rotation ->
                repeat(blockOpcodes.size) { offset ->
                    add(BuilderInstruction12x(blockOpcodes[(rotation + offset) % blockOpcodes.size], 0, 0))
                }
            }
        }
        val baseTokens = listOf("goto") + CommonOpcodeShingles.tokens(chunk)
        val retainedShingles = (0 until 5).mapTo(linkedSetOf()) { block ->
            baseTokens.subList(2 + block * 5, 7 + block * 5).joinToString("\u001f")
        }
        val completeRepairTokens = baseTokens.toMutableList().apply {
            repeat(5) { block -> this[2 + block * 5] = "const" }
        }
        repeat(4) { replacementCount ->
            val partial = baseTokens.toMutableList().apply {
                repeat(replacementCount + 1) { block -> this[2 + block * 5] = "const" }
            }
            assertTrue(CommonOpcodeShingles.shingles(partial).any(retainedShingles::contains))
        }
        assertTrue(CommonOpcodeShingles.shingles(completeRepairTokens).none(retainedShingles::contains))

        val method = SafeNopWeaver::class.java.getDeclaredMethod(
            "withStringMarkers",
            List::class.java,
            ByteArray::class.java,
            String::class.java,
            Int::class.javaPrimitiveType,
            List::class.java,
            Set::class.java,
        ).apply { isAccessible = true }
        @Suppress("UNCHECKED_CAST")
        val rewritten = method.invoke(
            SafeNopWeaver(),
            listOf(chunk),
            "complete-combination-salt".encodeToByteArray(),
            "$OWNED_CLASS->completeCombination()V",
            0,
            emptyList<BuilderInstruction>(),
            retainedShingles,
        ) as List<List<BuilderInstruction>>
        val rewrittenTokens = listOf("goto") + CommonOpcodeShingles.tokens(rewritten.flatten())

        assertTrue(
            CommonOpcodeShingles.shingles(rewrittenTokens).none(retainedShingles::contains),
            "markerIndexes=${rewritten.flatten().mapIndexedNotNull { index, instruction ->
                index.takeIf { instruction.opcode == Opcode.CONST_STRING_JUMBO }
            }}",
        )
    }

    @Test
    fun `register bearing producer emits exact deterministic diverse jumbo marker categories on v0`() {
        val original = longMethodsDex(listOf("markerAlpha", "markerBeta"))

        val first = transform(original, salt = "marker-salt")
        val repeated = transform(original, salt = "marker-salt")
        val changedSalt = transform(original, salt = "marker-salt-changed")
        val alpha = markerValues(entryPayload(implementation(first.dexBytes, "markerAlpha")))
        val beta = markerValues(entryPayload(implementation(first.dexBytes, "markerBeta")))
        val repeatedAlpha = markerValues(entryPayload(implementation(repeated.dexBytes, "markerAlpha")))
        val changedAlpha = markerValues(entryPayload(implementation(changedSalt.dexBytes, "markerAlpha")))

        assertMarkerValues(alpha)
        assertEquals(alpha, repeatedAlpha)
        val alphaByLength = alpha.associateBy(String::length)
        val betaByLength = beta.associateBy(String::length)
        val changedByLength = changedAlpha.associateBy(String::length)
        assertTrue((listOf(8, 9, 33, 129)).all { alphaByLength.getValue(it) != betaByLength.getValue(it) })
        assertTrue((listOf(8, 9, 33, 129)).all { alphaByLength.getValue(it) != changedByLength.getValue(it) })
    }

    @Test
    fun `payload contract accepts only exact marker set plus safe v0 integers`() {
        val valid = validMarkerPayload()
        assertTrue(SafeUnreachablePayloadContract.isValidPayload(valid, registerCount = 1))

        val mutations = listOf(
            valid.filterIndexed { index, _ -> index != 2 },
            valid + valid[1],
            valid.toMutableList().apply {
                this[2] = ImmutableInstruction31c(
                    Opcode.CONST_STRING_JUMBO,
                    0,
                    ImmutableStringReference("SLH1Sxxx"),
                )
            },
            valid.toMutableList().apply {
                this[2] = ImmutableInstruction31c(
                    Opcode.CONST_STRING_JUMBO,
                    1,
                    ImmutableStringReference("SLH1M:" + "a".repeat(3)),
                )
            },
            valid.toMutableList().apply {
                this[2] = com.android.tools.smali.dexlib2.immutable.instruction.ImmutableInstruction21c(
                    Opcode.CONST_STRING,
                    0,
                    ImmutableStringReference("SLH1M:" + "a".repeat(3)),
                )
            },
            valid + ImmutableInstruction31c(
                Opcode.CONST_STRING_JUMBO,
                0,
                ImmutableStringReference("arbitrary"),
            ),
        )
        mutations.forEachIndexed { index, mutation ->
            assertFalse(SafeUnreachablePayloadContract.isValidPayload(mutation, registerCount = 1), "mutation $index")
        }
    }

    @Test
    fun `register bearing long payload uses the complete safe integer alphabet on v0`() {
        val original = longMethodDex("diversePayload")

        val result = (0..1_000).firstNotNullOfOrNull { index ->
            transform(original, "diverse-payload-$index").takeIf { candidate ->
                entryPayload(implementation(candidate.dexBytes, "diversePayload"))
                    .filterNot { it.opcode == Opcode.CONST_STRING_JUMBO }
                    .map(Instruction::getOpcode)
                    .toSet() == SAFE_INTEGER_PAYLOAD_OPCODES
            }
        } ?: error("could not find deterministic complete safe payload alphabet")
        val implementation = implementation(result.dexBytes, "diversePayload")
        val instructions = implementation.instructions.toList()
        val entryJump = assertIs<OffsetInstruction>(instructions.first())
        val payload = entryPayload(implementation)

        assertEquals(Opcode.GOTO_32, entryJump.opcode)
        assertApprovedRegisterPayload(payload)
        assertEquals(1, implementation.registerCount)
        assertEquals(entryJump.codeUnits + payload.sumOf(Instruction::getCodeUnits), entryJump.codeOffset)
        var address = 0
        instructions.forEach { instruction ->
            if (instruction is OffsetInstruction) {
                val target = address + instruction.codeOffset
                assertTrue(target !in entryJump.codeUnits until entryJump.codeOffset)
            }
            address += instruction.codeUnits
        }
        assertTrue(payload.none { it.opcode.name.contains("DIV") || it.opcode.name.contains("REM") })
        DexIdTableValidator.requireValid(result.dexBytes, "diverse-payload.dex")
        assertContentEquals(
            MessageDigest.getInstance("SHA-1").digest(result.dexBytes.copyOfRange(32, result.dexBytes.size)),
            result.dexBytes.copyOfRange(12, 32),
        )
        val checksum = Adler32().apply { update(result.dexBytes, 12, result.dexBytes.size - 12) }.value.toInt()
        assertEquals(checksum, ByteBuffer.wrap(result.dexBytes, 8, 4).order(ByteOrder.LITTLE_ENDIAN).int)
    }

    @Test
    fun `same salt and method reproduce payload dex and report while another salt changes sequence`() {
        val original = longMethodDex("deterministic")

        val first = transform(original, salt = "deterministic-payload")
        val second = transform(original, salt = "deterministic-payload")
        val changed = transform(original, salt = "different-payload")

        assertEquals(
            payloadOpcodes(first.dexBytes, "deterministic"),
            payloadOpcodes(second.dexBytes, "deterministic"),
        )
        assertContentEquals(first.dexBytes, second.dexBytes)
        assertEquals(first.report, second.report)
        assertNotEquals(
            payloadOpcodes(first.dexBytes, "deterministic"),
            payloadOpcodes(changed.dexBytes, "deterministic"),
        )
    }

    @Test
    fun `fixed distinct method ids produce distinct five opcode payload shingle sets`() {
        val names = List(8) { index -> "method$index" }
        val original = longMethodsDex(names)

        val result = transform(original, salt = "method-specific-payload")
        val shingleSets = names.map { name ->
            payloadOpcodes(result.dexBytes, name).windowed(SHINGLE_WIDTH).toSet()
        }

        assertEquals(names.size, result.report.transformedMethodCount)
        assertEquals(names.size, result.report.methods.count { it.reason == MethodEligibilityReason.TRANSFORMED })
        assertTrue(shingleSets.all { it.isNotEmpty() })
        assertEquals(names.size, shingleSets.toSet().size)
    }

    @Test
    fun `accepted payload retains no original five opcode shingle`() {
        val original = longMethodDex("shingleRepair")

        val result = transform(original, salt = "shingle-repair")
        val before = implementation(original, "shingleRepair").instructions
        val after = implementation(result.dexBytes, "shingleRepair").instructions
        val originalShingles = CommonOpcodeShingles.shingles(CommonOpcodeShingles.tokens(before))
        val transformedShingles = CommonOpcodeShingles.shingles(CommonOpcodeShingles.tokens(after))

        assertTrue(originalShingles.intersect(transformedShingles).isEmpty())
        assertEquals(0.0, result.report.methods.single().opcodeShingleSimilarity)
        assertEquals(1.0, result.report.methods.single().shingleEffectiveness)
    }

    @Test
    fun `zero register method retains nop only entry payload fallback`() {
        val original = longMethodsDex(listOf("zeroRegisters"), registerCount = 0, opcode = Opcode.RETURN_VOID)

        val result = transform(original, salt = "zero-register-payload")
        val payload = entryPayload(implementation(result.dexBytes, "zeroRegisters"))

        assertTrue(payload.isNotEmpty())
        assertEquals(setOf(Opcode.NOP), payload.map(Instruction::getOpcode).toSet())
        assertEquals(0, implementation(result.dexBytes, "zeroRegisters").registerCount)
    }

    @Test
    fun `instance receiver register remains a live reference across the skipped payload`() {
        val original = instanceReceiverMethodDex("receiverBody")
        val originalMethod = method(original, "receiverBody")

        val result = transform(original, salt = "instance-receiver-payload")
        val transformedMethod = method(result.dexBytes, "receiverBody")
        val transformed = transformedMethod.implementation!!
        val addressedInstructions = addressedInstructions(transformed)
        val diamonds = opaqueEntryDiamonds(transformed, expectedReceiverRegister = 0, expectedCount = 3)
        val payload = diamonds.flatMap(OpaqueDiamond::payload)
        val originalEntryAddress = diamonds.last().continuationAddress
        val payloadAddresses = diamonds.flatMapTo(linkedSetOf()) { diamond ->
            addressedInstructions(transformed)
                .filter { (address, _) -> address in diamond.payloadAddressRange }
                .map(Pair<Int, Instruction>::first)
        }
        val report = result.report.methods.single()

        assertEquals(0, originalMethod.accessFlags and AccessFlags.STATIC.value)
        assertEquals(originalMethod.accessFlags, transformedMethod.accessFlags)
        assertEquals(originalMethod.implementation!!.registerCount, transformed.registerCount)
        assertTrue(payload.size in 24..40)
        diamonds.forEach { assertEquals(Opcode.CONST_4, it.payload.first().opcode) }
        assertSafeRegisterPayload(payload)
        assertEquals(0, report.insertedRelayInstructionCount)
        assertEquals(payload.size, report.insertedPayloadInstructionCount)
        assertEquals(
            Opcode.MOVE_OBJECT,
            addressedInstructions.single { it.first == originalEntryAddress }.second.opcode,
        )
        addressedInstructions.forEach { (address, instruction) ->
            if (instruction is OffsetInstruction) {
                assertTrue(address + instruction.codeOffset !in payloadAddresses || address < originalEntryAddress)
            }
        }
        val liveOpcodes = addressedInstructions
            .filter { it.first >= originalEntryAddress }
            .map { it.second.opcode }
            .filterNot { it == Opcode.NOP }
        assertEquals(
            List(160) { Opcode.MOVE_OBJECT } + Opcode.RETURN_VOID,
            liveOpcodes,
        )

        val debugLines = transformed.debugItems
            .filterIsInstance<com.android.tools.smali.dexlib2.iface.debug.LineNumber>()
            .associate { it.lineNumber to it.codeAddress }
        assertEquals(setOf(100, 200), debugLines.keys)
        assertEquals(originalEntryAddress, debugLines.getValue(100))
        assertEquals(
            Opcode.MOVE_OBJECT,
            addressedInstructions.single { it.first == debugLines.getValue(200) }.second.opcode,
        )
        assertEquals(
            80,
            addressedInstructions.count { (address, instruction) ->
                address in originalEntryAddress until debugLines.getValue(200) &&
                    instruction.opcode == Opcode.MOVE_OBJECT
            },
        )
    }

    @Test
    fun `ordinary eligible instance method emits one exact opaque diamond and zero relays`() {
        val original = instanceReceiverMethodDex("ordinaryReceiver", instructionCount = 24)

        val result = transform(original, salt = "ordinary-opaque-diamond")
        val transformed = implementation(result.dexBytes, "ordinaryReceiver")
        val diamonds = opaqueEntryDiamonds(transformed, expectedReceiverRegister = 0, expectedCount = 1)
        val report = result.report.methods.single()

        assertTrue(diamonds.single().payload.size in 8..16)
        assertSafeRegisterPayload(diamonds.single().payload)
        assertEquals(0, report.insertedRelayInstructionCount)
        assertEquals(diamonds.single().payload.size, report.insertedPayloadInstructionCount)
        assertEquals(Opcode.MOVE_OBJECT, opcodeAt(transformed, diamonds.single().continuationAddress))
    }

    @Test
    fun `instance diamond bytes are same salt deterministic and different salt diverse`() {
        val original = instanceReceiverMethodDex("receiverDeterminism", instructionCount = 24)

        val first = transform(original, salt = "receiver-determinism")
        val repeated = transform(original, salt = "receiver-determinism")
        val changed = transform(original, salt = "receiver-diversity")

        assertContentEquals(first.dexBytes, repeated.dexBytes)
        assertEquals(first.report, repeated.report)
        assertFalse(first.dexBytes.contentEquals(changed.dexBytes))
        assertNotEquals(
            first.report.methods.single().newBodySha256,
            changed.report.methods.single().newBodySha256,
        )
    }

    @Test
    fun `static and unrepresentable receivers retain entry goto while constructors remain excluded`() {
        val original = mixedReceiverFallbackDex()

        val result = transform(original, salt = "receiver-fallbacks")
        val reports = result.report.methods.associateBy { it.methodId.substringAfter("->").substringBefore('(') }
        val staticEntry = implementation(result.dexBytes, "staticMethod").instructions.first()
        val unrepresentableEntry = implementation(result.dexBytes, "wideReceiver").instructions.first()

        assertEquals(Opcode.GOTO_32, staticEntry.opcode)
        assertEquals(Opcode.GOTO_32, unrepresentableEntry.opcode)
        assertEquals(0, reports.getValue("staticMethod").insertedRelayInstructionCount)
        assertEquals(0, reports.getValue("wideReceiver").insertedRelayInstructionCount)
        assertEquals(MethodEligibilityReason.CONSTRUCTOR, reports.getValue("<init>").reason)
        assertContentEquals(
            implementation(original, "<init>").instructions.map(Instruction::getOpcode).toList(),
            implementation(result.dexBytes, "<init>").instructions.map(Instruction::getOpcode).toList(),
        )
    }

    private fun transform(input: ByteArray, salt: String): DexTransformationResult =
        SafeDexTransformer().transform(
            input,
            DexTransformRequest(
                ownedDescriptorPrefixes = setOf(OWNED_PREFIX),
                ownedDescriptors = setOf(OWNED_CLASS),
                salt = salt.encodeToByteArray(),
                minimumCoverage = 0.0,
                minimumSimHashDistance = 0,
                maximumGrowthRatio = 1.0,
                selectionRate = 1.0,
                enforceMaximumGrowth = false,
            ),
        )

    private fun method(bytes: ByteArray, methodName: String): Method =
        DexBackedDexFile.fromInputStream(null, bytes.inputStream())
            .classes.single { it.type == OWNED_CLASS }
            .methods.single { it.name == methodName }

    private fun implementation(bytes: ByteArray, methodName: String): MethodImplementation =
        method(bytes, methodName).implementation!!

    private fun payloadOpcodes(bytes: ByteArray, methodName: String): List<Opcode> =
        entryPayload(implementation(bytes, methodName)).map(Instruction::getOpcode)

    private fun markerValues(payload: List<Instruction>): List<String> = payload.mapNotNull { instruction ->
        if (instruction.opcode != Opcode.CONST_STRING_JUMBO) return@mapNotNull null
        assertEquals(0, assertIs<OneRegisterInstruction>(instruction).registerA)
        assertIs<StringReference>(assertIs<ReferenceInstruction>(instruction).reference).string
    }

    private fun assertMarkerValues(values: List<String>) {
        val sorted = values.sortedBy(String::length)
        assertEquals(listOf(0, 8, 9, 33, 129), sorted.map(String::length))
        assertEquals("", sorted[0])
        assertTrue(sorted[1].matches(Regex("SLH1S[0-9a-z]{3}")))
        assertTrue(sorted[2].matches(Regex("SLH1M:[0-9a-z]{3}")))
        assertTrue(sorted[3].matches(Regex("SLH1L:[0-9a-z]{27}")))
        assertTrue(sorted[4].matches(Regex("SLH1V:[0-9a-z]{123}")))
        assertEquals(values.size, values.toSet().size)
    }

    private fun validMarkerPayload(): List<Instruction> = listOf(
        ImmutableInstruction11n(Opcode.CONST_4, 0, 0),
        ImmutableInstruction31c(Opcode.CONST_STRING_JUMBO, 0, ImmutableStringReference("")),
        ImmutableInstruction31c(
            Opcode.CONST_STRING_JUMBO,
            0,
            ImmutableStringReference("SLH1Sabc"),
        ),
        ImmutableInstruction31c(
            Opcode.CONST_STRING_JUMBO,
            0,
            ImmutableStringReference("SLH1M:" + "a".repeat(3)),
        ),
        ImmutableInstruction31c(
            Opcode.CONST_STRING_JUMBO,
            0,
            ImmutableStringReference("SLH1L:" + "b".repeat(27)),
        ),
        ImmutableInstruction31c(
            Opcode.CONST_STRING_JUMBO,
            0,
            ImmutableStringReference("SLH1V:" + "c".repeat(123)),
        ),
        ImmutableInstruction12x(Opcode.NEG_INT, 0, 0),
        ImmutableInstruction12x(Opcode.XOR_INT_2ADDR, 0, 0),
    )

    private fun entryPayload(implementation: MethodImplementation): List<Instruction> {
        val instructions = implementation.instructions.toList()
        val jump = instructions.first() as OffsetInstruction
        var address = jump.codeUnits
        return instructions.drop(1).takeWhile { instruction ->
            (address < jump.codeOffset).also { address += instruction.codeUnits }
        }
    }

    private fun addressedInstructions(implementation: MethodImplementation): List<Pair<Int, Instruction>> = buildList {
        var address = 0
        implementation.instructions.forEach { instruction ->
            add(address to instruction)
            address += instruction.codeUnits
        }
    }

    private fun assertApprovedRegisterPayload(payload: List<Instruction>) {
        assertEquals(
            SAFE_INTEGER_PAYLOAD_OPCODES,
            payload.filterNot { it.opcode == Opcode.CONST_STRING_JUMBO }.map(Instruction::getOpcode).toSet(),
        )
        assertSafeRegisterPayload(payload)
    }

    private fun assertSafeRegisterPayload(payload: List<Instruction>) {
        assertEquals(Opcode.CONST_4, payload.first().opcode)
        assertMarkerValues(markerValues(payload))
        payload.forEachIndexed { index, instruction ->
            assertFalse(instruction is OffsetInstruction, "payload[$index] is a branch")
            if (instruction.opcode == Opcode.CONST_STRING_JUMBO) {
                assertEquals(0, assertIs<OneRegisterInstruction>(instruction).registerA)
                assertIs<StringReference>(assertIs<ReferenceInstruction>(instruction).reference)
                return@forEachIndexed
            }
            assertTrue(instruction.opcode in SAFE_INTEGER_PAYLOAD_OPCODES)
            assertFalse(instruction is ReferenceInstruction, "payload[$index] has an arbitrary reference")
            when (instruction.opcode) {
                Opcode.CONST_4 -> assertEquals(0, assertIs<OneRegisterInstruction>(instruction).registerA)
                else -> {
                    val registers = assertIs<TwoRegisterInstruction>(instruction)
                    assertEquals(0, registers.registerA)
                    assertEquals(0, registers.registerB)
                }
            }
        }
    }

    private fun longMethodDex(name: String): ByteArray = longMethodsDex(listOf(name))

    private fun longMethodsDex(
        names: List<String>,
        registerCount: Int = 1,
        opcode: Opcode = Opcode.NEG_INT,
    ): ByteArray {
        val methods = names.map { name ->
            ImmutableMethod(
                OWNED_CLASS,
                name,
                emptyList(),
                "V",
                AccessFlags.PRIVATE.value or AccessFlags.STATIC.value,
                emptySet(),
                emptySet(),
                ImmutableMethodImplementation(
                    registerCount,
                    buildList {
                        if (opcode == Opcode.NEG_INT) {
                            add(ImmutableInstruction11n(Opcode.CONST_4, 0, 0))
                            repeat(159) { add(ImmutableInstruction12x(Opcode.NEG_INT, 0, 0)) }
                        } else {
                            repeat(160) {
                                add(
                                    when (opcode) {
                                        Opcode.NOP, Opcode.RETURN_VOID -> ImmutableInstruction10x(opcode)
                                        else -> ImmutableInstruction12x(opcode, 0, 0)
                                    },
                                )
                            }
                        }
                        add(ImmutableInstruction10x(Opcode.RETURN_VOID))
                    },
                    emptyList(),
                    emptyList(),
                ),
            )
        }
        val clazz = ImmutableClassDef(
            OWNED_CLASS,
            AccessFlags.PUBLIC.value,
            "Ljava/lang/Object;",
            emptyList(),
            null,
            emptySet(),
            emptyList(),
            methods,
        )
        val store = MemoryDataStore()
        DexPool.writeTo(store, ImmutableDexFile(Opcodes.getDefault(), listOf(clazz)))
        return store.data
    }

    private fun instanceReceiverMethodDex(name: String, instructionCount: Int = 161): ByteArray {
        require(instructionCount >= 2)
        val method = ImmutableMethod(
            OWNED_CLASS,
            name,
            emptyList(),
            "V",
            AccessFlags.PRIVATE.value,
            emptySet(),
            emptySet(),
            ImmutableMethodImplementation(
                1,
                buildList {
                    repeat(instructionCount - 1) { add(ImmutableInstruction12x(Opcode.MOVE_OBJECT, 0, 0)) }
                    add(ImmutableInstruction10x(Opcode.RETURN_VOID))
                },
                emptyList(),
                if (instructionCount >= 161) {
                    listOf(ImmutableLineNumber(0, 100), ImmutableLineNumber(80, 200))
                } else {
                    emptyList()
                },
            ),
        )
        val clazz = ImmutableClassDef(
            OWNED_CLASS,
            AccessFlags.PUBLIC.value,
            "Ljava/lang/Object;",
            emptyList(),
            null,
            emptySet(),
            emptyList(),
            listOf(method),
        )
        val store = MemoryDataStore()
        DexPool.writeTo(store, ImmutableDexFile(Opcodes.getDefault(), listOf(clazz)))
        return store.data
    }

    private fun mixedReceiverFallbackDex(): ByteArray {
        val body = listOf(
            ImmutableInstruction12x(Opcode.MOVE_OBJECT, 0, 0),
            ImmutableInstruction12x(Opcode.MOVE_OBJECT, 0, 0),
            ImmutableInstruction12x(Opcode.MOVE_OBJECT, 0, 0),
            ImmutableInstruction12x(Opcode.MOVE_OBJECT, 0, 0),
            ImmutableInstruction12x(Opcode.MOVE_OBJECT, 0, 0),
            ImmutableInstruction12x(Opcode.MOVE_OBJECT, 0, 0),
            ImmutableInstruction12x(Opcode.MOVE_OBJECT, 0, 0),
            ImmutableInstruction12x(Opcode.MOVE_OBJECT, 0, 0),
            ImmutableInstruction12x(Opcode.MOVE_OBJECT, 0, 0),
            ImmutableInstruction12x(Opcode.MOVE_OBJECT, 0, 0),
            ImmutableInstruction12x(Opcode.MOVE_OBJECT, 0, 0),
            ImmutableInstruction10x(Opcode.RETURN_VOID),
        )
        fun method(name: String, accessFlags: Int, registerCount: Int) = ImmutableMethod(
            OWNED_CLASS,
            name,
            emptyList(),
            "V",
            accessFlags,
            emptySet(),
            emptySet(),
            ImmutableMethodImplementation(registerCount, body, emptyList(), emptyList()),
        )
        val clazz = ImmutableClassDef(
            OWNED_CLASS,
            AccessFlags.PUBLIC.value,
            "Ljava/lang/Object;",
            emptyList(),
            null,
            emptySet(),
            emptyList(),
            listOf(
                method("staticMethod", AccessFlags.PRIVATE.value or AccessFlags.STATIC.value, 1),
                method("wideReceiver", AccessFlags.PRIVATE.value, 257),
                method("<init>", AccessFlags.PRIVATE.value or AccessFlags.CONSTRUCTOR.value, 1),
            ),
        )
        val store = MemoryDataStore()
        DexPool.writeTo(store, ImmutableDexFile(Opcodes.getDefault(), listOf(clazz)))
        return store.data
    }

    private fun opaqueEntryDiamonds(
        implementation: MethodImplementation,
        expectedReceiverRegister: Int,
        expectedCount: Int,
    ): List<OpaqueDiamond> {
        val addressed = addressedInstructions(implementation)
        val instructions = addressed.map(Pair<Int, Instruction>::second)
        val indexByAddress = addressed.mapIndexed { index, (address, _) -> address to index }.toMap()
        var currentIndex = 0
        return List(expectedCount) {
            val conditional = assertIs<OffsetInstruction>(instructions[currentIndex])
            assertTrue(conditional.opcode == Opcode.IF_EQZ || conditional.opcode == Opcode.IF_NEZ)
            assertEquals(
                expectedReceiverRegister,
                assertIs<OneRegisterInstruction>(instructions[currentIndex]).registerA,
            )
            val falseGotoIndex = currentIndex + 1
            val trueGotoIndex = currentIndex + 2
            val falseGoto = assertIs<OffsetInstruction>(instructions[falseGotoIndex])
            val trueGoto = assertIs<OffsetInstruction>(instructions[trueGotoIndex])
            assertEquals(Opcode.GOTO_32, falseGoto.opcode)
            assertEquals(Opcode.GOTO_32, trueGoto.opcode)
            assertEquals(
                addressed[trueGotoIndex].first,
                addressed[currentIndex].first + conditional.codeOffset,
            )
            val falseContinuation = addressed[falseGotoIndex].first + falseGoto.codeOffset
            val trueContinuation = addressed[trueGotoIndex].first + trueGoto.codeOffset
            assertEquals(falseContinuation, trueContinuation)
            val continuationIndex = requireNotNull(indexByAddress[falseContinuation])
            assertTrue(continuationIndex > trueGotoIndex + 1)
            val payload = instructions.subList(trueGotoIndex + 1, continuationIndex)
            currentIndex = continuationIndex
            OpaqueDiamond(
                payload = payload,
                payloadAddressRange = addressed[trueGotoIndex + 1].first until falseContinuation,
                continuationAddress = falseContinuation,
            )
        }
    }

    private fun opcodeAt(implementation: MethodImplementation, address: Int): Opcode =
        addressedInstructions(implementation).single { it.first == address }.second.opcode

    private data class OpaqueDiamond(
        val payload: List<Instruction>,
        val payloadAddressRange: IntRange,
        val continuationAddress: Int,
    )

    private companion object {
        const val OWNED_PREFIX = "Lcom/example/demo/match/"
        const val OWNED_CLASS = "Lcom/example/demo/match/PayloadFixture;"
        const val SHINGLE_WIDTH = 5
        val SAFE_INTEGER_PAYLOAD_OPCODES = setOf(
            Opcode.CONST_4,
            Opcode.MOVE,
            Opcode.NEG_INT,
            Opcode.NOT_INT,
            Opcode.ADD_INT_2ADDR,
            Opcode.SUB_INT_2ADDR,
            Opcode.MUL_INT_2ADDR,
            Opcode.AND_INT_2ADDR,
            Opcode.OR_INT_2ADDR,
            Opcode.XOR_INT_2ADDR,
            Opcode.SHL_INT_2ADDR,
            Opcode.SHR_INT_2ADDR,
            Opcode.USHR_INT_2ADDR,
        )
    }
}
