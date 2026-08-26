package com.holin.android.hardening.dex

import com.android.tools.smali.dexlib2.AccessFlags
import com.android.tools.smali.dexlib2.Opcode
import com.android.tools.smali.dexlib2.Opcodes
import com.android.tools.smali.dexlib2.dexbacked.DexBackedDexFile
import com.android.tools.smali.dexlib2.iface.Method
import com.android.tools.smali.dexlib2.iface.MethodImplementation
import com.android.tools.smali.dexlib2.iface.instruction.Instruction
import com.android.tools.smali.dexlib2.iface.instruction.NarrowLiteralInstruction
import com.android.tools.smali.dexlib2.iface.instruction.OffsetInstruction
import com.android.tools.smali.dexlib2.iface.instruction.OneRegisterInstruction
import com.android.tools.smali.dexlib2.iface.instruction.TwoRegisterInstruction
import com.android.tools.smali.dexlib2.immutable.ImmutableClassDef
import com.android.tools.smali.dexlib2.immutable.ImmutableDexFile
import com.android.tools.smali.dexlib2.immutable.ImmutableExceptionHandler
import com.android.tools.smali.dexlib2.immutable.ImmutableMethod
import com.android.tools.smali.dexlib2.immutable.ImmutableMethodImplementation
import com.android.tools.smali.dexlib2.immutable.ImmutableMethodParameter
import com.android.tools.smali.dexlib2.immutable.ImmutableTryBlock
import com.android.tools.smali.dexlib2.immutable.debug.ImmutableLineNumber
import com.android.tools.smali.dexlib2.immutable.instruction.ImmutableInstruction10x
import com.android.tools.smali.dexlib2.immutable.instruction.ImmutableInstruction11n
import com.android.tools.smali.dexlib2.immutable.instruction.ImmutableInstruction11x
import com.android.tools.smali.dexlib2.immutable.instruction.ImmutableInstruction12x
import com.android.tools.smali.dexlib2.immutable.instruction.ImmutableInstruction21t
import com.android.tools.smali.dexlib2.immutable.instruction.ImmutableInstruction22t
import com.android.tools.smali.dexlib2.immutable.instruction.ImmutableInstruction31t
import com.android.tools.smali.dexlib2.immutable.instruction.ImmutablePackedSwitchPayload
import com.android.tools.smali.dexlib2.immutable.instruction.ImmutableSwitchElement
import com.android.tools.smali.dexlib2.writer.io.MemoryDataStore
import com.android.tools.smali.dexlib2.writer.pool.DexPool
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.MessageDigest
import java.util.zip.Adler32
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

class SafeDexTransformerConditionalExpansionTest {
    @Test
    fun `eligible conditional is expanded to inverse branch followed by goto32`() {
        val input = dex(clazz(OWNED_CLASS, listOf(conditionalMethod("conditional", Opcode.IF_EQZ))))

        val output = transform(input).dexBytes
        val opcodes = implementation(output, OWNED_CLASS, "conditional").instructions.map { it.opcode }

        assertTrue(Opcode.IF_NEZ in opcodes, "expected inverse conditional in $opcodes")
        assertTrue(Opcode.GOTO_32 in opcodes.drop(1), "expected a non-entry GOTO_32 in $opcodes")
    }

    @Test
    fun `conditional without a fallthrough instruction is not expanded`() {
        val invalid = ImmutableMethodImplementation(
            1,
            listOf(ImmutableInstruction21t(Opcode.IF_EQZ, 0, 0)),
            emptyList(),
            emptyList(),
        )

        val expanded = requireNotNull(ConditionalBranchExpander.expand(invalid))

        assertEquals(listOf(Opcode.IF_EQZ), expanded.instructions.map { it.opcode })
    }

    @Test
    fun `conditional expansion rejects widening of an original non conditional branch`() {
        val branchAtLimit = method(
            owner = OWNED_CLASS,
            name = "branchAtLimit",
            parameterTypes = emptyList(),
            returnType = "V",
            registerCount = 1,
            instructions = buildList {
                add(com.android.tools.smali.dexlib2.immutable.instruction.ImmutableInstruction10t(Opcode.GOTO, 127))
                add(ImmutableInstruction21t(Opcode.IF_EQZ, 0, 2))
                repeat(124) { add(ImmutableInstruction11n(Opcode.CONST_4, 0, it and 0x7)) }
                add(ImmutableInstruction10x(Opcode.RETURN_VOID))
            },
        )
        val input = dex(
            clazz(
                OWNED_CLASS,
                listOf(branchAtLimit, conditionalMethod("safeSibling", Opcode.IF_EQZ)),
            ),
        )

        val result = transform(input, salt = "conditional-branch-format")
        val report = result.report.methods.single { it.methodId == "$OWNED_CLASS->branchAtLimit()V" }

        assertEquals(MethodEligibilityReason.UNSTABLE_INSTRUCTION_ENCODING, report.reason)
        assertEquals(Opcode.GOTO, implementation(result.dexBytes, OWNED_CLASS, "branchAtLimit").instructions.first().opcode)
    }

    @Test
    fun `all supported conditionals preserve inverse pairs registers targets and return values`() {
        val cases = conditionalCases()
        val methods = cases.map { case -> conditionalMethod(case.name, case.opcode, debugLines = true) }
        val input = dex(clazz(OWNED_CLASS, methods))

        val output = transform(input, salt = "all-conditionals").dexBytes

        cases.forEach { case ->
            val before = implementation(input, OWNED_CLASS, case.name)
            val after = implementation(output, OWNED_CLASS, case.name)
            val originalConditional = before.instructions.first()
            val expansion = expansion(after, case.inverse)

            assertEquals(before.registerCount, after.registerCount, case.name)
            assertEquals(registers(originalConditional), registers(expansion.conditional.instruction), case.name)
            assertEquals(0, literalAt(after, expansion.inverseTargetAddress), "inverse target must be original fallthrough")
            assertEquals(1, literalAt(after, expansion.gotoTargetAddress), "goto target must be original true target")
            assertEquals(1, execute(input, case.name, case.trueArguments), "${case.name} original true")
            assertEquals(1, execute(output, case.name, case.trueArguments), "${case.name} transformed true")
            assertEquals(0, execute(input, case.name, case.falseArguments), "${case.name} original false")
            assertEquals(0, execute(output, case.name, case.falseArguments), "${case.name} transformed false")
            assertEquals(
                listOf(100, 200),
                after.debugItems.filterIsInstance<com.android.tools.smali.dexlib2.iface.debug.LineNumber>()
                    .map { it.lineNumber },
                case.name,
            )
        }
    }

    @Test
    fun `multiple forward backward and shared fallthrough targets retain original label ownership`() {
        val loop = method(
            owner = OWNED_CLASS,
            name = "loop",
            parameterTypes = emptyList(),
            returnType = "I",
            registerCount = 2,
            instructions = listOf(
                ImmutableInstruction11n(Opcode.CONST_4, 0, 2),
                ImmutableInstruction11n(Opcode.CONST_4, 1, 1),
                ImmutableInstruction21t(Opcode.IF_EQZ, 0, 5),
                ImmutableInstruction12x(Opcode.SUB_INT_2ADDR, 0, 1),
                ImmutableInstruction21t(Opcode.IF_NEZ, 0, -3),
                ImmutableInstruction11x(Opcode.RETURN, 0),
            ),
        )
        val sharedFallthrough = method(
            owner = OWNED_CLASS,
            name = "sharedFallthrough",
            parameterTypes = listOf("I"),
            returnType = "I",
            registerCount = 1,
            instructions = listOf(
                ImmutableInstruction21t(Opcode.IF_EQZ, 0, 2),
                ImmutableInstruction11n(Opcode.CONST_4, 0, 0),
                ImmutableInstruction11x(Opcode.RETURN, 0),
            ),
        )
        val distant = method(
            owner = OWNED_CLASS,
            name = "distant",
            parameterTypes = emptyList(),
            returnType = "V",
            registerCount = 2,
            instructions = buildList {
                add(ImmutableInstruction21t(Opcode.IF_EQZ, 0, 122))
                repeat(120) { add(ImmutableInstruction11n(Opcode.CONST_4, 1, it and 0x7)) }
                add(ImmutableInstruction10x(Opcode.RETURN_VOID))
            },
        )
        val input = dex(clazz(OWNED_CLASS, listOf(loop, sharedFallthrough, distant)))

        val output = transform(input, salt = "branch-shapes").dexBytes
        val loopAfter = implementation(output, OWNED_CLASS, "loop")
        val sharedAfter = implementation(output, OWNED_CLASS, "sharedFallthrough")
        val distantAfter = implementation(output, OWNED_CLASS, "distant")

        assertEquals(2, supportedConditionals(loopAfter).size)
        assertEquals(2, nonEntryGoto32(loopAfter).size)
        assertEquals(0, execute(output, "loop", intArrayOf()))
        val sharedExpansion = expansion(sharedAfter, Opcode.IF_NEZ)
        assertEquals(sharedExpansion.inverseTargetAddress, sharedExpansion.gotoTargetAddress)
        val distantExpansion = expansion(distantAfter, Opcode.IF_NEZ)
        assertEquals(Opcode.RETURN_VOID, instructionAt(distantAfter, distantExpansion.gotoTargetAddress).opcode)
        assertTrue(
            (distantExpansion.goto.instruction as OffsetInstruction).codeOffset > 122,
            "the original distant target must be rebased across inserted instructions",
        )
    }

    @Test
    fun `unsafe method and descriptor categories never receive conditional expansion`() {
        val tryMethod = method(
            owner = OWNED_CLASS,
            name = "tryBody",
            parameterTypes = emptyList(),
            returnType = "V",
            registerCount = 1,
            instructions = listOf(
                ImmutableInstruction11n(Opcode.CONST_4, 0, 0),
                ImmutableInstruction21t(Opcode.IF_EQZ, 0, 3),
                ImmutableInstruction10x(Opcode.RETURN_VOID),
                ImmutableInstruction10x(Opcode.RETURN_VOID),
                ImmutableInstruction11x(Opcode.MOVE_EXCEPTION, 0),
                ImmutableInstruction10x(Opcode.RETURN_VOID),
            ),
            tryBlocks = listOf(ImmutableTryBlock(0, 1, listOf(ImmutableExceptionHandler(null, 6)))),
        )
        val switchMethod = method(
            owner = OWNED_CLASS,
            name = "switchBody",
            parameterTypes = emptyList(),
            returnType = "V",
            registerCount = 1,
            instructions = listOf(
                ImmutableInstruction21t(Opcode.IF_EQZ, 0, 5),
                ImmutableInstruction31t(Opcode.PACKED_SWITCH, 0, 4),
                ImmutableInstruction10x(Opcode.RETURN_VOID),
                ImmutablePackedSwitchPayload(listOf(ImmutableSwitchElement(0, 3))),
            ),
        )
        val monitor = method(
            owner = OWNED_CLASS,
            name = "monitorBody",
            parameterTypes = listOf("Ljava/lang/Object;"),
            returnType = "V",
            registerCount = 1,
            instructions = listOf(
                ImmutableInstruction11x(Opcode.MONITOR_ENTER, 0),
                ImmutableInstruction11x(Opcode.MONITOR_EXIT, 0),
                ImmutableInstruction21t(Opcode.IF_EQZ, 0, 3),
                ImmutableInstruction10x(Opcode.RETURN_VOID),
                ImmutableInstruction10x(Opcode.RETURN_VOID),
            ),
        )
        val ownedMethods = listOf(
            tryMethod,
            switchMethod,
            monitor,
            voidConditionalMethod("<init>", AccessFlags.PRIVATE.value or AccessFlags.CONSTRUCTOR.value),
            voidConditionalMethod("<clinit>", AccessFlags.STATIC.value or AccessFlags.CONSTRUCTOR.value),
            voidConditionalMethod("synchronizedBody", PRIVATE_STATIC or AccessFlags.SYNCHRONIZED.value),
            voidConditionalMethod("bridgeBody", PRIVATE_STATIC or AccessFlags.BRIDGE.value),
            voidConditionalMethod("syntheticBody", PRIVATE_STATIC or AccessFlags.SYNTHETIC.value),
            voidConditionalMethod("externalBody", AccessFlags.PUBLIC.value or AccessFlags.STATIC.value),
            voidConditionalMethod("safeBody", PRIVATE_STATIC),
        )
        val coroutine = "Lcom/example/demo/match/ConditionalContinuation;"
        val junk = "Lcom/example/demo/match/junkcode/ConditionalJunk;"
        val denied = "Lcom/example/demo/match/denied/ConditionalDenied;"
        val generated = "Lcom/example/demo/match/R;"
        val thirdParty = "Lthird/party/ConditionalDependency;"
        val input = dex(
            clazz(OWNED_CLASS, ownedMethods),
            clazz(coroutine, listOf(voidConditionalMethod("invokeSuspend", PRIVATE_STATIC, coroutine))),
            clazz(junk, listOf(voidConditionalMethod("junk", PRIVATE_STATIC, junk))),
            clazz(denied, listOf(voidConditionalMethod("denied", PRIVATE_STATIC, denied))),
            clazz(generated, listOf(voidConditionalMethod("generated", PRIVATE_STATIC, generated))),
            clazz(thirdParty, listOf(voidConditionalMethod("thirdParty", PRIVATE_STATIC, thirdParty))),
        )

        val output = SafeDexTransformer().transform(
            input,
            request("excluded-conditionals").copy(
                ownedDescriptors = setOf(OWNED_CLASS, coroutine, junk, denied, generated),
                deniedDescriptorPrefixes = setOf(
                    "Lcom/example/demo/match/junkcode/",
                    "Lcom/example/demo/match/denied/",
                ),
                externalContractMethodIds = setOf("$OWNED_CLASS->externalBody()V"),
            ),
        ).dexBytes

        val excluded = listOf(
            OWNED_CLASS to "tryBody",
            OWNED_CLASS to "switchBody",
            OWNED_CLASS to "monitorBody",
            OWNED_CLASS to "<init>",
            OWNED_CLASS to "<clinit>",
            OWNED_CLASS to "synchronizedBody",
            OWNED_CLASS to "bridgeBody",
            OWNED_CLASS to "syntheticBody",
            OWNED_CLASS to "externalBody",
            coroutine to "invokeSuspend",
            junk to "junk",
            denied to "denied",
            generated to "generated",
            thirdParty to "thirdParty",
        )
        excluded.forEach { (owner, name) ->
            val opcodes = implementation(output, owner, name).instructions.map { it.opcode }
            assertTrue(Opcode.IF_EQZ in opcodes, "$owner->$name lost its original conditional")
            assertTrue(Opcode.IF_NEZ !in opcodes, "$owner->$name received conditional expansion")
        }
        assertTrue(Opcode.GOTO_32 in implementation(output, OWNED_CLASS, "tryBody").instructions.map { it.opcode })
        assertTrue(Opcode.IF_NEZ in implementation(output, OWNED_CLASS, "safeBody").instructions.map { it.opcode })
    }

    @Test
    fun `conditional structure is salt independent while nop payload bytes still vary`() {
        val input = dex(clazz(OWNED_CLASS, listOf(longConditionalMethod("salted", 120))))
        val results = (0 until 8).map { index -> transform(input, salt = "salt-$index") }

        assertEquals(1, results.map { result -> expansionFingerprint(implementation(result.dexBytes, OWNED_CLASS, "salted")) }.toSet().size)
        assertEquals(1, results.map { result -> nonEntryGoto32(implementation(result.dexBytes, OWNED_CLASS, "salted")).size }.toSet().size)
        assertTrue(results.map { it.report.methods.single().insertedNopCount }.toSet().size > 1)
        assertTrue(results.map { it.dexBytes.contentHashCode() }.toSet().size > 1)
    }

    @Test
    fun `expanded dex reloads validates checksums lines and register counts`() {
        val originalMethod = conditionalMethod("validated", Opcode.IF_GEZ, debugLines = true)
        val input = dex(clazz(OWNED_CLASS, listOf(originalMethod)))

        val output = transform(input, salt = "validated-conditional").dexBytes
        val reloaded = DexBackedDexFile.fromInputStream(null, output.inputStream())
        val emitted = reloaded.classes.single().methods.single().implementation!!

        DexIdTableValidator.requireValid(output, "conditional-output.dex")
        assertEquals(originalMethod.implementation!!.registerCount, emitted.registerCount)
        assertEquals(listOf(100, 200), emitted.debugItems.filterIsInstance<com.android.tools.smali.dexlib2.iface.debug.LineNumber>().map { it.lineNumber })
        assertContentEquals(MessageDigest.getInstance("SHA-1").digest(output.copyOfRange(32, output.size)), output.copyOfRange(12, 32))
        val checksum = Adler32().apply { update(output, 12, output.size - 12) }.value.toInt()
        assertEquals(checksum, ByteBuffer.wrap(output, 8, 4).order(ByteOrder.LITTLE_ENDIAN).int)
    }

    @Test
    fun `long conditional changes opcode shingles and cfg beyond the entry detour`() {
        val originalMethod = longConditionalMethod("longFingerprint", 110)
        assertTrue(originalMethod.implementation!!.instructions.size >= 100)
        val input = dex(clazz(OWNED_CLASS, listOf(originalMethod)))

        val output = transform(input, salt = "long-fingerprint").dexBytes
        val before = originalMethod.implementation!!.instructions.toList()
        val emitted = implementation(output, OWNED_CLASS, "longFingerprint")
        val after = coreAddressed(emitted).map(AddressedInstruction::instruction)

        assertNotEquals(
            CommonOpcodeShingles.shingles(CommonOpcodeShingles.tokens(before)),
            CommonOpcodeShingles.shingles(CommonOpcodeShingles.tokens(after)),
        )
        assertNotEquals(
            cfgFingerprint(originalMethod.implementation!!, stripEntryDetour = false),
            cfgFingerprint(emitted, stripEntryDetour = true),
        )
    }

    private fun transform(input: ByteArray, salt: String = "conditional-expansion") =
        SafeDexTransformer().transform(input, request(salt))

    private fun request(salt: String) = DexTransformRequest(
        ownedDescriptorPrefixes = setOf(OWNED_PREFIX),
        ownedDescriptors = setOf(OWNED_CLASS),
        salt = salt.encodeToByteArray(),
        minimumCoverage = 0.0,
        minimumSimHashDistance = 0,
        maximumGrowthRatio = 1.0,
        enforceMaximumGrowth = false,
        selectionRate = 1.0,
    )

    private fun conditionalCases() = listOf(
        ConditionalCase("ifEq", Opcode.IF_EQ, Opcode.IF_NE, intArrayOf(3, 3), intArrayOf(3, 4)),
        ConditionalCase("ifNe", Opcode.IF_NE, Opcode.IF_EQ, intArrayOf(3, 4), intArrayOf(3, 3)),
        ConditionalCase("ifLt", Opcode.IF_LT, Opcode.IF_GE, intArrayOf(3, 4), intArrayOf(4, 3)),
        ConditionalCase("ifGe", Opcode.IF_GE, Opcode.IF_LT, intArrayOf(4, 3), intArrayOf(3, 4)),
        ConditionalCase("ifGt", Opcode.IF_GT, Opcode.IF_LE, intArrayOf(4, 3), intArrayOf(3, 4)),
        ConditionalCase("ifLe", Opcode.IF_LE, Opcode.IF_GT, intArrayOf(3, 4), intArrayOf(4, 3)),
        ConditionalCase("ifEqz", Opcode.IF_EQZ, Opcode.IF_NEZ, intArrayOf(0), intArrayOf(1)),
        ConditionalCase("ifNez", Opcode.IF_NEZ, Opcode.IF_EQZ, intArrayOf(1), intArrayOf(0)),
        ConditionalCase("ifLtz", Opcode.IF_LTZ, Opcode.IF_GEZ, intArrayOf(-1), intArrayOf(1)),
        ConditionalCase("ifGez", Opcode.IF_GEZ, Opcode.IF_LTZ, intArrayOf(1), intArrayOf(-1)),
        ConditionalCase("ifGtz", Opcode.IF_GTZ, Opcode.IF_LEZ, intArrayOf(1), intArrayOf(-1)),
        ConditionalCase("ifLez", Opcode.IF_LEZ, Opcode.IF_GTZ, intArrayOf(-1), intArrayOf(1)),
    )

    private fun conditionalMethod(name: String, opcode: Opcode, debugLines: Boolean = false): ImmutableMethod {
        val twoRegisters = opcode in TWO_REGISTER_CONDITIONALS
        val instruction: Instruction = if (twoRegisters) {
            ImmutableInstruction22t(opcode, 0, 1, 4)
        } else {
            ImmutableInstruction21t(opcode, 0, 4)
        }
        return method(
            owner = OWNED_CLASS,
            name = name,
            parameterTypes = if (twoRegisters) listOf("I", "I") else listOf("I"),
            returnType = "I",
            registerCount = if (twoRegisters) 2 else 1,
            instructions = listOf(
                instruction,
                ImmutableInstruction11n(Opcode.CONST_4, 0, 0),
                ImmutableInstruction11x(Opcode.RETURN, 0),
                ImmutableInstruction11n(Opcode.CONST_4, 0, 1),
                ImmutableInstruction11x(Opcode.RETURN, 0),
            ),
            debugItems = if (debugLines) listOf(ImmutableLineNumber(0, 100), ImmutableLineNumber(4, 200)) else emptyList(),
        )
    }

    private fun voidConditionalMethod(name: String, accessFlags: Int, owner: String = OWNED_CLASS) = method(
        owner = owner,
        name = name,
        parameterTypes = emptyList(),
        returnType = "V",
        registerCount = 1,
        instructions = listOf(
            ImmutableInstruction21t(Opcode.IF_EQZ, 0, 3),
            ImmutableInstruction10x(Opcode.RETURN_VOID),
            ImmutableInstruction10x(Opcode.RETURN_VOID),
        ),
        accessFlags = accessFlags,
    )

    private fun longConditionalMethod(name: String, instructionCount: Int): ImmutableMethod = method(
        owner = OWNED_CLASS,
        name = name,
        parameterTypes = emptyList(),
        returnType = "V",
        registerCount = 2,
        instructions = buildList {
            add(ImmutableInstruction21t(Opcode.IF_EQZ, 0, instructionCount + 2))
            repeat(instructionCount) { add(ImmutableInstruction11n(Opcode.CONST_4, 1, it and 0x7)) }
            add(ImmutableInstruction10x(Opcode.RETURN_VOID))
        },
    )

    private fun method(
        owner: String,
        name: String,
        parameterTypes: List<String>,
        returnType: String,
        registerCount: Int,
        instructions: List<Instruction>,
        accessFlags: Int = PRIVATE_STATIC,
        tryBlocks: List<ImmutableTryBlock> = emptyList(),
        debugItems: List<ImmutableLineNumber> = emptyList(),
    ) = ImmutableMethod(
        owner,
        name,
        parameterTypes.map { ImmutableMethodParameter(it, emptySet(), null) },
        returnType,
        accessFlags,
        emptySet(),
        emptySet(),
        ImmutableMethodImplementation(registerCount, instructions, tryBlocks, debugItems),
    )

    private fun clazz(type: String, methods: List<ImmutableMethod>) = ImmutableClassDef(
        type,
        AccessFlags.PUBLIC.value,
        "Ljava/lang/Object;",
        emptyList(),
        null,
        emptySet(),
        emptyList(),
        methods,
    )

    private fun dex(vararg classes: ImmutableClassDef): ByteArray {
        val store = MemoryDataStore()
        DexPool.writeTo(store, ImmutableDexFile(Opcodes.getDefault(), classes.toList()))
        return store.data
    }

    private fun method(bytes: ByteArray, owner: String, name: String): Method =
        DexBackedDexFile.fromInputStream(null, bytes.inputStream())
            .classes.single { it.type == owner }
            .methods.single { it.name == name }

    private fun implementation(bytes: ByteArray, owner: String, name: String): MethodImplementation =
        method(bytes, owner, name).implementation!!

    private fun addressed(implementation: MethodImplementation): List<AddressedInstruction> {
        var address = 0
        return implementation.instructions.mapIndexed { index, instruction ->
            AddressedInstruction(index, address, instruction).also { address += instruction.codeUnits }
        }
    }

    private fun expansion(implementation: MethodImplementation, inverse: Opcode): Expansion {
        val instructions = addressed(implementation)
        val conditional = instructions.single { it.instruction.opcode == inverse }
        val inverseTarget = conditional.address + (conditional.instruction as OffsetInstruction).codeOffset
        val goto = instructions.subList(conditional.index + 1, instructions.indexOfFirst { it.address == inverseTarget })
            .single { it.instruction.opcode == Opcode.GOTO_32 }
        val gotoTarget = goto.address + (goto.instruction as OffsetInstruction).codeOffset
        return Expansion(conditional, goto, inverseTarget, gotoTarget)
    }

    private fun supportedConditionals(implementation: MethodImplementation) =
        addressed(implementation).filter { it.instruction.opcode in SUPPORTED_CONDITIONALS }

    private fun nonEntryGoto32(implementation: MethodImplementation) =
        reachableRelayInstructionIndexes(implementation).let { relayIndexes ->
            addressed(implementation).filter {
                it.index > 0 && it.instruction.opcode == Opcode.GOTO_32 && it.index !in relayIndexes
            }
        }

    private fun registers(instruction: Instruction): List<Int> = when (instruction) {
        is TwoRegisterInstruction -> listOf(instruction.registerA, instruction.registerB)
        is OneRegisterInstruction -> listOf(instruction.registerA)
        else -> error("not a conditional register instruction: ${instruction.opcode}")
    }

    private fun literalAt(implementation: MethodImplementation, address: Int): Int =
        (instructionAt(implementation, address) as NarrowLiteralInstruction).narrowLiteral

    private fun instructionAt(implementation: MethodImplementation, address: Int): Instruction =
        addressed(implementation).single { it.address == address }.instruction

    private fun execute(bytes: ByteArray, name: String, arguments: IntArray): Int {
        val implementation = implementation(bytes, OWNED_CLASS, name)
        val instructions = addressed(implementation)
        val byAddress = instructions.associateBy(AddressedInstruction::address)
        val registers = IntArray(implementation.registerCount)
        arguments.copyInto(registers, implementation.registerCount - arguments.size)
        var pc = 0
        while (true) {
            val current = requireNotNull(byAddress[pc])
            val instruction = current.instruction
            when (instruction.opcode) {
                Opcode.NOP -> pc += instruction.codeUnits
                Opcode.GOTO, Opcode.GOTO_16, Opcode.GOTO_32 -> pc += (instruction as OffsetInstruction).codeOffset
                Opcode.CONST_4 -> {
                    val codeUnits = instruction.codeUnits
                    registers[(instruction as OneRegisterInstruction).registerA] =
                        (instruction as NarrowLiteralInstruction).narrowLiteral
                    pc += codeUnits
                }
                Opcode.SUB_INT_2ADDR -> {
                    instruction as TwoRegisterInstruction
                    registers[instruction.registerA] -= registers[instruction.registerB]
                    pc += instruction.codeUnits
                }
                Opcode.RETURN -> return registers[(instruction as OneRegisterInstruction).registerA]
                in SUPPORTED_CONDITIONALS -> {
                    val takeBranch = evaluateConditional(instruction, registers)
                    pc += if (takeBranch) (instruction as OffsetInstruction).codeOffset else instruction.codeUnits
                }
                else -> error("unsupported interpreter opcode ${instruction.opcode}")
            }
        }
    }

    private fun evaluateConditional(instruction: Instruction, registers: IntArray): Boolean {
        val first = registers[(instruction as OneRegisterInstruction).registerA]
        val second = if (instruction is TwoRegisterInstruction) registers[instruction.registerB] else 0
        return when (instruction.opcode) {
            Opcode.IF_EQ, Opcode.IF_EQZ -> first == second
            Opcode.IF_NE, Opcode.IF_NEZ -> first != second
            Opcode.IF_LT, Opcode.IF_LTZ -> first < second
            Opcode.IF_GE, Opcode.IF_GEZ -> first >= second
            Opcode.IF_GT, Opcode.IF_GTZ -> first > second
            Opcode.IF_LE, Opcode.IF_LEZ -> first <= second
            else -> error("unsupported conditional ${instruction.opcode}")
        }
    }

    private fun expansionFingerprint(implementation: MethodImplementation): List<String> {
        val core = coreAddressed(implementation)
        val byAddress = core.withIndex().associate { it.value.address to it.index }
        return core.map { current ->
            val instruction = current.instruction
            buildString {
                append(instruction.opcode.name)
                if (instruction is OffsetInstruction) {
                    append(':').append(byAddress.getValue(current.address + instruction.codeOffset))
                }
            }
        }
    }

    private fun coreAddressed(implementation: MethodImplementation): List<AddressedInstruction> {
        val all = addressed(implementation)
        val entry = all.first().instruction as OffsetInstruction
        val entryTarget = all.first().address + entry.codeOffset
        val relayIndexes = reachableRelayInstructionIndexes(implementation)
        return all.dropWhile { it.address < entryTarget }
            .filterNot { it.instruction.opcode == Opcode.NOP || it.index in relayIndexes }
    }

    private fun reachableRelayInstructionIndexes(implementation: MethodImplementation): Set<Int> {
        val instructions = addressed(implementation)
        val indexByAddress = instructions.associate { it.address to it.index }
        return instructions.mapNotNull { source ->
            val sourceBranch = source.instruction as? OffsetInstruction ?: return@mapNotNull null
            if (source.instruction.opcode != Opcode.GOTO_32) return@mapNotNull null
            val relayIndex = indexByAddress[source.address + sourceBranch.codeOffset] ?: return@mapNotNull null
            if (relayIndex <= source.index) return@mapNotNull null
            val relay = instructions[relayIndex]
            val relayBranch = relay.instruction as? OffsetInstruction ?: return@mapNotNull null
            if (relay.instruction.opcode != Opcode.GOTO_32) return@mapNotNull null
            val continuation = instructions.subList(source.index + 1, relayIndex)
                .firstOrNull { it.instruction.opcode != Opcode.NOP }
                ?: return@mapNotNull null
            if (relay.address + relayBranch.codeOffset != continuation.address) return@mapNotNull null
            source.index to relayIndex
        }.flatMapTo(hashSetOf()) { (source, relay) -> listOf(source, relay) }
    }

    private fun cfgFingerprint(
        implementation: MethodImplementation,
        stripEntryDetour: Boolean,
    ): List<String> {
        val instructions = if (stripEntryDetour) {
            coreAddressed(implementation)
        } else {
            addressed(implementation).filterNot { it.instruction.opcode == Opcode.NOP }
        }
        val byAddress = instructions.withIndex().associate { it.value.address to it.index }
        return instructions.map { current ->
            val instruction = current.instruction
            val target = (instruction as? OffsetInstruction)?.let {
                byAddress.getValue(current.address + it.codeOffset)
            }
            "${CommonOpcodeShingles.tokens(listOf(instruction)).single()}:${target ?: "-"}"
        }
    }

    private data class ConditionalCase(
        val name: String,
        val opcode: Opcode,
        val inverse: Opcode,
        val trueArguments: IntArray,
        val falseArguments: IntArray,
    )

    private data class AddressedInstruction(val index: Int, val address: Int, val instruction: Instruction)

    private data class Expansion(
        val conditional: AddressedInstruction,
        val goto: AddressedInstruction,
        val inverseTargetAddress: Int,
        val gotoTargetAddress: Int,
    )

    private companion object {
        const val OWNED_PREFIX = "Lcom/example/demo/match/"
        const val OWNED_CLASS = "Lcom/example/demo/match/ConditionalFixture;"
        const val PRIVATE_STATIC = 0x000a
        val TWO_REGISTER_CONDITIONALS = setOf(
            Opcode.IF_EQ,
            Opcode.IF_NE,
            Opcode.IF_LT,
            Opcode.IF_GE,
            Opcode.IF_GT,
            Opcode.IF_LE,
        )
        val SUPPORTED_CONDITIONALS = TWO_REGISTER_CONDITIONALS + setOf(
            Opcode.IF_EQZ,
            Opcode.IF_NEZ,
            Opcode.IF_LTZ,
            Opcode.IF_GEZ,
            Opcode.IF_GTZ,
            Opcode.IF_LEZ,
        )
    }
}
