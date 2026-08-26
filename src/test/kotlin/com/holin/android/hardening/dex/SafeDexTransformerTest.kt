package com.holin.android.hardening.dex

import com.android.tools.smali.dexlib2.AccessFlags
import com.android.tools.smali.dexlib2.Opcode
import com.android.tools.smali.dexlib2.Opcodes
import com.android.tools.smali.dexlib2.dexbacked.DexBackedDexFile
import com.android.tools.smali.dexlib2.iface.Method
import com.android.tools.smali.dexlib2.iface.instruction.OffsetInstruction
import com.android.tools.smali.dexlib2.iface.instruction.OneRegisterInstruction
import com.android.tools.smali.dexlib2.iface.instruction.ThreeRegisterInstruction
import com.android.tools.smali.dexlib2.immutable.ImmutableClassDef
import com.android.tools.smali.dexlib2.immutable.ImmutableDexFile
import com.android.tools.smali.dexlib2.immutable.ImmutableExceptionHandler
import com.android.tools.smali.dexlib2.immutable.ImmutableMethod
import com.android.tools.smali.dexlib2.immutable.ImmutableMethodImplementation
import com.android.tools.smali.dexlib2.immutable.ImmutableMethodParameter
import com.android.tools.smali.dexlib2.immutable.ImmutableTryBlock
import com.android.tools.smali.dexlib2.immutable.debug.ImmutableLineNumber
import com.android.tools.smali.dexlib2.immutable.instruction.ImmutableInstruction10x
import com.android.tools.smali.dexlib2.immutable.instruction.ImmutableInstruction11x
import com.android.tools.smali.dexlib2.immutable.instruction.ImmutableInstruction23x
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
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

class SafeDexTransformerTest {
    @Test
    fun `mandatory writer floor is deducted before computing the detour code unit budget`() {
        assertEquals(
            6_000,
            detourCodeUnitBudget(
                inputSize = 1_000_000,
                floorOutputSize = 1_035_000,
                maximumGrowthRatio = 0.05,
                utilization = 0.80,
            ),
        )
        assertEquals(
            0,
            detourCodeUnitBudget(
                inputSize = 1_000_000,
                floorOutputSize = 1_050_001,
                maximumGrowthRatio = 0.05,
                utilization = 0.80,
            ),
        )
    }

    @Test
    fun `serialized output feedback scales only growth above the mandatory writer floor`() {
        assertEquals(
            0.098,
            nextDetourBudgetScale(
                currentScale = 1.0,
                floorOutputSize = 1_090,
                attemptedOutputSize = 1_190,
                maximumOutputSize = 1_100,
            ),
            absoluteTolerance = 1e-12,
        )
        assertEquals(
            0.0,
            nextDetourBudgetScale(
                currentScale = 0.25,
                floorOutputSize = 3_675_948,
                attemptedOutputSize = 3_700_000,
                maximumOutputSize = 3_640_971,
            ),
        )
    }

    @Test
    fun `owned straight line method gets a semantics preserving control flow prefix`() {
        val input = dex(
            clazz(
                OWNED_CLASS,
                methods = listOf(sumMethod(OWNED_CLASS)),
            ),
            clazz(
                "Lthird/party/Calculator;",
                methods = listOf(sumMethod("Lthird/party/Calculator;")),
            ),
        )

        val result = transform(input, salt = "semantic-salt")

        assertEquals(1, result.report.methods.size)
        val method = result.report.methods.single()
        assertEquals(MethodEligibilityReason.TRANSFORMED, method.reason)
        assertNotEquals(method.oldBodySha256, method.newBodySha256)
        assertTrue(method.newInstructionCount > method.oldInstructionCount)
        assertEquals(1.0, result.report.ownedInstructionCoverage)
        assertEquals(7, executeIntMethod(result.dexBytes, OWNED_CLASS, "sum", intArrayOf(3, 4)))
        assertEquals(
            listOf(Opcode.ADD_INT, Opcode.RETURN),
            method(result.dexBytes, "Lthird/party/Calculator;", "sum")
                .implementation!!.instructions.map { it.opcode },
        )
    }

    @Test
    fun `unsafe method categories are inventoried with explicit fail closed reasons`() {
        val privateStatic = AccessFlags.PRIVATE.value or AccessFlags.STATIC.value
        val methods = listOf(
            voidMethod("<init>", AccessFlags.CONSTRUCTOR.value or AccessFlags.PRIVATE.value),
            voidMethod("<clinit>", AccessFlags.CONSTRUCTOR.value or AccessFlags.STATIC.value),
            method("abstractMethod", AccessFlags.PUBLIC.value or AccessFlags.ABSTRACT.value, null),
            method("nativeMethod", AccessFlags.PUBLIC.value or AccessFlags.NATIVE.value, null),
            voidMethod("bridgeMethod", privateStatic or AccessFlags.BRIDGE.value),
            voidMethod("syntheticMethod", privateStatic or AccessFlags.SYNTHETIC.value),
            voidMethod("synchronizedMethod", privateStatic or AccessFlags.SYNCHRONIZED.value),
            method(
                "monitorMethod",
                privateStatic,
                implementation(
                    registerCount = 1,
                    ImmutableInstruction11x(Opcode.MONITOR_ENTER, 0),
                    ImmutableInstruction11x(Opcode.MONITOR_EXIT, 0),
                    ImmutableInstruction10x(Opcode.RETURN_VOID),
                ),
            ),
            method(
                "debugMethod",
                privateStatic,
                ImmutableMethodImplementation(
                    0,
                    listOf(ImmutableInstruction10x(Opcode.RETURN_VOID)),
                    emptyList(),
                    listOf(ImmutableLineNumber(0, 42)),
                ),
            ),
            method(
                "tryMethod",
                privateStatic,
                ImmutableMethodImplementation(
                    0,
                    listOf(ImmutableInstruction10x(Opcode.RETURN_VOID)),
                    listOf(ImmutableTryBlock(0, 1, listOf(ImmutableExceptionHandler(null, 0)))),
                    emptyList(),
                ),
            ),
            method(
                "switchMethod",
                privateStatic,
                implementation(
                    registerCount = 1,
                    ImmutableInstruction31t(Opcode.PACKED_SWITCH, 0, 4),
                    ImmutableInstruction10x(Opcode.RETURN_VOID),
                    ImmutablePackedSwitchPayload(listOf(ImmutableSwitchElement(0, 3))),
                ),
            ),
            voidMethod("publicContract", AccessFlags.PUBLIC.value or AccessFlags.STATIC.value),
            voidMethod("safeMethod", privateStatic),
        )
        val input = dex(
            clazz(OWNED_CLASS, methods = methods),
            clazz(
                type = "Lcom/example/demo/match/GeneratedContinuation;",
                superclass = "Lkotlin/coroutines/jvm/internal/ContinuationImpl;",
                methods = listOf(voidMethod("invokeSuspend", privateStatic)),
            ),
        )

        val result = SafeDexTransformer().transform(
            input,
            request("classification-salt").copy(
                ownedDescriptors = setOf(
                    OWNED_CLASS,
                    "Lcom/example/demo/match/GeneratedContinuation;",
                ),
            ),
        )
        val reportsByName = result.report.methods
            .associateBy { it.methodId.substringAfter("->").substringBefore('(') }
        val reports = reportsByName.mapValues { it.value.reason }

        assertEquals(MethodEligibilityReason.CONSTRUCTOR, reports["<init>"])
        assertEquals(MethodEligibilityReason.CLASS_INITIALIZER, reports["<clinit>"])
        assertEquals(MethodEligibilityReason.ABSTRACT, reports["abstractMethod"])
        assertEquals(MethodEligibilityReason.NATIVE, reports["nativeMethod"])
        assertEquals(MethodEligibilityReason.BRIDGE, reports["bridgeMethod"])
        assertEquals(MethodEligibilityReason.SYNTHETIC, reports["syntheticMethod"])
        assertEquals(MethodEligibilityReason.SYNCHRONIZED, reports["synchronizedMethod"])
        assertEquals(MethodEligibilityReason.MONITOR_INSTRUCTION, reports["monitorMethod"])
        assertEquals(MethodEligibilityReason.TRANSFORMED, reports["debugMethod"])
        assertEquals(MethodEligibilityReason.TRANSFORMED, reports["tryMethod"])
        assertEquals(MethodEligibilityReason.SWITCH_OR_PAYLOAD, reports["switchMethod"])
        assertEquals(MethodEligibilityReason.TRANSFORMED, reports["publicContract"])
        assertEquals(MethodEligibilityReason.COROUTINE_STATE_MACHINE, reports["invokeSuspend"])
        assertEquals(MethodEligibilityReason.TRANSFORMED, reports["safeMethod"])
        assertTrue(
            reportsByName.filterKeys { it !in setOf("debugMethod", "publicContract", "safeMethod") }
                .values.all { it.insertedRelayInstructionCount == 0 },
        )
        assertEquals(0, reportsByName.getValue("tryMethod").insertedRelayInstructionCount)
        assertEquals(
            listOf(42),
            method(result.dexBytes, OWNED_CLASS, "debugMethod").implementation!!.debugItems
                .filterIsInstance<com.android.tools.smali.dexlib2.iface.debug.LineNumber>()
                .map { it.lineNumber },
        )
        val retainedTry = method(result.dexBytes, OWNED_CLASS, "tryMethod").implementation!!.tryBlocks.single()
        assertTrue(retainedTry.startCodeAddress > 0)
        assertEquals(1, retainedTry.codeUnitCount)
        assertEquals(null, retainedTry.exceptionHandlers.single().exceptionType)
        assertEquals(retainedTry.startCodeAddress, retainedTry.exceptionHandlers.single().handlerCodeAddress)
    }

    @Test
    fun `same salt selects and emits identically while another salt changes output`() {
        val methods = (0 until 16).map { voidMethod("method$it", PRIVATE_STATIC) }
        val input = dex(clazz(OWNED_CLASS, methods = methods))
        val request = request("stable-salt", selectionRate = 0.5)

        val first = SafeDexTransformer().transform(input, request)
        val second = SafeDexTransformer().transform(input, request)
        val different = SafeDexTransformer().transform(input, request("different-salt", selectionRate = 0.5))

        assertContentEquals(first.dexBytes, second.dexBytes)
        assertEquals(first.report, second.report)
        assertEquals(selected(first), selected(second))
        assertNotEquals(selected(first), selected(different))
        assertTrue(!first.dexBytes.contentEquals(different.dexBytes))
    }

    @Test
    fun `emitted dex is reloadable and has rebuilt signature and checksum`() {
        val input = dex(clazz(OWNED_CLASS, methods = listOf(voidMethod("safe", PRIVATE_STATIC))))

        val output = transform(input, salt = "header-salt").dexBytes

        val reloaded = DexBackedDexFile.fromInputStream(null, output.inputStream())
        assertEquals(setOf(OWNED_CLASS), reloaded.classes.map { it.type }.toSet())
        assertContentEquals(MessageDigest.getInstance("SHA-1").digest(output.copyOfRange(32, output.size)), output.copyOfRange(12, 32))
        val adler = Adler32().apply { update(output, 12, output.size - 12) }.value.toInt()
        assertEquals(adler, ByteBuffer.wrap(output, 8, 4).order(ByteOrder.LITTLE_ENDIAN).int)
    }

    @Test
    fun `growth policy failure publishes no result`() {
        val input = dex(
            clazz(
                OWNED_CLASS,
                methods = (0 until 24).map { index -> growthMethod("growth$index") },
            ),
        )

        val growth = assertFailsWith<DexTransformationRejectedException> {
            SafeDexTransformer().transform(input, request("growth", maximumGrowthRatio = 0.0))
        }
        assertTrue(growth.message!!.contains("growth"))
    }

    @Test
    fun `disabled growth policy reports growth without rejecting the dex`() {
        val input = dex(
            clazz(
                OWNED_CLASS,
                methods = (0 until 24).map { index -> growthMethod("growth$index") },
            ),
        )

        val result = SafeDexTransformer().transform(
            input,
            request("unbounded-growth", maximumGrowthRatio = 0.0).copy(enforceMaximumGrowth = false),
        )

        assertTrue(result.report.byteGrowthRatio > 0.0)
        assertTrue(result.report.transformedMethodCount > 0)
    }

    @Test
    fun `invalid no eligible input is canonicalized by the minimum rewrite`() {
        val classInitializer = method(
            "<clinit>",
            AccessFlags.CONSTRUCTOR.value or AccessFlags.STATIC.value,
            implementation(0, ImmutableInstruction10x(Opcode.RETURN_VOID)),
        )
        val dependencyClass = "Lthird/party/DuplicateMethods;"
        val valid = dex(
            clazz(OWNED_CLASS, methods = listOf(classInitializer)),
            clazz(
                dependencyClass,
                methods = listOf(
                    method("alpha", PRIVATE_STATIC, implementation(0, ImmutableInstruction10x(Opcode.RETURN_VOID)), dependencyClass),
                    method("beta", PRIVATE_STATIC, implementation(0, ImmutableInstruction10x(Opcode.RETURN_VOID)), dependencyClass),
                ),
            ),
        )
        val invalid = duplicateLastMethodId(valid)
        DexBackedDexFile.fromInputStream(null, invalid.inputStream()).classes.size
        assertFailsWith<IllegalArgumentException> {
            DexIdTableValidator.requireValid(invalid, "invalid-input.dex")
        }

        val result = SafeDexTransformer().transform(
            invalid,
            request("canonicalize").copy(allowNoEligibleMethodsSkip = true),
        )

        assertFalse(invalid.contentEquals(result.dexBytes))
        assertTrue(result.report.inputCanonicalized)
        assertFalse(result.report.noEligibleMethodsSkipped)
        assertFalse(result.report.writerFloorSkipped)
        assertEquals(0, result.report.eligibleMethodCount)
        assertEquals(0, result.report.transformedMethodCount)
        assertEquals(0, result.report.transformedInstructionCount)
        DexIdTableValidator.requireValid(result.dexBytes, "canonicalized-output.dex")
    }

    @Test
    fun `writer floor skip returns the original dex with complete eligibility accounting`() {
        val constructor = voidMethod(
            "<init>",
            AccessFlags.CONSTRUCTOR.value or AccessFlags.PRIVATE.value,
        )
        val input = dex(
            clazz(
                OWNED_CLASS,
                methods = listOf(
                    voidMethod("safe", PRIVATE_STATIC),
                    constructor,
                ),
            ),
        )

        val result = SafeDexTransformer().transform(
            input,
            request("writer-floor", maximumGrowthRatio = 0.0).copy(allowWriterFloorSkip = true),
        )
        val reasons = result.report.methods.associate { method -> method.methodId to method.reason }

        assertContentEquals(input, result.dexBytes)
        assertTrue(result.report.writerFloorSkipped)
        assertEquals(result.report.inputSha256, result.report.outputSha256)
        assertEquals(2, result.report.ownedMethodCount)
        assertEquals(1, result.report.eligibleMethodCount)
        assertEquals(0, result.report.transformedMethodCount)
        assertEquals(0, result.report.transformedInstructionCount)
        assertEquals(0.0, result.report.transformedMethodCoverage)
        assertEquals(0.0, result.report.transformedInstructionCoverage)
        assertEquals(0.0, result.report.byteGrowthRatio)
        assertEquals(MethodEligibilityReason.WRITER_FLOOR_GROWTH, reasons["$OWNED_CLASS->safe()V"])
        assertEquals(MethodEligibilityReason.CONSTRUCTOR, reasons["$OWNED_CLASS-><init>()V"])
    }

    @Test
    fun `exact post R8 descriptor is authoritative and prefix cannot expand ownership`() {
        val obfuscatedOwned = "La/b;"
        val samePrefixSibling = "La/c;"
        val input = dex(
            clazz(obfuscatedOwned, methods = listOf(voidMethod("safe", PRIVATE_STATIC))),
            clazz(samePrefixSibling, methods = listOf(voidMethod("untouched", PRIVATE_STATIC))),
        )

        val result = SafeDexTransformer().transform(
            input,
            request("post-r8").copy(
                ownedDescriptorPrefixes = setOf("La/"),
                ownedDescriptors = setOf(obfuscatedOwned),
            ),
        )

        assertEquals(listOf("$obfuscatedOwned->safe()V"), result.report.methods.map { it.methodId })
        assertEquals(
            listOf(Opcode.RETURN_VOID),
            method(result.dexBytes, samePrefixSibling, "untouched").implementation!!.instructions.map { it.opcode },
        )
    }

    @Test
    fun `an owned descriptor is not denied by a project name substring`() {
        val descriptor = "Lcom/example/demo/match/PortableFeature;"
        val input = dex(
            clazz(
                descriptor,
                "Ljava/lang/Object;",
                listOf(method("safe", PRIVATE_STATIC, implementation(0, ImmutableInstruction10x(Opcode.RETURN_VOID)), descriptor)),
            ),
        )
        val result = SafeDexTransformer().transform(
            input,
            DexTransformRequest(
                emptySet(),
                setOf(descriptor),
                "portable-salt".toByteArray(),
                0.0,
                0,
                1.0,
                true,
                1.0,
                emptySet(),
                emptySet(),
                emptySet(),
                false,
                false,
            ),
        )

        assertEquals(MethodEligibilityReason.TRANSFORMED, result.report.methods.single().reason)
    }

    private fun transform(input: ByteArray, salt: String): DexTransformationResult =
        SafeDexTransformer().transform(input, request(salt))

    private fun request(
        salt: String,
        minimumCoverage: Double = 0.0,
        maximumGrowthRatio: Double = 1.0,
        selectionRate: Double = 1.0,
    ) = DexTransformRequest(
        ownedDescriptorPrefixes = setOf(OWNED_PREFIX),
        ownedDescriptors = setOf(OWNED_CLASS),
        salt = salt.toByteArray(),
        minimumCoverage = minimumCoverage,
        maximumGrowthRatio = maximumGrowthRatio,
        selectionRate = selectionRate,
    )

    private fun selected(result: DexTransformationResult): Set<String> = result.report.methods
        .filter { it.reason == MethodEligibilityReason.TRANSFORMED }
        .mapTo(linkedSetOf()) { it.methodId }

    private fun executeIntMethod(
        dexBytes: ByteArray,
        definingClass: String,
        name: String,
        arguments: IntArray,
    ): Int {
        val implementation = method(dexBytes, definingClass, name).implementation!!
        val instructions = implementation.instructions.toList()
        val addressToIndex = mutableMapOf<Int, Int>()
        var address = 0
        instructions.forEachIndexed { index, instruction ->
            addressToIndex[address] = index
            address += instruction.codeUnits
        }
        val registers = IntArray(implementation.registerCount)
        arguments.copyInto(registers, implementation.registerCount - arguments.size)
        var pc = 0
        while (true) {
            val instruction = instructions[requireNotNull(addressToIndex[pc])]
            when (instruction.opcode) {
                Opcode.NOP -> pc += instruction.codeUnits
                Opcode.GOTO, Opcode.GOTO_16, Opcode.GOTO_32 -> pc += (instruction as OffsetInstruction).codeOffset
                Opcode.ADD_INT -> {
                    instruction as ThreeRegisterInstruction
                    registers[instruction.registerA] = registers[instruction.registerB] + registers[instruction.registerC]
                    pc += instruction.codeUnits
                }
                Opcode.RETURN -> return registers[(instruction as OneRegisterInstruction).registerA]
                else -> error("Unsupported interpreter opcode ${instruction.opcode}")
            }
        }
    }

    private fun method(bytes: ByteArray, definingClass: String, name: String): Method =
        DexBackedDexFile.fromInputStream(null, bytes.inputStream())
            .classes.single { it.type == definingClass }
            .methods.single { it.name == name }

    private fun sumMethod(definingClass: String): ImmutableMethod = ImmutableMethod(
        definingClass,
        "sum",
        listOf(parameter("I"), parameter("I")),
        "I",
        PRIVATE_STATIC,
        emptySet(),
        emptySet(),
        implementation(
            registerCount = 2,
            ImmutableInstruction23x(Opcode.ADD_INT, 0, 0, 1),
            ImmutableInstruction11x(Opcode.RETURN, 0),
        ),
    )

    private fun voidMethod(name: String, accessFlags: Int): ImmutableMethod =
        method(name, accessFlags, implementation(0, ImmutableInstruction10x(Opcode.RETURN_VOID)))

    private fun growthMethod(name: String): ImmutableMethod = method(
        name,
        PRIVATE_STATIC,
        implementation(
            2,
            *Array(12) { ImmutableInstruction23x(Opcode.ADD_INT, 0, 0, 1) },
            ImmutableInstruction10x(Opcode.RETURN_VOID),
        ),
    )

    private fun method(
        name: String,
        accessFlags: Int,
        implementation: ImmutableMethodImplementation?,
        definingClass: String = OWNED_CLASS,
    ): ImmutableMethod = ImmutableMethod(
        definingClass,
        name,
        emptyList(),
        "V",
        accessFlags,
        emptySet(),
        emptySet(),
        implementation,
    )

    private fun implementation(
        registerCount: Int,
        vararg instructions: com.android.tools.smali.dexlib2.iface.instruction.Instruction,
    ) = ImmutableMethodImplementation(registerCount, instructions.asList(), emptyList(), emptyList())

    private fun parameter(type: String) = ImmutableMethodParameter(type, emptySet(), null)

    private fun clazz(
        type: String,
        superclass: String = "Ljava/lang/Object;",
        methods: List<ImmutableMethod>,
    ) = ImmutableClassDef(
        type,
        AccessFlags.PUBLIC.value,
        superclass,
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

    private fun duplicateLastMethodId(input: ByteArray): ByteArray {
        val bytes = input.copyOf()
        val buffer = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN)
        val methodIdsSize = buffer.getInt(0x58)
        val methodIdsOffset = buffer.getInt(0x5c)
        require(methodIdsSize >= 2)
        val sourceOffset = methodIdsOffset + (methodIdsSize - 2) * METHOD_ID_ITEM_SIZE
        val destinationOffset = sourceOffset + METHOD_ID_ITEM_SIZE
        bytes.copyInto(
            destination = bytes,
            destinationOffset = destinationOffset,
            startIndex = sourceOffset,
            endIndex = sourceOffset + METHOD_ID_ITEM_SIZE,
        )
        MessageDigest.getInstance("SHA-1")
            .digest(bytes.copyOfRange(32, bytes.size))
            .copyInto(bytes, 12)
        buffer.putInt(
            8,
            Adler32().apply { update(bytes, 12, bytes.size - 12) }.value.toInt(),
        )
        return bytes
    }

    private companion object {
        const val OWNED_PREFIX = "Lcom/example/demo/match/"
        const val OWNED_CLASS = "Lcom/example/demo/match/Calculator;"
        const val PRIVATE_STATIC = 0x000a
        const val METHOD_ID_ITEM_SIZE = 8
    }
}
