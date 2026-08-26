package com.holin.android.hardening.dex

import com.android.tools.smali.dexlib2.AccessFlags
import com.android.tools.smali.dexlib2.Opcode
import com.android.tools.smali.dexlib2.Opcodes
import com.android.tools.smali.dexlib2.dexbacked.DexBackedDexFile
import com.android.tools.smali.dexlib2.iface.Method
import com.android.tools.smali.dexlib2.iface.MethodImplementation
import com.android.tools.smali.dexlib2.iface.instruction.OffsetInstruction
import com.android.tools.smali.dexlib2.immutable.ImmutableClassDef
import com.android.tools.smali.dexlib2.immutable.ImmutableDexFile
import com.android.tools.smali.dexlib2.immutable.ImmutableExceptionHandler
import com.android.tools.smali.dexlib2.immutable.ImmutableMethod
import com.android.tools.smali.dexlib2.immutable.ImmutableMethodImplementation
import com.android.tools.smali.dexlib2.immutable.ImmutableTryBlock
import com.android.tools.smali.dexlib2.immutable.debug.ImmutableLineNumber
import com.android.tools.smali.dexlib2.immutable.instruction.ImmutableInstruction10x
import com.android.tools.smali.dexlib2.immutable.instruction.ImmutableInstruction10t
import com.android.tools.smali.dexlib2.immutable.instruction.ImmutableInstruction11n
import com.android.tools.smali.dexlib2.immutable.instruction.ImmutableInstruction11x
import com.android.tools.smali.dexlib2.immutable.instruction.ImmutableInstruction12x
import com.android.tools.smali.dexlib2.immutable.instruction.ImmutableInstruction23x
import com.android.tools.smali.dexlib2.immutable.instruction.ImmutableInstruction35c
import com.android.tools.smali.dexlib2.immutable.reference.ImmutableMethodReference
import com.android.tools.smali.dexlib2.immutable.reference.ImmutableTypeReference
import com.android.tools.smali.dexlib2.writer.io.MemoryDataStore
import com.android.tools.smali.dexlib2.writer.pool.DexPool
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

class SafeDexTransformerWeavingTest {
    @Test
    fun `public body is woven unless its exact method id is an external contract`() {
        val input = dex(
            clazz(
                OWNED_CLASS,
                listOf(
                    longVoidMethod(OWNED_CLASS, "publicBody", PUBLIC_STATIC),
                    longVoidMethod(OWNED_CLASS, "externalBody", PUBLIC_STATIC),
                ),
            ),
        )

        val result = transform(
            input,
            request().copy(externalContractMethodIds = setOf("$OWNED_CLASS->externalBody()V")),
        )
        val methods = result.report.methods.associateBy(MethodTransformationReport::methodId)

        assertEquals(MethodEligibilityReason.TRANSFORMED, methods.getValue("$OWNED_CLASS->publicBody()V").reason)
        assertEquals(MethodEligibilityReason.EXTERNAL_CONTRACT, methods.getValue("$OWNED_CLASS->externalBody()V").reason)
    }

    @Test
    fun `exact owned descriptor inventory excludes a same-prefix sibling class`() {
        val sibling = "Lcom/example/demo/match/UninventoriedSibling;"
        val input = dex(
            clazz(OWNED_CLASS, listOf(longVoidMethod(OWNED_CLASS, "owned", PUBLIC_STATIC))),
            clazz(sibling, listOf(longVoidMethod(sibling, "untouched", PUBLIC_STATIC))),
        )

        val result = transform(input, request(salt = "exact-owned"))

        assertEquals(1, result.report.ownedMethodCount)
        assertEquals(listOf("$OWNED_CLASS->owned()V"), result.report.methods.map(MethodTransformationReport::methodId))
        assertEquals(
            longInstructions().map { it.opcode },
            implementation(result.dexBytes, sibling, "untouched").instructions.map { it.opcode },
        )
    }

    @Test
    fun `entry detour skips unreachable padding and preserves the original instruction closure`() {
        val original = longInstructions()
        val input = dex(
            clazz(
                OWNED_CLASS,
                listOf(method(OWNED_CLASS, "detourBody", PUBLIC_STATIC, implementation(1, original))),
            ),
        )

        val result = transform(input, request(salt = "entry-detour", maximumGrowthRatio = 1.0))
        val emitted = implementation(result.dexBytes, OWNED_CLASS, "detourBody")
        val instructions = emitted.instructions.toList()
        val entry = instructions.first()
        val targetAddress = (entry as OffsetInstruction).codeOffset
        var address = entry.codeUnits
        for (instruction in instructions.drop(1)) {
            if (address >= targetAddress) break
            assertTrue(
                instruction.opcode in SafeUnreachablePayloadContract.REGISTER_BEARING_OPCODE_SET,
                "address=$address target=$targetAddress opcodes=${instructions.map { it.opcode }}",
            )
            address += instruction.codeUnits
        }
        val report = result.report.methods.single()

        assertEquals(Opcode.GOTO_32, entry.opcode)
        assertTrue(targetAddress > entry.codeUnits, "the entry branch must skip at least one padding NOP")
        assertEquals(targetAddress, address)
        assertEquals(original.first().opcode, opcodeAt(emitted, targetAddress))
        assertEquals(
            original.filterNot { it.opcode == Opcode.NOP }.map { it.opcode },
            semanticBodyOpcodes(emitted),
        )
        assertEquals(
            report.newInstructionCount - report.oldInstructionCount + 12 + report.insertedRelayInstructionCount * 2,
            report.codeUnitGrowth,
        )
        assertTrue(report.newInstructionCount >= report.oldInstructionCount * 3 / 2)
    }

    @Test
    fun `production weaving emits no reachable source tail relay pairs`() {
        val input = dex(
            clazz(
                OWNED_CLASS,
                listOf(sizedVoidMethod("reachableRelays", 24)),
            ),
        )

        val result = transform(input, request(salt = "reachable-relay-red"))
        val emitted = implementation(
            result.dexBytes,
            OWNED_CLASS,
            "reachableRelays",
        )

        val pairs = reachableRelayPairs(emitted)
        val report = result.report.methods.single()
        assertTrue(pairs.isEmpty())
        assertEquals(0, report.insertedRelayInstructionCount)
    }

    @Test
    fun `different salts change the entry detour padding length`() {
        val input = dex(
            clazz(
                OWNED_CLASS,
                listOf(sizedVoidMethod("saltedDetour", 48)),
            ),
        )

        val results = ('a'..'h').map { suffix ->
            transform(input, request("detour-salt-$suffix"))
        }
        val offsets = results.map { result ->
            implementation(result.dexBytes, OWNED_CLASS, "saltedDetour")
                .instructions.first().let { it as OffsetInstruction }.codeOffset
        }

        assertTrue(offsets.toSet().size > 1, "offsets=$offsets")
        assertTrue(results.map { it.dexBytes.toList() }.toSet().size > 1)
    }

    @Test
    fun `unreachable entry payload uses only the safe register bearing alphabet`() {
        val input = dex(
            clazz(
                OWNED_CLASS,
                listOf(sizedVoidMethod("saltedPayload", 48)),
            ),
        )

        val result = transform(input, request(salt = "payload-opcodes", maximumGrowthRatio = 1.0))
        val emitted = implementation(result.dexBytes, OWNED_CLASS, "saltedPayload")
        val instructions = emitted.instructions.toList()
        val targetAddress = (instructions.first() as OffsetInstruction).codeOffset
        var address = instructions.first().codeUnits
        val payload = instructions.drop(1).takeWhile { instruction ->
            if (address >= targetAddress) false else true.also { address += instruction.codeUnits }
        }
        val report = result.report.methods.single()

        assertEquals(Opcode.CONST_4, payload.first().opcode)
        assertTrue(payload.none { it.opcode == Opcode.NOP })
        assertTrue(payload.all { it.opcode in SafeUnreachablePayloadContract.REGISTER_BEARING_OPCODE_SET })
        assertEquals(payload.size, report.insertedPayloadInstructionCount)
        assertTrue(report.insertedNopCount < report.insertedPayloadInstructionCount + report.oldInstructionCount)
    }

    @Test
    fun `empty diversification and access compatibility inventories fail closed`() {
        val input = dex(clazz(OWNED_CLASS, listOf(longVoidMethod(OWNED_CLASS, "owned", PUBLIC_STATIC))))

        val failure = assertFailsWith<IllegalArgumentException> {
            transform(input, request().copy(ownedDescriptors = emptySet()))
        }

        assertTrue(failure.message!!.contains("owned or access compatibility descriptor"))
    }

    @Test
    fun `debug items remain attached to original instructions at rebased addresses`() {
        val originalInstructions = longInstructions()
        val debugMethod = method(
            definingClass = OWNED_CLASS,
            name = "debugBody",
            accessFlags = PUBLIC_STATIC,
            implementation = ImmutableMethodImplementation(
                1,
                originalInstructions,
                emptyList(),
                listOf(ImmutableLineNumber(0, 100), ImmutableLineNumber(6, 200)),
            ),
        )

        val result = transform(dex(clazz(OWNED_CLASS, listOf(debugMethod))), request(salt = "debug-weave"))

        val implementation = implementation(result.dexBytes, OWNED_CLASS, "debugBody")
        val lines = implementation.debugItems
            .filterIsInstance<com.android.tools.smali.dexlib2.iface.debug.LineNumber>()
            .associate { it.lineNumber to it.codeAddress }
        assertEquals(setOf(100, 200), lines.keys)
        assertTrue(lines.getValue(100) > 0)
        assertEquals(Opcode.CONST_4, opcodeAt(implementation, lines.getValue(100)))
        assertEquals(Opcode.CONST_4, opcodeAt(implementation, lines.getValue(200)))
        assertTrue(lines.getValue(200) > 6)
    }

    @Test
    fun `try labels and move exception handler are rebased without preceding nop`() {
        val instructions = buildList {
            repeat(6) { add(ImmutableInstruction11n(Opcode.CONST_4, 0, it and 0x7)) }
            add(ImmutableInstruction10x(Opcode.RETURN_VOID))
            repeat(3) { add(ImmutableInstruction11n(Opcode.CONST_4, 0, it)) }
            add(ImmutableInstruction11x(Opcode.MOVE_EXCEPTION, 0))
            add(ImmutableInstruction10x(Opcode.RETURN_VOID))
        }
        val tryMethod = method(
            definingClass = OWNED_CLASS,
            name = "tryBody",
            accessFlags = PUBLIC_STATIC,
            implementation = ImmutableMethodImplementation(
                1,
                instructions,
                listOf(ImmutableTryBlock(0, 6, listOf(ImmutableExceptionHandler(null, 10)))),
                emptyList(),
            ),
        )

        val result = transform(dex(clazz(OWNED_CLASS, listOf(tryMethod))), request(salt = "try-weave"))

        val implementation = implementation(result.dexBytes, OWNED_CLASS, "tryBody")
        val retainedTry = implementation.tryBlocks.single()
        val handlerAddress = retainedTry.exceptionHandlers.single().handlerCodeAddress
        assertTrue(retainedTry.startCodeAddress > 0)
        assertTrue(retainedTry.codeUnitCount > 6)
        assertEquals(Opcode.MOVE_EXCEPTION, opcodeAt(implementation, handlerAddress))
        assertNotEquals(Opcode.NOP, opcodeBefore(implementation, handlerAddress))
    }

    @Test
    fun `ordinary branch labels remain attached to their original target instruction`() {
        val instructions = buildList {
            add(ImmutableInstruction11n(Opcode.CONST_4, 0, 0))
            add(ImmutableInstruction10t(Opcode.GOTO, 9))
            repeat(8) { add(ImmutableInstruction11n(Opcode.CONST_4, 0, it and 0x7)) }
            add(ImmutableInstruction10x(Opcode.RETURN_VOID))
            add(ImmutableInstruction10x(Opcode.RETURN_VOID))
        }
        val input = dex(
            clazz(
                OWNED_CLASS,
                listOf(method(OWNED_CLASS, "branchBody", PUBLIC_STATIC, implementation(1, instructions))),
            ),
        )

        val result = transform(input, request(salt = "branch-label-weave"))

        val implementation = implementation(result.dexBytes, OWNED_CLASS, "branchBody")
        assertEquals(
            instructions.filterNot { it.opcode == Opcode.NOP }.map { it.opcode },
            semanticBodyOpcodes(implementation),
        )
        var address = 0
        val branch = implementation.instructions.firstNotNullOf { instruction ->
            if (instruction.opcode == Opcode.GOTO) address to (instruction as OffsetInstruction)
            else {
                address += instruction.codeUnits
                null
            }
        }
        assertTrue(branch.second.codeOffset > 9)
        assertEquals(Opcode.RETURN_VOID, opcodeAt(implementation, branch.first + branch.second.codeOffset))
    }

    @Test
    fun `weaving that widens an existing branch opcode leaves that method unchanged`() {
        val branchInstructions = buildList {
            add(ImmutableInstruction10t(Opcode.GOTO, 127))
            repeat(126) { add(ImmutableInstruction11n(Opcode.CONST_4, 0, it and 0x7)) }
            add(ImmutableInstruction10x(Opcode.RETURN_VOID))
        }
        val input = dex(
            clazz(
                OWNED_CLASS,
                listOf(
                    method(
                        OWNED_CLASS,
                        "branchAtEncodingLimit",
                        PRIVATE_STATIC,
                        implementation(1, branchInstructions),
                    ),
                    sizedVoidMethod("safeSibling", 12),
                ),
            ),
        )

        val result = transform(input, request(salt = "branch-format-stability"))
        val reports = result.report.methods.associateBy(MethodTransformationReport::methodId)
        val branchReport = reports.getValue("$OWNED_CLASS->branchAtEncodingLimit()V")

        assertEquals(MethodEligibilityReason.UNSTABLE_INSTRUCTION_ENCODING, branchReport.reason)
        assertEquals(branchReport.oldBodySha256, branchReport.newBodySha256)
        assertEquals(Opcode.GOTO, implementation(result.dexBytes, OWNED_CLASS, "branchAtEncodingLimit").instructions.first().opcode)
        assertEquals(
            MethodEligibilityReason.TRANSFORMED,
            reports.getValue("$OWNED_CLASS->safeSibling()V").reason,
        )
    }

    @Test
    fun `weaving never splits invoke or filled new array from move result`() {
        val helper = ImmutableMethodReference(OWNED_CLASS, "helper", emptyList<String>(), "I")
        val instructions = buildList {
            add(ImmutableInstruction35c(Opcode.INVOKE_STATIC, 0, 0, 0, 0, 0, 0, helper))
            add(ImmutableInstruction11x(Opcode.MOVE_RESULT, 0))
            add(
                ImmutableInstruction35c(
                    Opcode.FILLED_NEW_ARRAY,
                    1,
                    0,
                    0,
                    0,
                    0,
                    0,
                    ImmutableTypeReference("[I"),
                ),
            )
            add(ImmutableInstruction11x(Opcode.MOVE_RESULT_OBJECT, 1))
            repeat(8) { add(ImmutableInstruction11n(Opcode.CONST_4, 0, it and 0x7)) }
            add(ImmutableInstruction10x(Opcode.RETURN_VOID))
        }
        val input = dex(clazz(OWNED_CLASS, listOf(method(OWNED_CLASS, "adjacency", PUBLIC_STATIC, implementation(2, instructions)))))

        val result = transform(input, request(salt = "adjacency-weave"))

        val opcodes = implementation(result.dexBytes, OWNED_CLASS, "adjacency").instructions.map { it.opcode }
        assertEquals(Opcode.MOVE_RESULT, opcodes[opcodes.indexOf(Opcode.INVOKE_STATIC) + 1])
        assertEquals(Opcode.MOVE_RESULT_OBJECT, opcodes[opcodes.indexOf(Opcode.FILLED_NEW_ARRAY) + 1])
    }

    @Test
    fun `junk generated and caller denied descriptors are explicitly excluded`() {
        val junk = "Lcom/example/demo/match/junkcode/Junk;"
        val generated = "Lcom/example/demo/match/R;"
        val callerDenied = "Lcom/example/demo/match/algorithm/GeneratedNoise;"
        val input = dex(
            clazz(OWNED_CLASS, listOf(longVoidMethod(OWNED_CLASS, "safe", PUBLIC_STATIC))),
            clazz(junk, listOf(longVoidMethod(junk, "noise", PUBLIC_STATIC))),
            clazz(generated, listOf(longVoidMethod(generated, "generated", PUBLIC_STATIC))),
            clazz(callerDenied, listOf(longVoidMethod(callerDenied, "noise", PUBLIC_STATIC))),
        )

        val result = transform(
            input,
            request().copy(
                ownedDescriptors = setOf(OWNED_CLASS, junk, generated, callerDenied),
                deniedDescriptorPrefixes = setOf(
                    "Lcom/example/demo/match/junkcode/",
                    "Lcom/example/demo/match/algorithm/",
                ),
            ),
        )
        val reasons = result.report.methods.associate { it.methodId to it.reason }

        assertEquals(MethodEligibilityReason.TRANSFORMED, reasons["$OWNED_CLASS->safe()V"])
        assertEquals(MethodEligibilityReason.DENIED_DESCRIPTOR, reasons["$junk->noise()V"])
        assertEquals(MethodEligibilityReason.GENERATED_CLASS, reasons["$generated->generated()V"])
        assertEquals(MethodEligibilityReason.DENIED_DESCRIPTOR, reasons["$callerDenied->noise()V"])
    }

    @Test
    fun `external contract ids require a complete dex method descriptor`() {
        val input = dex(clazz(OWNED_CLASS, listOf(longVoidMethod(OWNED_CLASS, "safe", PUBLIC_STATIC))))
        val malformedIds = listOf(
            "Lfoo;->bar(",
            "$OWNED_CLASS->safe(I)Vjunk",
            "$OWNED_CLASS->safe([V)V",
            "$OWNED_CLASS->()V",
        )

        malformedIds.forEach { malformed ->
            assertFailsWith<IllegalArgumentException>(malformed) {
                transform(input, request().copy(externalContractMethodIds = setOf(malformed)))
            }
        }
    }

    @Test
    fun `report separates owned eligible transformed and shingle effective coverage`() {
        val input = dex(
            clazz(
                OWNED_CLASS,
                listOf(
                    longVoidMethod(OWNED_CLASS, "first", PUBLIC_STATIC),
                    longVoidMethod(OWNED_CLASS, "second", PRIVATE_STATIC),
                    method(OWNED_CLASS, "<init>", AccessFlags.CONSTRUCTOR.value or AccessFlags.PRIVATE.value, implementation(0, listOf(ImmutableInstruction10x(Opcode.RETURN_VOID)))),
                ),
            ),
        )

        val report = transform(input, request(salt = "coverage-stages")).report

        assertEquals(3, report.ownedMethodCount)
        assertEquals(2, report.eligibleMethodCount)
        assertEquals(2, report.transformedMethodCount)
        assertEquals(2, report.shingleEffectiveMethodCount)
        assertTrue(report.ownedInstructionCount > report.eligibleInstructionCount)
        assertEquals(report.eligibleInstructionCount, report.transformedInstructionCount)
        assertEquals(report.transformedInstructionCount, report.shingleEffectiveInstructionCount)
        assertEquals(2.0 / 3.0, report.eligibleMethodCoverage)
        assertEquals(1.0, report.transformedMethodCoverage)
        assertEquals(1.0, report.transformedInstructionCoverage)
        assertEquals(1.0, report.shingleEffectiveMethodCoverage)
        assertEquals(1.0, report.shingleEffectiveInstructionCoverage)
        report.methods.filter { it.reason == MethodEligibilityReason.TRANSFORMED }.forEach { method ->
            assertEquals(0.0, method.opcodeShingleSimilarity)
            assertEquals(1.0, method.shingleEffectiveness)
        }
    }

    @Test
    fun `transformed report records the independently recomputable SimHash distance`() {
        val input = dex(
            clazz(
                OWNED_CLASS,
                listOf(longVoidMethod(OWNED_CLASS, "simHash", PRIVATE_STATIC)),
            ),
        )

        val result = transform(
            input,
            request(salt = "simhash-report", minimumSimHashDistance = 4),
        )
        val method = result.report.methods.single()
        val independentlyComputed = NormalizedOpcodeSimHash.distance(
            implementation(input, OWNED_CLASS, "simHash").instructions,
            implementation(result.dexBytes, OWNED_CLASS, "simHash").instructions,
        )

        assertEquals(4, result.report.minimumSimHashDistance)
        assertTrue(independentlyComputed >= 4)
        assertEquals(independentlyComputed, method.simHashDistance)
        assertEquals(MethodEligibilityReason.TRANSFORMED, method.reason)
    }

    @Test
    fun `methods below the configured SimHash distance retain their original body with an explicit reason`() {
        val methods = (1..12).map { seed -> variedOpcodeMethod("simHashGate$seed", seed) }
        val input = dex(clazz(OWNED_CLASS, methods))
        val baseline = transform(
            input,
            request(salt = "simhash-gate-reason", minimumSimHashDistance = 0, maximumGrowthRatio = 3.0),
        ).report.methods.associateBy(MethodTransformationReport::methodId)
        val threshold = baseline.values.maxOf(MethodTransformationReport::simHashDistance)
        val belowThreshold = baseline.values.filter { it.simHashDistance < threshold }.map { it.methodId }.toSet()
        assertTrue(belowThreshold.isNotEmpty(), "fixture must contain more than one SimHash distance")

        val gated = transform(
            input,
            request(salt = "simhash-gate-reason", minimumSimHashDistance = threshold, maximumGrowthRatio = 3.0),
        ).report.methods.associateBy(MethodTransformationReport::methodId)

        belowThreshold.forEach { methodId ->
            val report = gated.getValue(methodId)
            assertEquals(MethodEligibilityReason.INSUFFICIENT_SIMHASH_DISTANCE, report.reason)
            assertEquals(report.oldBodySha256, report.newBodySha256)
            assertEquals(baseline.getValue(methodId).simHashDistance, report.simHashDistance)
        }
        gated.values.filter { it.methodId !in belowThreshold }.forEach { report ->
            assertEquals(MethodEligibilityReason.TRANSFORMED, report.reason)
            assertTrue(report.simHashDistance >= threshold)
        }
    }

    @Test
    fun `adaptive detour padding remains below the dex growth gate and is distributed`() {
        val methods = (0 until 48).map { index -> sizedVoidMethod("budget$index", 24 + index % 5) }
        val dependency = "Lthird/party/LargeDependency;"
        val dependencyMethods = (0 until 192).map { index ->
            sizedVoidMethod(dependency, "dependency$index", 24 + index % 5)
        }
        val input = dex(
            clazz(OWNED_CLASS, methods),
            clazz(dependency, dependencyMethods, sourceFile = "budget-carrier-" + "x".repeat(250_000)),
        )
        val maximumGrowth = 0.05

        val result = transform(
            input,
            request(salt = "bounded-detours", maximumGrowthRatio = maximumGrowth),
        )
        val transformed = result.report.methods.filter { it.reason == MethodEligibilityReason.TRANSFORMED }
        val inputMass = methods.sumOf { it.implementation!!.instructions.sumOf { instruction -> instruction.codeUnits } }
        val outputMass = implementationMass(result.dexBytes, OWNED_CLASS)

        assertTrue(result.report.byteGrowthRatio <= maximumGrowth)
        assertTrue(
            result.report.byteGrowthRatio >= maximumGrowth * 0.70,
            "growth=${result.report.byteGrowthRatio} transformed=${transformed.size} " +
                "reasons=${result.report.methods.groupingBy(MethodTransformationReport::reason).eachCount()}",
        )
        assertTrue(transformed.count { it.codeUnitGrowth > 3 } >= transformed.size / 2)
        assertTrue(transformed.maxOf { it.codeUnitGrowth } <= 128)
        assertTrue(outputMass > inputMass * 1.10)
    }

    @Test
    fun `serialized debug address overhead is fed back into the detour budget`() {
        val methods = (0 until 1_000).map { index ->
            debugSizedVoidMethod("debugBudget$index", 10)
        }
        val dependency = "Lthird/party/DebugBudgetPayload;"
        val input = dex(
            clazz(OWNED_CLASS, methods),
            clazz(dependency, emptyList(), sourceFile = "dependency-source-" + "x".repeat(6_000_000)),
        )
        val maximumGrowth = 0.05

        val result = transform(
            input,
            request(salt = "debug-budget-feedback", maximumGrowthRatio = maximumGrowth),
        )

        assertTrue(result.report.byteGrowthRatio <= maximumGrowth)
        assertEquals(methods.size, result.report.transformedMethodCount)
        assertTrue(result.report.methods.all { it.reason == MethodEligibilityReason.TRANSFORMED })
    }

    @Test
    fun `enabled growth keeps zero register long payloads below the marker floor`() {
        val methods = (0 until 256).map { index -> zeroRegisterVoidMethod("zeroBudget$index", 120) }
        val input = dex(
            clazz(OWNED_CLASS, methods),
            clazz(
                "Lthird/party/ZeroRegisterBudgetCarrier;",
                emptyList(),
                sourceFile = "zero-register-budget-" + "x".repeat(1_000_000),
            ),
        )

        val result = transform(
            input,
            request(salt = "zero-register-budget", maximumGrowthRatio = 0.02),
        )

        assertEquals(methods.size, result.report.transformedMethodCount)
        assertTrue(result.report.byteGrowthRatio <= 0.02)
        assertTrue(
            result.report.methods.all { it.insertedPayloadInstructionCount in 1 until 24 },
            result.report.methods.map(MethodTransformationReport::insertedPayloadInstructionCount).toString(),
        )
    }

    @Test
    fun `long methods consume thirty thousand padding units when the five percent budget permits`() {
        val longMethods = (0 until 64).map { index -> sizedVoidMethod("longBudget$index", 120 + index % 7) }
        val dependency = "Lthird/party/LargeStringPayload;"
        val input = dex(
            clazz(OWNED_CLASS, longMethods),
            clazz(dependency, emptyList(), sourceFile = "dependency-source-" + "x".repeat(4_000_000)),
        )
        val first = transform(input, request(salt = "long-priority-a", maximumGrowthRatio = 0.05))
        val second = transform(input, request(salt = "long-priority-b", maximumGrowthRatio = 0.05))
        val firstPadding = entryPaddingByMethod(input, first, OWNED_CLASS)
        val secondPadding = entryPaddingByMethod(input, second, OWNED_CLASS)
        val theoreticalCodeUnitBudget = (input.size * 0.05 / 2.0).toInt()
        val codeUnitBudgetAfterMarkerPool = theoreticalCodeUnitBudget - longMethods.size * 220 / 2
        val usedCodeUnits = first.report.methods.sumOf { it.codeUnitGrowth }
        val relayCodeUnits = first.report.methods.sumOf { it.insertedRelayInstructionCount * 3 }
        val nonRelayCodeUnits = usedCodeUnits - relayCodeUnits

        assertTrue(firstPadding.values.sum() >= 30_000)
        assertTrue(
            nonRelayCodeUnits >= codeUnitBudgetAfterMarkerPool * 0.75,
            "nonRelay=$nonRelayCodeUnits available=$codeUnitBudgetAfterMarkerPool theoretical=$theoreticalCodeUnitBudget",
        )
        assertTrue(
            nonRelayCodeUnits <= theoreticalCodeUnitBudget * 0.90,
            "nonRelay=$nonRelayCodeUnits theoretical=$theoreticalCodeUnitBudget",
        )
        assertTrue(usedCodeUnits <= theoreticalCodeUnitBudget)
        assertTrue(first.report.byteGrowthRatio <= 0.05)
        assertTrue(second.report.byteGrowthRatio <= 0.05)
        assertNotEquals(firstPadding, secondPadding)
        assertFalse(first.dexBytes.contentEquals(second.dexBytes))
    }

    @Test
    fun `discretionary budget is allocated above register floors and reaches the long target`() {
        val longMethods = (0 until 64).map { index -> sizedVoidMethod("floorBudget$index", 120 + index % 7) }
        val input = dex(clazz(OWNED_CLASS, longMethods))
        val request = request(salt = "floor-plus-discretionary", maximumGrowthRatio = 0.10)
        val inputSize = 1_000_000
        val floorOutputSize = 1_020_000
        val transformer = SafeDexTransformer()
        val digestMethod = SafeDexTransformer::class.java.getDeclaredMethod(
            "saltedDigest",
            ByteArray::class.java,
            String::class.java,
        ).apply { isAccessible = true }
        val utilizationByte = (digestMethod.invoke(transformer, request.salt, "<detour-budget>") as ByteArray)
            .first().toInt() and 0xff
        val utilization = 0.78 + (0.84 - 0.78) * utilizationByte / 255.0
        val discretionaryBudget = detourCodeUnitBudget(
            inputSize = inputSize,
            floorOutputSize = floorOutputSize,
            maximumGrowthRatio = request.maximumGrowthRatio,
            utilization = utilization,
        )
        val planner = SafeDexTransformer::class.java.getDeclaredMethod(
            "planDetourPadding",
            DexBackedDexFile::class.java,
            DexTransformRequest::class.java,
            ByteArray::class.java,
            Set::class.java,
            Int::class.javaPrimitiveType,
            Int::class.javaPrimitiveType,
            Double::class.javaPrimitiveType,
        ).apply { isAccessible = true }
        @Suppress("UNCHECKED_CAST")
        val padding = planner.invoke(
            transformer,
            DexBackedDexFile.fromInputStream(null, input.inputStream()),
            request,
            request.salt,
            emptySet<String>(),
            inputSize,
            floorOutputSize,
            1.0,
        ) as Map<String, Int>
        val structuralFloor = longMethods.size * 24

        assertTrue(floorOutputSize > inputSize)
        assertEquals(discretionaryBudget, padding.values.sum() - structuralFloor)
        assertTrue(padding.values.sum() >= 30_000)
    }

    @Test
    fun `disabled growth enforcement ignores the maximum growth ratio for detour allocation`() {
        val methods = (0 until 4).map { index -> sizedVoidMethod("unbounded$index", 120 + index) }
        val input = dex(
            clazz(OWNED_CLASS, methods),
            clazz("Lthird/party/DetourBudgetCarrier;", emptyList(), sourceFile = "x".repeat(3_000_000)),
        )
        val results = listOf(0.0, 0.05, 1.0).map { maximumGrowthRatio ->
            transform(
                input,
                request(salt = "unbounded-budget", maximumGrowthRatio = maximumGrowthRatio)
                    .copy(enforceMaximumGrowth = false),
            )
        }

        assertEquals(1, results.map { entryPaddingByMethod(input, it, OWNED_CLASS) }.toSet().size)
        assertEquals(1, results.map { it.report.methods }.toSet().size)
        assertTrue(results.drop(1).all { result -> result.dexBytes.contentEquals(results.first().dexBytes) })
    }

    @Test
    fun `disabled growth enforcement gives every selected method a bounded heterogeneous payload`() {
        val methods = listOf(
            sizedVoidMethod("shortFirst", 24),
            sizedVoidMethod("shortSecond", 48),
            sizedVoidMethod("longFirst", 120),
            sizedVoidMethod("longSecond", 132),
        )
        val input = dex(clazz(OWNED_CLASS, methods))
        val firstSalt = "full-detour-cap"
        val request = request(salt = firstSalt, maximumGrowthRatio = 0.0)
            .copy(enforceMaximumGrowth = false)
        val first = transform(input, request)
        val second = transform(input, request)
        val differentSalt = transform(
            input,
            request(salt = "full-detour-cap-different", maximumGrowthRatio = 0.0)
                .copy(enforceMaximumGrowth = false),
        )

        val firstPadding = first.report.methods.associate {
            it.methodId.substringAfter("->").substringBefore('(') to it.insertedPayloadInstructionCount
        }
        val changedPadding = differentSalt.report.methods.associate {
            it.methodId.substringAfter("->").substringBefore('(') to it.insertedPayloadInstructionCount
        }
        assertTrue(firstPadding.filterKeys { it.startsWith("short") }.values.all { it in 8..16 }, firstPadding.toString())
        assertTrue(firstPadding.filterKeys { it.startsWith("long") }.values.all { it in 24..40 }, firstPadding.toString())
        assertTrue(first.report.methods.all { it.insertedRelayInstructionCount == 0 })
        assertTrue(differentSalt.report.methods.all { it.insertedRelayInstructionCount == 0 })
        assertNotEquals(first.report.methods.map { it.newBodySha256 }, differentSalt.report.methods.map { it.newBodySha256 })
        assertTrue(
            changedPadding.filterKeys { it.startsWith("short") }.values.all { it in 8..16 },
            changedPadding.toString(),
        )
        assertTrue(
            changedPadding.filterKeys { it.startsWith("long") }.values.all { it in 24..40 },
            changedPadding.toString(),
        )
        assertEquals(methods.size, first.report.transformedMethodCount)
        assertEquals(methods.map { it.implementation!!.instructions.count() }.sum(), first.report.transformedInstructionCount)
        assertContentEquals(first.dexBytes, second.dexBytes)
        assertEquals(first.report, second.report)
        assertFalse(first.dexBytes.contentEquals(differentSalt.dexBytes))
    }

    @Test
    fun `enabled growth enforcement keeps detour allocation ratio sensitive and fitted`() {
        val methods = (0 until 16).map { index -> sizedVoidMethod("fitted$index", 120 + index % 4) }
        val input = dex(
            clazz(OWNED_CLASS, methods),
            clazz("Lthird/party/FittedDetourBudgetCarrier;", emptyList(), sourceFile = "x".repeat(200_000)),
        )
        val tight = transform(input, request(salt = "fitted-detours", maximumGrowthRatio = 0.05))
        val loose = transform(input, request(salt = "fitted-detours", maximumGrowthRatio = 0.10))

        assertTrue(tight.report.byteGrowthRatio <= 0.05)
        assertTrue(loose.report.byteGrowthRatio <= 0.10)
        assertTrue(
            entryPaddingByMethod(input, loose, OWNED_CLASS).values.sum() >
                entryPaddingByMethod(input, tight, OWNED_CLASS).values.sum(),
        )
        assertFalse(tight.dexBytes.contentEquals(loose.dexBytes))
    }

    @Test
    fun `minimum instruction coverage fails independently when method coverage passes`() {
        val input = dex(
            clazz(
                OWNED_CLASS,
                listOf(
                    sizedVoidMethod("shortA", 12),
                    sizedVoidMethod("shortB", 12),
                    sizedVoidMethod("longC", 72),
                ),
            ),
        )

        val salt = coverageSalt(
            input,
            "coverage-i",
            "eligible method coverage 0.6666666666666666",
            "eligible instruction coverage 0.25",
        )
        val failure = assertFailsWith<DexTransformationRejectedException> {
            transform(
                input,
                request(salt, 0.50, 0, 1.0, 0.5),
            )
        }

        assertTrue(failure.message!!.contains("eligible method coverage 0.6666666666666666"))
        assertTrue(failure.message!!.contains("eligible instruction coverage 0.25"))
    }

    @Test
    fun `minimum method coverage fails independently when instruction coverage passes`() {
        val input = dex(
            clazz(
                OWNED_CLASS,
                listOf(
                    sizedVoidMethod("longA", 72),
                    sizedVoidMethod("shortB", 12),
                    sizedVoidMethod("shortC", 12),
                ),
            ),
        )

        val salt = coverageSalt(
            input,
            "coverage-m",
            "eligible method coverage 0.3333333333333333",
            "eligible instruction coverage 0.75",
        )
        val failure = assertFailsWith<DexTransformationRejectedException> {
            transform(
                input,
                request(salt, 0.50, 0, 1.0, 0.5),
            )
        }

        assertTrue(failure.message!!.contains("eligible method coverage 0.3333333333333333"))
        assertTrue(failure.message!!.contains("eligible instruction coverage 0.75"))
    }

    private fun coverageSalt(
        input: ByteArray,
        prefix: String,
        methodCoverage: String,
        instructionCoverage: String,
    ): String = (0..1_000).firstNotNullOfOrNull { index ->
        val salt = "$prefix-$index"
        runCatching { transform(input, request(salt, 0.50, 0, 1.0, 0.5)) }
            .exceptionOrNull()
            ?.takeIf { failure ->
                failure is DexTransformationRejectedException &&
                    failure.message.orEmpty().contains(methodCoverage) &&
                    failure.message.orEmpty().contains(instructionCoverage)
            }
            ?.let { salt }
    } ?: error("could not find deterministic coverage salt for $prefix")

    @Test
    fun `an ineffective nop-only weave fails closed when it is the only candidate`() {
        val instructions = List(12) { ImmutableInstruction10x(Opcode.NOP) } + ImmutableInstruction10x(Opcode.RETURN_VOID)
        val input = dex(clazz(OWNED_CLASS, listOf(method(OWNED_CLASS, "nopOnly", PRIVATE_STATIC, implementation(0, instructions)))))

        val failure = assertFailsWith<DexTransformationRejectedException> {
            transform(input, request(salt = "ineffective", minimumCoverage = 0.0))
        }

        assertTrue(failure.message!!.contains("at least one shingle-effective transformation"))
    }

    @Test
    fun `rejected candidate metrics describe the unchanged emitted body`() {
        val partlyIneffective = buildList {
            repeat(6) { add(ImmutableInstruction10x(Opcode.NOP)) }
            repeat(6) { add(ImmutableInstruction11n(Opcode.CONST_4, 0, it and 0x7)) }
            add(ImmutableInstruction10x(Opcode.RETURN_VOID))
        }
        val input = dex(
            clazz(
                OWNED_CLASS,
                listOf(
                    longVoidMethod(OWNED_CLASS, "effective", PRIVATE_STATIC),
                    method(OWNED_CLASS, "rejected", PRIVATE_STATIC, implementation(1, partlyIneffective)),
                ),
            ),
        )

        val report = transform(input, request(salt = "rejected-metrics")).report.methods
            .single { it.methodId == "$OWNED_CLASS->rejected()V" }

        assertEquals(MethodEligibilityReason.INEFFECTIVE_SHINGLE_TRANSFORM, report.reason)
        assertEquals(report.oldBodySha256, report.newBodySha256)
        assertEquals(1.0, report.opcodeShingleSimilarity)
        assertEquals(0.0, report.shingleEffectiveness)
    }

    @Test
    fun `entry padding reconciliation rejects a transformed report without an emitted detour`() {
        val (input, result) = ineffectiveEntryDetourFixture()
        val rejectedMethodId = "$OWNED_CLASS->rejected()V"
        val mutated = result.copy(
            report = result.report.copy(
                methods = result.report.methods.map { report ->
                    if (report.methodId == rejectedMethodId) {
                        report.copy(reason = MethodEligibilityReason.TRANSFORMED)
                    } else {
                        report
                    }
                },
            ),
        )

        val failure = assertFailsWith<AssertionError> {
            entryPaddingByMethod(input, mutated, OWNED_CLASS)
        }

        assertTrue(failure.message!!.contains("entry detour method IDs"))
    }

    @Test
    fun `entry padding reconciliation requires the exact ineffective reason for an omitted method`() {
        val (input, result) = ineffectiveEntryDetourFixture()
        val rejectedMethodId = "$OWNED_CLASS->rejected()V"
        val mutated = result.copy(
            report = result.report.copy(
                methods = result.report.methods.map { report ->
                    if (report.methodId == rejectedMethodId) {
                        report.copy(reason = MethodEligibilityReason.INSUFFICIENT_SIMHASH_DISTANCE)
                    } else {
                        report
                    }
                },
            ),
        )

        val failure = assertFailsWith<AssertionError> {
            entryPaddingByMethod(input, mutated, OWNED_CLASS)
        }

        assertTrue(failure.message!!.contains("omitted detour must be ineffective"))
    }

    @Test
    fun `entry padding reconciliation requires an omitted method body to be unchanged`() {
        val (_, result) = ineffectiveEntryDetourFixture()
        val changedRejected = buildList {
            repeat(6) { add(ImmutableInstruction10x(Opcode.NOP)) }
            repeat(6) { add(ImmutableInstruction11n(Opcode.CONST_4, 0, (it + 1) and 0x7)) }
            add(ImmutableInstruction10x(Opcode.RETURN_VOID))
        }
        val changedInput = dex(
            clazz(
                OWNED_CLASS,
                listOf(
                    longVoidMethod(OWNED_CLASS, "effective", PRIVATE_STATIC),
                    method(OWNED_CLASS, "rejected", PRIVATE_STATIC, implementation(1, changedRejected)),
                ),
            ),
        )

        val failure = assertFailsWith<AssertionError> {
            entryPaddingByMethod(changedInput, result, OWNED_CLASS)
        }

        assertTrue(failure.message!!.contains("omitted method body must be unchanged"))
    }

    @Test
    fun `no eligible method fails closed even with zero minimum coverage`() {
        val constructor = method(
            OWNED_CLASS,
            "<init>",
            AccessFlags.CONSTRUCTOR.value or AccessFlags.PRIVATE.value,
            implementation(0, listOf(ImmutableInstruction10x(Opcode.RETURN_VOID))),
        )

        val failure = assertFailsWith<DexTransformationRejectedException> {
            transform(dex(clazz(OWNED_CLASS, listOf(constructor))), request(minimumCoverage = 0.0))
        }

        assertTrue(failure.message!!.contains("at least one shingle-effective transformation"))
    }

    @Test
    fun `planner may preserve a dex with owned classes but no eligible methods`() {
        val classInitializer = method(
            OWNED_CLASS,
            "<clinit>",
            AccessFlags.STATIC.value or AccessFlags.CONSTRUCTOR.value,
            implementation(0, listOf(ImmutableInstruction10x(Opcode.RETURN_VOID))),
        )
        val input = dex(clazz(OWNED_CLASS, listOf(classInitializer)))

        val result = transform(
            input,
            request(minimumCoverage = 0.0).copy(allowNoEligibleMethodsSkip = true),
        )

        assertContentEquals(input, result.dexBytes)
        assertTrue(result.report.noEligibleMethodsSkipped)
        assertFalse(result.report.writerFloorSkipped)
        assertEquals(result.report.inputSha256, result.report.outputSha256)
        assertEquals(1, result.report.ownedMethodCount)
        assertEquals(0, result.report.eligibleMethodCount)
        assertEquals(0, result.report.transformedMethodCount)
        assertEquals(MethodEligibilityReason.CLASS_INITIALIZER, result.report.methods.single().reason)
    }

    private fun request(
        salt: String = "weave-salt",
        minimumCoverage: Double = 0.0,
        minimumSimHashDistance: Int = 0,
        maximumGrowthRatio: Double = 1.0,
        selectionRate: Double = 1.0,
    ) = DexTransformRequest(
        ownedDescriptorPrefixes = setOf(OWNED_PREFIX),
        ownedDescriptors = setOf(OWNED_CLASS),
        salt = salt.toByteArray(),
        minimumCoverage = minimumCoverage,
        minimumSimHashDistance = minimumSimHashDistance,
        maximumGrowthRatio = maximumGrowthRatio,
        selectionRate = selectionRate,
    )

    private fun transform(input: ByteArray, request: DexTransformRequest): DexTransformationResult =
        SafeDexTransformer().transform(input, request)

    private fun longVoidMethod(definingClass: String, name: String, accessFlags: Int): ImmutableMethod =
        method(definingClass, name, accessFlags, implementation(1, longInstructions()))

    private fun sizedVoidMethod(name: String, instructionCount: Int): ImmutableMethod {
        return sizedVoidMethod(OWNED_CLASS, name, instructionCount)
    }

    private fun sizedVoidMethod(
        definingClass: String,
        name: String,
        instructionCount: Int,
    ): ImmutableMethod {
        require(instructionCount >= 2)
        val instructions = buildList {
            repeat(instructionCount - 1) { add(ImmutableInstruction11n(Opcode.CONST_4, 0, it and 0x7)) }
            add(ImmutableInstruction10x(Opcode.RETURN_VOID))
        }
        return method(definingClass, name, PRIVATE_STATIC, implementation(1, instructions))
    }

    private fun debugSizedVoidMethod(name: String, instructionCount: Int): ImmutableMethod {
        val original = sizedVoidMethod(name, instructionCount)
        return ImmutableMethod(
            original.definingClass,
            original.name,
            original.parameters,
            original.returnType,
            original.accessFlags,
            original.annotations,
            original.hiddenApiRestrictions,
            ImmutableMethodImplementation(
                original.implementation!!.registerCount,
                original.implementation!!.instructions,
                emptyList(),
                listOf(ImmutableLineNumber(0, 100)),
            ),
        )
    }

    private fun variedOpcodeMethod(name: String, seed: Int): ImmutableMethod {
        var state = seed
        val instructions = buildList {
            repeat(24) { index ->
                state = state * 1_103_515_245 + 12_345 + index
                when ((state ushr 16) and 3) {
                    0 -> add(ImmutableInstruction11n(Opcode.CONST_4, 0, index and 0x7))
                    1 -> add(ImmutableInstruction12x(Opcode.MOVE, 0, 0))
                    2 -> add(ImmutableInstruction12x(Opcode.NEG_INT, 0, 0))
                    else -> add(ImmutableInstruction23x(Opcode.ADD_INT, 0, 0, 0))
                }
            }
            add(ImmutableInstruction10x(Opcode.RETURN_VOID))
        }
        return method(OWNED_CLASS, name, PRIVATE_STATIC, implementation(1, instructions))
    }

    private fun zeroRegisterVoidMethod(name: String, instructionCount: Int): ImmutableMethod = method(
        OWNED_CLASS,
        name,
        PRIVATE_STATIC,
        implementation(0, List(instructionCount) { ImmutableInstruction10x(Opcode.RETURN_VOID) }),
    )

    private fun longInstructions() = buildList {
        repeat(11) { add(ImmutableInstruction11n(Opcode.CONST_4, 0, it and 0x7)) }
        add(ImmutableInstruction10x(Opcode.RETURN_VOID))
    }

    private fun implementation(registerCount: Int, instructions: List<com.android.tools.smali.dexlib2.iface.instruction.Instruction>) =
        ImmutableMethodImplementation(registerCount, instructions, emptyList(), emptyList())

    private fun method(
        definingClass: String,
        name: String,
        accessFlags: Int,
        implementation: ImmutableMethodImplementation?,
    ) = ImmutableMethod(
        definingClass,
        name,
        emptyList(),
        "V",
        accessFlags,
        emptySet(),
        emptySet(),
        implementation,
    )

    private fun clazz(
        type: String,
        methods: List<ImmutableMethod>,
        sourceFile: String? = null,
    ) = ImmutableClassDef(
        type,
        AccessFlags.PUBLIC.value,
        "Ljava/lang/Object;",
        emptyList(),
        sourceFile,
        emptySet(),
        emptyList(),
        methods,
    )

    private fun dex(vararg classes: ImmutableClassDef): ByteArray {
        val store = MemoryDataStore()
        DexPool.writeTo(store, ImmutableDexFile(Opcodes.getDefault(), classes.toList()))
        return store.data
    }

    private fun implementation(bytes: ByteArray, definingClass: String, name: String): MethodImplementation =
        DexBackedDexFile.fromInputStream(null, bytes.inputStream())
            .classes.single { it.type == definingClass }
            .methods.single { it.name == name }
            .implementation!!

    private fun implementationMass(bytes: ByteArray, definingClass: String): Int =
        DexBackedDexFile.fromInputStream(null, bytes.inputStream())
            .classes.single { it.type == definingClass }
            .methods.sumOf { method -> method.implementation?.instructions?.sumOf { it.codeUnits } ?: 0 }

    private fun ineffectiveEntryDetourFixture(): Pair<ByteArray, DexTransformationResult> {
        val partlyIneffective = buildList {
            repeat(6) { add(ImmutableInstruction10x(Opcode.NOP)) }
            repeat(6) { add(ImmutableInstruction11n(Opcode.CONST_4, 0, it and 0x7)) }
            add(ImmutableInstruction10x(Opcode.RETURN_VOID))
        }
        val input = dex(
            clazz(
                OWNED_CLASS,
                listOf(
                    longVoidMethod(OWNED_CLASS, "effective", PRIVATE_STATIC),
                    method(OWNED_CLASS, "rejected", PRIVATE_STATIC, implementation(1, partlyIneffective)),
                ),
            ),
        )
        return input to transform(input, request(salt = "rejected-metrics"))
    }

    private fun entryPaddingByMethod(
        inputBytes: ByteArray,
        result: DexTransformationResult,
        definingClass: String,
    ): Map<String, Int> {
        val originalMethods = DexBackedDexFile.fromInputStream(null, inputBytes.inputStream())
            .classes.single { it.type == definingClass }
            .methods.associateBy(::testMethodId)
        val emittedMethods = DexBackedDexFile.fromInputStream(null, result.dexBytes.inputStream())
            .classes.single { it.type == definingClass }
            .methods.associateBy(::testMethodId)
        val reports = result.report.methods
            .filter { it.methodId.startsWith("$definingClass->") }
            .associateBy(MethodTransformationReport::methodId)
        assertEquals(originalMethods.keys, emittedMethods.keys, "original and emitted method IDs must match")
        assertEquals(emittedMethods.keys, reports.keys, "emitted and reported method IDs must match")

        val padding = emittedMethods.mapNotNull { (methodId, method) ->
            val implementation = requireNotNull(method.implementation)
            val instructions = implementation.instructions.toList()
            val entry = instructions.firstOrNull() as? OffsetInstruction ?: return@mapNotNull null
            val instructionBoundaries = buildSet {
                var address = 0
                instructions.forEach { instruction ->
                    add(address)
                    address += instruction.codeUnits
                }
            }
            if (
                entry.opcode != Opcode.GOTO_32 ||
                entry.codeOffset <= entry.codeUnits ||
                entry.codeOffset !in instructionBoundaries
            ) {
                return@mapNotNull null
            }
            methodId to (entry.codeOffset - entry.codeUnits)
        }.toMap()
        val transformedMethodIds = reports.values
            .filter { it.reason == MethodEligibilityReason.TRANSFORMED }
            .mapTo(linkedSetOf(), MethodTransformationReport::methodId)
        assertEquals(
            transformedMethodIds,
            padding.keys,
            "entry detour method IDs must equal reported TRANSFORMED method IDs",
        )

        (reports.keys - padding.keys).forEach { methodId ->
            val report = reports.getValue(methodId)
            assertEquals(
                MethodEligibilityReason.INEFFECTIVE_SHINGLE_TRANSFORM,
                report.reason,
                "omitted detour must be ineffective: $methodId",
            )
            val originalBodySha256 = testBodySha256(requireNotNull(originalMethods.getValue(methodId).implementation))
            val emittedBodySha256 = testBodySha256(requireNotNull(emittedMethods.getValue(methodId).implementation))
            assertEquals(
                originalBodySha256,
                emittedBodySha256,
                "omitted method body must be unchanged: $methodId",
            )
            assertEquals(originalBodySha256, report.oldBodySha256, "reported original body hash must match: $methodId")
            assertEquals(emittedBodySha256, report.newBodySha256, "reported emitted body hash must match: $methodId")
        }
        return padding
    }

    private fun testMethodId(method: Method): String = buildString {
        append(method.definingClass).append("->").append(method.name).append('(')
        method.parameterTypes.forEach(::append)
        append(')').append(method.returnType)
    }

    private fun testBodySha256(implementation: MethodImplementation): String {
        val method = SafeDexTransformer::class.java.getDeclaredMethod(
            "bodySha256",
            MethodImplementation::class.java,
        ).apply { isAccessible = true }
        return method.invoke(SafeDexTransformer(), implementation) as String
    }

    private fun opcodeAt(implementation: MethodImplementation, address: Int): Opcode {
        var current = 0
        implementation.instructions.forEach { instruction ->
            if (current == address) return instruction.opcode
            current += instruction.codeUnits
        }
        error("No instruction at code address $address")
    }

    private fun opcodeBefore(implementation: MethodImplementation, address: Int): Opcode? {
        var current = 0
        var previous: Opcode? = null
        implementation.instructions.forEach { instruction ->
            if (current == address) return previous
            previous = instruction.opcode
            current += instruction.codeUnits
        }
        error("No instruction at code address $address")
    }

    private fun reachableRelayPairs(implementation: MethodImplementation): List<Pair<Int, Int>> {
        val instructions = implementation.instructions.toList()
        val addresses = IntArray(instructions.size)
        var address = 0
        instructions.forEachIndexed { index, instruction ->
            addresses[index] = address
            address += instruction.codeUnits
        }
        val indexByAddress = addresses.withIndex().associate { it.value to it.index }
        val terminalIndex = instructions.indexOfLast { instruction ->
            instruction.opcode.name.startsWith("RETURN") || instruction.opcode == Opcode.THROW
        }
        return instructions.mapIndexedNotNull { sourceIndex, source ->
            val sourceBranch = source as? OffsetInstruction ?: return@mapIndexedNotNull null
            if (source.opcode != Opcode.GOTO_32) return@mapIndexedNotNull null
            val relayIndex = indexByAddress[addresses[sourceIndex] + sourceBranch.codeOffset]
                ?: return@mapIndexedNotNull null
            if (relayIndex <= terminalIndex) return@mapIndexedNotNull null
            val relay = instructions[relayIndex] as? OffsetInstruction ?: return@mapIndexedNotNull null
            if (relay.opcode != Opcode.GOTO_32) return@mapIndexedNotNull null
            val continuationIndex = (sourceIndex + 1 until relayIndex)
                .firstOrNull { instructions[it].opcode != Opcode.NOP }
                ?: return@mapIndexedNotNull null
            val continuationAddress = addresses[continuationIndex]
            if (addresses[relayIndex] + relay.codeOffset != continuationAddress) return@mapIndexedNotNull null
            sourceIndex to relayIndex
        }
    }

    private fun semanticBodyOpcodes(implementation: MethodImplementation): List<Opcode> {
        val instructions = implementation.instructions.toList()
        val relayIndexes = reachableRelayPairs(implementation).flatMapTo(hashSetOf()) { listOf(it.first, it.second) }
        val entryTargetAddress = (instructions.first() as OffsetInstruction).codeOffset
        var address = 0
        return instructions.mapIndexedNotNull { index, instruction ->
            val currentAddress = address
            address += instruction.codeUnits
            instruction.opcode.takeIf {
                currentAddress >= entryTargetAddress && instruction.opcode != Opcode.NOP && index !in relayIndexes
            }
        }
    }

    private companion object {
        const val OWNED_PREFIX = "Lcom/example/demo/match/"
        const val OWNED_CLASS = "Lcom/example/demo/match/Calculator;"
        const val PUBLIC_STATIC = 0x0009
        const val PRIVATE_STATIC = 0x000a
        val GOTO_OPCODES = setOf(Opcode.GOTO, Opcode.GOTO_16, Opcode.GOTO_32)
    }
}
