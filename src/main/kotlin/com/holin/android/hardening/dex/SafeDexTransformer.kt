package com.holin.android.hardening.dex

import com.android.tools.smali.dexlib2.AccessFlags
import com.android.tools.smali.dexlib2.Opcode
import com.android.tools.smali.dexlib2.dexbacked.DexBackedDexFile
import com.android.tools.smali.dexlib2.formatter.DexFormatter
import com.android.tools.smali.dexlib2.iface.ClassDef
import com.android.tools.smali.dexlib2.iface.Method
import com.android.tools.smali.dexlib2.iface.MethodImplementation
import com.android.tools.smali.dexlib2.iface.instruction.DualReferenceInstruction
import com.android.tools.smali.dexlib2.iface.instruction.FieldOffsetInstruction
import com.android.tools.smali.dexlib2.iface.instruction.FiveRegisterInstruction
import com.android.tools.smali.dexlib2.iface.instruction.InlineIndexInstruction
import com.android.tools.smali.dexlib2.iface.instruction.Instruction
import com.android.tools.smali.dexlib2.iface.instruction.OffsetInstruction
import com.android.tools.smali.dexlib2.iface.instruction.OneRegisterInstruction
import com.android.tools.smali.dexlib2.iface.instruction.PayloadInstruction
import com.android.tools.smali.dexlib2.iface.instruction.ReferenceInstruction
import com.android.tools.smali.dexlib2.iface.instruction.RegisterRangeInstruction
import com.android.tools.smali.dexlib2.iface.instruction.ThreeRegisterInstruction
import com.android.tools.smali.dexlib2.iface.instruction.TwoRegisterInstruction
import com.android.tools.smali.dexlib2.iface.instruction.VariableRegisterInstruction
import com.android.tools.smali.dexlib2.iface.instruction.VerificationErrorInstruction
import com.android.tools.smali.dexlib2.iface.instruction.VtableIndexInstruction
import com.android.tools.smali.dexlib2.iface.instruction.WideLiteralInstruction
import com.android.tools.smali.dexlib2.iface.instruction.formats.ArrayPayload
import com.android.tools.smali.dexlib2.iface.instruction.formats.PackedSwitchPayload
import com.android.tools.smali.dexlib2.iface.instruction.formats.SparseSwitchPayload
import com.android.tools.smali.dexlib2.immutable.ImmutableClassDef
import com.android.tools.smali.dexlib2.immutable.ImmutableMethod
import com.android.tools.smali.dexlib2.writer.io.MemoryDataStore
import com.android.tools.smali.dexlib2.writer.pool.DexPool
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.util.zip.Adler32

private const val DEX_BUDGET_FEEDBACK_HEADROOM = 0.98

internal fun maximumDexOutputBytes(inputSize: Int, maximumGrowthRatio: Double): Long {
    require(inputSize > 0) { "DEX input size must be positive" }
    require(maximumGrowthRatio.isFinite() && maximumGrowthRatio >= 0.0) {
        "maximumGrowthRatio must be finite and non-negative"
    }
    return (inputSize.toDouble() * (1.0 + maximumGrowthRatio)).toLong()
}

internal fun detourCodeUnitBudget(
    inputSize: Int,
    floorOutputSize: Int,
    maximumGrowthRatio: Double,
    utilization: Double,
): Int {
    require(inputSize > 0 && floorOutputSize > 0) { "DEX sizes must be positive" }
    require(maximumGrowthRatio.isFinite() && maximumGrowthRatio >= 0.0) {
        "maximumGrowthRatio must be finite and non-negative"
    }
    require(utilization.isFinite() && utilization in 0.0..1.0) {
        "utilization must be between 0.0 and 1.0"
    }
    val maximumAllowedOutputBytes = maximumDexOutputBytes(inputSize, maximumGrowthRatio)
    val remainingGrowthBytes = (maximumAllowedOutputBytes - floorOutputSize.toLong()).coerceAtLeast(0L)
    return (remainingGrowthBytes * utilization / 2.0)
        .toLong()
        .coerceAtMost(Int.MAX_VALUE.toLong())
        .toInt()
}

internal fun nextDetourBudgetScale(
    currentScale: Double,
    floorOutputSize: Int,
    attemptedOutputSize: Int,
    maximumOutputSize: Long,
): Double {
    require(currentScale.isFinite() && currentScale in 0.0..1.0) {
        "currentScale must be between 0.0 and 1.0"
    }
    require(floorOutputSize > 0 && attemptedOutputSize >= floorOutputSize) {
        "DEX output sizes are inconsistent"
    }
    require(maximumOutputSize > 0) { "maximumOutputSize must be positive" }
    if (maximumOutputSize <= floorOutputSize || currentScale == 0.0) return 0.0
    if (attemptedOutputSize <= maximumOutputSize) return currentScale

    val availableGrowth = maximumOutputSize - floorOutputSize
    val observedGrowth = attemptedOutputSize.toLong() - floorOutputSize
    return (currentScale * availableGrowth.toDouble() / observedGrowth * DEX_BUDGET_FEEDBACK_HEADROOM)
        .coerceIn(0.0, currentScale)
}

/**
 * Fail-closed DEX diversification for caller-selected, owned post-R8 descriptors.
 *
 * Eligible method bodies are copied into dexlib2's mutable label model. Each transformed
 * method receives deterministic conditional expansion where safe, plus an entry control-flow
 * prefix over verifier-safe unreachable payload. Additional NOPs are woven only at safe
 * instruction boundaries. Existing registers, debug items, try blocks, handlers, and branch
 * targets stay attached to their original mutable locations and are rebased by dexlib2.
 */
class SafeDexTransformer {
    fun transform(inputDex: ByteArray, request: DexTransformRequest): DexTransformationResult {
        validateRequest(request)
        val input = inputDex.copyOf()
        val dex = DexBackedDexFile.fromInputStream(null, input.inputStream())
        val salt = request.salt.copyOf()
        val deniedPrefixes = request.deniedDescriptorPrefixes
        val maximumOutputSize = if (request.enforceMaximumGrowth) {
            maximumDexOutputBytes(input.size, request.maximumGrowthRatio)
        } else {
            null
        }
        val minimumAttempt = rewriteAttempt(
            input,
            dex,
            request,
            salt,
            deniedPrefixes,
            input.size,
            0.0,
        )
        if (
            minimumAttempt.report.eligibleMethodCount == 0 &&
            request.publicClassDescriptors.isEmpty() &&
            request.allowNoEligibleMethodsSkip
        ) {
            return noEligibleMethodsResult(input, minimumAttempt)
        }
        if (!request.enforceMaximumGrowth) {
            val fullAttempt = rewriteAttempt(
                input,
                dex,
                request,
                salt,
                deniedPrefixes,
                minimumAttempt.dexBytes.size,
                1.0,
            )
            return fullAttempt.takeIf { meetsTransformationGates(it.report, request) }
                ?: throwTransformationGateFailure(fullAttempt.report, request)
        }
        val enforcedMaximumOutputSize = requireNotNull(maximumOutputSize)
        if (minimumAttempt.dexBytes.size.toLong() > enforcedMaximumOutputSize) {
            return writerFloorResultOrThrow(
                input,
                dex,
                request,
                salt,
                deniedPrefixes,
                minimumAttempt.dexBytes.size,
            )
        }
        if (minimumAttempt.dexBytes.size.toLong() == enforcedMaximumOutputSize) {
            return minimumAttempt.takeIf { meetsTransformationGates(it.report, request) }
                ?: throwTransformationGateFailure(minimumAttempt.report, request)
        }

        var best = minimumAttempt.takeIf { meetsTransformationGates(it.report, request) }
        var bestFittingAttempt = minimumAttempt
        var fittingScale = 0.0
        var failingScale = 1.0
        var budgetScale = 1.0
        var searchAttempts = 0
        while (
            searchAttempts < MAX_BUDGET_SEARCH_ATTEMPTS &&
            failingScale - fittingScale > EPSILON
        ) {
            searchAttempts++
            val attempt = rewriteAttempt(
                input,
                dex,
                request,
                salt,
                deniedPrefixes,
                minimumAttempt.dexBytes.size,
                budgetScale,
            )
            if (attempt.dexBytes.size.toLong() <= enforcedMaximumOutputSize) {
                bestFittingAttempt = attempt
                fittingScale = budgetScale
                if (meetsTransformationGates(attempt.report, request)) {
                    best = attempt
                    if (budgetScale == 1.0) return attempt
                }
            } else {
                failingScale = budgetScale
            }
            val feedbackScale = if (
                attempt.dexBytes.size.toLong() > enforcedMaximumOutputSize &&
                attempt.dexBytes.size >= minimumAttempt.dexBytes.size
            ) {
                nextDetourBudgetScale(
                    currentScale = budgetScale,
                    floorOutputSize = minimumAttempt.dexBytes.size,
                    attemptedOutputSize = attempt.dexBytes.size,
                    maximumOutputSize = enforcedMaximumOutputSize,
                )
            } else {
                Double.NaN
            }
            budgetScale = feedbackScale.takeIf {
                it.isFinite() && it > fittingScale + EPSILON && it < failingScale - EPSILON
            } ?: ((fittingScale + failingScale) / 2.0)
        }
        return best ?: throwTransformationGateFailure(bestFittingAttempt.report, request)
    }

    private fun rewriteAttempt(
        input: ByteArray,
        dex: DexBackedDexFile,
        request: DexTransformRequest,
        salt: ByteArray,
        deniedDescriptorPrefixes: Set<String>,
        growthFloorOutputSize: Int,
        budgetScale: Double,
    ): DexTransformationResult {
        val reports = mutableListOf<MethodTransformationReport>()
        var ownedMethodCount = 0
        var eligibleMethodCount = 0
        var transformedMethodCount = 0
        var shingleEffectiveMethodCount = 0
        var ownedInstructionCount = 0
        var eligibleInstructionCount = 0
        var transformedInstructionCount = 0
        var shingleEffectiveInstructionCount = 0
        val weaver = SafeNopWeaver()
        val detourPaddingByMethod = planDetourPadding(
            dex,
            request,
            salt,
            deniedDescriptorPrefixes,
            input.size,
            growthFloorOutputSize,
            budgetScale,
        )

        val rewrittenClasses = dex.classes.sortedBy(ClassDef::getType).map { classDef ->
            if (
                classDef.type !in request.ownedDescriptors &&
                classDef.type !in request.publicClassDescriptors
            ) {
                ImmutableClassDef.of(classDef)
            } else {
                val methods = if (classDef.type !in request.ownedDescriptors) {
                    classDef.methods.sortedBy(::methodId).map(ImmutableMethod::of)
                } else {
                    classDef.methods.sortedBy(::methodId).map { method ->
                    val implementation = method.implementation
                    val oldInstructions = implementation?.instructions?.toList().orEmpty()
                    val oldHash = bodySha256(implementation)
                    ownedMethodCount++
                    ownedInstructionCount += oldInstructions.size
                    val exclusion = classify(
                        classDef,
                        method,
                        implementation,
                        oldInstructions,
                        deniedDescriptorPrefixes,
                        request.externalContractMethodIds,
                    )
                    if (exclusion == null) {
                        eligibleMethodCount++
                        eligibleInstructionCount += oldInstructions.size
                    }
                    val selected = exclusion == null && selected(salt, methodId(method), request.selectionRate)
                    if (exclusion != null || !selected) {
                        reports += MethodTransformationReport(
                            methodId = methodId(method),
                            reason = exclusion ?: MethodEligibilityReason.NOT_SELECTED_BY_SALT,
                            oldBodySha256 = oldHash,
                            newBodySha256 = oldHash,
                            oldInstructionCount = oldInstructions.size,
                            newInstructionCount = oldInstructions.size,
                            codeUnitGrowth = 0,
                            insertedNopCount = 0,
                            opcodeShingleSimilarity = 1.0,
                            shingleEffectiveness = 0.0,
                        )
                        ImmutableMethod.of(method)
                    } else {
                        val receiverRegister = initializedReceiverRegister(method, requireNotNull(implementation))
                        when (
                            val weave = weaveWithShingleFallback(
                                weaver,
                                requireNotNull(implementation),
                                salt,
                                methodId(method),
                                requireNotNull(detourPaddingByMethod[methodId(method)]) {
                                    "selected eligible method has no detour budget"
                                },
                                requireNotNull(implementation).tryBlocks.none(),
                                receiverRegister,
                                if (receiverRegister != null) {
                                    if (oldInstructions.size >= LONG_METHOD_INSTRUCTION_THRESHOLD) 3 else 1
                                } else {
                                    0
                                },
                            )
                        ) {
                            NopWeaveResult.NoSafeBoundary -> {
                                reports += unchangedReport(
                                    method = method,
                                    reason = MethodEligibilityReason.NO_SAFE_WEAVE_BOUNDARY,
                                    bodySha256 = oldHash,
                                    instructionCount = oldInstructions.size,
                                )
                                ImmutableMethod.of(method)
                            }

                            NopWeaveResult.UnstableInstructionEncoding -> {
                                reports += unchangedReport(
                                    method = method,
                                    reason = MethodEligibilityReason.UNSTABLE_INSTRUCTION_ENCODING,
                                    bodySha256 = oldHash,
                                    instructionCount = oldInstructions.size,
                                )
                                ImmutableMethod.of(method)
                            }

                            is NopWeaveResult.Candidate -> {
                                if (weave.shingleEffectiveness + EPSILON < 1.0) {
                                    reports += unchangedReport(
                                        method = method,
                                        reason = MethodEligibilityReason.INEFFECTIVE_SHINGLE_TRANSFORM,
                                        bodySha256 = oldHash,
                                        instructionCount = oldInstructions.size,
                                    )
                                    ImmutableMethod.of(method)
                                } else if (weave.simHashDistance < request.minimumSimHashDistance) {
                                    reports += unchangedReport(
                                        method = method,
                                        reason = MethodEligibilityReason.INSUFFICIENT_SIMHASH_DISTANCE,
                                        bodySha256 = oldHash,
                                        instructionCount = oldInstructions.size,
                                        simHashDistance = weave.simHashDistance,
                                    )
                                    ImmutableMethod.of(method)
                                } else {
                                    val rewrittenImplementation = weave.implementation
                                    val newInstructions = rewrittenImplementation.instructions
                                    transformedMethodCount++
                                    shingleEffectiveMethodCount++
                                    transformedInstructionCount += oldInstructions.size
                                    shingleEffectiveInstructionCount += oldInstructions.size
                                    reports += MethodTransformationReport(
                                        methodId = methodId(method),
                                        reason = MethodEligibilityReason.TRANSFORMED,
                                        oldBodySha256 = oldHash,
                                        newBodySha256 = bodySha256(rewrittenImplementation),
                                        oldInstructionCount = oldInstructions.size,
                                        newInstructionCount = newInstructions.size,
                                        codeUnitGrowth = newInstructions.sumOf(Instruction::getCodeUnits) -
                                            oldInstructions.sumOf(Instruction::getCodeUnits),
                                        insertedNopCount = weave.insertedNopCount,
                                        insertedPayloadInstructionCount = weave.insertedPayloadInstructionCount,
                                        insertedRelayInstructionCount = weave.insertedRelayInstructionCount,
                                        insertedOpaqueDiamondCount = weave.insertedOpaqueDiamondCount,
                                        opcodeShingleSimilarity = weave.opcodeShingleSimilarity,
                                        shingleEffectiveness = weave.shingleEffectiveness,
                                        simHashDistance = weave.simHashDistance,
                                    )
                                    ImmutableMethod(
                                        method.definingClass,
                                        method.name,
                                        method.parameters,
                                        method.returnType,
                                        method.accessFlags,
                                        method.annotations,
                                        method.hiddenApiRestrictions,
                                        rewrittenImplementation,
                                    )
                                }
                            }
                        }
                    }
                    }
                }
                ImmutableClassDef(
                    classDef.type,
                    publicizedAccessFlags(classDef, request.publicClassDescriptors),
                    classDef.superclass,
                    classDef.interfaces,
                    classDef.sourceFile,
                    classDef.annotations,
                    classDef.fields,
                    methods,
                )
            }
        }

        val transformedMethodCoverage = coverage(transformedMethodCount, eligibleMethodCount)
        val transformedInstructionCoverage = coverage(transformedInstructionCount, eligibleInstructionCount)

        val output = writeDex(dex, rewrittenClasses)
        verifyDexHeader(output)
        DexIdTableValidator.requireValid(output, "rewritten DEX")
        DexBackedDexFile.fromInputStream(null, output.inputStream()).classes.size
        val growth = (output.size - input.size).toDouble() / input.size

        return DexTransformationResult(
            output,
            DexTransformationReport(
                inputSha256 = sha256(input),
                outputSha256 = sha256(output),
                saltSha256 = sha256(salt),
                methods = reports.sortedBy(MethodTransformationReport::methodId),
                ownedMethodCount = ownedMethodCount,
                eligibleMethodCount = eligibleMethodCount,
                transformedMethodCount = transformedMethodCount,
                shingleEffectiveMethodCount = shingleEffectiveMethodCount,
                ownedInstructionCount = ownedInstructionCount,
                eligibleInstructionCount = eligibleInstructionCount,
                transformedInstructionCount = transformedInstructionCount,
                shingleEffectiveInstructionCount = shingleEffectiveInstructionCount,
                ownedInstructionCoverage = coverage(transformedInstructionCount, ownedInstructionCount),
                eligibleMethodCoverage = coverage(eligibleMethodCount, ownedMethodCount),
                eligibleInstructionCoverage = coverage(eligibleInstructionCount, ownedInstructionCount),
                transformedMethodCoverage = transformedMethodCoverage,
                transformedInstructionCoverage = transformedInstructionCoverage,
                shingleEffectiveMethodCoverage = coverage(shingleEffectiveMethodCount, eligibleMethodCount),
                shingleEffectiveInstructionCoverage = coverage(
                    shingleEffectiveInstructionCount,
                    eligibleInstructionCount,
                ),
                byteGrowthRatio = growth,
                writerFloorSkipped = false,
                noEligibleMethodsSkipped = false,
                minimumSimHashDistance = request.minimumSimHashDistance,
                publicizedClassDescriptors = request.publicClassDescriptors.toSortedSet(),
            ),
        )
    }

    private fun weaveWithShingleFallback(
        weaver: SafeNopWeaver,
        implementation: MethodImplementation,
        salt: ByteArray,
        methodId: String,
        detourPaddingNopCount: Int,
        expandConditionals: Boolean,
        receiverRegister: Int?,
        opaqueDiamondCount: Int,
    ): NopWeaveResult {
        val first = weaver.weave(
            implementation,
            salt,
            methodId,
            detourPaddingNopCount,
            expandConditionals,
            receiverRegister,
            opaqueDiamondCount,
        )
        if (first !is NopWeaveResult.Candidate || first.shingleEffectiveness + EPSILON >= 1.0) {
            return first
        }
        for (retry in 1..MAX_SHINGLE_WEAVE_RETRIES) {
            val candidate = weaver.weave(
                implementation,
                salt,
                "$methodId\u0000shingle-retry-$retry",
                detourPaddingNopCount,
                expandConditionals,
                receiverRegister,
                opaqueDiamondCount,
            )
            if (candidate is NopWeaveResult.Candidate && candidate.shingleEffectiveness + EPSILON >= 1.0) {
                return candidate
            }
        }
        return first
    }

    private fun meetsTransformationGates(
        report: DexTransformationReport,
        request: DexTransformRequest,
    ): Boolean = (report.transformedMethodCount > 0 || report.publicizedClassDescriptors.isNotEmpty()) &&
        report.transformedMethodCoverage + EPSILON >= request.minimumCoverage &&
        report.transformedInstructionCoverage + EPSILON >= request.minimumCoverage

    private fun throwTransformationGateFailure(
        report: DexTransformationReport,
        request: DexTransformRequest,
    ): Nothing {
        if (report.transformedMethodCount == 0) {
            if (report.methods.any { it.reason == MethodEligibilityReason.INSUFFICIENT_SIMHASH_DISTANCE }) {
                throw DexTransformationRejectedException(
                    "DEX hardening requires at least one transformation meeting minimum SimHash distance " +
                        request.minimumSimHashDistance,
                )
            }
            throw DexTransformationRejectedException(
                "DEX hardening requires at least one shingle-effective transformation",
            )
        }
        throw DexTransformationRejectedException(
            "eligible method coverage ${report.transformedMethodCoverage} and eligible instruction coverage " +
                "${report.transformedInstructionCoverage} must both meet minimum coverage ${request.minimumCoverage}",
        )
    }

    private fun writerFloorResultOrThrow(
        input: ByteArray,
        dex: DexBackedDexFile,
        request: DexTransformRequest,
        salt: ByteArray,
        deniedDescriptorPrefixes: Set<String>,
        floorOutputSize: Int,
    ): DexTransformationResult {
        val growth = (floorOutputSize - input.size).toDouble() / input.size
        if (request.publicClassDescriptors.isNotEmpty()) {
            throw DexTransformationRejectedException(
                "required DEX class access compatibility exceeds maximum growth ${request.maximumGrowthRatio}",
            )
        }
        if (!request.allowWriterFloorSkip) {
            throw DexTransformationRejectedException(
                "DEX byte growth $growth exceeds maximum growth ${request.maximumGrowthRatio}",
            )
        }

        val reports = mutableListOf<MethodTransformationReport>()
        var ownedMethodCount = 0
        var eligibleMethodCount = 0
        var ownedInstructionCount = 0
        var eligibleInstructionCount = 0
        dex.classes.sortedBy(ClassDef::getType)
            .filter { classDef -> classDef.type in request.ownedDescriptors }
            .forEach { classDef ->
                classDef.methods.sortedBy(::methodId).forEach { method ->
                    val implementation = method.implementation
                    val instructions = implementation?.instructions?.toList().orEmpty()
                    val bodyHash = bodySha256(implementation)
                    ownedMethodCount++
                    ownedInstructionCount += instructions.size
                    val exclusion = classify(
                        classDef,
                        method,
                        implementation,
                        instructions,
                        deniedDescriptorPrefixes,
                        request.externalContractMethodIds,
                    )
                    if (exclusion == null) {
                        eligibleMethodCount++
                        eligibleInstructionCount += instructions.size
                    }
                    reports += unchangedReport(
                        method = method,
                        reason = exclusion ?: MethodEligibilityReason.WRITER_FLOOR_GROWTH,
                        bodySha256 = bodyHash,
                        instructionCount = instructions.size,
                    )
                }
            }
        val inputHash = sha256(input)
        DexIdTableValidator.requireValid(input, "writer-floor preserved DEX")
        return DexTransformationResult(
            dexBytes = input.copyOf(),
            report = DexTransformationReport(
                inputSha256 = inputHash,
                outputSha256 = inputHash,
                saltSha256 = sha256(salt),
                methods = reports,
                ownedMethodCount = ownedMethodCount,
                eligibleMethodCount = eligibleMethodCount,
                transformedMethodCount = 0,
                shingleEffectiveMethodCount = 0,
                ownedInstructionCount = ownedInstructionCount,
                eligibleInstructionCount = eligibleInstructionCount,
                transformedInstructionCount = 0,
                shingleEffectiveInstructionCount = 0,
                ownedInstructionCoverage = 0.0,
                eligibleMethodCoverage = coverage(eligibleMethodCount, ownedMethodCount),
                eligibleInstructionCoverage = coverage(eligibleInstructionCount, ownedInstructionCount),
                transformedMethodCoverage = 0.0,
                transformedInstructionCoverage = 0.0,
                shingleEffectiveMethodCoverage = 0.0,
                shingleEffectiveInstructionCoverage = 0.0,
                byteGrowthRatio = 0.0,
                writerFloorSkipped = true,
                noEligibleMethodsSkipped = false,
                minimumSimHashDistance = request.minimumSimHashDistance,
            ),
        )
    }

    private fun noEligibleMethodsResult(
        input: ByteArray,
        minimumAttempt: DexTransformationResult,
    ): DexTransformationResult {
        val attemptedReport = minimumAttempt.report
        require(attemptedReport.eligibleMethodCount == 0) {
            "no-eligible-method skip requires zero eligible methods"
        }
        require(attemptedReport.transformedMethodCount == 0 && attemptedReport.transformedInstructionCount == 0) {
            "no-eligible-method skip cannot discard transformed code"
        }
        val inputValidationFailure = runCatching {
            DexIdTableValidator.requireValid(input, "no-eligible input DEX")
        }.exceptionOrNull()
        if (inputValidationFailure != null) {
            DexIdTableValidator.requireValid(minimumAttempt.dexBytes, "canonicalized no-eligible DEX")
            require(!input.contentEquals(minimumAttempt.dexBytes)) {
                "DexPool did not canonicalize invalid no-eligible DEX: ${inputValidationFailure.message}"
            }
            return minimumAttempt.copy(
                report = attemptedReport.copy(
                    writerFloorSkipped = false,
                    noEligibleMethodsSkipped = false,
                    inputCanonicalized = true,
                ),
            )
        }
        val inputHash = sha256(input)
        return DexTransformationResult(
            dexBytes = input.copyOf(),
            report = attemptedReport.copy(
                inputSha256 = inputHash,
                outputSha256 = inputHash,
                byteGrowthRatio = 0.0,
                writerFloorSkipped = false,
                noEligibleMethodsSkipped = true,
                inputCanonicalized = false,
            ),
        )
    }

    private fun validateRequest(request: DexTransformRequest) {
        require(request.ownedDescriptorPrefixes.all(::isDescriptorPrefix)) {
            "ownedDescriptorPrefixes must use DEX form such as Lcom/example/"
        }
        require(request.ownedDescriptors.isNotEmpty() || request.publicClassDescriptors.isNotEmpty()) {
            "At least one exact owned or access compatibility descriptor is required"
        }
        require(request.ownedDescriptors.all(::isObjectDescriptor)) {
            "ownedDescriptors must contain exact DEX class descriptors"
        }
        require(request.publicClassDescriptors.all(::isObjectDescriptor)) {
            "publicClassDescriptors must contain exact DEX class descriptors"
        }
        require(request.salt.isNotEmpty()) { "Deterministic salt must not be empty" }
        require(request.minimumCoverage.isFinite() && request.minimumCoverage in 0.0..1.0) {
            "minimumCoverage must be between 0.0 and 1.0"
        }
        require(request.minimumSimHashDistance in 0..Long.SIZE_BITS) {
            "minimumSimHashDistance must be between 0 and 64"
        }
        require(request.maximumGrowthRatio.isFinite() && request.maximumGrowthRatio >= 0.0) {
            "maximumGrowthRatio must be finite and non-negative"
        }
        require(request.selectionRate.isFinite() && request.selectionRate in 0.0..1.0) {
            "selectionRate must be between 0.0 and 1.0"
        }
        require(request.deniedDescriptorPrefixes.all(::isDescriptorPrefix)) {
            "deniedDescriptorPrefixes must use DEX form such as Lcom/example/"
        }
        require(request.externalContractMethodIds.all(::isDexMethodId)) {
            "externalContractMethodIds must use full DEX method IDs"
        }
    }

    private fun classify(
        classDef: ClassDef,
        method: Method,
        implementation: MethodImplementation?,
        instructions: List<Instruction>,
        deniedDescriptorPrefixes: Set<String>,
        externalContractMethodIds: Set<String>,
    ): MethodEligibilityReason? {
        if (deniedDescriptorPrefixes.any(classDef.type::startsWith)) {
            return MethodEligibilityReason.DENIED_DESCRIPTOR
        }
        if (GENERATED_CLASS.containsMatchIn(classDef.type)) return MethodEligibilityReason.GENERATED_CLASS
        if (method.name == "<init>") return MethodEligibilityReason.CONSTRUCTOR
        if (method.name == "<clinit>") return MethodEligibilityReason.CLASS_INITIALIZER
        if (AccessFlags.ABSTRACT.isSet(method.accessFlags)) return MethodEligibilityReason.ABSTRACT
        if (AccessFlags.NATIVE.isSet(method.accessFlags)) return MethodEligibilityReason.NATIVE
        if (AccessFlags.BRIDGE.isSet(method.accessFlags)) return MethodEligibilityReason.BRIDGE
        if (AccessFlags.SYNTHETIC.isSet(method.accessFlags)) return MethodEligibilityReason.SYNTHETIC
        if (
            AccessFlags.SYNCHRONIZED.isSet(method.accessFlags) ||
            AccessFlags.DECLARED_SYNCHRONIZED.isSet(method.accessFlags)
        ) return MethodEligibilityReason.SYNCHRONIZED
        if (isCoroutineStateMachine(classDef, method)) return MethodEligibilityReason.COROUTINE_STATE_MACHINE
        if (methodId(method) in externalContractMethodIds) return MethodEligibilityReason.EXTERNAL_CONTRACT
        if (implementation == null) return MethodEligibilityReason.NO_IMPLEMENTATION
        if (instructions.isEmpty()) return MethodEligibilityReason.EMPTY_IMPLEMENTATION
        if (instructions.any { it.opcode == Opcode.MONITOR_ENTER || it.opcode == Opcode.MONITOR_EXIT }) {
            return MethodEligibilityReason.MONITOR_INSTRUCTION
        }
        if (instructions.any(::isSwitchOrPayload)) return MethodEligibilityReason.SWITCH_OR_PAYLOAD
        return null
    }

    private fun isCoroutineStateMachine(classDef: ClassDef, method: Method): Boolean {
        if (method.name == "invokeSuspend") return true
        val superclass = classDef.superclass.orEmpty()
        if (COROUTINE_SUPERCLASS_MARKERS.any(superclass::contains)) return true
        return classDef.interfaces.any { it == "Lkotlin/coroutines/Continuation;" }
    }

    private fun publicizedAccessFlags(classDef: ClassDef, publicClassDescriptors: Set<String>): Int {
        if (classDef.type !in publicClassDescriptors) return classDef.accessFlags
        require(
            !AccessFlags.PUBLIC.isSet(classDef.accessFlags) &&
                !AccessFlags.PRIVATE.isSet(classDef.accessFlags) &&
                !AccessFlags.PROTECTED.isSet(classDef.accessFlags),
        ) { "DEX access compatibility can only publicize package-private classes: ${classDef.type}" }
        return classDef.accessFlags or AccessFlags.PUBLIC.value
    }

    private fun isDescriptorPrefix(value: String): Boolean = value.startsWith('L') && value.endsWith('/')

    private fun isDexMethodId(value: String): Boolean {
        val arrow = value.indexOf("->")
        if (arrow <= 0 || value.indexOf("->", arrow + 2) >= 0) return false
        if (!isObjectDescriptor(value.substring(0, arrow))) return false
        val parametersStart = value.indexOf('(', arrow + 2)
        if (parametersStart <= arrow + 2) return false
        val parametersEnd = value.indexOf(')', parametersStart + 1)
        if (parametersEnd < 0 || value.indexOf(')', parametersEnd + 1) >= 0) return false
        val methodName = value.substring(arrow + 2, parametersStart)
        if (methodName.any { it == '(' || it == ')' || it == ';' || it == '[' || it == '/' }) return false

        var cursor = parametersStart + 1
        while (cursor < parametersEnd) {
            val end = descriptorEnd(value, cursor, allowVoid = false) ?: return false
            if (end > parametersEnd) return false
            cursor = end
        }
        if (cursor != parametersEnd) return false
        val returnEnd = descriptorEnd(value, parametersEnd + 1, allowVoid = true) ?: return false
        return returnEnd == value.length
    }

    private fun isObjectDescriptor(value: String): Boolean =
        descriptorEnd(value, 0, allowVoid = false) == value.length && value.startsWith('L')

    private fun descriptorEnd(value: String, start: Int, allowVoid: Boolean): Int? {
        if (start !in value.indices) return null
        var cursor = start
        while (cursor < value.length && value[cursor] == '[') cursor++
        val arrayDepth = cursor - start
        if (cursor >= value.length) return null
        return when (value[cursor]) {
            'V' -> (cursor + 1).takeIf { allowVoid && arrayDepth == 0 }
            'Z', 'B', 'S', 'C', 'I', 'J', 'F', 'D' -> cursor + 1
            'L' -> {
                val end = value.indexOf(';', cursor + 1)
                val body = if (end >= 0) value.substring(cursor + 1, end) else ""
                (end + 1).takeIf {
                    end >= 0 &&
                        body.isNotEmpty() &&
                        body.split('/').all(String::isNotEmpty) &&
                        body.none { it == '.' || it == '[' || it == '(' || it == ')' }
                }
            }
            else -> null
        }
    }

    private fun isSwitchOrPayload(instruction: Instruction): Boolean =
        instruction is PayloadInstruction ||
            instruction.opcode == Opcode.PACKED_SWITCH ||
            instruction.opcode == Opcode.SPARSE_SWITCH ||
            instruction.opcode == Opcode.FILL_ARRAY_DATA

    private fun selected(salt: ByteArray, methodId: String, selectionRate: Double): Boolean {
        if (selectionRate == 1.0) return true
        if (selectionRate == 0.0) return false
        val digest = saltedDigest(salt, methodId)
        val bucket = ((digest[0].toInt() and 0xff) shl 8) or (digest[1].toInt() and 0xff)
        return bucket / 65536.0 < selectionRate
    }

    private fun planDetourPadding(
        dex: DexBackedDexFile,
        request: DexTransformRequest,
        salt: ByteArray,
        deniedDescriptorPrefixes: Set<String>,
        inputSize: Int,
        growthFloorOutputSize: Int,
        budgetScale: Double,
    ): Map<String, Int> {
        require(budgetScale.isFinite() && budgetScale in 0.0..1.0) {
            "budgetScale must be between 0.0 and 1.0"
        }
        val candidates = dex.classes.asSequence()
            .filter { it.type in request.ownedDescriptors }
            .flatMap { classDef ->
                classDef.methods.asSequence().mapNotNull { method ->
                    val implementation = method.implementation ?: return@mapNotNull null
                    val instructions = implementation.instructions.toList()
                    val id = methodId(method)
                    if (
                        classify(
                            classDef,
                            method,
                            implementation,
                            instructions,
                            deniedDescriptorPrefixes,
                            request.externalContractMethodIds,
                        ) != null || !selected(salt, id, request.selectionRate)
                    ) {
                        return@mapNotNull null
                    }
                    DetourCandidate(
                        methodId = id,
                        instructionCount = instructions.size,
                        payloadFloor = when {
                            implementation.registerCount == 0 -> 1
                            instructions.size >= LONG_METHOD_INSTRUCTION_THRESHOLD -> MIN_LONG_METHOD_BOUNDED_PAYLOAD
                            else -> MIN_METHOD_BOUNDED_PAYLOAD
                        },
                        originalCodeUnits = instructions.sumOf(Instruction::getCodeUnits),
                        originalBodySha256 = bodySha256(implementation),
                    )
                }
            }
            .toList()
        if (candidates.isEmpty()) return emptyMap()
        if (!request.enforceMaximumGrowth) {
            return candidates.associate { candidate ->
                candidate.methodId to boundedPayloadTarget(candidate, salt)
            }
        }

        // Keep headroom for code-item alignment and metadata while using most of the
        // theoretical two-byte-per-code-unit growth budget.
        val utilizationByte = saltedDigest(salt, DETOUR_BUDGET_ID)[0].toInt() and 0xff
        val utilization = MIN_BUDGET_UTILIZATION +
            (MAX_BUDGET_UTILIZATION - MIN_BUDGET_UTILIZATION) * utilizationByte / 255.0
        val targetCodeUnits = detourCodeUnitBudget(
            inputSize = inputSize,
            floorOutputSize = growthFloorOutputSize,
            maximumGrowthRatio = request.maximumGrowthRatio,
            utilization = utilization * budgetScale,
        )
        val ordered = candidates.sortedBy { candidate ->
            hex(saltedDigest(salt, candidate.methodId + DETOUR_ORDER_SUFFIX))
        }
        val padding = ordered.associateTo(linkedMapOf()) { it.methodId to it.payloadFloor }
        var remaining = targetCodeUnits
        val longMethods = ordered.filter { it.instructionCount >= LONG_METHOD_INSTRUCTION_THRESHOLD }
        val longPaddingNeeded = (LONG_METHOD_PADDING_TARGET - longMethods.sumOf { padding.getValue(it.methodId) })
            .coerceAtLeast(0)
        remaining -= allocateDetourPadding(
            candidates = longMethods,
            requested = minOf(remaining, longPaddingNeeded),
            padding = padding,
            salt = salt,
        )
        allocateDetourPadding(
            candidates = ordered,
            requested = remaining,
            padding = padding,
            salt = salt,
        )
        return padding
    }

    private fun allocateDetourPadding(
        candidates: List<DetourCandidate>,
        requested: Int,
        padding: MutableMap<String, Int>,
        salt: ByteArray,
    ): Int {
        var remaining = requested
        var active = candidates
        while (remaining > 0 && active.isNotEmpty()) {
            var progressed = false
            val next = ArrayList<DetourCandidate>(active.size)
            active.forEachIndexed { index, candidate ->
                val current = padding.getValue(candidate.methodId)
                val cap = detourPaddingCap(candidate, salt)
                val room = cap - current
                if (room <= 0) return@forEachIndexed
                val methodsLeft = active.size - index
                val fairShare = maxOf(1, remaining / methodsLeft)
                val granted = minOf(room, fairShare, remaining)
                padding[candidate.methodId] = current + granted
                remaining -= granted
                progressed = progressed || granted > 0
                if (current + granted < cap) next += candidate
            }
            if (!progressed) break
            active = next
        }
        return requested - remaining
    }

    private fun detourPaddingCap(candidate: DetourCandidate, salt: ByteArray): Int {
        val longMethod = candidate.instructionCount >= LONG_METHOD_INSTRUCTION_THRESHOLD
        val absoluteCap = if (longMethod) {
            maxOf(MIN_LONG_METHOD_DETOUR_CAP, candidate.originalCodeUnits * 4)
                .coerceAtMost(MAX_LONG_METHOD_DETOUR_CAP)
        } else {
            maxOf(MIN_METHOD_DETOUR_PADDING, candidate.originalCodeUnits / 3)
                .coerceAtMost(MAX_METHOD_DETOUR_PADDING)
        }
        val minimumSaltedCap = if (longMethod) {
            minOf(absoluteCap, MIN_LONG_METHOD_SALTED_CAP)
        } else {
            maxOf(1, absoluteCap / 2)
        }
        val bucket = saltedDigest(salt, candidate.methodId + DETOUR_CAP_SUFFIX)[0].toInt() and 0xff
        return minimumSaltedCap + bucket % (absoluteCap - minimumSaltedCap + 1)
    }

    private fun boundedPayloadTarget(candidate: DetourCandidate, salt: ByteArray): Int {
        val range = if (candidate.instructionCount >= LONG_METHOD_INSTRUCTION_THRESHOLD) {
            MIN_LONG_METHOD_BOUNDED_PAYLOAD..MAX_LONG_METHOD_BOUNDED_PAYLOAD
        } else {
            MIN_METHOD_BOUNDED_PAYLOAD..MAX_METHOD_BOUNDED_PAYLOAD
        }
        val digest = saltedDigest(
            salt,
            candidate.methodId + BOUNDED_PAYLOAD_SUFFIX + candidate.originalBodySha256,
        )
        val bucket = ((digest[0].toInt() and 0xff) shl 8) or (digest[1].toInt() and 0xff)
        return range.first + bucket % (range.last - range.first + 1)
    }

    private fun initializedReceiverRegister(method: Method, implementation: MethodImplementation): Int? {
        if (AccessFlags.STATIC.isSet(method.accessFlags) || method.name == "<init>" || method.name == "<clinit>") {
            return null
        }
        val parameterWidth = method.parameterTypes.fold(1) { width, type ->
            width + if (type.toString() == "J" || type.toString() == "D") 2 else 1
        }
        val receiverRegister = implementation.registerCount - parameterWidth
        return receiverRegister.takeIf { it in 0..UByte.MAX_VALUE.toInt() }
    }

    private fun writeDex(
        source: DexBackedDexFile,
        classes: List<ImmutableClassDef>,
    ): ByteArray {
        val pool = DexPool(source.opcodes)
        classes.forEach(pool::internClass)
        val store = MemoryDataStore()
        pool.writeTo(store)
        return store.data
    }

    private fun verifyDexHeader(bytes: ByteArray) {
        require(bytes.size >= 112) { "DEX output is too short" }
        require(bytes.copyOfRange(0, 4).contentEquals(byteArrayOf('d'.code.toByte(), 'e'.code.toByte(), 'x'.code.toByte(), '\n'.code.toByte()))) {
            "DEX output has invalid magic"
        }
        val expectedSignature = MessageDigest.getInstance("SHA-1").digest(bytes.copyOfRange(32, bytes.size))
        check(expectedSignature.contentEquals(bytes.copyOfRange(12, 32))) { "dexlib2 emitted an invalid DEX signature" }
        val expectedChecksum = Adler32().apply { update(bytes, 12, bytes.size - 12) }.value.toInt()
        val actualChecksum = ByteBuffer.wrap(bytes, 8, 4).order(ByteOrder.LITTLE_ENDIAN).int
        check(expectedChecksum == actualChecksum) { "dexlib2 emitted an invalid DEX checksum" }
    }

    private fun saltedDigest(salt: ByteArray, methodId: String): ByteArray =
        MessageDigest.getInstance("SHA-256").apply {
            update(SALT_DOMAIN)
            updateInt(salt.size)
            update(salt)
            val methodBytes = methodId.toByteArray(StandardCharsets.UTF_8)
            updateInt(methodBytes.size)
            update(methodBytes)
        }.digest()

    private fun MessageDigest.updateInt(value: Int) {
        update(ByteBuffer.allocate(Int.SIZE_BYTES).order(ByteOrder.BIG_ENDIAN).putInt(value).array())
    }

    private fun bodySha256(implementation: MethodImplementation?): String {
        val digest = MessageDigest.getInstance("SHA-256")
        if (implementation == null) return hex(digest.digest())
        digest.update("registers=${implementation.registerCount}\n".toByteArray(StandardCharsets.UTF_8))
        implementation.instructions.forEach { instruction ->
            digest.update(canonicalInstruction(instruction).toByteArray(StandardCharsets.UTF_8))
            digest.update('\n'.code.toByte())
        }
        return hex(digest.digest())
    }

    private fun canonicalInstruction(instruction: Instruction): String = buildString {
        append(instruction.opcode.name)
        append('|').append(instruction.codeUnits)
        if (instruction is OneRegisterInstruction) append("|a=").append(instruction.registerA)
        if (instruction is TwoRegisterInstruction) append("|b=").append(instruction.registerB)
        if (instruction is ThreeRegisterInstruction) append("|c=").append(instruction.registerC)
        if (instruction is VariableRegisterInstruction) append("|count=").append(instruction.registerCount)
        if (instruction is FiveRegisterInstruction) {
            append("|cdefg=").append(instruction.registerC).append(',').append(instruction.registerD)
                .append(',').append(instruction.registerE).append(',').append(instruction.registerF)
                .append(',').append(instruction.registerG)
        }
        if (instruction is RegisterRangeInstruction) append("|start=").append(instruction.startRegister)
        if (instruction is WideLiteralInstruction) append("|literal=").append(instruction.wideLiteral)
        if (instruction is OffsetInstruction) append("|offset=").append(instruction.codeOffset)
        if (instruction is ReferenceInstruction) {
            append("|reference=").append(DexFormatter.INSTANCE.getReference(instruction.reference))
            append("|referenceType=").append(instruction.referenceType)
        }
        if (instruction is DualReferenceInstruction) {
            append("|reference2=").append(DexFormatter.INSTANCE.getReference(instruction.reference2))
            append("|referenceType2=").append(instruction.referenceType2)
        }
        if (instruction is VerificationErrorInstruction) append("|verificationError=").append(instruction.verificationError)
        if (instruction is InlineIndexInstruction) append("|inlineIndex=").append(instruction.inlineIndex)
        if (instruction is VtableIndexInstruction) append("|vtableIndex=").append(instruction.vtableIndex)
        if (instruction is FieldOffsetInstruction) append("|fieldOffset=").append(instruction.fieldOffset)
        when (instruction) {
            is ArrayPayload -> append("|arrayWidth=").append(instruction.elementWidth)
                .append("|elements=").append(instruction.arrayElements.joinToString(","))
            is PackedSwitchPayload -> append("|packed=").append(
                instruction.switchElements.joinToString(",") { "${it.key}:${it.offset}" },
            )
            is SparseSwitchPayload -> append("|sparse=").append(
                instruction.switchElements.joinToString(",") { "${it.key}:${it.offset}" },
            )
        }
    }

    private fun methodId(method: Method): String = buildString {
        append(method.definingClass).append("->").append(method.name).append('(')
        method.parameterTypes.forEach(::append)
        append(')').append(method.returnType)
    }

    private fun sha256(bytes: ByteArray): String = hex(MessageDigest.getInstance("SHA-256").digest(bytes))

    private fun coverage(numerator: Int, denominator: Int): Double =
        if (denominator == 0) 0.0 else numerator.toDouble() / denominator

    private fun unchangedReport(
        method: Method,
        reason: MethodEligibilityReason,
        bodySha256: String,
        instructionCount: Int,
        opcodeShingleSimilarity: Double = 1.0,
        shingleEffectiveness: Double = 0.0,
        simHashDistance: Int = 0,
    ) = MethodTransformationReport(
        methodId = methodId(method),
        reason = reason,
        oldBodySha256 = bodySha256,
        newBodySha256 = bodySha256,
        oldInstructionCount = instructionCount,
        newInstructionCount = instructionCount,
        codeUnitGrowth = 0,
        insertedNopCount = 0,
        opcodeShingleSimilarity = opcodeShingleSimilarity,
        shingleEffectiveness = shingleEffectiveness,
        simHashDistance = simHashDistance,
    )

    private fun hex(bytes: ByteArray): String = bytes.joinToString("") { "%02x".format(it.toInt() and 0xff) }

    private companion object {
        const val EPSILON = 1e-12
        const val MIN_METHOD_DETOUR_PADDING = 8
        const val MAX_METHOD_DETOUR_PADDING = 96
        const val LONG_METHOD_INSTRUCTION_THRESHOLD = 100
        const val MIN_METHOD_BOUNDED_PAYLOAD = 8
        const val MAX_METHOD_BOUNDED_PAYLOAD = 16
        const val MIN_LONG_METHOD_BOUNDED_PAYLOAD = 24
        const val MAX_LONG_METHOD_BOUNDED_PAYLOAD = 40
        const val LONG_METHOD_PADDING_TARGET = 30_000
        const val MIN_LONG_METHOD_DETOUR_CAP = 2_048
        const val MIN_LONG_METHOD_SALTED_CAP = 1_024
        const val MAX_LONG_METHOD_DETOUR_CAP = 4_096
        const val MIN_BUDGET_UTILIZATION = 0.78
        const val MAX_BUDGET_UTILIZATION = 0.84
        const val MAX_BUDGET_SEARCH_ATTEMPTS = 8
        const val MAX_SHINGLE_WEAVE_RETRIES = 16
        const val DETOUR_BUDGET_ID = "<detour-budget>"
        const val DETOUR_ORDER_SUFFIX = "\u0000detour-order"
        const val DETOUR_CAP_SUFFIX = "\u0000detour-cap"
        const val BOUNDED_PAYLOAD_SUFFIX = "\u0000bounded-payload\u0000"
        val SALT_DOMAIN = "com.holin.android.hardening/1.3.0/safe-dex/v1\u0000".toByteArray(StandardCharsets.UTF_8)
        val COROUTINE_SUPERCLASS_MARKERS = listOf(
            "BaseContinuationImpl",
            "ContinuationImpl",
            "SuspendLambda",
            "RestrictedContinuationImpl",
        )
        val GENERATED_CLASS = Regex(
            "(?:/R(?:\\$[^;]+)?|/BR|/BuildConfig|/MyObjectBox);$|/databinding/[^;]*Binding;$",
        )
    }

    private data class DetourCandidate(
        val methodId: String,
        val instructionCount: Int,
        val payloadFloor: Int,
        val originalCodeUnits: Int,
        val originalBodySha256: String,
    )
}
