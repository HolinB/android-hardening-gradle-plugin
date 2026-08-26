package com.holin.android.hardening.dex

data class DexTransformRequest(
    val ownedDescriptorPrefixes: Set<String>,
    val ownedDescriptors: Set<String>,
    val salt: ByteArray,
    val minimumCoverage: Double = 0.0,
    val minimumSimHashDistance: Int = 0,
    val maximumGrowthRatio: Double = 0.10,
    val enforceMaximumGrowth: Boolean = true,
    val selectionRate: Double = 1.0,
    val deniedDescriptorPrefixes: Set<String> = emptySet(),
    val externalContractMethodIds: Set<String> = emptySet(),
    val publicClassDescriptors: Set<String> = emptySet(),
    val allowWriterFloorSkip: Boolean = false,
    val allowNoEligibleMethodsSkip: Boolean = false,
)

data class DexTransformationResult(
    val dexBytes: ByteArray,
    val report: DexTransformationReport,
)

data class DexTransformationReport(
    val inputSha256: String,
    val outputSha256: String,
    val saltSha256: String,
    val methods: List<MethodTransformationReport>,
    val ownedMethodCount: Int,
    val eligibleMethodCount: Int,
    val transformedMethodCount: Int,
    val shingleEffectiveMethodCount: Int,
    val ownedInstructionCount: Int,
    val eligibleInstructionCount: Int,
    val transformedInstructionCount: Int,
    val shingleEffectiveInstructionCount: Int,
    val ownedInstructionCoverage: Double,
    val eligibleMethodCoverage: Double,
    val eligibleInstructionCoverage: Double,
    val transformedMethodCoverage: Double,
    val transformedInstructionCoverage: Double,
    val shingleEffectiveMethodCoverage: Double,
    val shingleEffectiveInstructionCoverage: Double,
    val byteGrowthRatio: Double,
    val writerFloorSkipped: Boolean,
    val noEligibleMethodsSkipped: Boolean = false,
    val inputCanonicalized: Boolean = false,
    val minimumSimHashDistance: Int = 0,
    val publicizedClassDescriptors: Set<String> = emptySet(),
)

data class MethodTransformationReport(
    val methodId: String,
    val reason: MethodEligibilityReason,
    val oldBodySha256: String,
    val newBodySha256: String,
    val oldInstructionCount: Int,
    val newInstructionCount: Int,
    val codeUnitGrowth: Int,
    val insertedNopCount: Int,
    val insertedPayloadInstructionCount: Int = 0,
    val insertedRelayInstructionCount: Int = 0,
    val insertedOpaqueDiamondCount: Int = 0,
    val opcodeShingleSimilarity: Double,
    val shingleEffectiveness: Double,
    val simHashDistance: Int = 0,
)

enum class MethodEligibilityReason {
    TRANSFORMED,
    NOT_SELECTED_BY_SALT,
    CONSTRUCTOR,
    CLASS_INITIALIZER,
    ABSTRACT,
    NATIVE,
    BRIDGE,
    SYNTHETIC,
    SYNCHRONIZED,
    COROUTINE_STATE_MACHINE,
    EXTERNAL_CONTRACT,
    DENIED_DESCRIPTOR,
    GENERATED_CLASS,
    NO_IMPLEMENTATION,
    EMPTY_IMPLEMENTATION,
    MONITOR_INSTRUCTION,
    SWITCH_OR_PAYLOAD,
    NO_SAFE_WEAVE_BOUNDARY,
    UNSTABLE_INSTRUCTION_ENCODING,
    INEFFECTIVE_SHINGLE_TRANSFORM,
    INSUFFICIENT_SIMHASH_DISTANCE,
    WRITER_FLOOR_GROWTH,
}

class DexTransformationRejectedException(message: String) : IllegalStateException(message)
