package com.holin.android.hardening.artifact

import com.android.aapt.Resources
import com.android.tools.smali.dexlib2.AccessFlags
import com.android.tools.smali.dexlib2.Opcode
import com.android.tools.smali.dexlib2.dexbacked.DexBackedDexFile
import com.android.tools.smali.dexlib2.formatter.DexFormatter
import com.android.tools.smali.dexlib2.iface.ClassDef
import com.android.tools.smali.dexlib2.iface.Method
import com.android.tools.smali.dexlib2.iface.MethodImplementation
import com.android.tools.smali.dexlib2.iface.debug.EndLocal
import com.android.tools.smali.dexlib2.iface.debug.LineNumber
import com.android.tools.smali.dexlib2.iface.debug.LocalInfo
import com.android.tools.smali.dexlib2.iface.debug.RestartLocal
import com.android.tools.smali.dexlib2.iface.debug.SetSourceFile
import com.android.tools.smali.dexlib2.iface.debug.StartLocal
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
import com.android.tools.smali.dexlib2.iface.value.BooleanEncodedValue
import com.android.tools.smali.dexlib2.iface.value.ByteEncodedValue
import com.android.tools.smali.dexlib2.iface.value.CharEncodedValue
import com.android.tools.smali.dexlib2.iface.value.DoubleEncodedValue
import com.android.tools.smali.dexlib2.iface.value.EncodedValue
import com.android.tools.smali.dexlib2.iface.value.FloatEncodedValue
import com.android.tools.smali.dexlib2.iface.value.IntEncodedValue
import com.android.tools.smali.dexlib2.iface.value.LongEncodedValue
import com.android.tools.smali.dexlib2.iface.value.NullEncodedValue
import com.android.tools.smali.dexlib2.iface.value.ShortEncodedValue
import com.google.protobuf.UnknownFieldSet
import com.holin.android.hardening.dex.DexIdTableValidator
import com.holin.android.hardening.dex.DexClassAccessCompatibility
import com.holin.android.hardening.dex.MethodEligibilityReason
import com.holin.android.hardening.dex.NormalizedOpcodeSimHash
import com.holin.android.hardening.dex.SafeUnreachablePayloadContract
import com.holin.android.hardening.resources.ImageMetrics
import com.holin.android.hardening.resources.ImageTransformStatus
import com.holin.android.hardening.resources.PROTO_DIVERSIFICATION_FIELD_NUMBER
import com.holin.android.hardening.resources.AaptResourceEntryCompat
import com.holin.android.hardening.resources.SfntFontDiversifier
import com.holin.android.hardening.resources.WebpImageMetrics
import com.holin.android.hardening.state.Sha256
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.file.Path
import java.security.MessageDigest
import java.util.zip.Adler32
import java.util.zip.ZipFile

data class DexSemanticVerificationScope(
    val ownedDescriptors: Set<String>,
    val deniedDescriptorPrefixes: Set<String>,
    val externalContractMethodIds: Set<String>,
    val accessCompatibilityDescriptors: Set<String> = ownedDescriptors,
)

/**
 * Establishes semantic equivalence after the rewritten AAB has been materialized.
 * This verifier deliberately reparses both archives and never treats planner output
 * bytes, replacement declarations, or the ZIP rewriter as evidence of success.
 */
class BundlePostRewriteSemanticVerifier {
    private val sfntFontDiversifier = SfntFontDiversifier()

    fun verify(
        ordinaryBundle: Path,
        rewrittenBundle: Path,
        manifest: BundleRewriteManifest,
        plan: HardenedBundlePlanReport,
        contentSalt: ByteArray,
        dexScope: DexSemanticVerificationScope,
    ): List<BundleSemanticVerificationResult> {
        require(contentSalt.isNotEmpty()) { "semantic verification content salt must not be empty" }
        val contentSaltSha256 = Sha256.hex(contentSalt)
        require(plan.contentSaltSha256 == manifest.contentSaltSha256) {
            "semantic verification plan and manifest content salt hashes differ"
        }
        require(contentSaltSha256 == plan.contentSaltSha256) {
            "semantic verification content salt does not match the plan"
        }
        require(contentSaltSha256 == manifest.contentSaltSha256) {
            "semantic verification content salt does not match the rewrite manifest"
        }
        require(Sha256.file(ordinaryBundle) == manifest.originalAabSha256) {
            "semantic verification ordinary AAB does not match the rewrite manifest"
        }
        require(plan.sourceAabSha256 == manifest.originalAabSha256) {
            "semantic verification plan does not match the ordinary AAB"
        }
        val ordinary = readEntries(ordinaryBundle)
        val rewritten = readEntries(rewrittenBundle)
        verifyDexClosure(ordinary, rewritten, manifest, plan.dex, dexScope)
        return manifest.entries.asSequence()
            .filter { it.action == BundleRewriteAction.TRANSFORMED }
            .map { entry ->
                val oldPath = requireNotNull(entry.oldPath)
                val newPath = requireNotNull(entry.newPath)
                val before = requireNotNull(ordinary[oldPath]) { "semantic verifier cannot read $oldPath" }
                val after = requireNotNull(rewritten[newPath]) { "semantic verifier cannot read $newPath" }
                require(Sha256.hex(before) == entry.oldSha256 && Sha256.hex(after) == entry.newSha256) {
                    "semantic verifier entry hashes differ from the rewrite manifest for $oldPath"
                }
                when (requireNotNull(entry.semanticVerifier)) {
                    BundleSemanticVerifier.DEX_SEMANTICS -> verifyDex(
                        oldPath,
                        before,
                        after,
                        plan.dex,
                        contentSalt,
                        dexScope,
                    )
                    BundleSemanticVerifier.RESOURCE_SEMANTICS -> verifyResource(
                        oldPath,
                        newPath,
                        before,
                        after,
                        manifest,
                        plan.resources,
                        contentSalt,
                    )
                }
                BundleSemanticVerificationResult(oldPath, newPath, entry.semanticVerifier, successful = true)
            }
            .toList()
    }

    private fun verifyDex(
        path: String,
        before: ByteArray,
        after: ByteArray,
        dexPlan: PlannedDexSummary,
        contentSalt: ByteArray,
        dexScope: DexSemanticVerificationScope,
    ) {
        val planned = requireNotNull(dexPlan.entries.singleOrNull { it.path == path }) {
            "$path is absent from the DEX transformation plan"
        }
        require(planned.status == PlannedDexStatus.TRANSFORMED || planned.status == PlannedDexStatus.CANONICALIZED) {
            "$path is not declared as a transformed or canonicalized DEX"
        }
        require(planned.inputSha256 == Sha256.hex(before) && planned.outputSha256 == Sha256.hex(after)) {
            "$path hashes differ from the DEX transformation plan"
        }
        require(planned.inputByteCount == before.size.toLong() && planned.outputByteCount == after.size.toLong()) {
            "$path byte counts differ from the DEX transformation plan"
        }
        verifyDexHeader(before, "$path ordinary")
        verifyDexHeader(after, "$path rewritten")
        DexIdTableValidator.requireValid(after, "$path rewritten")
        val original = parseDex(before, "$path ordinary")
        val candidate = parseDex(after, "$path rewritten")
        val originalClasses = original.classes.associateBy(ClassDef::getType)
        val candidateClasses = candidate.classes.associateBy(ClassDef::getType)
        require(originalClasses.keys == candidateClasses.keys) { "$path changed the DEX class set" }
        val transformedMethods = planned.transformedMethods.associateBy(PlannedDexMethod::methodId)
        require(transformedMethods.size == planned.transformedMethods.size) {
            "$path contains duplicate transformed method plan entries"
        }
        require(originalClasses.keys.intersect(dexScope.ownedDescriptors).size == planned.ownedDescriptorCount) {
            "$path authoritative owned descriptor count differs from the plan"
        }
        var originalNops = 0
        var candidateNops = 0
        originalClasses.toSortedMap().forEach { (type, oldClass) ->
            val newClass = requireNotNull(candidateClasses[type])
            verifyClassMetadata(path, oldClass, newClass, planned.publicizedClassDescriptors)
            val oldMethods = oldClass.methods.associateBy(::methodId)
            val newMethods = newClass.methods.associateBy(::methodId)
            require(oldMethods.keys == newMethods.keys) { "$path changed methods in $type" }
            oldMethods.toSortedMap().forEach { (id, oldMethod) ->
                val newMethod = requireNotNull(newMethods[id])
                verifyMethodMetadata(path, oldMethod, newMethod)
                originalNops += oldMethod.implementation?.instructions?.count { it.opcode == Opcode.NOP } ?: 0
                candidateNops += newMethod.implementation?.instructions?.count { it.opcode == Opcode.NOP } ?: 0
                val diversificationPlan = transformedMethods[id]
                val requiredDiamondCount = diversificationPlan?.let { methodPlan ->
                    require(type in dexScope.ownedDescriptors) {
                        "$path planned transformation of unowned method $id"
                    }
                    val exclusion = classifyForSemanticVerification(oldClass, oldMethod, dexScope)
                    require(exclusion == null) {
                        "$path planned transformation of excluded method $id: $exclusion"
                    }
                    val implementation = requireNotNull(oldMethod.implementation) {
                        "$path planned transformation of a method without an implementation: $id"
                    }
                    val receiverRegister = initializedReceiverRegister(oldMethod, implementation)
                    val expected = if (receiverRegister != null) {
                        if (implementation.instructions.count() >= LONG_METHOD_INSTRUCTION_THRESHOLD) 3 else 1
                    } else {
                        0
                    }
                    require(methodPlan.opaqueDiamondCount == expected) {
                        "$path opaque entry architecture for $id requires $expected diamonds, " +
                            "but the plan reports ${methodPlan.opaqueDiamondCount}"
                    }
                    expected
                }
                verifyImplementation(
                    path,
                    id,
                    oldMethod,
                    newMethod,
                    diversificationPlan = diversificationPlan,
                    requiredDiamondCount = requiredDiamondCount,
                    contentSalt = contentSalt,
                )
            }
        }
        if (planned.status == PlannedDexStatus.TRANSFORMED && planned.transformedMethodCount > 0) {
            require(candidateNops > originalNops) { "$path contains no independently observable NOP weaving" }
        }
    }

    private fun verifyDexClosure(
        ordinary: Map<String, ByteArray>,
        rewritten: Map<String, ByteArray>,
        manifest: BundleRewriteManifest,
        dexPlan: PlannedDexSummary,
        dexScope: DexSemanticVerificationScope,
    ) {
        val manifestByOldPath = manifest.entries.associateBy { it.oldPath }
        val requiredPublicClasses = DexClassAccessCompatibility.requiredPublicClassDescriptors(
            ordinary.filterKeys(DEX_PATH::matches).values,
            dexScope.accessCompatibilityDescriptors,
        )
        val plannedPublicClasses = dexPlan.entries.flatMapTo(linkedSetOf()) {
            it.publicizedClassDescriptors
        }
        require(plannedPublicClasses == requiredPublicClasses) {
            "DEX access compatibility plan differs from the ordinary multidex reference closure"
        }
        var independentlyObservedMethodCount = 0
        var independentlyObservedInstructionCount = 0
        val transformedDexEntries = manifest.entries.filter { entry ->
            entry.action == BundleRewriteAction.TRANSFORMED && entry.oldPath?.let(DEX_PATH::matches) == true
        }
        require(transformedDexEntries.all { it.semanticVerifier == BundleSemanticVerifier.DEX_SEMANTICS }) {
            "a transformed DEX has no DEX semantic verifier"
        }
        val plannedReplacementPaths = dexPlan.entries.asSequence()
            .filter {
                it.status == PlannedDexStatus.TRANSFORMED || it.status == PlannedDexStatus.CANONICALIZED
            }
            .mapTo(linkedSetOf(), PlannedDexEntry::path)
        require(transformedDexEntries.mapTo(linkedSetOf()) { requireNotNull(it.oldPath) } == plannedReplacementPaths) {
            "DEX transformation plan and rewrite manifest do not have the same transformed path closure"
        }

        dexPlan.entries.forEach { planned ->
            val before = requireNotNull(ordinary[planned.path]) {
                "DEX transformation plan references an absent ordinary entry: ${planned.path}"
            }
            require(
                planned.inputSha256 == Sha256.hex(before) && planned.inputByteCount == before.size.toLong(),
            ) { "DEX transformation plan input differs from the ordinary AAB: ${planned.path}" }
            val manifestEntry = requireNotNull(manifestByOldPath[planned.path]) {
                "DEX transformation plan path is absent from the rewrite manifest: ${planned.path}"
            }
            when (planned.status) {
                PlannedDexStatus.TRANSFORMED -> require(
                    manifestEntry.action == BundleRewriteAction.TRANSFORMED &&
                        manifestEntry.semanticVerifier == BundleSemanticVerifier.DEX_SEMANTICS &&
                        manifestEntry.newPath == planned.path,
                ) { "transformed DEX plan entry is inconsistent with the rewrite manifest: ${planned.path}" }
                PlannedDexStatus.CANONICALIZED -> require(
                    manifestEntry.action == BundleRewriteAction.TRANSFORMED &&
                        manifestEntry.semanticVerifier == BundleSemanticVerifier.DEX_SEMANTICS &&
                        manifestEntry.newPath == planned.path,
                ) { "canonicalized DEX plan entry is inconsistent with the rewrite manifest: ${planned.path}" }
                PlannedDexStatus.WRITER_FLOOR_SKIPPED -> require(
                    manifestEntry.action == BundleRewriteAction.PRESERVED && manifestEntry.newPath == planned.path,
                ) { "writer-floor skipped DEX is not preserved by the rewrite manifest: ${planned.path}" }
                PlannedDexStatus.NO_ELIGIBLE_METHODS_SKIPPED -> require(
                    manifestEntry.action == BundleRewriteAction.PRESERVED && manifestEntry.newPath == planned.path,
                ) { "no-eligible-method skipped DEX is not preserved by the rewrite manifest: ${planned.path}" }
            }
            val after = requireNotNull(rewritten[requireNotNull(manifestEntry.newPath)]) {
                "DEX transformation plan references an absent rewritten entry: ${planned.path}"
            }
            require(
                planned.outputSha256 == Sha256.hex(after) && planned.outputByteCount == after.size.toLong(),
            ) { "DEX transformation plan output differs from the rewritten AAB: ${planned.path}" }
            verifyDexHeader(after, "${planned.path} rewritten closure")
            DexIdTableValidator.requireValid(after, "${planned.path} rewritten closure")
            val observed = independentlyVerifySimHashClosure(
                path = planned.path,
                before = before,
                after = after,
                planned = planned,
                minimumDistance = dexPlan.minimumSimHashDistance,
            )
            independentlyObservedMethodCount += observed.methodCount
            independentlyObservedInstructionCount += observed.instructionCount
            when (planned.status) {
                PlannedDexStatus.TRANSFORMED, PlannedDexStatus.CANONICALIZED -> require(
                    !before.contentEquals(after),
                ) { "rewritten DEX retained its input bytes: ${planned.path}" }
                PlannedDexStatus.WRITER_FLOOR_SKIPPED,
                PlannedDexStatus.NO_ELIGIBLE_METHODS_SKIPPED,
                -> require(before.contentEquals(after)) {
                    "skipped DEX changed in the rewritten AAB: ${planned.path}"
                }
            }
        }
        val plannedMethodCount = dexPlan.entries.sumOf(PlannedDexEntry::transformedMethodCount)
        val plannedInstructionCount = dexPlan.entries.sumOf(PlannedDexEntry::transformedInstructionCount)
        require(independentlyObservedMethodCount == plannedMethodCount) {
            "independently observed transformed DEX method count differs from the plan"
        }
        require(independentlyObservedInstructionCount == plannedInstructionCount) {
            "independently observed transformed DEX instruction count differs from the plan"
        }
        val methodCoverage = coverage(
            independentlyObservedMethodCount,
            dexPlan.entries.sumOf(PlannedDexEntry::eligibleMethodCount),
        )
        val instructionCoverage = coverage(
            independentlyObservedInstructionCount,
            dexPlan.entries.sumOf(PlannedDexEntry::eligibleInstructionCount),
        )
        require(
            methodCoverage + EPSILON >= dexPlan.minimumCodeCoverage &&
                instructionCoverage + EPSILON >= dexPlan.minimumCodeCoverage,
        ) {
            "independently recomputed DEX coverage method=$methodCoverage instruction=$instructionCoverage " +
                "is below ${dexPlan.minimumCodeCoverage}"
        }
    }

    private fun independentlyVerifySimHashClosure(
        path: String,
        before: ByteArray,
        after: ByteArray,
        planned: PlannedDexEntry,
        minimumDistance: Int,
    ): ObservedDexTransformation {
        verifyDexHeader(before, "$path ordinary SimHash input")
        verifyDexHeader(after, "$path rewritten SimHash input")
        val originalMethods = parseDex(before, "$path ordinary SimHash input").classes
            .flatMap(ClassDef::getMethods)
            .associateBy(::methodId)
        val candidateMethods = parseDex(after, "$path rewritten SimHash input").classes
            .flatMap(ClassDef::getMethods)
            .associateBy(::methodId)
        require(originalMethods.keys == candidateMethods.keys) {
            "$path changed the method closure before SimHash verification"
        }
        val plannedMethods = planned.transformedMethods.associateBy(PlannedDexMethod::methodId)
        val observedIds = linkedSetOf<String>()
        var observedInstructions = 0
        originalMethods.toSortedMap().forEach { (id, originalMethod) ->
            val candidateMethod = requireNotNull(candidateMethods[id])
            val originalInstructions = originalMethod.implementation?.instructions?.toList().orEmpty()
            val candidateInstructions = candidateMethod.implementation?.instructions?.toList().orEmpty()
            val opcodeSequenceChanged = writerCanonicalOpcodeSequence(originalInstructions) !=
                writerCanonicalOpcodeSequence(candidateInstructions)
            if (!opcodeSequenceChanged) {
                require(id !in plannedMethods) { "$path claims an unchanged transformed method $id" }
                return@forEach
            }
            val methodPlan = requireNotNull(plannedMethods[id]) {
                "$path changed an unreported DEX method $id"
            }
            val distance = NormalizedOpcodeSimHash.distance(originalInstructions, candidateInstructions)
            require(distance == methodPlan.simHashDistance) {
                "$path SimHash distance for $id is $distance but the plan reports ${methodPlan.simHashDistance}"
            }
            require(distance >= minimumDistance) {
                "$path SimHash distance for $id is below $minimumDistance"
            }
            require(methodPlan.originalInstructionCount == originalInstructions.size) {
                "$path original instruction count differs from the plan for $id"
            }
            observedIds += id
            observedInstructions += originalInstructions.size
        }
        require(observedIds == plannedMethods.keys) {
            "$path independently observed transformed method closure differs from the plan"
        }
        require(observedIds.size == planned.transformedMethodCount) {
            "$path independently observed transformed method count differs from the plan"
        }
        require(observedInstructions == planned.transformedInstructionCount) {
            "$path independently observed transformed instruction count differs from the plan"
        }
        return ObservedDexTransformation(observedIds.size, observedInstructions)
    }

    private fun verifyClassMetadata(
        path: String,
        before: ClassDef,
        after: ClassDef,
        publicizedClassDescriptors: Set<String>,
    ) {
        val expectedAccessFlags = if (before.type in publicizedClassDescriptors) {
            require(
                !AccessFlags.PUBLIC.isSet(before.accessFlags) &&
                    !AccessFlags.PRIVATE.isSet(before.accessFlags) &&
                    !AccessFlags.PROTECTED.isSet(before.accessFlags),
            ) { "$path planned public widening for a non-package-private class ${before.type}" }
            before.accessFlags or AccessFlags.PUBLIC.value
        } else {
            before.accessFlags
        }
        require(expectedAccessFlags == after.accessFlags && before.superclass == after.superclass) {
            "$path changed class flags or superclass for ${before.type}"
        }
        require(before.interfaces == after.interfaces && before.sourceFile == after.sourceFile) {
            "$path changed class interfaces or source metadata for ${before.type}"
        }
        require(before.annotations == after.annotations) { "$path changed class annotations for ${before.type}" }
        val oldFields = before.fields.sortedWith(compareBy({ it.name }, { it.type }))
        val newFields = after.fields.sortedWith(compareBy({ it.name }, { it.type }))
        require(oldFields.size == newFields.size) { "$path changed fields for ${before.type}" }
        oldFields.zip(newFields).forEach { (old, new) ->
            require(
                old.name == new.name && old.type == new.type && old.accessFlags == new.accessFlags &&
                    equivalentDexFieldInitialValue(old.type, old.accessFlags, old.initialValue, new.initialValue) &&
                    old.annotations == new.annotations &&
                    old.hiddenApiRestrictions == new.hiddenApiRestrictions,
            ) { "$path changed field metadata for ${before.type}->${old.name}" }
        }
    }

    private fun verifyMethodMetadata(path: String, before: Method, after: Method) {
        require(
            before.name == after.name && before.parameterTypes == after.parameterTypes &&
                before.returnType == after.returnType && before.accessFlags == after.accessFlags &&
                before.annotations == after.annotations && before.hiddenApiRestrictions == after.hiddenApiRestrictions,
        ) { "$path changed method metadata for ${methodId(before)}" }
        require(before.parameters.size == after.parameters.size) { "$path changed method parameters for ${methodId(before)}" }
        before.parameters.zip(after.parameters).forEach { (old, new) ->
            require(
                old.type == new.type && old.name == new.name && old.signature == new.signature &&
                    old.annotations == new.annotations,
            ) { "$path changed parameter metadata for ${methodId(before)}" }
        }
    }

    private fun verifyImplementation(
        path: String,
        methodId: String,
        beforeMethod: Method,
        afterMethod: Method,
        diversificationPlan: PlannedDexMethod?,
        requiredDiamondCount: Int?,
        contentSalt: ByteArray,
    ) {
        val before = beforeMethod.implementation
        val after = afterMethod.implementation
        val allowDiversification = diversificationPlan != null
        require((before == null) == (after == null)) { "$path changed method implementation presence for $methodId" }
        if (before == null || after == null) return
        require(before.registerCount == after.registerCount) { "$path changed register count for $methodId" }
        val plannedDiamondCount = requiredDiamondCount ?: 0
        val receiverRegister = initializedReceiverRegister(beforeMethod, before)
        if (plannedDiamondCount > 0) {
            requireNotNull(receiverRegister) {
                "$path planned opaque entry diamonds for a method without a representable initialized receiver: $methodId"
            }
        }
        val originalInstructions = before.instructions.toList()
        val oldLayout = InstructionLayout(
            implementation = before,
            normalizeEntryPayload = false,
            opaqueDiamondCount = 0,
            opaqueReceiverRegister = null,
            normalizeConditionalExpansions = false,
            normalizeReachableRelays = false,
            expectedMarkerValues = null,
        )
        val newLayout = InstructionLayout(
            implementation = after,
            normalizeEntryPayload = allowDiversification && plannedDiamondCount == 0,
            opaqueDiamondCount = plannedDiamondCount,
            opaqueReceiverRegister = receiverRegister,
            normalizeConditionalExpansions = allowDiversification &&
                before.tryBlocks.none() &&
                originalInstructions.none(::isSwitchOrPayload),
            normalizeReachableRelays = false,
            expectedMarkerValues = if (allowDiversification && after.registerCount > 0) {
                SafeUnreachablePayloadContract.markerValues(contentSalt, methodId)
            } else {
                null
            },
        )
        if (!allowDiversification) {
            require(oldLayout.completeInstructions == newLayout.completeInstructions) {
                "$path changed canonicalized instructions for $methodId"
            }
        }
        require(oldLayout.semanticInstructions == newLayout.semanticInstructions) {
            "$path changed a non-NOP instruction or control-flow target for $methodId"
        }
        require(normalizedTryBlocks(before, oldLayout) == normalizedTryBlocks(after, newLayout)) {
            "$path changed try/catch semantics for $methodId"
        }
        val oldDebugItems = normalizedDebugItems(before, oldLayout)
        val newDebugItems = normalizedDebugItems(after, newLayout)
        require(oldDebugItems == newDebugItems) {
            "$path changed debug semantics for $methodId: before=$oldDebugItems after=$newDebugItems"
        }
    }

    private fun initializedReceiverRegister(method: Method, implementation: MethodImplementation): Int? {
        if (AccessFlags.STATIC.isSet(method.accessFlags) || method.name == "<init>" || method.name == "<clinit>") {
            return null
        }
        val parameterWidth = method.parameterTypes.fold(1) { width, type ->
            width + if (type.toString() == "J" || type.toString() == "D") 2 else 1
        }
        return (implementation.registerCount - parameterWidth).takeIf { it in 0..UByte.MAX_VALUE.toInt() }
    }

    private fun classifyForSemanticVerification(
        classDef: ClassDef,
        method: Method,
        scope: DexSemanticVerificationScope,
    ): MethodEligibilityReason? {
        if (scope.deniedDescriptorPrefixes.any(classDef.type::startsWith)) {
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
        if (methodId(method) in scope.externalContractMethodIds) return MethodEligibilityReason.EXTERNAL_CONTRACT
        val implementation = method.implementation ?: return MethodEligibilityReason.NO_IMPLEMENTATION
        val instructions = implementation.instructions.toList()
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

    private fun normalizedTryBlocks(implementation: MethodImplementation, layout: InstructionLayout): List<String> =
        implementation.tryBlocks.map { block ->
            val start = layout.semanticBoundary(block.startCodeAddress)
            val end = layout.semanticBoundary(block.startCodeAddress + block.codeUnitCount)
            val handlers = block.exceptionHandlers.joinToString(",") {
                "${it.exceptionType}:${layout.semanticBoundary(it.handlerCodeAddress)}"
            }
            "$start-$end:$handlers"
        }

    private fun normalizedDebugItems(implementation: MethodImplementation, layout: InstructionLayout): List<String> =
        implementation.debugItems.map { item ->
            val detail = when (item) {
                is LineNumber -> "line=${item.lineNumber}"
                is StartLocal -> "register=${item.register},name=${item.name},type=${item.type},signature=${item.signature}"
                is EndLocal -> "register=${item.register},name=${item.name},type=${item.type},signature=${item.signature}"
                is RestartLocal -> "register=${item.register},name=${item.name},type=${item.type},signature=${item.signature}"
                is SetSourceFile -> "source=${item.sourceFile}"
                is LocalInfo -> "name=${item.name},type=${item.type},signature=${item.signature}"
                else -> ""
            }
            "${item.debugItemType}:${layout.semanticDebugAddress(item.codeAddress)}:$detail"
        }

    private fun isSwitchOrPayload(instruction: Instruction): Boolean =
        instruction is PayloadInstruction ||
            instruction.opcode == Opcode.PACKED_SWITCH ||
            instruction.opcode == Opcode.SPARSE_SWITCH ||
            instruction.opcode == Opcode.FILL_ARRAY_DATA

    private fun verifyResource(
        oldPath: String,
        newPath: String,
        before: ByteArray,
        after: ByteArray,
        manifest: BundleRewriteManifest,
        resources: PlannedResourceSummary,
        contentSalt: ByteArray,
    ) {
        when {
            oldPath == RESOURCES_PB_PATH && newPath == RESOURCES_PB_PATH ->
                verifyResourceTable(before, after, manifest, resources)
            imageExtension(oldPath) != null && imageExtension(oldPath) == imageExtension(newPath) ->
                verifyImage(oldPath, newPath, before, after, resources)
            oldPath.endsWith(".xml", ignoreCase = true) && newPath.endsWith(".xml", ignoreCase = true) ->
                verifyXml(oldPath, before, after)
            isSfntFont(oldPath) && oldPath.substringAfterLast('.').equals(newPath.substringAfterLast('.'), true) ->
                sfntFontDiversifier.verify(before, after, contentSalt, oldPath)
            else -> throw IllegalArgumentException("no independent resource semantic verifier for $oldPath -> $newPath")
        }
    }

    private fun isSfntFont(path: String): Boolean =
        path.endsWith(".ttf", true) || path.endsWith(".otf", true)

    private fun verifyResourceTable(
        before: ByteArray,
        after: ByteArray,
        manifest: BundleRewriteManifest,
        resources: PlannedResourceSummary,
    ) {
        val original = parseResourceTable(before, "ordinary resources.pb")
        val candidate = parseResourceTable(after, "rewritten resources.pb")
        verifyDiversificationUnknownFields(original.unknownFields, candidate.unknownFields, "resources.pb")
        val inversePaths = manifest.entries.asSequence()
            .filter {
                it.oldPath != null && it.newPath != null && it.oldPath != it.newPath &&
                    requireNotNull(it.oldPath).contains("/res/") && requireNotNull(it.newPath).contains("/res/")
            }
            .associate {
                requireNotNull(it.newPath).substringAfter('/') to requireNotNull(it.oldPath).substringAfter('/')
            }
        val renames = resources.renames.associateBy(PlannedResourceRename::resourceId)
        val restored = candidate.toBuilder().setUnknownFields(UnknownFieldSet.getDefaultInstance())
        val seenIds = linkedSetOf<Int>()
        val seenPaths = linkedSetOf<String>()
        repeat(restored.packageCount) { packageIndex ->
            val pkg = restored.getPackageBuilder(packageIndex)
            require(pkg.hasPackageId()) { "rewritten resources.pb package has no ID" }
            repeat(pkg.typeCount) { typeIndex ->
                val type = pkg.getTypeBuilder(typeIndex)
                require(type.hasTypeId()) { "rewritten resources.pb type has no ID" }
                repeat(type.entryCount) { entryIndex ->
                    val entry = type.getEntryBuilder(entryIndex)
                    require(entry.hasEntryId()) { "rewritten resources.pb entry has no ID" }
                    val id = (pkg.packageId.id shl 24) or (type.typeId.id shl 16) or entry.entryId.id
                    renames[id]?.let { rename ->
                        require(entry.name == rename.newName) {
                            "resources.pb did not apply the declared name for resource 0x${id.toUInt().toString(16)}"
                        }
                        entry.name = rename.oldName
                        seenIds += id
                    }
                    restoreFileReferences(entry, inversePaths, seenPaths)
                }
            }
        }
        require(seenIds == renames.keys) { "resources.pb resource rename set differs from the plan" }
        require(seenPaths == inversePaths.keys) { "resources.pb file reference rename set differs from the manifest" }
        val normalizedOriginal = original.toBuilder().setUnknownFields(UnknownFieldSet.getDefaultInstance()).build()
        require(restored.build() == normalizedOriginal) {
            "resources.pb changed fields outside declared resource names, paths, and root diversification metadata"
        }
    }

    private fun restoreFileReferences(
        entry: Resources.Entry.Builder,
        inversePaths: Map<String, String>,
        seenPaths: MutableSet<String>,
    ) {
        fun restore(config: Resources.ConfigValue.Builder): Boolean {
            if (!config.hasValue() || !config.value.hasItem() || !config.value.item.hasFile()) return false
            val file = config.valueBuilder.itemBuilder.fileBuilder
            val oldPath = inversePaths[file.path] ?: return false
            seenPaths += file.path
            file.path = oldPath
            return true
        }
        repeat(entry.configValueCount) { restore(entry.getConfigValueBuilder(it)) }
        AaptResourceEntryCompat.updateFlagDisabledConfigValues(entry, ::restore)
        AaptResourceEntryCompat.updateReadwriteConfigValues(entry, ::restore)
    }

    private fun verifyXml(path: String, before: ByteArray, after: ByteArray) {
        val original = parseXml(before, "$path ordinary")
        val candidate = parseXml(after, "$path rewritten")
        verifyDiversificationUnknownFields(original.unknownFields, candidate.unknownFields, path)
        require(
            original.toBuilder().setUnknownFields(UnknownFieldSet.getDefaultInstance()).build() ==
                candidate.toBuilder().setUnknownFields(UnknownFieldSet.getDefaultInstance()).build(),
        ) { "$path changed compiled XML semantics" }
    }

    private fun verifyDiversificationUnknownFields(
        original: UnknownFieldSet,
        candidate: UnknownFieldSet,
        path: String,
    ) {
        val candidateWithoutMarker = candidate.toBuilder().clearField(PROTO_DIVERSIFICATION_FIELD_NUMBER).build()
        val originalWithoutMarker = original.toBuilder().clearField(PROTO_DIVERSIFICATION_FIELD_NUMBER).build()
        require(candidateWithoutMarker == originalWithoutMarker) { "$path changed undeclared protobuf unknown fields" }
        val marker = candidate.getField(PROTO_DIVERSIFICATION_FIELD_NUMBER)
        val markerText = marker.lengthDelimitedList.singleOrNull()?.toStringUtf8()
        require(
            marker.varintList.isEmpty() && marker.fixed32List.isEmpty() && marker.fixed64List.isEmpty() &&
                marker.groupList.isEmpty() && marker.lengthDelimitedList.size == 1 &&
                markerText != null && markerText.matches(DIVERSIFICATION_MARKER),
        ) { "$path has an invalid diversification marker" }
    }

    private fun verifyImage(
        oldPath: String,
        newPath: String,
        before: ByteArray,
        after: ByteArray,
        resources: PlannedResourceSummary,
    ) {
        val planned = requireNotNull(resources.images.singleOrNull { it.oldPath == oldPath }) {
            "transformed image $oldPath is absent from the transformation report"
        }
        require(planned.status == ImageTransformStatus.TRANSFORMED && planned.newPath == newPath) {
            "transformed image $oldPath does not match the transformation report"
        }
        require(planned.originalSha256 == Sha256.hex(before) && planned.transformedSha256 == Sha256.hex(after)) {
            "transformed image hashes do not match the transformation report for $oldPath"
        }
        val metrics = when (imageExtension(oldPath)) {
            "png" -> ImageMetrics.comparePng(before, after).let {
                ObservedImageMetrics(it.width, it.height, it.alphaPreserved, it.ssim, it.pHashDistance)
            }
            "webp" -> WebpImageMetrics.compare(before, after).let {
                ObservedImageMetrics(it.width, it.height, it.alphaPreserved, it.ssim, it.pHashDistance)
            }
            else -> error("unsupported transformed image extension for $oldPath")
        }
        require(metrics.alphaPreserved) { "$oldPath changed image alpha samples" }
        require(metrics.ssim + EPSILON >= resources.minimumImageSsim) {
            "$oldPath image SSIM ${metrics.ssim} is below ${resources.minimumImageSsim}"
        }
        require(metrics.pHashDistance >= resources.minimumImagePHashDistance) {
            "$oldPath image pHash distance ${metrics.pHashDistance} is below ${resources.minimumImagePHashDistance}"
        }
        require(planned.width == metrics.width && planned.height == metrics.height && planned.alphaPreserved == true) {
            "$oldPath image dimensions or alpha report is inconsistent"
        }
    }

    private fun readEntries(bundle: Path): Map<String, ByteArray> = ZipFile(bundle.toFile()).use { zip ->
        val entries = zip.entries().asSequence().toList()
        BundleZipRewriter.requireSafeUniqueEntryNames(entries.map { it.name })
        entries.filterNot { it.isDirectory }.associate { entry ->
            entry.name to zip.getInputStream(entry).use { it.readBytes() }
        }
    }

    private fun parseDex(bytes: ByteArray, label: String): DexBackedDexFile = try {
        DexBackedDexFile.fromInputStream(null, bytes.inputStream())
    } catch (failure: RuntimeException) {
        throw IllegalArgumentException("$label is not a readable DEX", failure)
    }

    private fun verifyDexHeader(bytes: ByteArray, label: String) {
        require(bytes.size >= DEX_HEADER_SIZE && bytes.copyOfRange(0, 4).contentEquals(DEX_MAGIC)) {
            "$label has an invalid DEX header"
        }
        val declaredSize = ByteBuffer.wrap(bytes, 32, 4).order(ByteOrder.LITTLE_ENDIAN).int
        require(declaredSize == bytes.size) { "$label has an invalid declared file size" }
        val signature = MessageDigest.getInstance("SHA-1").digest(bytes.copyOfRange(32, bytes.size))
        require(signature.contentEquals(bytes.copyOfRange(12, 32))) { "$label has an invalid DEX signature" }
        val checksum = Adler32().apply { update(bytes, 12, bytes.size - 12) }.value.toInt()
        require(checksum == ByteBuffer.wrap(bytes, 8, 4).order(ByteOrder.LITTLE_ENDIAN).int) {
            "$label has an invalid DEX checksum"
        }
    }

    private fun parseResourceTable(bytes: ByteArray, label: String): Resources.ResourceTable = try {
        Resources.ResourceTable.parseFrom(bytes)
    } catch (failure: RuntimeException) {
        throw IllegalArgumentException("$label is not a valid AAPT2 ResourceTable", failure)
    }

    private fun parseXml(bytes: ByteArray, label: String): Resources.XmlNode = try {
        Resources.XmlNode.parseFrom(bytes)
    } catch (failure: RuntimeException) {
        throw IllegalArgumentException("$label is not a valid AAPT2 XmlNode", failure)
    }

    private fun imageExtension(path: String): String? =
        IMAGE_EXTENSIONS.singleOrNull { path.endsWith(".$it", ignoreCase = true) }

    private fun coverage(numerator: Int, denominator: Int): Double =
        if (denominator == 0) 1.0 else numerator.toDouble() / denominator

    private fun methodId(method: Method): String = buildString {
        append(method.definingClass).append("->").append(method.name).append('(')
        method.parameterTypes.forEach(::append)
        append(')').append(method.returnType)
    }

    private class InstructionLayout(
        implementation: MethodImplementation,
        normalizeEntryPayload: Boolean,
        opaqueDiamondCount: Int,
        opaqueReceiverRegister: Int?,
        normalizeConditionalExpansions: Boolean,
        normalizeReachableRelays: Boolean,
        private val expectedMarkerValues: List<String>?,
    ) {
        private val instructions = implementation.instructions.toList()
        private val registerCount = implementation.registerCount
        private val addresses = IntArray(instructions.size)
        private val totalCodeUnits: Int
        private val ignoredInstructionIndexes: Set<Int>
        private val conditionalExpansions: Map<Int, ConditionalExpansion>

        init {
            var address = 0
            instructions.forEachIndexed { index, instruction ->
                addresses[index] = address
                address += instruction.codeUnits
            }
            totalCodeUnits = address
            val incomingBranchTargetAddresses = instructions.mapIndexedNotNull { index, instruction ->
                (instruction as? OffsetInstruction)?.let { addresses[index] + it.codeOffset }
            }.toSet()
            val incomingBranchSourceIndexes = instructions.mapIndexedNotNull { index, instruction ->
                val branch = instruction as? OffsetInstruction ?: return@mapIndexedNotNull null
                val targetIndex = addresses.binarySearch(addresses[index] + branch.codeOffset)
                targetIndex.takeIf { it >= 0 }?.let { it to index }
            }.groupBy({ it.first }, { it.second })
            val opaqueEntryTargetIndex = if (opaqueDiamondCount > 0) {
                opaqueEntryTargetIndex(
                    implementation = implementation,
                    plannedCount = opaqueDiamondCount,
                    receiverRegister = requireNotNull(opaqueReceiverRegister),
                )
            } else {
                null
            }
            val entryPayloadTargetIndex = if (normalizeEntryPayload && instructions.isNotEmpty()) {
                safePayloadDetourTarget(0)
            } else {
                null
            }
            entryPayloadTargetIndex?.let { targetIndex ->
                val payloadAddresses = addresses[1] until addresses[targetIndex]
                instructions.forEachIndexed { sourceIndex, instruction ->
                    val branch = instruction as? OffsetInstruction ?: return@forEachIndexed
                    require(
                        sourceIndex < targetIndex || addresses[sourceIndex] + branch.codeOffset !in payloadAddresses,
                    ) { "live branch targets ignored entry payload" }
                }
            }
            val baseIgnored = buildSet {
                instructions.forEachIndexed { index, instruction ->
                    if (instruction.opcode == Opcode.NOP) add(index)
                }
                entryPayloadTargetIndex?.let { targetIndex ->
                    add(0)
                    addAll(1 until targetIndex)
                }
                opaqueEntryTargetIndex?.let { targetIndex -> addAll(0 until targetIndex) }
            }
            val relayPairs = if (normalizeReachableRelays) {
                require(instructions.none(::isSwitchOrPayload)) {
                    "reachable relay normalization does not support switch or payload instructions"
                }
                reachableRelayPairs(
                    baseIgnored = baseIgnored,
                    incomingBranchSourceIndexes = incomingBranchSourceIndexes,
                    reachableInstructionIndexes = rawReachableInstructionIndexes(),
                    forbiddenSuffixAddresses = buildSet {
                        implementation.debugItems.forEach { add(it.codeAddress) }
                        implementation.tryBlocks.forEach { block ->
                            add(block.startCodeAddress)
                            add(block.startCodeAddress + block.codeUnitCount)
                            block.exceptionHandlers.forEach { add(it.handlerCodeAddress) }
                        }
                    },
                )
            } else {
                emptyList()
            }
            val ignored = baseIgnored + relayPairs.flatMap { listOf(it.sourceIndex, it.relayIndex) }
            conditionalExpansions = if (normalizeConditionalExpansions) buildMap {
                instructions.indices.forEach { index ->
                    val conditional = instructions[index] as? OffsetInstruction ?: return@forEach
                    val originalOpcode = inverseConditional(conditional.opcode) ?: return@forEach
                    val gotoIndex = (index + 1 until instructions.size).firstOrNull { it !in ignored }
                        ?: return@forEach
                    if ((index + 1 until gotoIndex).any { it !in ignored }) return@forEach
                    val jump = instructions[gotoIndex] as? OffsetInstruction ?: return@forEach
                    if (jump.opcode != Opcode.GOTO_32 || jump.codeUnits != 3) return@forEach
                    if ((index + 1..gotoIndex).any { addresses[it] in incomingBranchTargetAddresses }) {
                        return@forEach
                    }
                    val fallthroughAddress = addresses[index] + conditional.codeOffset
                    val fallthroughIndex = addresses.binarySearch(fallthroughAddress)
                    if (fallthroughIndex <= gotoIndex || fallthroughIndex !in instructions.indices) return@forEach
                    if ((gotoIndex + 1 until fallthroughIndex).any { it !in ignored }) return@forEach
                    val trueTargetAddress = addresses[gotoIndex] + jump.codeOffset
                    if (addresses.binarySearch(trueTargetAddress) < 0) return@forEach
                    put(index, ConditionalExpansion(originalOpcode, gotoIndex, trueTargetAddress))
                }
            } else emptyMap()
            ignoredInstructionIndexes = ignored + conditionalExpansions.values.map(ConditionalExpansion::gotoIndex)
        }

        private val writerAlignmentNops = writerAlignmentNopIndexes(instructions)
        val semanticInstructions: List<String> = instructions.mapIndexedNotNull { index, instruction ->
            if (index in ignoredInstructionIndexes) {
                null
            } else {
                canonicalInstruction(instruction, addresses[index], conditionalExpansions[index])
            }
        }
        val completeInstructions: List<String> = instructions.mapIndexedNotNull { index, instruction ->
            if (index in writerAlignmentNops) {
                null
            } else {
                canonicalInstruction(instruction, addresses[index], null)
            }
        }

        fun semanticBoundary(address: Int): Int {
            require(address == totalCodeUnits || addresses.binarySearch(address) >= 0) {
                "DEX address $address is not an instruction boundary"
            }
            return instructions.indices.count { addresses[it] < address && it !in ignoredInstructionIndexes }
        }

        fun semanticDebugAddress(address: Int): Int {
            require(address in 0..totalCodeUnits) { "DEX debug address $address is outside the method body" }
            if (address == totalCodeUnits) {
                return instructions.indices.count { it !in ignoredInstructionIndexes }
            }
            val match = addresses.binarySearch(address)
            val instructionIndex = if (match >= 0) match else -match - 2
            require(instructionIndex in instructions.indices) {
                "DEX debug address $address has no containing instruction"
            }
            require(address - addresses[instructionIndex] in 0 until instructions[instructionIndex].codeUnits) {
                "DEX debug address $address has an invalid intra-instruction offset"
            }
            return (0 until instructionIndex).count { it !in ignoredInstructionIndexes }
        }

        private fun safePayloadDetourTarget(index: Int): Int? {
            if (index != 0) return null
            val jump = instructions[index] as? OffsetInstruction ?: return null
            if (jump.opcode != Opcode.GOTO_32 || jump.codeUnits != 3 || jump.codeOffset <= jump.codeUnits) return null
            val targetAddress = addresses[index] + jump.codeOffset
            val targetIndex = addresses.binarySearch(targetAddress)
            if (targetIndex <= index + 1 || targetIndex !in instructions.indices) return null
            val payload = instructions.subList(index + 1, targetIndex)
            if (!SafeUnreachablePayloadContract.isValidPayload(payload, registerCount)) return null
            require(
                expectedMarkerValues == null ||
                    SafeUnreachablePayloadContract.hasExpectedMarkerValues(listOf(payload), expectedMarkerValues),
            ) {
                EXACT_MARKER_FAILURE
            }
            return targetIndex
        }

        private fun opaqueEntryTargetIndex(
            implementation: MethodImplementation,
            plannedCount: Int,
            receiverRegister: Int,
        ): Int {
            require(plannedCount > 0) { "opaque entry diamond count must be positive" }
            require(instructions.none(::isSwitchOrPayload)) {
                "opaque entry diamond normalization does not support switch or payload instructions"
            }
            val allowedEdges = linkedSetOf<Pair<Int, Int>>()
            val payloadChunks = mutableListOf<List<Instruction>>()
            var currentIndex = 0
            repeat(plannedCount) { diamondIndex ->
                require(currentIndex + 2 < instructions.size) {
                    "opaque entry diamond $diamondIndex is truncated"
                }
                val conditional = instructions[currentIndex] as? OffsetInstruction
                require(
                    conditional != null &&
                        (conditional.opcode == Opcode.IF_EQZ || conditional.opcode == Opcode.IF_NEZ) &&
                        conditional.codeUnits == 2 &&
                        (instructions[currentIndex] as? OneRegisterInstruction)?.registerA == receiverRegister,
                ) { "opaque entry diamond $diamondIndex has the wrong conditional or receiver" }
                val falseGotoIndex = currentIndex + 1
                val trueGotoIndex = currentIndex + 2
                val falseGoto = instructions[falseGotoIndex] as? OffsetInstruction
                val trueGoto = instructions[trueGotoIndex] as? OffsetInstruction
                require(
                    falseGoto != null && falseGoto.opcode == Opcode.GOTO_32 && falseGoto.codeUnits == 3 &&
                        trueGoto != null && trueGoto.opcode == Opcode.GOTO_32 && trueGoto.codeUnits == 3,
                ) { "opaque entry diamond $diamondIndex does not contain two distinct GOTO_32 instructions" }
                val conditionalTarget = instructionIndexAt(addresses[currentIndex] + conditional.codeOffset)
                require(conditionalTarget == trueGotoIndex) {
                    "opaque entry diamond $diamondIndex conditional targets the wrong true GOTO"
                }
                val falseContinuation = instructionIndexAt(addresses[falseGotoIndex] + falseGoto.codeOffset)
                val trueContinuation = instructionIndexAt(addresses[trueGotoIndex] + trueGoto.codeOffset)
                require(
                    falseContinuation != null &&
                        falseContinuation == trueContinuation &&
                        falseContinuation > trueGotoIndex + 1,
                ) { "opaque entry diamond $diamondIndex has a one-sided or invalid continuation" }
                val payload = instructions.subList(trueGotoIndex + 1, falseContinuation)
                payloadChunks += payload
                allowedEdges += currentIndex to trueGotoIndex
                allowedEdges += falseGotoIndex to falseContinuation
                allowedEdges += trueGotoIndex to falseContinuation
                currentIndex = falseContinuation
            }
            require(SafeUnreachablePayloadContract.isValidPayloadChunks(payloadChunks, registerCount)) {
                "opaque entry diamond has a malformed dead payload"
            }
            require(
                expectedMarkerValues == null ||
                    SafeUnreachablePayloadContract.hasExpectedMarkerValues(payloadChunks, expectedMarkerValues),
            ) {
                EXACT_MARKER_FAILURE
            }

            val protectedIndexes = 0 until currentIndex
            instructions.forEachIndexed { sourceIndex, instruction ->
                val branch = instruction as? OffsetInstruction ?: return@forEachIndexed
                val targetIndex = requireNotNull(instructionIndexAt(addresses[sourceIndex] + branch.codeOffset)) {
                    "opaque entry diamond contains a branch to a non-instruction boundary"
                }
                if (targetIndex in protectedIndexes) {
                    require(sourceIndex to targetIndex in allowedEdges) {
                        "branch enters an opaque entry diamond protected span"
                    }
                }
            }
            val protectedAddresses = 0 until addresses[currentIndex]
            implementation.debugItems.forEach { item ->
                require(item.codeAddress !in protectedAddresses) {
                    "debug boundary enters an opaque entry diamond protected span"
                }
            }
            implementation.tryBlocks.forEach { block ->
                val boundaries = buildList {
                    add(block.startCodeAddress)
                    add(block.startCodeAddress + block.codeUnitCount)
                    block.exceptionHandlers.forEach { add(it.handlerCodeAddress) }
                }
                require(boundaries.none { it in protectedAddresses }) {
                    "try or handler boundary enters an opaque entry diamond protected span"
                }
            }
            return currentIndex
        }

        private fun reachableRelayPairs(
            baseIgnored: Set<Int>,
            incomingBranchSourceIndexes: Map<Int, List<Int>>,
            reachableInstructionIndexes: Set<Int>,
            forbiddenSuffixAddresses: Set<Int>,
        ): List<RelayPair> {
            val possibleRelayIndexes = instructions.mapIndexedNotNullTo(linkedSetOf()) { sourceIndex, instruction ->
                val source = instruction as? OffsetInstruction ?: return@mapIndexedNotNullTo null
                if (instruction.opcode != Opcode.GOTO_32 || instruction.codeUnits != 3) {
                    return@mapIndexedNotNullTo null
                }
                val targetIndex = instructionIndexAt(addresses[sourceIndex] + source.codeOffset)
                    ?: return@mapIndexedNotNullTo null
                targetIndex.takeIf {
                    it > sourceIndex &&
                        instructions[it].opcode == Opcode.GOTO_32 &&
                        instructions[it].codeUnits == 3
                }
            }
            if (possibleRelayIndexes.isEmpty()) return emptyList()

            val firstRelayIndex = possibleRelayIndexes.sorted().firstOrNull { candidate ->
                (candidate until instructions.size).all { index ->
                    instructions[index].opcode == Opcode.NOP ||
                        (instructions[index].opcode == Opcode.GOTO_32 && instructions[index].codeUnits == 3)
                } && previousNonNopIndex(candidate)?.let { isTerminal(instructions[it]) } == true
            } ?: return emptyList()
            var suffixStartIndex = firstRelayIndex
            while (suffixStartIndex > 0 && instructions[suffixStartIndex - 1].opcode == Opcode.NOP) {
                suffixStartIndex--
            }
            val terminalIndex = previousNonNopIndex(suffixStartIndex)
            require(terminalIndex != null && isTerminal(instructions[terminalIndex])) {
                "reachable relay suffix has a fallthrough entry"
            }
            require(forbiddenSuffixAddresses.none { it >= addresses[suffixStartIndex] }) {
                "reachable relay suffix contains a debug or try boundary"
            }

            val relayIndexes = (suffixStartIndex until instructions.size)
                .filter { instructions[it].opcode != Opcode.NOP }
            require(relayIndexes.isNotEmpty()) { "reachable relay suffix contains no relay" }
            require(relayIndexes.all { instructions[it].opcode == Opcode.GOTO_32 && instructions[it].codeUnits == 3 }) {
                "reachable relay suffix contains a non-GOTO_32 instruction"
            }

            val pairs = relayIndexes.map { relayIndex ->
                val incoming = incomingBranchSourceIndexes[relayIndex].orEmpty()
                require(incoming.size == 1) { "reachable relay must have exactly one incoming source" }
                val sourceIndex = incoming.single()
                val source = instructions[sourceIndex]
                require(
                    sourceIndex < suffixStartIndex &&
                        source.opcode == Opcode.GOTO_32 &&
                        source.codeUnits == 3,
                ) { "reachable relay source must be a live GOTO_32" }
                require(incomingBranchSourceIndexes[sourceIndex].isNullOrEmpty()) {
                    "reachable relay source has an incoming branch"
                }
                val previousIndex = previousSemanticIndex(sourceIndex, baseIgnored)
                require(previousIndex != null && isOrdinaryFallthrough(instructions[previousIndex])) {
                    "reachable relay source is not at a safe fallthrough boundary"
                }
                require((previousIndex + 1 until sourceIndex).all(baseIgnored::contains)) {
                    "reachable relay source boundary contains a live instruction"
                }
                require(previousIndex in reachableInstructionIndexes && sourceIndex in reachableInstructionIndexes) {
                    "reachable relay source is not reachable from method entry"
                }
                val continuationIndex = nextSemanticIndex(sourceIndex, baseIgnored)
                require(continuationIndex != null && continuationIndex < suffixStartIndex) {
                    "reachable relay source has no original continuation"
                }
                val continuation = instructions[continuationIndex]
                require(
                    continuation.opcode != Opcode.MOVE_EXCEPTION &&
                        !(continuation.opcode in MOVE_RESULT_OPCODES && instructions[previousIndex].opcode.setsResult()),
                ) { "reachable relay source splits a verifier-coupled instruction pair" }
                val relay = instructions[relayIndex] as OffsetInstruction
                require(instructionIndexAt(addresses[relayIndex] + relay.codeOffset) == continuationIndex) {
                    "reachable relay targets the wrong continuation"
                }
                require(incomingBranchSourceIndexes[continuationIndex].orEmpty() == listOf(relayIndex)) {
                    "reachable relay continuation has an unpaired incoming branch"
                }
                (previousIndex + 1 until continuationIndex).forEach { protectedIndex ->
                    require(incomingBranchSourceIndexes[protectedIndex].isNullOrEmpty()) {
                        "branch enters the middle of a normalized relay span"
                    }
                }
                RelayPair(sourceIndex, relayIndex)
            }
            require(pairs.map(RelayPair::sourceIndex).distinct().size == pairs.size) {
                "reachable relay source is paired more than once"
            }
            val sourceByRelay = pairs.associate { it.relayIndex to it.sourceIndex }
            (suffixStartIndex until instructions.size).forEach { index ->
                val incoming = incomingBranchSourceIndexes[index].orEmpty()
                if (instructions[index].opcode == Opcode.NOP) {
                    require(incoming.isEmpty()) { "branch enters relay suffix padding" }
                } else {
                    require(incoming == listOf(sourceByRelay.getValue(index))) {
                        "reachable relay has an unpaired incoming edge"
                    }
                    val relay = instructions[index] as OffsetInstruction
                    val targetIndex = instructionIndexAt(addresses[index] + relay.codeOffset)
                    require(targetIndex != null && targetIndex < suffixStartIndex) {
                        "reachable relay targets another relay"
                    }
                }
            }
            return pairs
        }

        private fun rawReachableInstructionIndexes(): Set<Int> {
            if (instructions.isEmpty()) return emptySet()
            val reachable = linkedSetOf<Int>()
            val pending = ArrayDeque<Int>()
            pending += 0
            while (pending.isNotEmpty()) {
                val index = pending.removeFirst()
                if (index !in instructions.indices || !reachable.add(index)) continue
                val instruction = instructions[index]
                val branchTarget = (instruction as? OffsetInstruction)?.let { branch ->
                    requireNotNull(instructionIndexAt(addresses[index] + branch.codeOffset)) {
                        "reachable relay candidate has an invalid branch target"
                    }
                }
                when {
                    instruction.opcode in GOTO_OPCODES -> pending += requireNotNull(branchTarget)
                    inverseConditional(instruction.opcode) != null -> {
                        pending += requireNotNull(branchTarget)
                        if (index + 1 < instructions.size) pending += index + 1
                    }
                    isTerminal(instruction) -> Unit
                    index + 1 < instructions.size -> pending += index + 1
                }
            }
            return reachable
        }

        private fun instructionIndexAt(address: Int): Int? =
            addresses.binarySearch(address).takeIf { it >= 0 }

        private fun previousNonNopIndex(index: Int): Int? =
            (index - 1 downTo 0).firstOrNull { instructions[it].opcode != Opcode.NOP }

        private fun previousSemanticIndex(index: Int, ignored: Set<Int>): Int? =
            (index - 1 downTo 0).firstOrNull { it !in ignored }

        private fun nextSemanticIndex(index: Int, ignored: Set<Int>): Int? =
            (index + 1 until instructions.size).firstOrNull { it !in ignored }

        private fun isOrdinaryFallthrough(instruction: Instruction): Boolean =
            instruction !is OffsetInstruction &&
                instruction !is PayloadInstruction &&
                !isTerminal(instruction)

        private fun isTerminal(instruction: Instruction): Boolean = instruction.opcode in TERMINAL_OPCODES

        private fun isSwitchOrPayload(instruction: Instruction): Boolean =
            instruction is PayloadInstruction ||
                instruction.opcode == Opcode.PACKED_SWITCH ||
                instruction.opcode == Opcode.SPARSE_SWITCH ||
                instruction.opcode == Opcode.FILL_ARRAY_DATA

        private fun canonicalInstruction(
            instruction: Instruction,
            address: Int,
            conditionalExpansion: ConditionalExpansion?,
        ): String = buildString {
            val canonicalOpcode = writerCanonicalOpcode(conditionalExpansion?.originalOpcode ?: instruction.opcode)
            append(canonicalOpcode.name).append('|').append(
                when {
                    instruction.opcode in STRING_REFERENCE_OPCODES -> STRING_REFERENCE_CODE_UNITS
                    instruction.opcode in WRITER_GOTO_OPCODES -> GOTO_CODE_UNITS
                    else -> instruction.codeUnits
                },
            )
            if (instruction is OneRegisterInstruction) append("|a=").append(instruction.registerA)
            if (instruction is TwoRegisterInstruction) append("|b=").append(instruction.registerB)
            if (instruction is ThreeRegisterInstruction) append("|c=").append(instruction.registerC)
            if (instruction is VariableRegisterInstruction) append("|count=").append(instruction.registerCount)
            if (instruction is FiveRegisterInstruction) append("|cdefg=").append(instruction.registerC).append(',')
                .append(instruction.registerD).append(',').append(instruction.registerE).append(',')
                .append(instruction.registerF).append(',').append(instruction.registerG)
            if (instruction is RegisterRangeInstruction) append("|start=").append(instruction.startRegister)
            if (instruction is WideLiteralInstruction) append("|literal=").append(instruction.wideLiteral)
            if (instruction is OffsetInstruction) {
                append("|target=").append(
                    semanticBoundary(conditionalExpansion?.trueTargetAddress ?: (address + instruction.codeOffset)),
                )
                when (instruction.opcode) {
                    Opcode.PACKED_SWITCH -> appendSwitchCases(
                        instruction,
                        address,
                        PackedSwitchPayload::class.java,
                    )
                    Opcode.SPARSE_SWITCH -> appendSwitchCases(
                        instruction,
                        address,
                        SparseSwitchPayload::class.java,
                    )
                    else -> Unit
                }
            }
            if (instruction is ReferenceInstruction) append("|reference=")
                .append(DexFormatter.INSTANCE.getReference(instruction.reference)).append('|').append(instruction.referenceType)
            if (instruction is DualReferenceInstruction) append("|reference2=")
                .append(DexFormatter.INSTANCE.getReference(instruction.reference2)).append('|').append(instruction.referenceType2)
            if (instruction is VerificationErrorInstruction) append("|verificationError=").append(instruction.verificationError)
            if (instruction is InlineIndexInstruction) append("|inlineIndex=").append(instruction.inlineIndex)
            if (instruction is VtableIndexInstruction) append("|vtableIndex=").append(instruction.vtableIndex)
            if (instruction is FieldOffsetInstruction) append("|fieldOffset=").append(instruction.fieldOffset)
            when (instruction) {
                is ArrayPayload -> append("|arrayWidth=").append(instruction.elementWidth)
                    .append("|elements=").append(instruction.arrayElements.joinToString(","))
                is PackedSwitchPayload -> appendSwitchPayload("packed", instruction, address)
                is SparseSwitchPayload -> appendSwitchPayload("sparse", instruction, address)
            }
        }

        private fun StringBuilder.appendSwitchCases(
            instruction: OffsetInstruction,
            address: Int,
            expectedPayloadType: Class<out PayloadInstruction>,
        ) {
            val payloadAddress = address + instruction.codeOffset
            val payloadIndex = requireNotNull(instructionIndexAt(payloadAddress)) {
                "switch payload target is not an instruction boundary"
            }
            val payload = instructions[payloadIndex]
            require(expectedPayloadType.isInstance(payload)) {
                "switch payload type does not match ${instruction.opcode}"
            }
            val elements = when (payload) {
                is PackedSwitchPayload -> payload.switchElements
                is SparseSwitchPayload -> payload.switchElements
                else -> error("unsupported switch payload ${payload.opcode}")
            }
            append("|cases=").append(
                elements.joinToString(",") { "${it.key}:${semanticBoundary(address + it.offset)}" },
            )
        }

        private fun StringBuilder.appendSwitchPayload(
            label: String,
            payload: PayloadInstruction,
            address: Int,
        ) {
            val elements = when (payload) {
                is PackedSwitchPayload -> payload.switchElements
                is SparseSwitchPayload -> payload.switchElements
                else -> error("unsupported switch payload ${payload.opcode}")
            }
            append('|').append(label).append("Keys=").append(elements.joinToString(",") { it.key.toString() })
            val referenced = instructions.indices.any { index ->
                val candidate = instructions[index] as? OffsetInstruction ?: return@any false
                candidate.opcode in SWITCH_OPCODES && addresses[index] + candidate.codeOffset == address
            }
            if (!referenced) {
                append("|rawOffsets=").append(elements.joinToString(",") { it.offset.toString() })
            }
        }

        private data class ConditionalExpansion(
            val originalOpcode: Opcode,
            val gotoIndex: Int,
            val trueTargetAddress: Int,
        )

        private data class RelayPair(
            val sourceIndex: Int,
            val relayIndex: Int,
        )

        private fun inverseConditional(opcode: Opcode): Opcode? = when (opcode) {
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

        private companion object {
            val GOTO_OPCODES = setOf(Opcode.GOTO, Opcode.GOTO_16, Opcode.GOTO_32)
            val MOVE_RESULT_OPCODES = setOf(
                Opcode.MOVE_RESULT,
                Opcode.MOVE_RESULT_WIDE,
                Opcode.MOVE_RESULT_OBJECT,
            )
            val TERMINAL_OPCODES = setOf(
                Opcode.GOTO,
                Opcode.GOTO_16,
                Opcode.GOTO_32,
                Opcode.RETURN_VOID,
                Opcode.RETURN,
                Opcode.RETURN_WIDE,
                Opcode.RETURN_OBJECT,
                Opcode.THROW,
            )
        }
    }

    private companion object {
        const val EXACT_MARKER_FAILURE = "marker values do not match content salt and method id"
        const val RESOURCES_PB_PATH = "base/resources.pb"
        const val DEX_HEADER_SIZE = 112
        const val EPSILON = 1e-12
        const val LONG_METHOD_INSTRUCTION_THRESHOLD = 100
        val COROUTINE_SUPERCLASS_MARKERS = listOf(
            "BaseContinuationImpl",
            "ContinuationImpl",
            "SuspendLambda",
            "RestrictedContinuationImpl",
        )
        val GENERATED_CLASS = Regex(
            "(?:/R(?:\\$[^;]+)?|/BR|/BuildConfig|/MyObjectBox);$|/databinding/[^;]*Binding;$",
        )
        val DIVERSIFICATION_MARKER = Regex("hardening_marker_v1_[A-Za-z0-9_-]{43}")
        val DEX_MAGIC = byteArrayOf('d'.code.toByte(), 'e'.code.toByte(), 'x'.code.toByte(), '\n'.code.toByte())
        val IMAGE_EXTENSIONS = setOf("png", "webp", "jpg", "jpeg")
        val DEX_PATH = Regex("base/dex/classes(?:[2-9][0-9]*)?\\.dex")
    }

    private data class ObservedDexTransformation(
        val methodCount: Int,
        val instructionCount: Int,
    )

    private data class ObservedImageMetrics(
        val width: Int,
        val height: Int,
        val alphaPreserved: Boolean,
        val ssim: Double,
        val pHashDistance: Int,
    )
}

private fun writerCanonicalOpcode(opcode: Opcode): Opcode = when (opcode) {
    Opcode.CONST_STRING_JUMBO -> Opcode.CONST_STRING
    Opcode.GOTO, Opcode.GOTO_16, Opcode.GOTO_32 -> Opcode.GOTO
    else -> opcode
}

private fun writerCanonicalOpcodeSequence(instructions: List<Instruction>): List<Opcode> {
    val alignmentNops = writerAlignmentNopIndexes(instructions)
    return instructions.mapIndexedNotNull { index, instruction ->
        writerCanonicalOpcode(instruction.opcode).takeUnless { index in alignmentNops }
    }
}

private fun writerAlignmentNopIndexes(instructions: List<Instruction>): Set<Int> {
    val addresses = IntArray(instructions.size)
    var address = 0
    instructions.forEachIndexed { index, instruction ->
        addresses[index] = address
        address += instruction.codeUnits
    }
    val branchTargets = hashSetOf<Int>()
    instructions.forEachIndexed { index, instruction ->
        val branch = instruction as? OffsetInstruction ?: return@forEachIndexed
        val branchAddress = addresses[index]
        val payloadAddress = branchAddress + branch.codeOffset
        branchTargets += payloadAddress
        val switchElements = when (branch.opcode) {
            Opcode.PACKED_SWITCH -> instructions.getOrNull(addresses.binarySearch(payloadAddress))
                ?.let { it as? PackedSwitchPayload }
                ?.switchElements
            Opcode.SPARSE_SWITCH -> instructions.getOrNull(addresses.binarySearch(payloadAddress))
                ?.let { it as? SparseSwitchPayload }
                ?.switchElements
            else -> null
        }
        switchElements?.forEach { element -> branchTargets += branchAddress + element.offset }
    }
    return instructions.indices.filterTo(linkedSetOf()) { index ->
        instructions[index].opcode == Opcode.NOP &&
            addresses[index] % 2 == 1 &&
            instructions.getOrNull(index + 1) is PayloadInstruction &&
            addresses[index] !in branchTargets
    }
}

private val STRING_REFERENCE_OPCODES = setOf(Opcode.CONST_STRING, Opcode.CONST_STRING_JUMBO)
private val WRITER_GOTO_OPCODES = setOf(Opcode.GOTO, Opcode.GOTO_16, Opcode.GOTO_32)
private val SWITCH_OPCODES = setOf(Opcode.PACKED_SWITCH, Opcode.SPARSE_SWITCH)
private const val STRING_REFERENCE_CODE_UNITS = 2
private const val GOTO_CODE_UNITS = 1

internal fun equivalentDexFieldInitialValue(
    type: String,
    accessFlags: Int,
    before: EncodedValue?,
    after: EncodedValue?,
): Boolean {
    if (before == after) return true
    if (!AccessFlags.STATIC.isSet(accessFlags)) return false
    return isDexDefaultValue(type, before) && isDexDefaultValue(type, after)
}

private fun isDexDefaultValue(type: String, value: EncodedValue?): Boolean {
    if (value == null) return true
    return when (type) {
        "Z" -> value is BooleanEncodedValue && !value.value
        "B" -> value is ByteEncodedValue && value.value.toInt() == 0
        "S" -> value is ShortEncodedValue && value.value.toInt() == 0
        "C" -> value is CharEncodedValue && value.value.code == 0
        "I" -> value is IntEncodedValue && value.value == 0
        "J" -> value is LongEncodedValue && value.value == 0L
        "F" -> value is FloatEncodedValue && value.value.toRawBits() == 0
        "D" -> value is DoubleEncodedValue && value.value.toRawBits() == 0L
        else -> (type.startsWith('L') || type.startsWith('[')) && value is NullEncodedValue
    }
}
