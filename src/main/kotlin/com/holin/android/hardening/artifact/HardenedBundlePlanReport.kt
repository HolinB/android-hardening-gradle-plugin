package com.holin.android.hardening.artifact

import com.holin.android.hardening.resources.ImageIneligibilityReason
import com.holin.android.hardening.resources.ImageTransformStatus
import com.holin.android.hardening.resources.ResourceType
import com.holin.android.hardening.state.StrictJson
import groovy.json.JsonSlurper

data class HardenedBundlePlanReport(
    val schemaVersion: Int = 1,
    val sourceAabSha256: String,
    val contentSaltSha256: String,
    val namespace: String,
    val generation: Long,
    val ownedModules: Set<String>,
    val dex: PlannedDexSummary,
    val resources: PlannedResourceSummary,
    val fixedSeedProvided: Boolean = false,
    val fixedSeedHash: String? = null,
) {
    init {
        require(schemaVersion == 1) { "unsupported bundle hardening plan schema $schemaVersion" }
        requireSha256(sourceAabSha256, "sourceAabSha256")
        requireSha256(contentSaltSha256, "contentSaltSha256")
        require(namespace.isNotBlank()) { "namespace must not be blank" }
        require(generation > 0) { "generation must be positive" }
        require(ownedModules.isNotEmpty()) { "bundle hardening report scope must not be empty" }
        require(fixedSeedProvided == (fixedSeedHash != null)) {
            "fixed seed hash must be present exactly when fixedSeedProvided is true"
        }
        fixedSeedHash?.let { hash -> requireSha256(hash, "fixedSeedHash") }
    }
}

data class PlannedDexSummary(
    val discoveredOwnedDescriptorCount: Int,
    val boundaryAcceptedDescriptorCount: Int,
    val boundaryFilteredDescriptorCount: Int,
    val minimumCodeCoverage: Double,
    val minimumSimHashDistance: Int = 0,
    val maximumGrowthRatio: Double,
    val enforceMaximumGrowth: Boolean = true,
    val entries: List<PlannedDexEntry>,
) {
    val eligibleMethodCoverage: Double = coverage(
        entries.sumOf(PlannedDexEntry::transformedMethodCount),
        entries.sumOf(PlannedDexEntry::eligibleMethodCount),
    )
    val eligibleInstructionCoverage: Double = coverage(
        entries.sumOf(PlannedDexEntry::transformedInstructionCount),
        entries.sumOf(PlannedDexEntry::eligibleInstructionCount),
    )
    val totalInputBytes: Long = entries.sumOf(PlannedDexEntry::inputByteCount)
    val totalOutputBytes: Long = entries.sumOf(PlannedDexEntry::outputByteCount)
    val transformedDexCount: Int = entries.count { it.status == PlannedDexStatus.TRANSFORMED }
    val canonicalizedDexPaths: List<String> = entries.asSequence()
        .filter { it.status == PlannedDexStatus.CANONICALIZED }
        .map(PlannedDexEntry::path)
        .sorted()
        .toList()
    val writerFloorSkippedDexPaths: List<String> = entries.asSequence()
        .filter { it.status == PlannedDexStatus.WRITER_FLOOR_SKIPPED }
        .map(PlannedDexEntry::path)
        .sorted()
        .toList()
    val noEligibleMethodsSkippedDexPaths: List<String> = entries.asSequence()
        .filter { it.status == PlannedDexStatus.NO_ELIGIBLE_METHODS_SKIPPED }
        .map(PlannedDexEntry::path)
        .sorted()
        .toList()

    init {
        require(discoveredOwnedDescriptorCount > 0) { "owned DEX inventory must not be empty" }
        require(boundaryAcceptedDescriptorCount > 0) { "owned DEX boundary accepted no descriptors" }
        require(boundaryFilteredDescriptorCount >= 0) { "filtered descriptor count must not be negative" }
        require(boundaryAcceptedDescriptorCount + boundaryFilteredDescriptorCount == discoveredOwnedDescriptorCount) {
            "owned descriptor accounting is inconsistent"
        }
        requireUnitInterval(minimumCodeCoverage, "minimumCodeCoverage")
        require(minimumSimHashDistance in 0..64) { "minimumSimHashDistance must be in 0..64" }
        require(maximumGrowthRatio.isFinite() && maximumGrowthRatio >= 0.0) {
            "maximumGrowthRatio must be finite and non-negative"
        }
        requireUnitInterval(eligibleMethodCoverage, "eligibleMethodCoverage")
        requireUnitInterval(eligibleInstructionCoverage, "eligibleInstructionCoverage")
        require(
            eligibleMethodCoverage + EPSILON >= minimumCodeCoverage &&
                eligibleInstructionCoverage + EPSILON >= minimumCodeCoverage,
        ) {
            "aggregate DEX coverage method=$eligibleMethodCoverage instruction=$eligibleInstructionCoverage " +
                "is below $minimumCodeCoverage"
        }
        require(totalInputBytes > 0 && totalOutputBytes > 0) { "DEX byte totals must be positive" }
        require(entries.sumOf(PlannedDexEntry::ownedDescriptorCount) == boundaryAcceptedDescriptorCount) {
            "owned DEX descriptor accounting is inconsistent"
        }
        require(transformedDexCount > 0) {
            "at least one effective DEX transformation is required"
        }
        require(entries.map(PlannedDexEntry::path).distinct().size == entries.size) { "duplicate DEX report path" }
        BundleZipRewriter.requireSafeUniqueEntryNames(entries.map(PlannedDexEntry::path))
        if (enforceMaximumGrowth) {
            require(entries.all { it.byteGrowthRatio - EPSILON <= maximumGrowthRatio }) {
                "a DEX entry exceeds its growth gate"
            }
            val aggregateGrowth = (totalOutputBytes - totalInputBytes).toDouble() / totalInputBytes
            require(aggregateGrowth - EPSILON <= maximumGrowthRatio) { "aggregate DEX growth exceeds its gate" }
        }
        require(
            entries.flatMap(PlannedDexEntry::transformedMethods)
                .all { it.simHashDistance >= minimumSimHashDistance },
        ) { "a transformed DEX method is below its SimHash distance gate" }
    }
}

enum class PlannedDexStatus {
    TRANSFORMED,
    CANONICALIZED,
    WRITER_FLOOR_SKIPPED,
    NO_ELIGIBLE_METHODS_SKIPPED,
}

data class PlannedDexEntry(
    val path: String,
    val status: PlannedDexStatus,
    val inputSha256: String,
    val outputSha256: String,
    val inputByteCount: Long,
    val outputByteCount: Long,
    val ownedDescriptorCount: Int,
    val ownedMethodCount: Int,
    val eligibleMethodCount: Int,
    val transformedMethodCount: Int,
    val ownedInstructionCount: Int,
    val eligibleInstructionCount: Int,
    val transformedInstructionCount: Int,
    val publicizedClassDescriptors: Set<String> = emptySet(),
    val transformedMethods: List<PlannedDexMethod> = emptyList(),
) {
    val transformedMethodCoverage: Double = coverage(transformedMethodCount, eligibleMethodCount)
    val transformedInstructionCoverage: Double = coverage(transformedInstructionCount, eligibleInstructionCount)
    val byteGrowthRatio: Double = (outputByteCount - inputByteCount).toDouble() / inputByteCount

    init {
        require(DEX_PATH.matches(path)) { "invalid base DEX path $path" }
        BundleZipRewriter.requireSafeUniqueEntryNames(listOf(path))
        requireSha256(inputSha256, "DEX inputSha256")
        requireSha256(outputSha256, "DEX outputSha256")
        require(inputByteCount > 0 && outputByteCount > 0) { "DEX byte counts must be positive" }
        require(ownedDescriptorCount >= 0) { "DEX entry has a negative exact owned descriptor count" }
        require(ownedDescriptorCount > 0 || publicizedClassDescriptors.isNotEmpty()) {
            "DEX entry has no exact owned descriptors or access compatibility changes"
        }
        require(ownedMethodCount >= eligibleMethodCount && eligibleMethodCount >= transformedMethodCount) {
            "DEX method counts are inconsistent"
        }
        require(ownedInstructionCount >= eligibleInstructionCount && eligibleInstructionCount >= transformedInstructionCount) {
            "DEX instruction counts are inconsistent"
        }
        requireUnitInterval(transformedMethodCoverage, "transformedMethodCoverage")
        requireUnitInterval(transformedInstructionCoverage, "transformedInstructionCoverage")
        require(byteGrowthRatio.isFinite()) { "DEX growth ratio must be finite" }
        require(transformedMethods.map(PlannedDexMethod::methodId).distinct().size == transformedMethods.size) {
            "DEX entry contains duplicate transformed method IDs"
        }
        require(publicizedClassDescriptors.all(DEX_CLASS_DESCRIPTOR::matches)) {
            "DEX entry contains an invalid publicized class descriptor"
        }
        require(transformedMethods.size == transformedMethodCount) {
            "DEX transformed method records differ from transformedMethodCount"
        }
        require(transformedMethods.sumOf(PlannedDexMethod::originalInstructionCount) == transformedInstructionCount) {
            "DEX transformed method instruction records differ from transformedInstructionCount"
        }
        when (status) {
            PlannedDexStatus.TRANSFORMED -> {
                require(inputSha256 != outputSha256) { "effective DEX transformation must change its hash" }
                require(transformedMethodCount > 0 || publicizedClassDescriptors.isNotEmpty()) {
                    "DEX entry has no transformed methods or access compatibility changes"
                }
                require(transformedMethodCount == 0 || transformedInstructionCount > 0) {
                    "DEX entry transformed methods have no transformed instructions"
                }
            }
            PlannedDexStatus.CANONICALIZED -> require(
                inputSha256 != outputSha256 && eligibleMethodCount == 0 && eligibleInstructionCount == 0 &&
                    transformedMethodCount == 0 && transformedInstructionCount == 0,
            ) { "canonicalized DEX must change bytes and have zero eligible or transformed code" }
            PlannedDexStatus.WRITER_FLOOR_SKIPPED -> require(
                inputSha256 == outputSha256 && inputByteCount == outputByteCount &&
                    transformedMethodCount == 0 && transformedInstructionCount == 0,
            ) { "writer-floor skipped DEX must retain bytes and claim no transformed code" }
            PlannedDexStatus.NO_ELIGIBLE_METHODS_SKIPPED -> require(
                inputSha256 == outputSha256 && inputByteCount == outputByteCount &&
                    eligibleMethodCount == 0 && eligibleInstructionCount == 0 &&
                    transformedMethodCount == 0 && transformedInstructionCount == 0,
            ) { "no-eligible-method skipped DEX must retain bytes and have zero eligible code" }
        }
    }
}

data class PlannedDexMethod(
    val methodId: String,
    val originalInstructionCount: Int,
    val simHashDistance: Int,
    val opaqueDiamondCount: Int = 0,
) {
    init {
        require(DEX_METHOD_ID.matches(methodId)) { "invalid transformed DEX method ID $methodId" }
        require(originalInstructionCount > 0) { "transformed DEX method has no original instructions" }
        require(simHashDistance in 0..64) { "transformed DEX method SimHash distance must be in 0..64" }
        require(opaqueDiamondCount >= 0) { "transformed DEX method opaque diamond count must not be negative" }
    }
}

data class PlannedResourceSummary(
    val inventoryVariantCount: Int,
    val renamedResourceCount: Int,
    val renamedFileCount: Int,
    val resourcesPbInputSha256: String,
    val resourcesPbOutputSha256: String,
    val minimumImageCoverage: Double,
    val minimumImageSsim: Double,
    val minimumImagePHashDistance: Int,
    val eligibleImageCount: Int,
    val transformedImageCount: Int,
    val imageCoverage: Double,
    val eligibleImageBytes: Long = 0,
    val transformedImageBytes: Long = 0,
    val imageByteCoverage: Double = 1.0,
    val transformedPngCount: Int,
    val transformedWebpCount: Int,
    val diversifiedProtoXmlCount: Int,
    val renames: List<PlannedResourceRename>,
    val images: List<PlannedImageEntry>,
) {
    init {
        require(inventoryVariantCount > 0) { "owned resource inventory must not be empty" }
        require(renamedResourceCount == renames.size && renamedResourceCount > 0) {
            "at least one effective resource rename is required"
        }
        require(renamedFileCount == renames.sumOf(PlannedResourceRename::renamedFileCount)) {
            "renamed resource path accounting is inconsistent"
        }
        requireSha256(resourcesPbInputSha256, "resources.pb input hash")
        requireSha256(resourcesPbOutputSha256, "resources.pb output hash")
        require(resourcesPbInputSha256 != resourcesPbOutputSha256) { "resources.pb transformation is ineffective" }
        requireUnitInterval(minimumImageCoverage, "minimumImageCoverage")
        require(minimumImageSsim.isFinite() && minimumImageSsim in 0.995..1.0) {
            "minimumImageSsim must be in 0.995..1.0"
        }
        require(minimumImagePHashDistance in 11..64) { "minimumImagePHashDistance must be in 11..64" }
        require(eligibleImageCount == images.count { it.status != ImageTransformStatus.EXCLUDED }) {
            "eligible image accounting is inconsistent"
        }
        require(transformedImageCount == images.count { it.status == ImageTransformStatus.TRANSFORMED }) {
            "transformed image accounting is inconsistent"
        }
        val expectedCoverage = if (eligibleImageCount == 0) 1.0 else transformedImageCount.toDouble() / eligibleImageCount
        requireUnitInterval(imageCoverage, "imageCoverage")
        require(kotlin.math.abs(imageCoverage - expectedCoverage) <= EPSILON) {
            "image coverage accounting is inconsistent"
        }
        require(imageCoverage + EPSILON >= minimumImageCoverage) { "image coverage is below its gate" }
        require(eligibleImageBytes >= 0 && transformedImageBytes in 0..eligibleImageBytes) {
            "image byte accounting is inconsistent"
        }
        val expectedByteCoverage = if (eligibleImageBytes == 0L) {
            1.0
        } else {
            transformedImageBytes.toDouble() / eligibleImageBytes
        }
        requireUnitInterval(imageByteCoverage, "imageByteCoverage")
        require(kotlin.math.abs(imageByteCoverage - expectedByteCoverage) <= EPSILON) {
            "image byte coverage accounting is inconsistent"
        }
        require(imageByteCoverage + EPSILON >= minimumImageCoverage) {
            "image byte coverage is below its gate"
        }
        require(transformedPngCount == images.count {
            it.status == ImageTransformStatus.TRANSFORMED && it.oldPath.lowercase().endsWith(".png")
        }) {
            "transformed PNG accounting is inconsistent"
        }
        require(transformedWebpCount == images.count {
            it.status == ImageTransformStatus.TRANSFORMED && it.oldPath.lowercase().endsWith(".webp")
        }) {
            "transformed WebP accounting is inconsistent"
        }
        require(transformedPngCount + transformedWebpCount == transformedImageCount) {
            "transformed image format accounting is inconsistent"
        }
        require(diversifiedProtoXmlCount >= 0 && diversifiedProtoXmlCount <= renamedFileCount) {
            "diversified proto XML accounting is inconsistent"
        }
        require(renames.map { it.resourceId }.distinct().size == renames.size) { "duplicate resource rename ID" }
        require(images.map(PlannedImageEntry::oldPath).distinct().size == images.size) { "duplicate image report path" }
    }
}

data class PlannedResourceRename(
    val resourceId: Int,
    val type: ResourceType,
    val oldName: String,
    val newName: String,
    val renamedFileCount: Int,
) {
    init {
        require(oldName.isNotBlank() && newName.isNotBlank() && oldName != newName) { "invalid resource rename" }
        require(renamedFileCount >= 0) { "renamedFileCount must not be negative" }
    }
}

data class PlannedImageEntry(
    val oldPath: String,
    val newPath: String?,
    val status: ImageTransformStatus,
    val reason: ImageIneligibilityReason,
    val originalSha256: String,
    val transformedSha256: String?,
    val width: Int?,
    val height: Int?,
    val alphaPreserved: Boolean?,
    val ssim: Double?,
    val pHashDistance: Int?,
) {
    init {
        BundleZipRewriter.requireSafeUniqueEntryNames(listOf(oldPath) + listOfNotNull(newPath))
        requireSha256(originalSha256, "image original hash")
        when (status) {
            ImageTransformStatus.TRANSFORMED -> {
                require(reason == ImageIneligibilityReason.TRANSFORMED) { "transformed image reason is inconsistent" }
                require(newPath != null && transformedSha256 != null && transformedSha256 != originalSha256) {
                    "transformed image must have a changed output"
                }
                requireSha256(requireNotNull(transformedSha256), "image transformed hash")
                require(width != null && width > 0 && height != null && height > 0) { "transformed image dimensions are invalid" }
                require(alphaPreserved == true) { "transformed image alpha must be preserved" }
                require(ssim != null && ssim.isFinite() && ssim in -1.0..1.0) { "transformed image SSIM is invalid" }
                require(pHashDistance != null && pHashDistance in 0..64) { "transformed image pHash distance is invalid" }
            }
            ImageTransformStatus.INELIGIBLE,
            ImageTransformStatus.EXCLUDED,
            -> require(
                transformedSha256 == null && width == null && height == null && alphaPreserved == null &&
                    ssim == null && pHashDistance == null,
            ) { "non-transformed image must not claim output metrics" }
        }
    }
}

object HardenedBundlePlanReportCodec {
    fun encode(report: HardenedBundlePlanReport): String = buildString {
        append("{\"schemaVersion\":").append(report.schemaVersion)
        append(",\"sourceAabSha256\":").append(json(report.sourceAabSha256))
        append(",\"contentSaltSha256\":").append(json(report.contentSaltSha256))
        append(",\"fixedSeedProvided\":").append(report.fixedSeedProvided)
        append(",\"fixedSeedHash\":").append(jsonNullable(report.fixedSeedHash))
        append(",\"namespace\":").append(json(report.namespace))
        append(",\"generation\":").append(report.generation)
        append(",\"ownedModules\":[")
        report.ownedModules.sorted().forEachIndexed { index, module ->
            if (index > 0) append(',')
            append(json(module))
        }
        append("],\"dex\":")
        appendDex(report.dex)
        append(",\"resources\":")
        appendResources(report.resources)
        append("}\n")
    }

    fun decode(json: String): HardenedBundlePlanReport {
        StrictJson.validateDocument(json)
        val root = JsonSlurper().parseText(json).planMap("report")
        root.exactKeys(REPORT_KEYS, "report")
        return HardenedBundlePlanReport(
            root.planInt("schemaVersion"),
            root.planString("sourceAabSha256"),
            root.planString("contentSaltSha256"),
            root.planString("namespace"),
            root.planLong("generation"),
            root.planList("ownedModules").mapTo(linkedSetOf()) {
                it as? String ?: invalidPlan("ownedModules values must be strings")
            },
            decodeDex(root["dex"]),
            decodeResources(root["resources"]),
            root.planBoolean("fixedSeedProvided"),
            root.planNullableString("fixedSeedHash"),
        )
    }

    private fun StringBuilder.appendDex(dex: PlannedDexSummary) {
        append("{\"discoveredOwnedDescriptorCount\":").append(dex.discoveredOwnedDescriptorCount)
        append(",\"boundaryAcceptedDescriptorCount\":").append(dex.boundaryAcceptedDescriptorCount)
        append(",\"boundaryFilteredDescriptorCount\":").append(dex.boundaryFilteredDescriptorCount)
        append(",\"minimumCodeCoverage\":").append(dex.minimumCodeCoverage)
        append(",\"minimumSimHashDistance\":").append(dex.minimumSimHashDistance)
        append(",\"maximumGrowthRatio\":").append(dex.maximumGrowthRatio)
        append(",\"enforceMaximumGrowth\":").append(dex.enforceMaximumGrowth)
        append(",\"eligibleMethodCoverage\":").append(dex.eligibleMethodCoverage)
        append(",\"eligibleInstructionCoverage\":").append(dex.eligibleInstructionCoverage)
        append(",\"totalInputBytes\":").append(dex.totalInputBytes)
        append(",\"totalOutputBytes\":").append(dex.totalOutputBytes)
        append(",\"transformedDexCount\":").append(dex.transformedDexCount)
        append(",\"canonicalizedDexPaths\":[")
        dex.canonicalizedDexPaths.forEachIndexed { index, path ->
            if (index > 0) append(',')
            append(json(path))
        }
        append("],\"writerFloorSkippedDexPaths\":[")
        dex.writerFloorSkippedDexPaths.forEachIndexed { index, path ->
            if (index > 0) append(',')
            append(json(path))
        }
        append("],\"noEligibleMethodsSkippedDexPaths\":[")
        dex.noEligibleMethodsSkippedDexPaths.forEachIndexed { index, path ->
            if (index > 0) append(',')
            append(json(path))
        }
        append("],\"entries\":[")
        dex.entries.forEachIndexed { index, entry ->
            if (index > 0) append(',')
            append("{\"path\":").append(json(entry.path))
            append(",\"status\":").append(json(entry.status.name))
            append(",\"inputSha256\":").append(json(entry.inputSha256))
            append(",\"outputSha256\":").append(json(entry.outputSha256))
            append(",\"inputByteCount\":").append(entry.inputByteCount)
            append(",\"outputByteCount\":").append(entry.outputByteCount)
            append(",\"ownedDescriptorCount\":").append(entry.ownedDescriptorCount)
            append(",\"ownedMethodCount\":").append(entry.ownedMethodCount)
            append(",\"eligibleMethodCount\":").append(entry.eligibleMethodCount)
            append(",\"transformedMethodCount\":").append(entry.transformedMethodCount)
            append(",\"ownedInstructionCount\":").append(entry.ownedInstructionCount)
            append(",\"eligibleInstructionCount\":").append(entry.eligibleInstructionCount)
            append(",\"transformedInstructionCount\":").append(entry.transformedInstructionCount)
            append(",\"transformedMethodCoverage\":").append(entry.transformedMethodCoverage)
            append(",\"transformedInstructionCoverage\":").append(entry.transformedInstructionCoverage)
            append(",\"byteGrowthRatio\":").append(entry.byteGrowthRatio)
            append(",\"publicizedClassDescriptors\":[")
            entry.publicizedClassDescriptors.sorted().forEachIndexed { descriptorIndex, descriptor ->
                if (descriptorIndex > 0) append(',')
                append(json(descriptor))
            }
            append("],\"transformedMethods\":[")
            entry.transformedMethods.sortedBy(PlannedDexMethod::methodId).forEachIndexed { methodIndex, method ->
                if (methodIndex > 0) append(',')
                append("{\"methodId\":").append(json(method.methodId))
                append(",\"originalInstructionCount\":").append(method.originalInstructionCount)
                append(",\"simHashDistance\":").append(method.simHashDistance)
                append(",\"opaqueDiamondCount\":").append(method.opaqueDiamondCount).append('}')
            }
            append("]}")
        }
        append("]}")
    }

    private fun StringBuilder.appendResources(resources: PlannedResourceSummary) {
        append("{\"inventoryVariantCount\":").append(resources.inventoryVariantCount)
        append(",\"renamedResourceCount\":").append(resources.renamedResourceCount)
        append(",\"renamedFileCount\":").append(resources.renamedFileCount)
        append(",\"resourcesPbInputSha256\":").append(json(resources.resourcesPbInputSha256))
        append(",\"resourcesPbOutputSha256\":").append(json(resources.resourcesPbOutputSha256))
        append(",\"minimumImageCoverage\":").append(resources.minimumImageCoverage)
        append(",\"minimumImageSsim\":").append(resources.minimumImageSsim)
        append(",\"minimumImagePHashDistance\":").append(resources.minimumImagePHashDistance)
        append(",\"eligibleImageCount\":").append(resources.eligibleImageCount)
        append(",\"transformedImageCount\":").append(resources.transformedImageCount)
        append(",\"imageCoverage\":").append(resources.imageCoverage)
        append(",\"eligibleImageBytes\":").append(resources.eligibleImageBytes)
        append(",\"transformedImageBytes\":").append(resources.transformedImageBytes)
        append(",\"imageByteCoverage\":").append(resources.imageByteCoverage)
        append(",\"transformedPngCount\":").append(resources.transformedPngCount)
        append(",\"transformedWebpCount\":").append(resources.transformedWebpCount)
        append(",\"diversifiedProtoXmlCount\":").append(resources.diversifiedProtoXmlCount)
        append(",\"renames\":[")
        resources.renames.forEachIndexed { index, rename ->
            if (index > 0) append(',')
            append("{\"resourceId\":").append(rename.resourceId)
            append(",\"type\":").append(json(rename.type.name))
            append(",\"oldName\":").append(json(rename.oldName))
            append(",\"newName\":").append(json(rename.newName))
            append(",\"renamedFileCount\":").append(rename.renamedFileCount).append('}')
        }
        append("],\"images\":[")
        resources.images.forEachIndexed { index, image ->
            if (index > 0) append(',')
            append("{\"oldPath\":").append(json(image.oldPath))
            append(",\"newPath\":").append(jsonNullable(image.newPath))
            append(",\"status\":").append(json(image.status.name))
            append(",\"reason\":").append(json(image.reason.name))
            append(",\"originalSha256\":").append(json(image.originalSha256))
            append(",\"transformedSha256\":").append(jsonNullable(image.transformedSha256))
            append(",\"width\":").append(image.width ?: "null")
            append(",\"height\":").append(image.height ?: "null")
            append(",\"alphaPreserved\":").append(image.alphaPreserved ?: "null")
            append(",\"ssim\":").append(image.ssim ?: "null")
            append(",\"pHashDistance\":").append(image.pHashDistance ?: "null").append('}')
        }
        append("]}")
    }

    private fun decodeDex(raw: Any?): PlannedDexSummary {
        val value = raw.planMap("dex")
        value.exactKeys(DEX_KEYS, "dex")
        val result = PlannedDexSummary(
            discoveredOwnedDescriptorCount = value.planInt("discoveredOwnedDescriptorCount"),
            boundaryAcceptedDescriptorCount = value.planInt("boundaryAcceptedDescriptorCount"),
            boundaryFilteredDescriptorCount = value.planInt("boundaryFilteredDescriptorCount"),
            minimumCodeCoverage = value.planDouble("minimumCodeCoverage"),
            minimumSimHashDistance = value.planInt("minimumSimHashDistance"),
            maximumGrowthRatio = value.planDouble("maximumGrowthRatio"),
            enforceMaximumGrowth = value.planBoolean("enforceMaximumGrowth"),
            entries = value.planList("entries").mapIndexed { index, item -> decodeDexEntry(item, index) },
        )
        requireMetric(
            result.eligibleMethodCoverage,
            value.planDouble("eligibleMethodCoverage"),
            "eligibleMethodCoverage",
        )
        requireMetric(
            result.eligibleInstructionCoverage,
            value.planDouble("eligibleInstructionCoverage"),
            "eligibleInstructionCoverage",
        )
        require(result.totalInputBytes == value.planLong("totalInputBytes")) {
            "totalInputBytes differs from its DEX entries"
        }
        require(result.totalOutputBytes == value.planLong("totalOutputBytes")) {
            "totalOutputBytes differs from its DEX entries"
        }
        require(result.transformedDexCount == value.planInt("transformedDexCount")) {
            "transformedDexCount differs from its DEX entries"
        }
        val canonicalizedPaths = value.planList("canonicalizedDexPaths").mapIndexed { index, item ->
            item as? String ?: invalidPlan("dex.canonicalizedDexPaths[$index] must be a string")
        }
        require(result.canonicalizedDexPaths == canonicalizedPaths) {
            "canonicalizedDexPaths differs from its DEX entries"
        }
        val skippedPaths = value.planList("writerFloorSkippedDexPaths").mapIndexed { index, item ->
            item as? String ?: invalidPlan("dex.writerFloorSkippedDexPaths[$index] must be a string")
        }
        require(result.writerFloorSkippedDexPaths == skippedPaths) {
            "writerFloorSkippedDexPaths differs from its DEX entries"
        }
        val noEligiblePaths = value.planList("noEligibleMethodsSkippedDexPaths").mapIndexed { index, item ->
            item as? String ?: invalidPlan("dex.noEligibleMethodsSkippedDexPaths[$index] must be a string")
        }
        require(result.noEligibleMethodsSkippedDexPaths == noEligiblePaths) {
            "noEligibleMethodsSkippedDexPaths differs from its DEX entries"
        }
        return result
    }

    private fun decodeDexEntry(raw: Any?, index: Int): PlannedDexEntry {
        val value = raw.planMap("dex.entries[$index]")
        value.exactKeys(DEX_ENTRY_KEYS, "dex.entries[$index]")
        val result = PlannedDexEntry(
            value.planString("path"),
            enumValueOf(value.planString("status")),
            value.planString("inputSha256"),
            value.planString("outputSha256"),
            value.planLong("inputByteCount"),
            value.planLong("outputByteCount"),
            value.planInt("ownedDescriptorCount"),
            value.planInt("ownedMethodCount"),
            value.planInt("eligibleMethodCount"),
            value.planInt("transformedMethodCount"),
            value.planInt("ownedInstructionCount"),
            value.planInt("eligibleInstructionCount"),
            value.planInt("transformedInstructionCount"),
            value.planList("publicizedClassDescriptors").mapIndexedTo(linkedSetOf()) {
                    descriptorIndex, item ->
                item as? String ?: invalidPlan(
                    "dex.entries[$index].publicizedClassDescriptors[$descriptorIndex] must be a string",
                )
            },
            value.planList("transformedMethods").mapIndexed { methodIndex, item ->
                decodeDexMethod(item, index, methodIndex)
            },
        )
        requireMetric(
            result.transformedMethodCoverage,
            value.planDouble("transformedMethodCoverage"),
            "dex.entries[$index].transformedMethodCoverage",
        )
        requireMetric(
            result.transformedInstructionCoverage,
            value.planDouble("transformedInstructionCoverage"),
            "dex.entries[$index].transformedInstructionCoverage",
        )
        requireMetric(
            result.byteGrowthRatio,
            value.planDouble("byteGrowthRatio"),
            "dex.entries[$index].byteGrowthRatio",
        )
        return result
    }

    private fun decodeDexMethod(raw: Any?, entryIndex: Int, methodIndex: Int): PlannedDexMethod {
        val label = "dex.entries[$entryIndex].transformedMethods[$methodIndex]"
        val value = raw.planMap(label)
        value.exactKeys(DEX_METHOD_KEYS, label)
        return PlannedDexMethod(
            methodId = value.planString("methodId"),
            originalInstructionCount = value.planInt("originalInstructionCount"),
            simHashDistance = value.planInt("simHashDistance"),
            opaqueDiamondCount = value.planInt("opaqueDiamondCount"),
        )
    }

    private fun decodeResources(raw: Any?): PlannedResourceSummary {
        val value = raw.planMap("resources")
        value.exactKeys(RESOURCE_KEYS, "resources")
        return PlannedResourceSummary(
            inventoryVariantCount = value.planInt("inventoryVariantCount"),
            renamedResourceCount = value.planInt("renamedResourceCount"),
            renamedFileCount = value.planInt("renamedFileCount"),
            resourcesPbInputSha256 = value.planString("resourcesPbInputSha256"),
            resourcesPbOutputSha256 = value.planString("resourcesPbOutputSha256"),
            minimumImageCoverage = value.planDouble("minimumImageCoverage"),
            minimumImageSsim = value.planDouble("minimumImageSsim"),
            minimumImagePHashDistance = value.planInt("minimumImagePHashDistance"),
            eligibleImageCount = value.planInt("eligibleImageCount"),
            transformedImageCount = value.planInt("transformedImageCount"),
            imageCoverage = value.planDouble("imageCoverage"),
            eligibleImageBytes = value.planLong("eligibleImageBytes"),
            transformedImageBytes = value.planLong("transformedImageBytes"),
            imageByteCoverage = value.planDouble("imageByteCoverage"),
            transformedPngCount = value.planInt("transformedPngCount"),
            transformedWebpCount = value.planInt("transformedWebpCount"),
            diversifiedProtoXmlCount = value.planInt("diversifiedProtoXmlCount"),
            renames = value.planList("renames").mapIndexed { index, item -> decodeRename(item, index) },
            images = value.planList("images").mapIndexed { index, item -> decodeImage(item, index) },
        )
    }

    private fun decodeRename(raw: Any?, index: Int): PlannedResourceRename {
        val value = raw.planMap("resources.renames[$index]")
        value.exactKeys(RENAME_KEYS, "resources.renames[$index]")
        return PlannedResourceRename(
            resourceId = value.planInt("resourceId"),
            type = enumValueOf(value.planString("type")),
            oldName = value.planString("oldName"),
            newName = value.planString("newName"),
            renamedFileCount = value.planInt("renamedFileCount"),
        )
    }

    private fun decodeImage(raw: Any?, index: Int): PlannedImageEntry {
        val value = raw.planMap("resources.images[$index]")
        value.exactKeys(IMAGE_KEYS, "resources.images[$index]")
        return PlannedImageEntry(
            oldPath = value.planString("oldPath"),
            newPath = value.planNullableString("newPath"),
            status = enumValueOf(value.planString("status")),
            reason = enumValueOf(value.planString("reason")),
            originalSha256 = value.planString("originalSha256"),
            transformedSha256 = value.planNullableString("transformedSha256"),
            width = value.planNullableInt("width"),
            height = value.planNullableInt("height"),
            alphaPreserved = value.planNullableBoolean("alphaPreserved"),
            ssim = value.planNullableDouble("ssim"),
            pHashDistance = value.planNullableInt("pHashDistance"),
        )
    }

    private fun json(value: String): String = buildString {
        append('"')
        value.forEach { character ->
            when (character) {
                '"' -> append("\\\"")
                '\\' -> append("\\\\")
                '\b' -> append("\\b")
                '\u000c' -> append("\\f")
                '\n' -> append("\\n")
                '\r' -> append("\\r")
                '\t' -> append("\\t")
                else -> if (character.code < 0x20) append("\\u%04x".format(character.code)) else append(character)
            }
        }
        append('"')
    }

    private fun jsonNullable(value: String?): String = value?.let(::json) ?: "null"

    private val REPORT_KEYS = setOf(
        "schemaVersion", "sourceAabSha256", "contentSaltSha256", "fixedSeedProvided", "fixedSeedHash",
        "namespace", "generation", "ownedModules", "dex", "resources",
    )
    private val DEX_KEYS = setOf(
        "discoveredOwnedDescriptorCount", "boundaryAcceptedDescriptorCount", "boundaryFilteredDescriptorCount",
        "minimumCodeCoverage", "minimumSimHashDistance", "maximumGrowthRatio", "enforceMaximumGrowth",
        "eligibleMethodCoverage", "eligibleInstructionCoverage", "totalInputBytes", "totalOutputBytes",
        "transformedDexCount", "canonicalizedDexPaths", "writerFloorSkippedDexPaths",
        "noEligibleMethodsSkippedDexPaths", "entries",
    )
    private val DEX_ENTRY_KEYS = setOf(
        "path", "status", "inputSha256", "outputSha256", "inputByteCount", "outputByteCount",
        "ownedDescriptorCount", "ownedMethodCount", "eligibleMethodCount", "transformedMethodCount",
        "ownedInstructionCount", "eligibleInstructionCount", "transformedInstructionCount", "transformedMethodCoverage",
        "transformedInstructionCoverage", "byteGrowthRatio", "publicizedClassDescriptors", "transformedMethods",
    )
    private val DEX_METHOD_KEYS = setOf(
        "methodId", "originalInstructionCount", "simHashDistance", "opaqueDiamondCount",
    )
    private val RESOURCE_KEYS = setOf(
        "inventoryVariantCount", "renamedResourceCount", "renamedFileCount", "resourcesPbInputSha256",
        "resourcesPbOutputSha256", "minimumImageCoverage", "minimumImageSsim", "minimumImagePHashDistance",
        "eligibleImageCount", "transformedImageCount", "imageCoverage", "eligibleImageBytes",
        "transformedImageBytes", "imageByteCoverage", "transformedPngCount", "transformedWebpCount",
        "diversifiedProtoXmlCount",
        "renames", "images",
    )
    private val RENAME_KEYS = setOf("resourceId", "type", "oldName", "newName", "renamedFileCount")
    private val IMAGE_KEYS = setOf(
        "oldPath", "newPath", "status", "reason", "originalSha256", "transformedSha256", "width", "height",
        "alphaPreserved", "ssim", "pHashDistance",
    )
}

private fun requireSha256(value: String, label: String) {
    require(SHA_256.matches(value)) { "$label must be a lowercase SHA-256 value" }
}

private fun requireUnitInterval(value: Double, label: String) {
    require(value.isFinite() && value in 0.0..1.0) { "$label must be between 0.0 and 1.0" }
}

private fun requireMetric(expected: Double, actual: Double, label: String) {
    require(kotlin.math.abs(expected - actual) <= EPSILON) { "$label differs from its source counts" }
}

private fun coverage(numerator: Int, denominator: Int): Double =
    if (denominator == 0) 1.0 else numerator.toDouble() / denominator

private fun Any?.planMap(label: String): Map<*, *> =
    this as? Map<*, *> ?: invalidPlan("$label must be an object")

private fun Map<*, *>.exactKeys(expected: Set<String>, label: String) {
    require(keys == expected) { "$label keys must be exactly $expected" }
}

private fun Map<*, *>.planString(key: String): String =
    this[key] as? String ?: invalidPlan("$key must be a string")

private fun Map<*, *>.planNullableString(key: String): String? = when (val value = this[key]) {
    null -> null
    is String -> value
    else -> invalidPlan("$key must be a string or null")
}

private fun Map<*, *>.planLong(key: String): Long {
    val number = this[key] as? Number ?: invalidPlan("$key must be a number")
    val decimal = number.toString()
    require(!decimal.contains('.') && !decimal.contains('e', ignoreCase = true)) { "$key must be an integer" }
    return decimal.toLongOrNull() ?: invalidPlan("$key is outside the signed 64-bit range")
}

private fun Map<*, *>.planInt(key: String): Int {
    val value = planLong(key)
    require(value in Int.MIN_VALUE..Int.MAX_VALUE) { "$key must fit a signed 32-bit integer" }
    return value.toInt()
}

private fun Map<*, *>.planDouble(key: String): Double {
    val value = (this[key] as? Number)?.toDouble() ?: invalidPlan("$key must be a number")
    require(value.isFinite()) { "$key must be finite" }
    return value
}

private fun Map<*, *>.planBoolean(key: String): Boolean =
    this[key] as? Boolean ?: invalidPlan("$key must be a boolean")

private fun Map<*, *>.planNullableDouble(key: String): Double? = when (val value = this[key]) {
    null -> null
    is Number -> value.toDouble().also { require(it.isFinite()) { "$key must be finite" } }
    else -> invalidPlan("$key must be a number or null")
}

private fun Map<*, *>.planNullableInt(key: String): Int? = when (this[key]) {
    null -> null
    else -> planInt(key)
}

private fun Map<*, *>.planNullableBoolean(key: String): Boolean? = when (val value = this[key]) {
    null -> null
    is Boolean -> value
    else -> invalidPlan("$key must be a boolean or null")
}

private fun Map<*, *>.planList(key: String): List<*> =
    this[key] as? List<*> ?: invalidPlan("$key must be an array")

private fun invalidPlan(message: String): Nothing = throw IllegalArgumentException(message)

private const val EPSILON = 1e-12
private val SHA_256 = Regex("[0-9a-f]{64}")
private val DEX_PATH = Regex("base/dex/classes(?:[2-9][0-9]*)?\\.dex")
private val DEX_METHOD_ID = Regex("L[^;]+;->[^();/]+\\([^)]*\\).+")
private val DEX_CLASS_DESCRIPTOR = Regex("L[^;]+;")
