package com.holin.android.hardening.resources

enum class ResourceEntryTransformAction {
    RENAMED,
    RENAMED_AND_TRANSFORMED,
}

enum class ResourceExclusionReason {
    UNOWNED_MODULE,
    OUTSIDE_CONFIGURED_WEBP_SCOPE,
    OUTSIDE_CONFIGURED_IMAGE_SCOPE,
    DEPENDENCY,
    GENERATED,
    EXTERNALLY_NAMED,
    NINE_PATCH,
    ANIMATION,
    NOTIFICATION_ICON,
    WEBP_UNSUPPORTED,
    UNSUPPORTED_FORMAT,
    UNSAFE_OR_UNVERIFIED_IMAGE,
}

enum class ResourceTransformFailure {
    IMAGE_COVERAGE_NOT_MET,
}

data class ResourceExclusion(
    val module: String,
    val resourceId: Int,
    val type: ResourceType,
    val name: String,
    val aabPath: String?,
    val reason: ResourceExclusionReason,
)

data class TransformedResourceEntry(
    val module: String,
    val resourceId: Int,
    val oldPath: String,
    val newPath: String,
    val action: ResourceEntryTransformAction,
    val oldSha256: String,
    val newSha256: String,
    val bytes: ByteArray,
)

data class ImageResourceReport(
    val module: String,
    val resourceId: Int,
    val oldPath: String,
    val status: ImageTransformStatus,
    val reason: ImageIneligibilityReason,
    val metrics: PngComparisonMetrics?,
    val originalWidth: Int? = null,
    val originalHeight: Int? = null,
    val newWidth: Int? = null,
    val newHeight: Int? = null,
    val dimensionChanged: Boolean = false,
    val resizeFallback: Boolean = false,
    val resizeFallbackReason: String? = null,
)

data class OwnedResourceTransformReport(
    val schemaVersion: Int = 1,
    val accepted: Boolean,
    val failure: ResourceTransformFailure?,
    val minimumImageCoverage: Double,
    val imageCoverage: Double,
    val imageCandidates: Int,
    val transformedImages: Int,
    val renameReport: ResourceRenameReport,
    val images: List<ImageResourceReport>,
    val exclusions: List<ResourceExclusion>,
)

data class OwnedResourceTransformResult(
    val outputEntries: List<TransformedResourceEntry>,
    val nameState: ResourceNameState,
    val report: OwnedResourceTransformReport,
)

class OwnedResourceTransformer(
    lineageSeed: ByteArray,
    private val minimumImageCoverage: Double,
    minimumSsim: Double = 0.995,
    minimumPHashDistance: Int = 11,
) {
    private val seed = lineageSeed.copyOf()
    private val pngDiversifier = PngDiversifier(minimumSsim, minimumPHashDistance)
    private val dimensionResizer = ImageDimensionResizer()

    init {
        require(seed.size == 32) { "resource lineage seed must be exactly 32 bytes" }
        require(minimumImageCoverage in 0.0..1.0) { "minimum image coverage must be in 0..1" }
    }

    fun transform(
        inventory: Collection<ResourceInventoryEntry>,
        generation: Long,
        contentSalt: ByteArray,
        previousNameState: ResourceNameState? = null,
    ): OwnedResourceTransformResult {
        require(contentSalt.isNotEmpty()) { "content salt must not be empty" }
        val exclusions = mutableListOf<ResourceExclusion>()
        val structurallyEligible = inventory.filter { entry ->
            val reason = structuralExclusion(entry)
            if (reason != null) exclusions += entry.exclusion(reason)
            reason == null
        }

        val imageResults = linkedMapOf<ResourceInventoryEntry, PngDiversificationResult>()
        structurallyEligible.filter(::isPng).forEach { entry ->
            val result = pngDiversifier.diversify(entry, contentSalt)
            imageResults[entry] = result
            if (result.status == ImageTransformStatus.EXCLUDED) {
                exclusions += entry.exclusion(result.reason.toResourceExclusion())
            }
        }
        val resizeResults = structurallyEligible
            .filter { entry ->
                entry.imageDiversificationEnabled && entry.imageFormat != null && entry.bytes != null &&
                    canResize(entry, imageResults[entry])
            }
            .associateWith { entry ->
                dimensionResizer.resize(requireNotNull(entry.bytes), requireNotNull(entry.imageFormat), contentSalt)
            }
        val imageEntries = (imageResults.keys + resizeResults.keys).distinct()
        val imageCandidates = imageEntries.count { entry ->
            imageResults[entry]?.status != ImageTransformStatus.EXCLUDED &&
                resizeResults[entry]?.status != ImageTransformStatus.EXCLUDED
        }
        val transformedImages = imageEntries.count { entry ->
            resizeResults[entry]?.status == ImageTransformStatus.TRANSFORMED ||
                imageResults[entry]?.status == ImageTransformStatus.TRANSFORMED
        }
        val imageCoverage = if (imageCandidates == 0) 1.0 else transformedImages.toDouble() / imageCandidates

        val renameEligible = structurallyEligible.filter { entry ->
            val diversificationStatus = imageResults[entry]?.status
            val resizeStatus = resizeResults[entry]?.status
            when {
                diversificationStatus == ImageTransformStatus.EXCLUDED -> false
                entry.imageDiversificationEnabled && resizeStatus == ImageTransformStatus.INELIGIBLE -> false
                entry.imageDiversificationEnabled && entry.aabPath?.lowercase()?.endsWith(".webp") == true &&
                    entry.bytes?.let(::isAnimatedWebp) == true -> false
                resizeStatus == ImageTransformStatus.EXCLUDED -> false
                diversificationStatus == ImageTransformStatus.INELIGIBLE ->
                    resizeStatus == ImageTransformStatus.TRANSFORMED
                else -> true
            }
        }
        imageResults.filterValues { it.status == ImageTransformStatus.INELIGIBLE }.keys
            .filterNot { resizeResults[it]?.status == ImageTransformStatus.TRANSFORMED }
            .forEach { entry ->
                exclusions += entry.exclusion(ResourceExclusionReason.UNSAFE_OR_UNVERIFIED_IMAGE)
            }

        val allocator = previousNameState?.let { ResourceNameAllocator.restore(seed, it) } ?: ResourceNameAllocator(seed)
        val allocation = allocator.reconcile(renameEligible, generation)
        val accepted = imageCoverage >= minimumImageCoverage
        val failure = if (accepted) null else ResourceTransformFailure.IMAGE_COVERAGE_NOT_MET
        val imageReports = imageResults.map { (entry, result) ->
            val resize = resizeResults[entry]
            val status = if (resize?.status == ImageTransformStatus.TRANSFORMED) {
                ImageTransformStatus.TRANSFORMED
            } else {
                result.status
            }
            ImageResourceReport(
                module = entry.module,
                resourceId = entry.resourceId,
                oldPath = requireNotNull(entry.aabPath),
                status = status,
                reason = if (status == ImageTransformStatus.TRANSFORMED) {
                    ImageIneligibilityReason.TRANSFORMED
                } else {
                    result.reason
                },
                metrics = if (resize?.dimensionChanged == true) null else result.metrics,
                originalWidth = resize?.originalWidth,
                originalHeight = resize?.originalHeight,
                newWidth = resize?.newWidth,
                newHeight = resize?.newHeight,
                dimensionChanged = resize?.dimensionChanged == true,
                resizeFallback = resize?.fallback == true,
                resizeFallbackReason = resize?.fallbackReason?.name,
            )
        } + resizeResults.keys.filterNot(imageResults::containsKey).map { entry ->
            val result = resizeResults.getValue(entry)
            ImageResourceReport(
                module = entry.module,
                resourceId = entry.resourceId,
                oldPath = requireNotNull(entry.aabPath),
                status = result.status,
                reason = if (result.status == ImageTransformStatus.TRANSFORMED) {
                    ImageIneligibilityReason.TRANSFORMED
                } else {
                    ImageIneligibilityReason.UNSUPPORTED_FORMAT
                },
                metrics = null,
                originalWidth = result.originalWidth,
                originalHeight = result.originalHeight,
                newWidth = result.newWidth,
                newHeight = result.newHeight,
                dimensionChanged = result.dimensionChanged,
                resizeFallback = result.fallback,
                resizeFallbackReason = result.fallbackReason?.name,
            )
        }.sortedBy(ImageResourceReport::oldPath)

        val outputEntries = if (accepted) {
            buildOutputEntries(renameEligible, allocation.report, imageResults, resizeResults)
        } else {
            emptyList()
        }
        return OwnedResourceTransformResult(
            outputEntries = outputEntries,
            nameState = allocation.state,
            report = OwnedResourceTransformReport(
                accepted = accepted,
                failure = failure,
                minimumImageCoverage = minimumImageCoverage,
                imageCoverage = imageCoverage,
                imageCandidates = imageCandidates,
                transformedImages = transformedImages,
                renameReport = allocation.report,
                images = imageReports,
                exclusions = exclusions.sortedWith(compareBy(ResourceExclusion::module, ResourceExclusion::resourceId, ResourceExclusion::aabPath)),
            ),
        )
    }

    private fun buildOutputEntries(
        eligible: List<ResourceInventoryEntry>,
        renameReport: ResourceRenameReport,
        imageResults: Map<ResourceInventoryEntry, PngDiversificationResult>,
        resizeResults: Map<ResourceInventoryEntry, ImageDimensionResult>,
    ): List<TransformedResourceEntry> {
        val renamesByOldPath = renameReport.renames.flatMap(ResourceRename::entries)
            .associateBy(ResourceEntryRename::oldPath)
        return eligible.mapNotNull { entry ->
            val oldPath = entry.aabPath ?: return@mapNotNull null
            val originalBytes = requireNotNull(entry.bytes) { "AAB inventory entry $oldPath has no bytes" }
            val rename = requireNotNull(renamesByOldPath[oldPath]) { "rename report omitted $oldPath" }
            val imageResult = imageResults[entry]
            val transformedBytes = resizeResults[entry]?.transformedBytes ?: imageResult?.transformedBytes ?: originalBytes
            TransformedResourceEntry(
                module = entry.module,
                resourceId = entry.resourceId,
                oldPath = oldPath,
                newPath = rename.newPath,
                action = if (
                    resizeResults[entry]?.status == ImageTransformStatus.TRANSFORMED ||
                    imageResult?.status == ImageTransformStatus.TRANSFORMED
                ) {
                    ResourceEntryTransformAction.RENAMED_AND_TRANSFORMED
                } else {
                    ResourceEntryTransformAction.RENAMED
                },
                oldSha256 = ImageMetrics.sha256(originalBytes),
                newSha256 = ImageMetrics.sha256(transformedBytes),
                bytes = transformedBytes,
            )
        }.sortedBy(TransformedResourceEntry::oldPath)
    }

    private fun structuralExclusion(entry: ResourceInventoryEntry): ResourceExclusionReason? {
        val lowerPath = entry.aabPath?.lowercase()
        return when {
            entry.origin == ResourceOrigin.DEPENDENCY -> ResourceExclusionReason.DEPENDENCY
            entry.origin == ResourceOrigin.GENERATED -> ResourceExclusionReason.GENERATED
            entry.externallyNamed -> ResourceExclusionReason.EXTERNALLY_NAMED
            entry.notificationIcon -> ResourceExclusionReason.NOTIFICATION_ICON
            entry.animation -> ResourceExclusionReason.ANIMATION
            lowerPath?.endsWith(".9.png") == true -> ResourceExclusionReason.NINE_PATCH
            entry.type == ResourceType.DRAWABLE && lowerPath?.endsWith(".webp") == true &&
                !entry.webpDiversificationEnabled -> ResourceExclusionReason.OUTSIDE_CONFIGURED_WEBP_SCOPE
            !hasSupportedRepresentation(entry, lowerPath) -> ResourceExclusionReason.UNSUPPORTED_FORMAT
            else -> null
        }
    }

    private fun hasSupportedRepresentation(entry: ResourceInventoryEntry, lowerPath: String?): Boolean = when (entry.type) {
        ResourceType.STYLE -> lowerPath == null && entry.bytes == null
        ResourceType.LAYOUT,
        ResourceType.ANIM,
        ResourceType.ANIMATOR,
        ResourceType.XML,
        -> lowerPath?.endsWith(".xml") == true && entry.bytes != null
        ResourceType.DRAWABLE ->
            (lowerPath?.endsWith(".xml") == true || lowerPath?.endsWith(".png") == true ||
                lowerPath?.endsWith(".webp") == true || lowerPath?.endsWith(".jpg") == true ||
                lowerPath?.endsWith(".jpeg") == true) && entry.bytes != null
        ResourceType.MIPMAP ->
            (lowerPath?.endsWith(".xml") == true || lowerPath?.endsWith(".png") == true ||
                lowerPath?.endsWith(".webp") == true || lowerPath?.endsWith(".jpg") == true ||
                lowerPath?.endsWith(".jpeg") == true) && entry.bytes != null
        ResourceType.FONT ->
            FONT_EXTENSIONS.any { lowerPath?.endsWith(it) == true } && entry.bytes != null
        ResourceType.RAW -> lowerPath != null && entry.bytes != null
    }

    private fun isPng(entry: ResourceInventoryEntry): Boolean =
        entry.type in setOf(ResourceType.DRAWABLE, ResourceType.MIPMAP) &&
            entry.aabPath?.lowercase()?.endsWith(".png") == true

    private fun canResize(
        entry: ResourceInventoryEntry,
        diversification: PngDiversificationResult?,
    ): Boolean {
        if (entry.aabPath?.lowercase()?.endsWith(".webp") == true &&
            entry.bytes?.let(::isAnimatedWebp) == true
        ) return false
        return when {
            diversification == null -> true
            diversification.status == ImageTransformStatus.EXCLUDED -> false
            diversification.status == ImageTransformStatus.TRANSFORMED -> true
            diversification.reason == ImageIneligibilityReason.NO_SAFE_PERTURBATION -> true
            diversification.reason == ImageIneligibilityReason.BYTE_GROWTH_LIMIT -> true
            else -> false
        }
    }

    private fun isAnimatedWebp(bytes: ByteArray): Boolean {
        if (bytes.size < 16 || !bytes.copyOfRange(0, 4).contentEquals("RIFF".encodeToByteArray()) ||
            !bytes.copyOfRange(8, 12).contentEquals("WEBP".encodeToByteArray())
        ) return false
        var offset = 12
        while (offset + 8 <= bytes.size) {
            val type = bytes.copyOfRange(offset, offset + 4).toString(Charsets.ISO_8859_1)
            val length = littleEndianInt(bytes, offset + 4)
            if (length < 0 || offset + 8L + length > bytes.size) return false
            if (type == "ANIM") return true
            if (type == "VP8X" && length >= 5 && (bytes[offset + 8 + 4].toInt() and 0x02) != 0) return true
            offset += 8 + length + (length and 1)
        }
        return false
    }

    private fun littleEndianInt(bytes: ByteArray, offset: Int): Int =
        (bytes[offset].toInt() and 0xff) or
            ((bytes[offset + 1].toInt() and 0xff) shl 8) or
            ((bytes[offset + 2].toInt() and 0xff) shl 16) or
            ((bytes[offset + 3].toInt() and 0xff) shl 24)

    private fun ResourceInventoryEntry.exclusion(reason: ResourceExclusionReason) = ResourceExclusion(
        module = module,
        resourceId = resourceId,
        type = type,
        name = name,
        aabPath = aabPath,
        reason = reason,
    )

    private fun ImageIneligibilityReason.toResourceExclusion(): ResourceExclusionReason = when (this) {
        ImageIneligibilityReason.UNOWNED_MODULE -> ResourceExclusionReason.UNOWNED_MODULE
        ImageIneligibilityReason.OUTSIDE_CONFIGURED_WEBP_SCOPE ->
            ResourceExclusionReason.OUTSIDE_CONFIGURED_WEBP_SCOPE
        ImageIneligibilityReason.OUTSIDE_CONFIGURED_IMAGE_SCOPE ->
            ResourceExclusionReason.OUTSIDE_CONFIGURED_IMAGE_SCOPE
        ImageIneligibilityReason.NINE_PATCH -> ResourceExclusionReason.NINE_PATCH
        ImageIneligibilityReason.ANIMATION -> ResourceExclusionReason.ANIMATION
        ImageIneligibilityReason.NOTIFICATION_ICON -> ResourceExclusionReason.NOTIFICATION_ICON
        ImageIneligibilityReason.EXTERNALLY_NAMED -> ResourceExclusionReason.EXTERNALLY_NAMED
        ImageIneligibilityReason.WEBP_UNSUPPORTED -> ResourceExclusionReason.WEBP_UNSUPPORTED
        ImageIneligibilityReason.DEPENDENCY_RESOURCE -> ResourceExclusionReason.DEPENDENCY
        ImageIneligibilityReason.GENERATED_RESOURCE -> ResourceExclusionReason.GENERATED
        ImageIneligibilityReason.UNSUPPORTED_FORMAT -> ResourceExclusionReason.UNSUPPORTED_FORMAT
        ImageIneligibilityReason.UNVERIFIED_PNG,
        ImageIneligibilityReason.UNVERIFIED_WEBP,
        ImageIneligibilityReason.BYTE_GROWTH_LIMIT,
        ImageIneligibilityReason.CORPUS_PHASH_CONFLICT,
        ImageIneligibilityReason.NO_SAFE_PERTURBATION,
        ImageIneligibilityReason.TRANSFORMED,
        -> ResourceExclusionReason.UNSAFE_OR_UNVERIFIED_IMAGE
    }

    companion object {
        private val FONT_EXTENSIONS = setOf(".xml", ".ttf", ".otf", ".ttc")
    }
}
