package com.holin.android.hardening.resources

enum class ResourceEntryTransformAction {
    RENAMED,
    RENAMED_AND_TRANSFORMED,
}

enum class ResourceExclusionReason {
    UNOWNED_MODULE,
    OUTSIDE_CONFIGURED_WEBP_SCOPE,
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
        val imageCandidates = imageResults.values.count { it.status != ImageTransformStatus.EXCLUDED }
        val transformedImages = imageResults.values.count { it.status == ImageTransformStatus.TRANSFORMED }
        val imageCoverage = if (imageCandidates == 0) 1.0 else transformedImages.toDouble() / imageCandidates

        val renameEligible = structurallyEligible.filter { entry ->
            imageResults[entry]?.status.let { status -> status == null || status == ImageTransformStatus.TRANSFORMED }
        }
        imageResults.filterValues { it.status == ImageTransformStatus.INELIGIBLE }.keys.forEach { entry ->
            exclusions += entry.exclusion(ResourceExclusionReason.UNSAFE_OR_UNVERIFIED_IMAGE)
        }

        val allocator = previousNameState?.let { ResourceNameAllocator.restore(seed, it) } ?: ResourceNameAllocator(seed)
        val allocation = allocator.reconcile(renameEligible, generation)
        val accepted = imageCoverage >= minimumImageCoverage
        val failure = if (accepted) null else ResourceTransformFailure.IMAGE_COVERAGE_NOT_MET
        val imageReports = imageResults.map { (entry, result) ->
            ImageResourceReport(
                module = entry.module,
                resourceId = entry.resourceId,
                oldPath = requireNotNull(entry.aabPath),
                status = result.status,
                reason = result.reason,
                metrics = result.metrics,
            )
        }.sortedBy(ImageResourceReport::oldPath)

        val outputEntries = if (accepted) {
            buildOutputEntries(renameEligible, allocation.report, imageResults)
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
    ): List<TransformedResourceEntry> {
        val renamesByOldPath = renameReport.renames.flatMap(ResourceRename::entries)
            .associateBy(ResourceEntryRename::oldPath)
        return eligible.mapNotNull { entry ->
            val oldPath = entry.aabPath ?: return@mapNotNull null
            val originalBytes = requireNotNull(entry.bytes) { "AAB inventory entry $oldPath has no bytes" }
            val rename = requireNotNull(renamesByOldPath[oldPath]) { "rename report omitted $oldPath" }
            val imageResult = imageResults[entry]
            val transformedBytes = imageResult?.transformedBytes ?: originalBytes
            TransformedResourceEntry(
                module = entry.module,
                resourceId = entry.resourceId,
                oldPath = oldPath,
                newPath = rename.newPath,
                action = if (imageResult?.status == ImageTransformStatus.TRANSFORMED) {
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
                lowerPath?.endsWith(".webp") == true) && entry.bytes != null
        ResourceType.MIPMAP ->
            (lowerPath?.endsWith(".xml") == true || lowerPath?.endsWith(".png") == true ||
                lowerPath?.endsWith(".webp") == true) && entry.bytes != null
        ResourceType.FONT ->
            FONT_EXTENSIONS.any { lowerPath?.endsWith(it) == true } && entry.bytes != null
        ResourceType.RAW -> lowerPath != null && entry.bytes != null
    }

    private fun isPng(entry: ResourceInventoryEntry): Boolean =
        entry.type == ResourceType.DRAWABLE && entry.aabPath?.lowercase()?.endsWith(".png") == true

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
        ImageIneligibilityReason.NO_SAFE_PERTURBATION,
        ImageIneligibilityReason.TRANSFORMED,
        -> ResourceExclusionReason.UNSAFE_OR_UNVERIFIED_IMAGE
    }

    companion object {
        private val FONT_EXTENSIONS = setOf(".xml", ".ttf", ".otf", ".ttc")
    }
}
