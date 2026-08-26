package com.holin.android.hardening.artifact

import com.android.tools.smali.dexlib2.dexbacked.DexBackedDexFile
import com.holin.android.hardening.HardeningOwnership
import com.holin.android.hardening.HardcodedReferenceKind
import com.holin.android.hardening.audit.HardeningSourceAudit
import com.holin.android.hardening.audit.HardeningSourceAuditScanner
import com.holin.android.hardening.dex.DexTransformRequest
import com.holin.android.hardening.dex.DexClassAccessCompatibility
import com.holin.android.hardening.dex.MethodEligibilityReason
import com.holin.android.hardening.dex.SafeDexTransformer
import com.holin.android.hardening.inventory.OwnedDexDescriptorProof
import com.holin.android.hardening.inventory.OwnedDexInventoryBuilder
import com.holin.android.hardening.naming.PseudowordRegistry
import com.holin.android.hardening.naming.RegistrySnapshot
import com.holin.android.hardening.resources.ImageTransformStatus
import com.holin.android.hardening.resources.ImageIneligibilityReason
import com.holin.android.hardening.resources.OwnedResourceInventoryBuilder
import com.holin.android.hardening.resources.PngDiversifier
import com.holin.android.hardening.resources.ProtoResourceDiversifier
import com.holin.android.hardening.resources.ResourcePseudowordAllocator
import com.holin.android.hardening.resources.ResourceTableTransformer
import com.holin.android.hardening.resources.ResourceType
import com.holin.android.hardening.resources.SfntFontDiversifier
import com.holin.android.hardening.resources.WebpDiversifier
import com.holin.android.hardening.resources.WebpEncodingPolicy
import com.holin.android.hardening.resources.WebpIneligibilityReason
import com.holin.android.hardening.state.Sha256
import com.holin.android.hardening.similarity.OwnedArtifactInventory
import com.holin.android.hardening.similarity.OwnedResourceKey
import com.holin.android.hardening.similarity.OwnedResourceLocation
import com.holin.android.hardening.similarity.ValidatedOwnedArtifactInventories
import java.nio.file.Files
import java.nio.file.Path
import java.util.zip.ZipFile

data class HardenedBundlePlanRequest(
    val ordinaryAab: Path,
    val repositoryRoot: Path,
    val r8MappingText: String,
    val namespace: String,
    val applicationId: String,
    val lineageSeed: ByteArray,
    val registrySnapshot: RegistrySnapshot,
    val generation: Long,
    val contentSalt: ByteArray,
    val minimumCodeCoverage: Double,
    val minimumSimHashDistance: Int = 4,
    val maximumDexGrowthRatio: Double,
    val enforceMaximumDexGrowth: Boolean = true,
    val minimumImageCoverage: Double,
    val minimumImageSsim: Double,
    val minimumImagePHashDistance: Int,
    val applicationModulePath: String,
    val ownership: HardeningOwnership,
    val fixedSeedProvided: Boolean = false,
    val fixedSeedHash: String? = null,
) {
    init {
        require(fixedSeedProvided == (fixedSeedHash != null)) {
            "fixed seed hash must be present exactly when fixedSeedProvided is true"
        }
        fixedSeedHash?.let { hash ->
            require(FIXED_SEED_SHA_256.matches(hash)) { "fixedSeedHash must be a lowercase SHA-256" }
        }
    }
}

data class HardenedBundlePlan(
    val replacements: List<BundleEntryReplacement>,
    val updatedRegistry: RegistrySnapshot,
    val report: HardenedBundlePlanReport,
    val ownedArtifactInventory: OwnedArtifactInventory,
    val ownedArtifactAnalysisInventory: OwnedArtifactInventory,
    val dexVerificationScope: DexSemanticVerificationScope,
)

/**
 * Builds an in-memory, closed-world transformation plan for an ordinary AAB.
 *
 * This class is intentionally read-only: the caller owns persistence and only commits the
 * returned registry after the rewritten, validated and signed artifact has succeeded.
 */
class HardenedBundlePlanner(
    private val dexTransformer: SafeDexTransformer = SafeDexTransformer(),
    private val resourceTableTransformer: ResourceTableTransformer = ResourceTableTransformer(),
    private val protoResourceDiversifier: ProtoResourceDiversifier = ProtoResourceDiversifier(),
    private val sfntFontDiversifier: SfntFontDiversifier = SfntFontDiversifier(),
) {
    fun plan(request: HardenedBundlePlanRequest): HardenedBundlePlan {
        validateRequest(request)
        val ordinary = request.ordinaryAab.toAbsolutePath().normalize()
        val repository = request.repositoryRoot.toAbsolutePath().normalize()
        val lineageSeed = request.lineageSeed.copyOf()
        val contentSalt = request.contentSalt.copyOf()
        val entries = readEntries(ordinary)

        val dexInventory = OwnedDexInventoryBuilder(repository, request.ownership).build(request.r8MappingText)
        val provenDescriptors = dexInventory.descriptorProofs
            .mapTo(sortedSetOf(), OwnedDexDescriptorProof::outputDescriptor)
        require(provenDescriptors == dexInventory.acceptedDexDescriptors && provenDescriptors.isNotEmpty()) {
            "owned DEX inventory has no complete exact output descriptor proof"
        }
        val filteredDescriptors = dexInventory.mixedOrUnownedMergedDescriptors
        val discoveredDescriptors = provenDescriptors + filteredDescriptors
        val dexPlan = planDex(
            entries,
            provenDescriptors,
            dexInventory.accessCompatibilityDexDescriptors,
            discoveredDescriptors.size,
            filteredDescriptors.size,
            contentSalt,
            request.minimumCodeCoverage,
            request.minimumSimHashDistance,
            request.maximumDexGrowthRatio,
            request.enforceMaximumDexGrowth,
            request.ownership.deniedDexDescriptorPrefixes,
        )

        val resourcesPb = requireNotNull(entries[RESOURCES_PB_PATH]) {
            "ordinary AAB is missing $RESOURCES_PB_PATH"
        }
        val sourceAudit = HardeningSourceAuditScanner(
            repository,
            request.ownership.modules.single { it.path == request.applicationModulePath }.directory,
            request.namespace,
            ownership = request.ownership,
        ).scan()
        val externallyNamedResources = scopedExternallyNamedResources(
            sourceAudit,
            request.namespace,
            request.applicationId,
        )
        val resourceInventory = OwnedResourceInventoryBuilder(
            repository,
            request.ownership,
            externallyNamedResources = externallyNamedResources,
        )
            .build(resourcesPb, entries)
        val allocatableInventory = resourceInventory.filterNot { it.externallyNamed }
        val renameableInventory = allocatableInventory.filterNot { it.notificationIcon }
        require(renameableInventory.isNotEmpty()) {
            "owned resource inventory has no renameable hardening resource"
        }
        val restoredRegistry = PseudowordRegistry.restore(lineageSeed, request.registrySnapshot)
        val allocation = ResourcePseudowordAllocator(request.namespace, restoredRegistry)
            .allocate(allocatableInventory, request.generation)
        require(allocation.report.renames.any { it.oldName != it.newName }) {
            "resource hardening produced no effective logical rename"
        }
        val notificationRenames = allocation.report.renames.filter { it.oldName == NOTIFICATION_ICON }
        require(notificationRenames.size <= 1 && notificationRenames.all { rename ->
            rename.type == ResourceType.DRAWABLE && rename.newName == NOTIFICATION_ICON && rename.entries.isNotEmpty()
        }) {
            "$NOTIFICATION_ICON must retain its logical name and receive physical path replacements when present"
        }
        val tableResult = resourceTableTransformer.transform(resourcesPb, allocation.report)
        require(!tableResult.resourcesPb.contentEquals(resourcesPb)) {
            "resource hardening did not change resources.pb"
        }
        val resourcePlan = planResources(
            entries = entries,
            inventory = resourceInventory,
            tableResult = tableResult,
            contentSalt = contentSalt,
            minimumImageCoverage = request.minimumImageCoverage,
            minimumImageSsim = request.minimumImageSsim,
            minimumImagePHashDistance = request.minimumImagePHashDistance,
        )

        val replacements = (dexPlan.replacements + resourcePlan.replacements)
            .sortedBy(BundleEntryReplacement::oldPath)
        validateReplacementClosure(entries.keys, replacements)
        val report = HardenedBundlePlanReport(
            1,
            Sha256.file(ordinary),
            Sha256.hex(contentSalt),
            request.namespace,
            request.generation,
            request.ownership.modulePaths,
            dexPlan.report,
            resourcePlan.report,
            request.fixedSeedProvided,
            request.fixedSeedHash,
        )
        val ownedArtifactInventory = ownedArtifactInventory(
            request.ownership.modulePaths,
            provenDescriptors,
            resourceInventory,
            tableResult.logicalZipPathRenames,
        )
        val ownedArtifactAnalysisInventory = ownedArtifactInventory(
            request.ownership.modulePaths,
            provenDescriptors,
            resourceInventory,
            tableResult.zipPathRenames,
        )
        ValidatedOwnedArtifactInventories(ownedArtifactInventory, ownedArtifactAnalysisInventory)
        return HardenedBundlePlan(
            replacements,
            allocation.registry,
            report,
            ownedArtifactInventory,
            ownedArtifactAnalysisInventory,
            DexSemanticVerificationScope(
                provenDescriptors.toSet(),
                request.ownership.deniedDexDescriptorPrefixes,
                emptySet(),
                dexInventory.accessCompatibilityDexDescriptors,
            ),
        )
    }

    private fun ownedArtifactInventory(
        ownedModules: Set<String>,
        ownedDescriptors: Set<String>,
        resources: List<com.holin.android.hardening.resources.ResourceInventoryEntry>,
        hardenedPaths: Map<String, String>,
    ): OwnedArtifactInventory {
        val fileResources = resources.asSequence()
            .filter { it.aabPath != null && it.bytes != null }
            .sortedWith(compareBy({ it.resourceId }, { it.qualifier }))
            .toList()
        require(fileResources.isNotEmpty()) { "compiled owned resource inventory has no file locations" }
        val ordinary = linkedMapOf<OwnedResourceKey, OwnedResourceLocation>()
        val hardened = linkedMapOf<OwnedResourceKey, OwnedResourceLocation>()
        fileResources.forEach { resource ->
            val key = OwnedResourceKey(resource.resourceId, resource.qualifier)
            val ordinaryPath = requireNotNull(resource.aabPath)
            val hardenedPath = hardenedPaths[ordinaryPath] ?: ordinaryPath
            val semanticHash = Sha256.hex(
                listOf(resource.resourceId, resource.qualifier, resource.type.name, resource.name)
                    .joinToString("\u0000").toByteArray(Charsets.UTF_8),
            )
            require(ordinary.put(
                key,
                OwnedResourceLocation(
                    entryName = ordinaryPath.substringAfterLast('/'),
                    aabPath = ordinaryPath,
                    apkPath = ordinaryPath.removePrefix("base/"),
                    semanticHash = semanticHash,
                ),
            ) == null) { "compiled owned resource inventory contains a duplicate key $key" }
            hardened[key] = OwnedResourceLocation(
                entryName = hardenedPath.substringAfterLast('/'),
                aabPath = hardenedPath,
                apkPath = hardenedPath.removePrefix("base/"),
                semanticHash = semanticHash,
            )
        }
        return OwnedArtifactInventory(ownedModules, ownedDescriptors, ordinary, hardened)
    }

    private fun planDex(
        entries: Map<String, ByteArray>,
        acceptedDescriptors: Set<String>,
        accessCompatibilityDescriptors: Set<String>,
        discoveredDescriptorCount: Int,
        filteredDescriptorCount: Int,
        contentSalt: ByteArray,
        minimumCoverage: Double,
        minimumSimHashDistance: Int,
        maximumGrowthRatio: Double,
        enforceMaximumGrowth: Boolean,
        deniedDescriptorPrefixes: Set<String>,
    ): DexPlan {
        val dexEntries = entries.filterKeys(DEX_PATH::matches).toSortedMap()
        require(dexEntries.isNotEmpty()) { "ordinary AAB contains no base DEX entries" }
        val replacements = mutableListOf<BundleEntryReplacement>()
        val reports = mutableListOf<PlannedDexEntry>()
        val seenAcceptedDescriptors = linkedSetOf<String>()
        val requiredPublicClasses = DexClassAccessCompatibility.requiredPublicClassDescriptors(
            dexEntries.values,
            accessCompatibilityDescriptors,
        )

        dexEntries.forEach { (path, bytes) ->
            val dexDescriptors = runCatching {
                DexBackedDexFile.fromInputStream(null, bytes.inputStream()).classes.mapTo(linkedSetOf()) { it.type }
            }.getOrElse { failure -> throw IllegalArgumentException("$path is not a readable DEX", failure) }
            val exactOwned = acceptedDescriptors.intersect(dexDescriptors)
            val publicClassesInDex = requiredPublicClasses.intersect(dexDescriptors)
            if (exactOwned.isEmpty() && publicClassesInDex.isEmpty()) return@forEach
            val duplicateDescriptors = exactOwned.intersect(seenAcceptedDescriptors)
            require(duplicateDescriptors.isEmpty()) {
                "$path duplicates accepted owned DEX descriptors: ${duplicateDescriptors.sorted()}"
            }
            seenAcceptedDescriptors += exactOwned
            val transformed = dexTransformer.transform(
                bytes,
                DexTransformRequest(
                    emptySet(),
                    exactOwned,
                    contentSalt,
                    0.0,
                    minimumSimHashDistance,
                    maximumGrowthRatio,
                    enforceMaximumGrowth,
                    1.0,
                    deniedDescriptorPrefixes,
                    emptySet(),
                    publicClassesInDex,
                    true,
                    true,
                ),
            )
            val dexReport = transformed.report
            require(dexReport.publicizedClassDescriptors == publicClassesInDex) {
                "$path DEX access compatibility report differs from its global plan"
            }
            if (dexReport.inputCanonicalized) {
                require(!transformed.dexBytes.contentEquals(bytes)) {
                    "$path canonicalization must replace the invalid input bytes"
                }
                require(
                    !dexReport.noEligibleMethodsSkipped && !dexReport.writerFloorSkipped &&
                        dexReport.eligibleMethodCount == 0 && dexReport.eligibleInstructionCount == 0 &&
                        dexReport.transformedMethodCount == 0 && dexReport.transformedInstructionCount == 0,
                ) { "$path canonicalization has inconsistent method accounting" }
                replacements += BundleEntryReplacement(
                    oldPath = path,
                    newPath = path,
                    bytes = transformed.dexBytes,
                    semanticVerifier = BundleSemanticVerifier.DEX_SEMANTICS,
                )
                reports += PlannedDexEntry(
                    path = path,
                    status = PlannedDexStatus.CANONICALIZED,
                    inputSha256 = dexReport.inputSha256,
                    outputSha256 = dexReport.outputSha256,
                    inputByteCount = bytes.size.toLong(),
                    outputByteCount = transformed.dexBytes.size.toLong(),
                    ownedDescriptorCount = exactOwned.size,
                    ownedMethodCount = dexReport.ownedMethodCount,
                    eligibleMethodCount = 0,
                    transformedMethodCount = 0,
                    ownedInstructionCount = dexReport.ownedInstructionCount,
                    eligibleInstructionCount = 0,
                    transformedInstructionCount = 0,
                    transformedMethods = emptyList(),
                )
                return@forEach
            }
            if (dexReport.noEligibleMethodsSkipped) {
                require(transformed.dexBytes.contentEquals(bytes)) {
                    "$path no-eligible-method skip must retain the original DEX bytes"
                }
                require(
                    dexReport.eligibleMethodCount == 0 && dexReport.eligibleInstructionCount == 0 &&
                        dexReport.transformedMethodCount == 0 && dexReport.transformedInstructionCount == 0,
                ) { "$path no-eligible-method skip has inconsistent method accounting" }
                reports += PlannedDexEntry(
                    path = path,
                    status = PlannedDexStatus.NO_ELIGIBLE_METHODS_SKIPPED,
                    inputSha256 = dexReport.inputSha256,
                    outputSha256 = dexReport.outputSha256,
                    inputByteCount = bytes.size.toLong(),
                    outputByteCount = bytes.size.toLong(),
                    ownedDescriptorCount = exactOwned.size,
                    ownedMethodCount = dexReport.ownedMethodCount,
                    eligibleMethodCount = 0,
                    transformedMethodCount = 0,
                    ownedInstructionCount = dexReport.ownedInstructionCount,
                    eligibleInstructionCount = 0,
                    transformedInstructionCount = 0,
                    transformedMethods = emptyList(),
                )
                return@forEach
            }
            if (dexReport.writerFloorSkipped) {
                require(transformed.dexBytes.contentEquals(bytes)) {
                    "$path writer-floor skip must retain the original DEX bytes"
                }
                require(dexReport.transformedMethodCount == 0 && dexReport.transformedInstructionCount == 0) {
                    "$path writer-floor skip must not claim transformed code"
                }
                reports += PlannedDexEntry(
                    path = path,
                    status = PlannedDexStatus.WRITER_FLOOR_SKIPPED,
                    inputSha256 = dexReport.inputSha256,
                    outputSha256 = dexReport.outputSha256,
                    inputByteCount = bytes.size.toLong(),
                    outputByteCount = bytes.size.toLong(),
                    ownedDescriptorCount = exactOwned.size,
                    ownedMethodCount = dexReport.ownedMethodCount,
                    eligibleMethodCount = dexReport.eligibleMethodCount,
                    transformedMethodCount = dexReport.transformedMethodCount,
                    ownedInstructionCount = dexReport.ownedInstructionCount,
                    eligibleInstructionCount = dexReport.eligibleInstructionCount,
                    transformedInstructionCount = dexReport.transformedInstructionCount,
                    transformedMethods = emptyList(),
                )
                return@forEach
            }
            require(
                !transformed.dexBytes.contentEquals(bytes) &&
                    (dexReport.transformedMethodCount > 0 || dexReport.publicizedClassDescriptors.isNotEmpty()),
            ) {
                "$path produced no effective DEX transformation"
            }
            replacements += BundleEntryReplacement(
                oldPath = path,
                newPath = path,
                bytes = transformed.dexBytes,
                semanticVerifier = BundleSemanticVerifier.DEX_SEMANTICS,
            )
            reports += PlannedDexEntry(
                path,
                PlannedDexStatus.TRANSFORMED,
                dexReport.inputSha256,
                dexReport.outputSha256,
                bytes.size.toLong(),
                transformed.dexBytes.size.toLong(),
                exactOwned.size,
                dexReport.ownedMethodCount,
                dexReport.eligibleMethodCount,
                dexReport.transformedMethodCount,
                dexReport.ownedInstructionCount,
                dexReport.eligibleInstructionCount,
                dexReport.transformedInstructionCount,
                dexReport.publicizedClassDescriptors,
                dexReport.methods.asSequence()
                    .filter { method -> method.reason == MethodEligibilityReason.TRANSFORMED }
                    .map { method ->
                        PlannedDexMethod(
                            methodId = method.methodId,
                            originalInstructionCount = method.oldInstructionCount,
                            simHashDistance = method.simHashDistance,
                            opaqueDiamondCount = method.insertedOpaqueDiamondCount,
                        )
                    }
                    .sortedBy(PlannedDexMethod::methodId)
                    .toList(),
            )
        }
        val missingDescriptors = acceptedDescriptors - seenAcceptedDescriptors
        require(missingDescriptors.isEmpty()) {
            "accepted owned DEX descriptors are missing from the ordinary AAB: ${missingDescriptors.sorted()}"
        }
        require(replacements.isNotEmpty()) { "owned DEX inventory produced no effective DEX transformation" }
        return DexPlan(
            replacements,
            PlannedDexSummary(
                discoveredOwnedDescriptorCount = discoveredDescriptorCount,
                boundaryAcceptedDescriptorCount = acceptedDescriptors.size,
                boundaryFilteredDescriptorCount = filteredDescriptorCount,
                minimumCodeCoverage = minimumCoverage,
                minimumSimHashDistance = minimumSimHashDistance,
                maximumGrowthRatio = maximumGrowthRatio,
                enforceMaximumGrowth = enforceMaximumGrowth,
                entries = reports,
            ),
        )
    }

    private fun planResources(
        entries: Map<String, ByteArray>,
        inventory: List<com.holin.android.hardening.resources.ResourceInventoryEntry>,
        tableResult: com.holin.android.hardening.resources.ResourceTableTransformResult,
        contentSalt: ByteArray,
        minimumImageCoverage: Double,
        minimumImageSsim: Double,
        minimumImagePHashDistance: Int,
    ): ResourcePlan {
        val pngDiversifier = PngDiversifier(minimumImageSsim, minimumImagePHashDistance)
        val webpDiversifier = WebpDiversifier(
            minimumSsim = minimumImageSsim,
            minimumPHashDistance = minimumImagePHashDistance,
            encodingPolicy = WebpEncodingPolicy.GLOBAL_AAB_BUDGET,
        )
        val imageResults = linkedMapOf<String, DiversifiedImage>()
        inventory.asSequence()
            .filter { it.type == ResourceType.DRAWABLE && it.aabPath != null && it.bytes != null }
            .filter { resource ->
                val path = requireNotNull(resource.aabPath).lowercase()
                path.endsWith(".png") || path.endsWith(".webp")
            }
            .distinctBy { it.aabPath }
            .sortedBy { it.aabPath }
            .forEach { resource ->
                val oldPath = requireNotNull(resource.aabPath)
                val originalHash = Sha256.hex(requireNotNull(resource.bytes))
                imageResults[oldPath] = if (oldPath.lowercase().endsWith(".webp")) {
                    val result = webpDiversifier.diversify(resource, contentSalt)
                    val metrics = result.metrics
                    DiversifiedImage(
                        transformedBytes = result.transformedBytes,
                        originalByteCount = requireNotNull(resource.bytes).size.toLong(),
                        report = PlannedImageEntry(
                            oldPath = oldPath,
                            newPath = tableResult.zipPathRenames[oldPath],
                            status = result.status,
                            reason = result.reason.toImageReason(),
                            originalSha256 = originalHash,
                            transformedSha256 = metrics?.transformedSha256,
                            width = metrics?.width,
                            height = metrics?.height,
                            alphaPreserved = metrics?.alphaPreserved,
                            ssim = metrics?.ssim,
                            pHashDistance = metrics?.pHashDistance,
                        ),
                    )
                } else {
                    val result = pngDiversifier.diversify(resource, contentSalt)
                    val metrics = result.metrics
                    DiversifiedImage(
                        transformedBytes = result.transformedBytes,
                        originalByteCount = requireNotNull(resource.bytes).size.toLong(),
                        report = PlannedImageEntry(
                            oldPath = oldPath,
                            newPath = tableResult.zipPathRenames[oldPath],
                            status = result.status,
                            reason = result.reason,
                            originalSha256 = originalHash,
                            transformedSha256 = metrics?.transformedSha256,
                            width = metrics?.width,
                            height = metrics?.height,
                            alphaPreserved = metrics?.alphaPreserved,
                            ssim = metrics?.ssim,
                            pHashDistance = metrics?.pHashDistance,
                        ),
                    )
                }
            }

        val diversifiedTable = protoResourceDiversifier.diversifyResourceTable(tableResult.resourcesPb, contentSalt)
        val replacements = mutableListOf(
            BundleEntryReplacement(
                oldPath = RESOURCES_PB_PATH,
                newPath = RESOURCES_PB_PATH,
                bytes = diversifiedTable,
                semanticVerifier = BundleSemanticVerifier.RESOURCE_SEMANTICS,
            ),
        )
        var diversifiedProtoXmlCount = 0
        val resourcesByPath = inventory.filter { it.aabPath != null }.associateBy { requireNotNull(it.aabPath) }
        tableResult.zipPathRenames.toSortedMap().forEach { (oldPath, newPath) ->
            val original = requireNotNull(entries[oldPath]) { "resource rename source is missing from AAB: $oldPath" }
            val imageBytes = imageResults[oldPath]?.transformedBytes
            val resource = requireNotNull(resourcesByPath[oldPath]) {
                "resource path rename is absent from the owned inventory: $oldPath"
            }
            val xmlBytes = if (resource.type != ResourceType.RAW && oldPath.lowercase().endsWith(".xml")) {
                diversifiedProtoXmlCount++
                protoResourceDiversifier.diversifyXml(original, contentSalt, oldPath)
            } else {
                null
            }
            val fontBytes = if (
                resource.type == ResourceType.FONT &&
                (oldPath.endsWith(".ttf", true) || oldPath.endsWith(".otf", true))
            ) {
                sfntFontDiversifier.diversify(original, contentSalt, oldPath)
            } else {
                null
            }
            val replacementBytes = imageBytes ?: xmlBytes ?: fontBytes ?: original
            replacements += BundleEntryReplacement(
                oldPath = oldPath,
                newPath = newPath,
                bytes = replacementBytes,
                semanticVerifier = if (replacementBytes.contentEquals(original)) {
                    null
                } else {
                    BundleSemanticVerifier.RESOURCE_SEMANTICS
                },
            )
        }
        val tableReport = tableResult.report
        require(tableReport.renames.isNotEmpty()) { "resource table produced no effective transformation" }
        val renameReports = tableReport.renames.map { rename ->
            PlannedResourceRename(
                resourceId = rename.resourceId,
                type = rename.type,
                oldName = rename.oldName,
                newName = rename.newName,
                renamedFileCount = rename.fileReferencesChanged,
            )
        }
        val imageReports = imageResults.values.map(DiversifiedImage::report)
        imageReports.filter { it.status == ImageTransformStatus.TRANSFORMED }.forEach { image ->
            require(requireNotNull(image.ssim) + EPSILON >= minimumImageSsim) {
                "image ${image.oldPath} failed its SSIM gate"
            }
            require(requireNotNull(image.pHashDistance) >= minimumImagePHashDistance) {
                "image ${image.oldPath} failed its pHash gate"
            }
        }
        val eligibleImageCount = imageReports.count { it.status != ImageTransformStatus.EXCLUDED }
        val transformedImageCount = imageReports.count { it.status == ImageTransformStatus.TRANSFORMED }
        val imageCoverage = coverage(transformedImageCount, eligibleImageCount)
        require(imageCoverage + EPSILON >= minimumImageCoverage) {
            "safe bitmap coverage $imageCoverage ($transformedImageCount/$eligibleImageCount) is below " +
                "$minimumImageCoverage"
        }
        val eligibleImageBytes = imageResults.values
            .filter { it.report.status != ImageTransformStatus.EXCLUDED }
            .sumOf(DiversifiedImage::originalByteCount)
        val transformedImageBytes = imageResults.values
            .filter { it.report.status == ImageTransformStatus.TRANSFORMED }
            .sumOf(DiversifiedImage::originalByteCount)
        val imageByteCoverage = coverage(transformedImageBytes, eligibleImageBytes)
        require(imageByteCoverage + EPSILON >= minimumImageCoverage) {
            "safe bitmap byte coverage $imageByteCoverage ($transformedImageBytes/$eligibleImageBytes bytes) is below " +
                "$minimumImageCoverage"
        }
        return ResourcePlan(
            replacements,
            PlannedResourceSummary(
                inventoryVariantCount = inventory.size,
                renamedResourceCount = renameReports.size,
                renamedFileCount = renameReports.sumOf(PlannedResourceRename::renamedFileCount),
                resourcesPbInputSha256 = Sha256.hex(requireNotNull(entries[RESOURCES_PB_PATH])),
                resourcesPbOutputSha256 = Sha256.hex(diversifiedTable),
                minimumImageCoverage = minimumImageCoverage,
                minimumImageSsim = minimumImageSsim,
                minimumImagePHashDistance = minimumImagePHashDistance,
                eligibleImageCount = eligibleImageCount,
                transformedImageCount = transformedImageCount,
                imageCoverage = imageCoverage,
                eligibleImageBytes = eligibleImageBytes,
                transformedImageBytes = transformedImageBytes,
                imageByteCoverage = imageByteCoverage,
                transformedPngCount = imageReports.count {
                    it.status == ImageTransformStatus.TRANSFORMED && it.oldPath.lowercase().endsWith(".png")
                },
                transformedWebpCount = imageReports.count {
                    it.status == ImageTransformStatus.TRANSFORMED && it.oldPath.lowercase().endsWith(".webp")
                },
                diversifiedProtoXmlCount = diversifiedProtoXmlCount,
                renames = renameReports,
                images = imageReports,
            ),
        )
    }

    private fun validateRequest(request: HardenedBundlePlanRequest) {
        require(Files.isRegularFile(request.ordinaryAab)) { "ordinary AAB input is missing" }
        require(Files.isDirectory(request.repositoryRoot)) { "repository root is missing" }
        require(request.applicationModulePath in request.ownership.modulePaths) {
            "application module is outside the bundle hardening ownership scope: ${request.applicationModulePath}"
        }
        require(request.r8MappingText.isNotBlank()) { "R8 mapping must not be blank" }
        require(request.namespace.isNotBlank()) { "namespace must not be blank" }
        require(request.lineageSeed.size == 32) { "lineage seed must be exactly 32 bytes" }
        require(request.contentSalt.isNotEmpty()) { "content salt must not be empty" }
        require(request.generation > 0 && request.registrySnapshot.generation == request.generation) {
            "prepared registry generation does not match the hardening generation"
        }
        require(request.minimumCodeCoverage.isFinite() && request.minimumCodeCoverage in 0.0..1.0) {
            "minimum code coverage must be between 0.0 and 1.0"
        }
        require(request.minimumSimHashDistance in 0..64) {
            "minimum SimHash distance must be in 0..64"
        }
        require(request.maximumDexGrowthRatio.isFinite() && request.maximumDexGrowthRatio >= 0.0) {
            "maximum DEX growth ratio must be finite and non-negative"
        }
        require(request.minimumImageCoverage.isFinite() && request.minimumImageCoverage in 0.0..1.0) {
            "minimum image coverage must be between 0.0 and 1.0"
        }
        require(request.minimumImageSsim.isFinite() && request.minimumImageSsim in 0.995..1.0) {
            "minimum image SSIM must be in 0.995..1.0"
        }
        require(request.minimumImagePHashDistance in 11..64) {
            "minimum image pHash distance must be in 11..64"
        }
    }

    private fun readEntries(aab: Path): Map<String, ByteArray> = ZipFile(aab.toFile()).use { archive ->
        val allEntries = archive.entries().asSequence().toList()
        BundleZipRewriter.requireSafeUniqueEntryNames(allEntries.map { it.name })
        allEntries.asSequence()
            .filterNot { it.isDirectory }
            .associateTo(linkedMapOf()) { entry ->
                entry.name to archive.getInputStream(entry).use { it.readBytes() }
            }
    }

    private fun validateReplacementClosure(
        sourcePaths: Set<String>,
        replacements: List<BundleEntryReplacement>,
    ) {
        require(replacements.isNotEmpty()) { "hardening plan has no transformations" }
        val byOldPath = replacements.associateBy(BundleEntryReplacement::oldPath)
        require(byOldPath.size == replacements.size) { "hardening plan contains duplicate replacement sources" }
        require(byOldPath.keys.all(sourcePaths::contains)) { "hardening plan references a missing AAB entry" }
        replacements.forEach { replacement ->
            BundleZipRewriter.requireSafeUniqueEntryNames(listOf(replacement.oldPath))
            BundleZipRewriter.requireSafeUniqueEntryNames(listOf(replacement.newPath))
            require(replacement.bytes.isNotEmpty()) { "hardening replacement ${replacement.oldPath} is empty" }
        }
        val finalPaths = sourcePaths.map { path -> byOldPath[path]?.newPath ?: path }
        BundleZipRewriter.requireSafeUniqueEntryNames(finalPaths)
    }

    private fun coverage(numerator: Int, denominator: Int): Double =
        if (denominator == 0) 1.0 else numerator.toDouble() / denominator

    private fun coverage(numerator: Long, denominator: Long): Double =
        if (denominator == 0L) 1.0 else numerator.toDouble() / denominator

    private data class DexPlan(
        val replacements: List<BundleEntryReplacement>,
        val report: PlannedDexSummary,
    )

    private data class ResourcePlan(
        val replacements: List<BundleEntryReplacement>,
        val report: PlannedResourceSummary,
    )

    private data class DiversifiedImage(
        val transformedBytes: ByteArray?,
        val originalByteCount: Long,
        val report: PlannedImageEntry,
    )

    private companion object {
        const val RESOURCES_PB_PATH = "base/resources.pb"
        const val NOTIFICATION_ICON = "icon_notification"
        val DEX_PATH = Regex("base/dex/classes(?:[2-9][0-9]*)?\\.dex")
        const val EPSILON = 1e-12
    }
}

internal fun scopedExternallyNamedResources(
    sourceAudit: HardeningSourceAudit,
    namespace: String,
    applicationId: String,
): Set<Pair<ResourceType, String>> =
    sourceAudit.hardcodedReferenceFindings.asSequence()
        .filter { it.kind == HardcodedReferenceKind.RESOURCE_NAME }
        .mapNotNull { finding ->
            val packageName = finding.value.substringBefore(':', "")
            if (packageName != namespace && packageName != applicationId) return@mapNotNull null
            val typedName = finding.value.substringAfter(':', "")
            val directory = typedName.substringBefore('/', "")
            val name = typedName.substringAfter('/', "")
            ResourceType.values().firstOrNull { it.directoryName == directory }
                ?.takeIf { name.isNotBlank() }
                ?.let { it to name }
        }
        .toSet()

private fun WebpIneligibilityReason.toImageReason(): ImageIneligibilityReason = when (this) {
    WebpIneligibilityReason.TRANSFORMED -> ImageIneligibilityReason.TRANSFORMED
    WebpIneligibilityReason.UNOWNED_MODULE -> ImageIneligibilityReason.UNOWNED_MODULE
    WebpIneligibilityReason.OUTSIDE_CONFIGURED_WEBP_SCOPE ->
        ImageIneligibilityReason.OUTSIDE_CONFIGURED_WEBP_SCOPE
    WebpIneligibilityReason.ANIMATION -> ImageIneligibilityReason.ANIMATION
    WebpIneligibilityReason.NOTIFICATION_ICON -> ImageIneligibilityReason.NOTIFICATION_ICON
    WebpIneligibilityReason.EXTERNALLY_NAMED -> ImageIneligibilityReason.EXTERNALLY_NAMED
    WebpIneligibilityReason.UNSUPPORTED_FORMAT -> ImageIneligibilityReason.UNSUPPORTED_FORMAT
    WebpIneligibilityReason.DEPENDENCY_RESOURCE -> ImageIneligibilityReason.DEPENDENCY_RESOURCE
    WebpIneligibilityReason.GENERATED_RESOURCE -> ImageIneligibilityReason.GENERATED_RESOURCE
    WebpIneligibilityReason.UNVERIFIED_WEBP -> ImageIneligibilityReason.UNVERIFIED_WEBP
    WebpIneligibilityReason.NO_SAFE_PERTURBATION -> ImageIneligibilityReason.NO_SAFE_PERTURBATION
    WebpIneligibilityReason.BYTE_GROWTH_LIMIT -> ImageIneligibilityReason.BYTE_GROWTH_LIMIT
}

private val FIXED_SEED_SHA_256 = Regex("[0-9a-f]{64}")
