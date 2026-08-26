package com.holin.android.hardening.similarity

/** Caller-supplied features for one exact post-R8 owned method. */
data class MethodFingerprint(
    val identifier: String,
    val instructionCount: Int,
    val canonicalHash: String = "",
    val opcodeTokens: List<String>,
    val apiCalls: List<String>,
    val constants: List<String>,
    val blockSignature: List<String>,
) {
    init {
        require(identifier.isNotBlank()) { "method identifier must not be blank" }
        require(instructionCount >= 0) { "method instructionCount must not be negative" }
    }
}

/** A resource that has already been proven to belong to an owned module. */
class OwnedResourceFingerprint(
    val resourceId: Int,
    val qualifier: String,
    val originalEntryName: String,
    val aabPath: String,
    val apkPath: String,
    val size: Long,
    val sha256: String,
    val currentEntryName: String = originalEntryName,
    val semanticHash: String,
) {
    init {
        require(resourceId >= 0) { "resourceId must not be negative" }
        require(originalEntryName.isNotBlank() && currentEntryName.isNotBlank()) {
            "resource entry names must not be blank"
        }
        require(aabPath.isNotBlank() && apkPath.isNotBlank()) { "resource paths must not be blank" }
        require(size >= 0L) { "resource size must not be negative" }
        require(SHA_256.matches(sha256)) { "resource sha256 must be lowercase SHA-256" }
        require(semanticHash.isNotBlank() && SHA_256.matches(semanticHash)) {
            "resource semanticHash must be lowercase SHA-256"
        }
    }

    constructor(
        resourceId: Int,
        qualifier: String,
        originalEntryName: String,
        aabPath: String,
        apkPath: String,
        size: Long,
        sha256: String,
        currentEntryName: String = originalEntryName,
        missingSemanticHash: Nothing?,
    ) : this(
        resourceId, qualifier, originalEntryName, aabPath, apkPath, size, sha256, currentEntryName,
        semanticHash = rejectedMissingSemanticHash(missingSemanticHash),
    )

    override fun equals(other: Any?): Boolean = other is OwnedResourceFingerprint &&
        resourceId == other.resourceId && qualifier == other.qualifier &&
        originalEntryName == other.originalEntryName && currentEntryName == other.currentEntryName &&
        aabPath == other.aabPath && apkPath == other.apkPath && size == other.size &&
        sha256 == other.sha256 && semanticHash == other.semanticHash

    override fun hashCode(): Int = listOf(
        resourceId, qualifier, originalEntryName, currentEntryName, aabPath, apkPath, size, sha256, semanticHash,
    ).hashCode()

    private companion object {
        fun rejectedMissingSemanticHash(value: Nothing?): String = when (value) {
            null -> throw IllegalArgumentException("resource semanticHash must be lowercase SHA-256")
            else -> throw IllegalStateException("missing semantic hash must be null")
        }
    }
}

data class OwnedArtifactProfile(
    val aabSha256: String,
    val aabSize: Long,
    val universalApkSha256: String?,
    val universalApkSize: Long?,
    val methods: List<MethodFingerprint>,
    val resources: List<OwnedResourceFingerprint>,
) {
    init {
        require(SHA_256.matches(aabSha256)) { "AAB hash must be lowercase SHA-256" }
        require((universalApkSha256 == null) == (universalApkSize == null)) {
            "universal APK hash and size must be both present or both absent"
        }
        require(universalApkSha256 == null || SHA_256.matches(universalApkSha256)) {
            "universal APK hash must be lowercase SHA-256"
        }
        require(aabSize > 0L && (universalApkSize == null || universalApkSize > 0L)) {
            "artifact sizes must be greater than zero"
        }
        require(methods.map(MethodFingerprint::identifier).toSet().size == methods.size) {
            "owned method identifiers must be unique"
        }
        require(resources.map { it.resourceId to it.qualifier }.toSet().size == resources.size) {
            "owned resource id and qualifier pairs must be unique"
        }
    }
}

data class CodeSimilarityEvidence(
    val ordinaryDescriptor: String,
    val hardenedDescriptor: String,
    val ordinaryInstructionCount: Int,
    val similarity: Double,
) {
    init {
        require(ordinaryDescriptor.isNotBlank() && hardenedDescriptor.isNotBlank()) {
            "code evidence descriptors must not be blank"
        }
        require(ordinaryInstructionCount >= 0) { "code evidence instruction count must not be negative" }
        require(similarity.isFinite() && similarity in 0.0..1.0) { "code evidence similarity must be in 0.0..1.0" }
    }
}

data class ResourceSimilarityEvidence(
    val resourceId: Int,
    val qualifier: String,
    val ordinaryEntryName: String,
    val ordinarySize: Long,
) {
    init {
        require(resourceId >= 0 && ordinaryEntryName.isNotBlank() && ordinarySize >= 0L) {
            "resource evidence is invalid"
        }
    }
}

internal val SHA_256 = Regex("[0-9a-f]{64}")
