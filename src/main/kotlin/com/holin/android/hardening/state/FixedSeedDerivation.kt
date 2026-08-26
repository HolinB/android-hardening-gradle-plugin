package com.holin.android.hardening.state

import java.nio.ByteBuffer
import java.nio.charset.StandardCharsets
import java.util.UUID
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

internal data class ReproducibilityContext(
    val projectKey: String,
    val variant: String,
    val configurationSha256: String,
) {
    init {
        require(projectKey.isNotBlank()) { "reproducibility projectKey must not be blank" }
        require(variant.isNotBlank()) { "reproducibility variant must not be blank" }
        require(SHA_256.matches(configurationSha256)) {
            "reproducibility configuration identity must be a lowercase SHA-256"
        }
    }

    private companion object {
        val SHA_256 = Regex("[0-9a-f]{64}")
    }
}

internal enum class ReproducibilityPurpose(val domain: String) {
    CONTENT_SALT("content-salt"),
    NEW_LINEAGE_NAMING_SEED("new-lineage-naming-seed"),
    NEW_LINEAGE_IDENTITY("new-lineage-identity"),
}

internal object FixedSeedDerivation {
    fun seedSha256(rawSeed: String): String {
        require(rawSeed.isNotBlank()) { "reproducibility.fixedSeed must not be blank" }
        val bytes = rawSeed.toByteArray(StandardCharsets.UTF_8)
        return try {
            Sha256.hex(bytes)
        } finally {
            bytes.fill(0)
        }
    }

    fun derive(
        fixedSeedSha256: String,
        context: ReproducibilityContext,
        purpose: ReproducibilityPurpose,
    ): ByteArray {
        require(SHA_256.matches(fixedSeedSha256)) {
            "fixed seed identity must be a lowercase SHA-256"
        }
        val key = decodeHex(fixedSeedSha256)
        return try {
            Mac.getInstance(HMAC_SHA_256).run {
                init(SecretKeySpec(key, HMAC_SHA_256))
                updateFramed(DERIVATION_DOMAIN)
                updateFramed(purpose.domain)
                updateFramed(context.projectKey)
                updateFramed(context.variant)
                updateFramed(context.configurationSha256)
                doFinal()
            }
        } finally {
            key.fill(0)
        }
    }

    fun lineageId(fixedSeedSha256: String, context: ReproducibilityContext): String {
        val bytes = derive(fixedSeedSha256, context, ReproducibilityPurpose.NEW_LINEAGE_IDENTITY)
        return try {
            bytes[6] = ((bytes[6].toInt() and 0x0f) or 0x50).toByte()
            bytes[8] = ((bytes[8].toInt() and 0x3f) or 0x80).toByte()
            val buffer = ByteBuffer.wrap(bytes)
            UUID(buffer.long, buffer.long).toString().lowercase()
        } finally {
            bytes.fill(0)
        }
    }

    private fun Mac.updateFramed(value: String) {
        val bytes = value.toByteArray(StandardCharsets.UTF_8)
        update(ByteBuffer.allocate(Int.SIZE_BYTES).putInt(bytes.size).array())
        update(bytes)
    }

    private fun decodeHex(value: String): ByteArray = ByteArray(value.length / 2) { index ->
        value.substring(index * 2, index * 2 + 2).toInt(16).toByte()
    }

    private const val DERIVATION_DOMAIN = "android-hardening-fixed-seed-v1"
    private const val HMAC_SHA_256 = "HmacSHA256"
    private val SHA_256 = Regex("[0-9a-f]{64}")
}

enum class SeedDerivationMode { SECURE_RANDOM, FIXED_SEED }

class StateReproducibility private constructor(
    val derivationMode: SeedDerivationMode,
    val fixedSeedSha256: String?,
    private val lineageSeed: ByteArray?,
    val lineageId: String?,
) {
    fun newLineageSeed(): ByteArray {
        check(derivationMode == SeedDerivationMode.FIXED_SEED && lineageSeed != null) {
            "deterministic lineage seed is unavailable in secure-random mode"
        }
        return lineageSeed.copyOf()
    }

    companion object {
        fun secureRandom(): StateReproducibility = StateReproducibility(
            SeedDerivationMode.SECURE_RANDOM,
            null,
            null,
            null,
        )

        internal fun fixed(
            fixedSeedSha256: String,
            context: ReproducibilityContext,
        ): StateReproducibility = StateReproducibility(
            SeedDerivationMode.FIXED_SEED,
            fixedSeedSha256,
            FixedSeedDerivation.derive(
                fixedSeedSha256,
                context,
                ReproducibilityPurpose.NEW_LINEAGE_NAMING_SEED,
            ),
            FixedSeedDerivation.lineageId(fixedSeedSha256, context),
        )
    }
}
