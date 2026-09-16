package com.holin.android.hardening.resources

import java.awt.image.BufferedImage
import java.io.ByteArrayInputStream
import javax.imageio.ImageIO

class OrdinaryImageCorpus private constructor(
    private val hashes: List<PerceptualHash>,
) {
    val imageCount: Int get() = hashes.size

    fun nearestPHashDistance(image: BufferedImage): Int? {
        val candidate = ImageMetrics.perceptualHash(image)
        return hashes.minOfOrNull { original -> WebpImageMetrics.pHashDistance(original, candidate) }
    }

    companion object {
        fun empty(): OrdinaryImageCorpus = OrdinaryImageCorpus(emptyList())

        fun fromAabEntries(entries: Map<String, ByteArray>): OrdinaryImageCorpus = OrdinaryImageCorpus(
            entries.asSequence()
                .filter { (path, _) -> isSupportedImage(path) }
                .sortedBy(Map.Entry<String, ByteArray>::key)
                .mapNotNull { (path, bytes) -> decode(path, bytes) }
                .map(ImageMetrics::perceptualHash)
                .toList(),
        )

        private fun decode(path: String, bytes: ByteArray): BufferedImage? {
            val lower = path.lowercase()
            val image = when {
                lower.endsWith(".png") -> VerifiedPng.read(bytes)?.image
                lower.endsWith(".webp") -> VerifiedWebp.read(bytes)
                else -> runCatching {
                    ByteArrayInputStream(bytes).use(ImageIO::read)
                }.getOrNull()
            } ?: return null
            return image.takeIf { it.width > 0 && it.height > 0 && it.width.toLong() * it.height <= MAX_PIXELS }
        }

        private fun isSupportedImage(path: String): Boolean {
            val lower = path.lowercase()
            return lower.endsWith(".png") || lower.endsWith(".webp") ||
                lower.endsWith(".jpg") || lower.endsWith(".jpeg")
        }

        private const val MAX_PIXELS = 16_777_216L
    }
}
