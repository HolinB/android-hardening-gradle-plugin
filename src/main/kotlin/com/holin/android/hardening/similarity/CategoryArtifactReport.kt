package com.holin.android.hardening.similarity

import com.android.aapt.Resources
import com.holin.android.hardening.artifact.BundleZipRewriter
import com.holin.android.hardening.state.Sha256
import groovy.json.JsonOutput
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.file.Path
import java.security.MessageDigest
import java.util.zip.ZipFile

/** Supplemental measurements. These deliberately do not alter full-aab-structural-v1. */
object CategoryArtifactReport {
    fun compare(reference: Path, candidate: Path): String {
        val left = inventory(reference)
        val right = inventory(candidate)
        val categories = (left.values + right.values).map { it.category }.toSortedSet()
        val rows = categories.associateWith { category ->
            val a = left.filterValues { it.category == category }
            val b = right.filterValues { it.category == category }
            val paired = a.keys.intersect(b.keys)
            val hashes = b.values.map { it.sha256 }.toSet()
            val semanticHashes = b.values.mapNotNull { it.semanticSha256 }.toSet()
            mapOf(
                "referenceCount" to a.size, "candidateCount" to b.size,
                "samePathCount" to paired.size,
                "samePathAndBytes" to paired.count { a.getValue(it).sha256 == b.getValue(it).sha256 },
                "sameBytesAnyPath" to a.values.count { it.sha256 in hashes },
                "referenceBytes" to a.values.sumOf { it.bytes },
                "matchingBytesAnyPath" to a.values.filter { it.sha256 in hashes }.sumOf { it.bytes },
                "semanticMeasuredCount" to a.values.count { it.semanticSha256 != null },
                "semanticMatchingAnyPath" to a.values.count { it.semanticSha256 != null && it.semanticSha256 in semanticHashes },
            )
        }
        return JsonOutput.prettyPrint(JsonOutput.toJson(mapOf(
            "schemaVersion" to 1,
            "measurementVersion" to "category-artifacts-v1",
            "referenceSha256" to Sha256.file(reference), "candidateSha256" to Sha256.file(candidate),
            "legacyScorer" to "full-aab-structural-v1",
            "categories" to rows,
            "resourceValues" to resourceValues(reference, candidate),
            "manifest" to manifest(reference, candidate),
            "referenceInventory" to left.mapValues { it.value.record() },
            "candidateInventory" to right.mapValues { it.value.record() },
            "limitations" to listOf(
                "Hash membership is directional and is not a behavioral equivalence proof or a recognition probability.",
                "ELF semantic hashes cover program headers and exact PT_LOAD bytes; unparseable ELF has no semantic claim.",
                "Resource variants are paired by package/type/entry ID and configuration; source paths and comments are excluded.",
                "Manifest metrics use attribute multisets by element type; runtime component reachability is verified separately.",
                "Archive provenance is not proof of source ownership; transformation reports provide the ownership evidence.",
            ),
        ))) + "\n"
    }

    private data class Entry(val category: String, val bytes: Long, val sha256: String, val semanticSha256: String?) {
        fun record() = mapOf("category" to category, "bytes" to bytes, "sha256" to sha256, "semanticSha256" to semanticSha256)
    }

    private fun inventory(path: Path): Map<String, Entry> = ZipFile(path.toFile()).use { zip ->
        val entries = zip.entries().asSequence().toList()
        BundleZipRewriter.requireSafeUniqueEntryNames(entries.map { it.name })
        entries.filterNot { it.isDirectory }.associate { entry ->
            val bytes = zip.getInputStream(entry).use { it.readBytes() }
            val category = when {
                entry.name.endsWith(".so") && "/lib/" in entry.name -> "native"
                "/assets/" in entry.name -> "assets"
                entry.name.endsWith("/AndroidManifest.xml") -> "manifest"
                entry.name.endsWith("resources.pb") -> "resourceTable"
                entry.name.endsWith(".dex") -> "dex"
                "/res/" in entry.name -> "resources"
                BundleZipRewriter.isPreviousSignature(entry.name) -> "signature"
                else -> "metadata"
            }
            entry.name to Entry(category, bytes.size.toLong(), Sha256.hex(bytes),
                if (category == "native") runCatching { elfLoadFingerprint(bytes) }.getOrNull() else null)
        }
    }

    /** Includes exact mapped bytes and loader-relevant program headers, excludes non-loaded sections. */
    fun elfLoadFingerprint(bytes: ByteArray): String {
        require(bytes.size >= 52 && bytes.copyOfRange(0, 4).contentEquals(byteArrayOf(127, 69, 76, 70))) { "not ELF" }
        require(bytes[5].toInt() == 1) { "only little-endian ELF is supported" }
        val b = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN)
        val wide = bytes[4].toInt() == 2
        require(wide || bytes[4].toInt() == 1) { "invalid ELF class" }
        fun word(offset: Int): Long = if (wide) b.getLong(offset) else b.getInt(offset).toLong() and 0xffffffffL
        val offset = word(if (wide) 32 else 28)
        val size = b.getShort(if (wide) 54 else 42).toInt() and 0xffff
        val count = b.getShort(if (wide) 56 else 44).toInt() and 0xffff
        require(size == if (wide) 56 else 32)
        require(count > 0 && offset >= 0 && offset + size.toLong() * count <= bytes.size)
        val digest = MessageDigest.getInstance("SHA-256")
        digest.update(bytes.copyOfRange(offset.toInt(), (offset + size.toLong() * count).toInt()))
        var loads = 0
        repeat(count) { index ->
            val p = offset.toInt() + index * size
            if (b.getInt(p) == 1) {
                val start = word(p + if (wide) 8 else 4)
                val length = word(p + if (wide) 32 else 16)
                require(start >= 0 && length >= 0 && start <= bytes.size && length <= bytes.size - start)
                digest.update(bytes, start.toInt(), length.toInt())
                loads++
            }
        }
        require(loads > 0)
        return digest.digest().joinToString("") { "%02x".format(it) }
    }

    private fun values(path: Path): Map<String, Pair<String, String>> = ZipFile(path.toFile()).use { zip ->
        val result = sortedMapOf<String, Pair<String, String>>()
        zip.entries().asSequence().filter { it.name.endsWith("/resources.pb") }.forEach { file ->
            val table = zip.getInputStream(file).use { Resources.ResourceTable.parseFrom(it) }
            table.packageList.forEach { pkg -> pkg.typeList.forEach { type -> type.entryList.forEach { entry ->
                entry.configValueList.forEach { config ->
                    val key = "${file.name}:${pkg.packageId.id}:${type.name}:${entry.entryId.id}:${Sha256.hex(config.config.toByteArray())}"
                    val value = config.value.toBuilder().clearSource().clearComment().build()
                    result[key] = entry.name to Sha256.hex(value.toByteArray())
                }
            } } }
        }
        result
    }

    private fun resourceValues(reference: Path, candidate: Path): Map<String, Any> {
        val a = values(reference); val b = values(candidate)
        return listOf("string", "color", "dimen", "style", "plurals", "array").associateWith { type ->
            val aa = a.filterKeys { it.split(':')[2] == type }
            val bb = b.filterKeys { it.split(':')[2] == type }
            val paired = aa.keys.intersect(bb.keys)
            mapOf("referenceVariants" to aa.size, "candidateVariants" to bb.size, "pairedVariants" to paired.size,
                "sameLogicalName" to paired.count { aa.getValue(it).first == bb.getValue(it).first },
                "sameValue" to paired.count { aa.getValue(it).second == bb.getValue(it).second })
        }
    }

    private fun manifest(reference: Path, candidate: Path): Map<String, Any> {
        fun elements(path: Path): Map<String, List<String>> = ZipFile(path.toFile()).use { zip ->
            val rows = mutableMapOf<String, MutableList<String>>()
            fun visit(node: Resources.XmlNode) {
                if (!node.hasElement()) return
                val el = node.element
                val attrs = el.attributeList.map { "${it.namespaceUri}:${it.name}=${it.value}:${Sha256.hex(it.compiledItem.toByteArray())}" }.sorted()
                rows.getOrPut(el.name) { mutableListOf() }.add(Sha256.hex(attrs.joinToString("\n").toByteArray()))
                el.childList.forEach(::visit)
            }
            zip.entries().asSequence().filter { it.name.endsWith("/manifest/AndroidManifest.xml") }.forEach {
                visit(zip.getInputStream(it).use { input -> Resources.XmlNode.parseFrom(input) })
            }
            rows
        }
        val a = elements(reference); val b = elements(candidate)
        return (a.keys + b.keys).sorted().associateWith { tag ->
            val aa = a[tag].orEmpty().groupingBy { it }.eachCount()
            val bb = b[tag].orEmpty().groupingBy { it }.eachCount()
            mapOf("reference" to aa.values.sum(), "candidate" to bb.values.sum(),
                "equalAttributeMultisetCount" to aa.entries.sumOf { (hash, count) -> minOf(count, bb[hash] ?: 0) })
        }
    }
}
