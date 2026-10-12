package com.holin.android.hardening.artifact

import com.holin.android.hardening.state.Sha256
import groovy.json.JsonOutput
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardCopyOption.REPLACE_EXISTING
import java.util.zip.CRC32
import java.util.zip.ZipEntry
import java.util.zip.ZipFile
import java.util.zip.ZipOutputStream

/** A separate testing artifact. The release-processed APK remains intact. */
object DebugApkDerivative {
    fun derive(source: Path, target: Path, report: Path, zipalign: Path, material: SigningMaterial) {
        require(source.toAbsolutePath().normalize() != target.toAbsolutePath().normalize())
        val originalSigner = com.android.apksig.ApkVerifier.Builder(source.toFile()).build().verify()
        require(originalSigner.isVerified && originalSigner.signerCertificates.size == 1)
        val expectedSigner = Sha256.hex(originalSigner.signerCertificates.single().encoded)
        Files.createDirectories(target.parent)
        val temporary = Files.createTempDirectory(target.parent, ".debug-apk-")
        try {
            val unsigned = temporary.resolve("unsigned.apk")
            val aligned = temporary.resolve("aligned.apk")
            val signed = temporary.resolve("signed.apk")
            ZipFile(source.toFile()).use { zip ->
                val entries = zip.entries().asSequence().toList()
                BundleZipRewriter.requireSafeUniqueEntryNames(entries.map { it.name })
                require(entries.count { it.name == "AndroidManifest.xml" } == 1)
                ZipOutputStream(Files.newOutputStream(unsigned)).use { output -> entries.forEach { entry ->
                    if (BundleZipRewriter.isPreviousSignature(entry.name)) return@forEach
                    val bytes = zip.getInputStream(entry).use { it.readBytes() }
                    val result = if (entry.name == "AndroidManifest.xml") enableDebuggable(bytes) else bytes
                    output.putNextEntry(ZipEntry(entry.name).apply {
                        method = entry.method
                        time = DETERMINISTIC_ZIP_TIMESTAMP_MILLIS
                        if (method == ZipEntry.STORED) {
                            size = result.size.toLong()
                            crc = CRC32().apply { update(result) }.value
                        }
                    })
                    output.write(result)
                    output.closeEntry()
                } }
            }
            ApkZipaligner().align(zipalign, unsigned, aligned)
            val signing = ApkSignerEngine().sign(aligned, signed, material)
            require(signing.signerCertificateSha256 == expectedSigner) { "debug derivative signer changed" }
            ApkZipaligner().verify(zipalign, signed)
            val verifiedCount = verify(source, signed)
            Files.move(signed, target, REPLACE_EXISTING)
            Files.createDirectories(report.parent)
            Files.writeString(report, JsonOutput.prettyPrint(JsonOutput.toJson(mapOf(
                "schemaVersion" to 1, "status" to "PASS",
                "sourceSha256" to Sha256.file(source), "debugApkSha256" to Sha256.file(target),
                "signerCertificateSha256" to expectedSigner,
                "unchangedPayloadEntries" to verifiedCount,
                "allowedChanges" to listOf("application android:debuggable default/explicit false -> true", "APK signatures and ZIP alignment"),
                "dexNativeAssetsResourcesUnchanged" to true,
            ))) + "\n")
        } finally {
            Files.walk(temporary).use { paths -> paths.sorted(Comparator.reverseOrder()).forEach { Files.deleteIfExists(it) } }
        }
    }

    fun verify(source: Path, candidate: Path): Int = ZipFile(source.toFile()).use { a ->
        ZipFile(candidate.toFile()).use { b ->
            fun payload(zip: ZipFile) = zip.entries().asSequence()
                .filterNot { it.isDirectory || BundleZipRewriter.isPreviousSignature(it.name) }.map { it.name }.toSet()
            val paths = payload(a)
            require(paths == payload(b)) { "debug derivative payload set changed" }
            paths.forEach { path ->
                val left = a.getInputStream(a.getEntry(path)).use { it.readBytes() }
                val right = b.getInputStream(b.getEntry(path)).use { it.readBytes() }
                val expected = if (path == "AndroidManifest.xml") enableDebuggable(left) else left
                require(expected.contentEquals(right)) { "debug derivative modified unauthorized content: $path" }
            }
            paths.size - 1
        }
    }

    /** Changes the typed flag or adds it when Android defaults to false; existing XML fields remain exact. */
    fun enableDebuggable(input: ByteArray): ByteArray {
        val b = ByteBuffer.wrap(input).order(ByteOrder.LITTLE_ENDIAN)
        fun u16(offset: Int) = b.getShort(offset).toInt() and 0xffff
        require(input.size >= 8 && u16(0) == 3 && b.getInt(4) == input.size) { "invalid binary manifest" }
        var strings = emptyList<String>()
        var resources = emptyList<Int>()
        val dataOffsets = mutableListOf<Int>()
        var offset = u16(2)
        while (offset < input.size) {
            require(offset + 8 <= input.size)
            val type = u16(offset)
            val header = u16(offset + 2)
            val size = b.getInt(offset + 4)
            require(header >= 8 && size >= header && size <= input.size - offset)
            if (type == 1) {
                require(header == 28 && b.getInt(offset + 12) == 0) { "unsupported string pool" }
                val count = b.getInt(offset + 8)
                require(count >= 0 && count <= (size - header) / 4)
                val utf8 = b.getInt(offset + 16) and 0x100 != 0
                val start = b.getInt(offset + 20)
                strings = (0 until count).map { index ->
                    var p = offset + start + b.getInt(offset + header + index * 4)
                    require(p in offset until offset + size)
                    fun length8(): Int {
                        val first = input[p++].toInt() and 255
                        return if (first and 128 == 0) first else ((first and 127) shl 8) or (input[p++].toInt() and 255)
                    }
                    if (utf8) {
                        length8()
                        val length = length8()
                        require(p + length < offset + size && input[p + length].toInt() == 0)
                        String(input, p, length, Charsets.UTF_8)
                    } else {
                        var length = u16(p); p += 2
                        if (length and 0x8000 != 0) { length = ((length and 0x7fff) shl 16) or u16(p); p += 2 }
                        require(length >= 0 && length.toLong() * 2 + p + 2 <= offset + size)
                        String(input, p, length * 2, Charsets.UTF_16LE)
                    }
                }
            } else if (type == 0x180) {
                require((size - header) % 4 == 0)
                resources = (header until size step 4).map { b.getInt(offset + it) }
            } else if (type == 0x102) {
                require(header == 16 && size >= 36)
                val extension = offset + header
                val name = b.getInt(extension + 4)
                require(name in strings.indices)
                if (strings[name] == "application") {
                    val attrStart = u16(extension + 8)
                    val attrSize = u16(extension + 10)
                    val count = u16(extension + 12)
                    require(attrSize == 20 && attrStart >= 20 && attrStart + count * attrSize <= size - header)
                    repeat(count) { index ->
                        val attr = extension + attrStart + index * attrSize
                        if (resources.getOrNull(b.getInt(attr + 4)) == 0x0101000f) {
                            require(b.getInt(attr + 8) == -1 && u16(attr + 12) == 8 && input[attr + 15].toInt() == 0x12)
                            require(b.getInt(attr + 16) == 0) { "source APK must have debuggable=false" }
                            dataOffsets.add(attr + 16)
                        }
                    }
                }
            }
            offset += size
        }
        require(offset == input.size && dataOffsets.size <= 1) { "source manifest must not declare duplicate application debug flags" }
        if (dataOffsets.isEmpty()) return BinaryManifestDebugFlag.addAbsent(input, strings, resources)
        return input.copyOf().also { ByteBuffer.wrap(it).order(ByteOrder.LITTLE_ENDIAN).putInt(dataOffsets.single(), -1) }
    }
}
