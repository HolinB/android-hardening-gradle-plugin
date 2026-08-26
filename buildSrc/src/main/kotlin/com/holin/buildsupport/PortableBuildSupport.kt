package com.holin.buildsupport

import java.io.ByteArrayInputStream
import java.io.InputStream
import java.nio.file.Files
import java.nio.file.Path
import java.security.KeyStore
import java.security.MessageDigest
import java.util.Base64
import java.util.Locale
import java.util.zip.ZipFile
import java.util.zip.ZipInputStream

object OfflineGraphNormalizer {
    fun concreteClosure(
        roots: Collection<String>,
        dependencies: Map<String, Set<String>>,
        concreteComponents: Set<String>,
    ): List<String> {
        val result = sortedSetOf<String>()
        fun visit(component: String, traversal: Set<String>) {
            require(component !in traversal) {
                "offline dependency graph contains a metadata-only cycle at $component"
            }
            if (component in concreteComponents) {
                result += component
                return
            }
            dependencies[component].orEmpty().sorted().forEach { child ->
                visit(child, traversal + component)
            }
        }
        roots.sorted().forEach { component -> visit(component, emptySet()) }
        return result.toList()
    }
}

object ArchiveChecksumCoverage {
    fun requireExhaustive(
        entryNames: Collection<String>,
        checksumPaths: Collection<String>,
    ) {
        require(
            checksumPaths.sorted() == entryNames.filterNot { entryName ->
                entryName == "SHA256SUMS"
            }.sorted(),
        ) { "archive checksum coverage is incomplete" }
    }
}

data class VerificationArtifact(
    val group: String,
    val module: String,
    val version: String,
    val fileName: String,
    val sha256: String,
)

object PortableVerificationMetadata {
    fun render(repositories: Collection<Path>): String {
        require(repositories.isNotEmpty()) { "at least one Maven repository is required" }
        val artifacts = repositories.flatMap { repository -> artifacts(repository) }
            .distinctBy { artifact ->
                listOf(artifact.group, artifact.module, artifact.version, artifact.fileName)
            }
            .sortedWith(
                compareBy<VerificationArtifact>(VerificationArtifact::group)
                    .thenBy(VerificationArtifact::module)
                    .thenBy(VerificationArtifact::version)
                    .thenBy(VerificationArtifact::fileName),
            )
        return buildString {
            appendLine("<?xml version=\"1.0\" encoding=\"UTF-8\"?>")
            appendLine("<verification-metadata>")
            appendLine("  <configuration>")
            appendLine("    <verify-metadata>true</verify-metadata>")
            appendLine("    <verify-signatures>false</verify-signatures>")
            appendLine("    <trusted-artifacts>")
            appendLine("      <trust group=\"com.holin.fixture\" name=\"neutral-legacy-plugin\" reason=\"fixture generated at test runtime\"/>")
            appendLine("      <trust group=\"com.holin.fixture.legacy\" name=\"com.holin.fixture.legacy.gradle.plugin\" reason=\"fixture marker generated at test runtime\"/>")
            appendLine("    </trusted-artifacts>")
            appendLine("  </configuration>")
            appendLine("  <components>")
            artifacts.groupBy { artifact -> Triple(artifact.group, artifact.module, artifact.version) }
                .forEach { (coordinate, componentArtifacts) ->
                    appendLine("    <component group=\"${coordinate.first}\" name=\"${coordinate.second}\" version=\"${coordinate.third}\">")
                    componentArtifacts.forEach { artifact ->
                        appendLine("      <artifact name=\"${artifact.fileName}\">")
                        appendLine("        <sha256 value=\"${artifact.sha256}\"/>")
                        appendLine("      </artifact>")
                    }
                    appendLine("    </component>")
                }
            appendLine("  </components>")
            appendLine("</verification-metadata>")
        }
    }

    private fun artifacts(repository: Path): List<VerificationArtifact> {
        require(Files.isDirectory(repository)) { "Maven repository is missing: $repository" }
        return Files.walk(repository).use { paths ->
            paths.filter(Files::isRegularFile).map { artifact ->
                val segments = repository.relativize(artifact).iterator().asSequence()
                    .map(Path::toString)
                    .toList()
                require(segments.size >= 4) { "Maven artifact has no coordinate: $artifact" }
                VerificationArtifact(
                    segments.dropLast(3).joinToString("."),
                    segments[segments.lastIndex - 2],
                    segments[segments.lastIndex - 1],
                    segments.last(),
                    sha256(artifact),
                )
            }.toList()
        }
    }

    private fun sha256(path: Path): String = Files.newInputStream(path).use { input ->
        val digest = MessageDigest.getInstance("SHA-256")
        val buffer = ByteArray(DEFAULT_BUFFER_SIZE)
        while (true) {
            val count = input.read(buffer)
            if (count < 0) break
            digest.update(buffer, 0, count)
        }
        digest.digest().joinToString("") { byte -> "%02x".format(byte) }
    }
}

internal data class ReviewedPublicFixture(
    val artifactPath: String,
    val artifactSha256: String,
    val entryName: String,
)

object RecursiveArchiveSensitivityScanner {
    private val formerAppBrand = listOf("single", "link").joinToString("")
    private val formerVendorBrand = "joy" + "happier"
    private val formerUserName = ("Zhu" + "anz1").lowercase(Locale.ROOT)
    private val forbiddenBodyTokens = listOf(
        "com.$formerAppBrand",
        "com/$formerAppBrand",
        formerVendorBrand,
        formerUserName,
        "fixture-password",
        "app/$formerAppBrand.jks",
    )
    private val standaloneBrand = Regex(
        """(?<![A-Za-z0-9_])${Regex.escape(formerAppBrand)}(?![A-Za-z0-9_])""",
        RegexOption.IGNORE_CASE,
    )
    private val forbiddenNameSuffixes = listOf(".jks", ".keystore", ".p12", ".pfx", ".pem")
    private val archiveSuffixes = listOf(".zip", ".jar", ".aar", ".apk", ".aab", ".apks")
    private val macUserPath = Regex(
        """(?:^|[^A-Za-z0-9])/(?:private/)?Users/[A-Za-z0-9._-]+(?:/|$)""",
    )
    private val windowsUserPath = Regex(
        """(?:^|[^A-Za-z0-9\\])(?:[A-Za-z]:)?\\Users\\[^\\\s]+(?:\\|$)""",
        RegexOption.IGNORE_CASE,
    )
    private val googleTrustStoreIdentity = Regex(
        """.*/google-api-client-[^/!]+\.jar!/com/google/api/client/googleapis/google\.(p12|jks)$""",
    )
    private val privateKeyBlock = Regex(
        """-----BEGIN (PRIVATE KEY|RSA PRIVATE KEY|EC PRIVATE KEY)-----\s*([A-Za-z0-9+/=\s]+?)\s*-----END \1-----""",
        RegexOption.IGNORE_CASE,
    )
    // Exact public test/probe fixtures embedded in required vendor runtime artifacts.
    private val reviewedPublicFixtures = listOf(
        ReviewedPublicFixture(
            "matrix/agp-8.8.0/gradle/gradle-8.10.2/lib/plugins/google-http-client-1.42.2.jar",
            "97544ad0b0ae39b6ac14b1bcacc0f6c20c46c07ca05b9362ceb38f216c51e049",
            "com/google/api/client/testing/json/webtoken/TestCertificates.class",
        ),
        ReviewedPublicFixture(
            "matrix/agp-8.10.1/gradle/gradle-8.11.1/lib/plugins/google-http-client-1.42.2.jar",
            "97544ad0b0ae39b6ac14b1bcacc0f6c20c46c07ca05b9362ceb38f216c51e049",
            "com/google/api/client/testing/json/webtoken/TestCertificates.class",
        ),
        ReviewedPublicFixture(
            "matrix/agp-8.13.2/gradle/gradle-8.13/lib/plugins/google-http-client-1.42.2.jar",
            "97544ad0b0ae39b6ac14b1bcacc0f6c20c46c07ca05b9362ceb38f216c51e049",
            "com/google/api/client/testing/json/webtoken/TestCertificates.class",
        ),
        ReviewedPublicFixture(
            "matrix/agp-8.8.0/repository/io/netty/netty-handler/4.1.93.Final/netty-handler-4.1.93.Final.jar",
            "4e5f563ae14ed713381816d582f5fcfd0615aefb29203486cdfb782d8a00a02b",
            "io/netty/handler/ssl/OpenSsl.class",
        ),
        ReviewedPublicFixture(
            "matrix/agp-8.8.0/repository/io/netty/netty-handler/4.1.93.Final/netty-handler-4.1.93.Final.jar",
            "4e5f563ae14ed713381816d582f5fcfd0615aefb29203486cdfb782d8a00a02b",
            "io/netty/handler/ssl/SslUtils.class",
        ),
        ReviewedPublicFixture(
            "matrix/agp-8.8.0/repository/io/netty/netty-handler/4.1.93.Final/netty-handler-4.1.93.Final.jar",
            "4e5f563ae14ed713381816d582f5fcfd0615aefb29203486cdfb782d8a00a02b",
            "io/netty/handler/ssl/JdkSslServerContext.class",
        ),
        ReviewedPublicFixture(
            "matrix/agp-8.10.1/repository/io/netty/netty-handler/4.1.110.Final/netty-handler-4.1.110.Final.jar",
            "d5a08d7de364912e4285968de4d4cce3f01da4bb048d5c6937e5f2af1f8e148a",
            "io/netty/handler/ssl/OpenSsl.class",
        ),
        ReviewedPublicFixture(
            "matrix/agp-8.10.1/repository/io/netty/netty-handler/4.1.110.Final/netty-handler-4.1.110.Final.jar",
            "d5a08d7de364912e4285968de4d4cce3f01da4bb048d5c6937e5f2af1f8e148a",
            "io/netty/handler/ssl/SslUtils.class",
        ),
        ReviewedPublicFixture(
            "matrix/agp-8.10.1/repository/io/netty/netty-handler/4.1.110.Final/netty-handler-4.1.110.Final.jar",
            "d5a08d7de364912e4285968de4d4cce3f01da4bb048d5c6937e5f2af1f8e148a",
            "io/netty/handler/ssl/JdkSslServerContext.class",
        ),
        ReviewedPublicFixture(
            "matrix/agp-8.13.2/repository/io/netty/netty-handler/4.1.110.Final/netty-handler-4.1.110.Final.jar",
            "d5a08d7de364912e4285968de4d4cce3f01da4bb048d5c6937e5f2af1f8e148a",
            "io/netty/handler/ssl/OpenSsl.class",
        ),
        ReviewedPublicFixture(
            "matrix/agp-8.13.2/repository/io/netty/netty-handler/4.1.110.Final/netty-handler-4.1.110.Final.jar",
            "d5a08d7de364912e4285968de4d4cce3f01da4bb048d5c6937e5f2af1f8e148a",
            "io/netty/handler/ssl/SslUtils.class",
        ),
        ReviewedPublicFixture(
            "matrix/agp-8.13.2/repository/io/netty/netty-handler/4.1.110.Final/netty-handler-4.1.110.Final.jar",
            "d5a08d7de364912e4285968de4d4cce3f01da4bb048d5c6937e5f2af1f8e148a",
            "io/netty/handler/ssl/JdkSslServerContext.class",
        ),
        ReviewedPublicFixture(
            "matrix/agp-8.8.0/gradle/gradle-8.10.2/lib/file-events-osx-aarch64-0.22-milestone-26.jar",
            "2fc9c2ab84fd74b938300eaa0d90a74b7c81b24097bf07b147f69df7771df909",
            "net/rubygrapefruit/platform/osx-aarch64/libnative-platform-file-events.dylib",
        ),
        ReviewedPublicFixture(
            "matrix/agp-8.8.0/gradle/gradle-8.10.2/lib/file-events-osx-amd64-0.22-milestone-26.jar",
            "fd5a160e49f538eeec6f71efb8f4db59d3fa2b7b7faa0b22ac6ec071e3259bb6",
            "net/rubygrapefruit/platform/osx-amd64/libnative-platform-file-events.dylib",
        ),
        ReviewedPublicFixture(
            "matrix/agp-8.10.1/gradle/gradle-8.11.1/lib/file-events-osx-aarch64-0.22-milestone-26.jar",
            "2fc9c2ab84fd74b938300eaa0d90a74b7c81b24097bf07b147f69df7771df909",
            "net/rubygrapefruit/platform/osx-aarch64/libnative-platform-file-events.dylib",
        ),
        ReviewedPublicFixture(
            "matrix/agp-8.10.1/gradle/gradle-8.11.1/lib/file-events-osx-amd64-0.22-milestone-26.jar",
            "fd5a160e49f538eeec6f71efb8f4db59d3fa2b7b7faa0b22ac6ec071e3259bb6",
            "net/rubygrapefruit/platform/osx-amd64/libnative-platform-file-events.dylib",
        ),
        ReviewedPublicFixture(
            "matrix/agp-8.8.0/gradle/gradle-8.10.2/lib/jansi-1.18.jar",
            "109e64fc65767c7a1a3bd654709d76f107b0a3b39db32cbf11139e13a6f5229b",
            "META-INF/native/osx/libjansi.jnilib",
        ),
        ReviewedPublicFixture(
            "matrix/agp-8.8.0/gradle/gradle-8.10.2/lib/kotlin-compiler-embeddable-1.9.24.jar",
            "e71ff19e6b141ab85a9328fd010941531a302543026bd4244c95adc208d501f6",
            "META-INF/native/osx/libjansi.jnilib",
        ),
        ReviewedPublicFixture(
            "matrix/agp-8.10.1/gradle/gradle-8.11.1/lib/jansi-1.18.jar",
            "109e64fc65767c7a1a3bd654709d76f107b0a3b39db32cbf11139e13a6f5229b",
            "META-INF/native/osx/libjansi.jnilib",
        ),
        ReviewedPublicFixture(
            "matrix/agp-8.13.2/gradle/gradle-8.13/lib/jansi-1.18.jar",
            "109e64fc65767c7a1a3bd654709d76f107b0a3b39db32cbf11139e13a6f5229b",
            "META-INF/native/osx/libjansi.jnilib",
        ),
        ReviewedPublicFixture(
            "matrix/agp-8.8.0/gradle/gradle-8.10.2/lib/plugins/testng-6.3.1.jar",
            "57ed8e83e357c3838daad81b789a2753227fee8cfb86aa31a61b765c4093d6ad",
            "org/testng/xml/ResultXMLParser.class",
        ),
        ReviewedPublicFixture(
            "matrix/agp-8.10.1/gradle/gradle-8.11.1/lib/plugins/testng-6.3.1.jar",
            "57ed8e83e357c3838daad81b789a2753227fee8cfb86aa31a61b765c4093d6ad",
            "org/testng/xml/ResultXMLParser.class",
        ),
        ReviewedPublicFixture(
            "matrix/agp-8.13.2/gradle/gradle-8.13/lib/plugins/testng-6.3.1.jar",
            "57ed8e83e357c3838daad81b789a2753227fee8cfb86aa31a61b765c4093d6ad",
            "org/testng/xml/ResultXMLParser.class",
        ),
        ReviewedPublicFixture(
            "matrix/agp-8.8.0/repository/org/jetbrains/kotlin/kotlin-gradle-plugin/2.3.0/" +
                "kotlin-gradle-plugin-2.3.0-gradle88.jar",
            "84455c23d469593bb54f4253258747de86ac5dfcdfdfb8d5970bdc99fc82c6d0",
            "cocoapods/static/dummy.framework/dummy",
        ),
        ReviewedPublicFixture(
            "matrix/agp-8.8.0/repository/org/jetbrains/kotlin/kotlin-gradle-plugin/2.3.0/" +
                "kotlin-gradle-plugin-2.3.0.jar",
            "84455c23d469593bb54f4253258747de86ac5dfcdfdfb8d5970bdc99fc82c6d0",
            "cocoapods/static/dummy.framework/dummy",
        ),
        ReviewedPublicFixture(
            "matrix/agp-8.10.1/repository/org/jetbrains/kotlin/kotlin-gradle-plugin/2.3.0/" +
                "kotlin-gradle-plugin-2.3.0-gradle811.jar",
            "6bbdc0873c43f03386eae89a9737d912bf0285c72419b82697b7c9bb887e4227",
            "cocoapods/static/dummy.framework/dummy",
        ),
        ReviewedPublicFixture(
            "matrix/agp-8.10.1/repository/org/jetbrains/kotlin/kotlin-gradle-plugin/2.3.0/" +
                "kotlin-gradle-plugin-2.3.0.jar",
            "6bbdc0873c43f03386eae89a9737d912bf0285c72419b82697b7c9bb887e4227",
            "cocoapods/static/dummy.framework/dummy",
        ),
        ReviewedPublicFixture(
            "matrix/agp-8.13.2/repository/org/jetbrains/kotlin/kotlin-gradle-plugin/2.3.0/" +
                "kotlin-gradle-plugin-2.3.0-gradle813.jar",
            "3acf97d73a2581b032873fa89f56750d36b3b76d40d692d9839f2467ddae4d69",
            "cocoapods/static/dummy.framework/dummy",
        ),
        ReviewedPublicFixture(
            "matrix/agp-8.13.2/repository/org/jetbrains/kotlin/kotlin-gradle-plugin/2.3.0/" +
                "kotlin-gradle-plugin-2.3.0.jar",
            "3acf97d73a2581b032873fa89f56750d36b3b76d40d692d9839f2467ddae4d69",
            "cocoapods/static/dummy.framework/dummy",
        ),
    )

    fun verify(archive: Path) {
        verify(archive, emptyList())
    }

    fun verifyOfflineDistribution(archive: Path) {
        verify(archive, reviewedPublicFixtures)
    }

    internal fun verify(archive: Path, fixtures: Collection<ReviewedPublicFixture>) {
        require(Files.isRegularFile(archive)) { "archive is missing: $archive" }
        require(fixtures.distinct().size == fixtures.size) { "reviewed public fixture pins must be unique" }
        val fixtureHits = fixtures.associateWith { 0 }.toMutableMap()
        scanRoot(archive, fixtureHits)
        val invalidHits = fixtureHits.filterValues { hits -> hits != 1 }
        require(invalidHits.isEmpty()) {
            "reviewed public fixture pins must match exactly once: " +
                invalidHits.entries.joinToString { (fixture, hits) -> "${fixture.artifactPath}!/${fixture.entryName}=$hits" }
        }
    }

    private fun scanRoot(archive: Path, fixtureHits: MutableMap<ReviewedPublicFixture, Int>) {
        val identity = archive.fileName.toString()
        ZipFile(archive.toFile()).use { zip ->
            verifyComment("$identity#comment", zip.comment)
            var entryCount = 0
            zip.entries().asSequence().forEach { entry ->
                entryCount++
                val nestedIdentity = "$identity!/${entry.name}"
                verifyName(nestedIdentity)
                verifyComment("$nestedIdentity#comment", entry.comment)
                if (!entry.isDirectory) {
                    val bytes = zip.getInputStream(entry).use(InputStream::readBytes)
                    val nestedArchive = entry.name.lowercase(Locale.ROOT).let { name ->
                        archiveSuffixes.any(name::endsWith)
                    }
                    if (nestedArchive) {
                        scan(bytes, nestedIdentity, 1, sha256(bytes), fixtureHits)
                    } else {
                        verifyBody(nestedIdentity, bytes, identity, null, entry.name, fixtureHits)
                    }
                }
            }
            require(entryCount > 0) { "archive contains no entries: $identity" }
        }
    }

    private fun scan(
        archiveBytes: ByteArray,
        identity: String,
        depth: Int,
        archiveSha256: String?,
        fixtureHits: MutableMap<ReviewedPublicFixture, Int>,
    ) {
        require(depth <= 8) { "nested archive depth exceeds the verification limit at $identity" }
        val centralEntryNames = verifyNestedCentralDirectory(archiveBytes, identity)
        ZipInputStream(ByteArrayInputStream(archiveBytes).buffered()).use { zip ->
            var entryCount = 0
            while (true) {
                val entry = zip.nextEntry ?: break
                require(entryCount < centralEntryNames.size) {
                    "nested archive has more local entries than central entries at $identity"
                }
                require(entry.name == centralEntryNames[entryCount]) {
                    "nested archive local and central entry names differ at $identity: " +
                        "${entry.name} != ${centralEntryNames[entryCount]}"
                }
                entryCount++
                val nestedIdentity = "$identity!/${entry.name}"
                verifyName(nestedIdentity)
                if (!entry.isDirectory) {
                    val bytes = zip.readBytes()
                    val nestedArchive = entry.name.lowercase(Locale.ROOT).let { name ->
                        archiveSuffixes.any(name::endsWith)
                    }
                    if (nestedArchive) {
                        scan(bytes, nestedIdentity, depth + 1, sha256(bytes), fixtureHits)
                    } else {
                        verifyBody(nestedIdentity, bytes, identity, archiveSha256, entry.name, fixtureHits)
                    }
                }
                zip.closeEntry()
            }
            require(entryCount == centralEntryNames.size) {
                "nested archive local and central entry counts differ at $identity"
            }
            require(entryCount > 0) { "archive contains no entries: $identity" }
        }
    }

    private fun verifyName(identity: String) {
        val lower = identity.lowercase(Locale.ROOT)
        require(forbiddenNameSuffixes.none(lower::endsWith) || googleTrustStoreIdentity.matches(lower)) {
            "archive contains sensitive key material: $identity"
        }
        require(
            forbiddenBodyTokens.none(lower::contains) &&
                !standaloneBrand.containsMatchIn(identity) &&
                !containsAbsoluteUserPath(identity)
        ) {
            "archive contains sensitive identity or path: $identity"
        }
    }

    private fun verifyBody(
        identity: String,
        bytes: ByteArray,
        archiveIdentity: String,
        archiveSha256: String?,
        entryName: String,
        fixtureHits: MutableMap<ReviewedPublicFixture, Int>,
    ) {
        if (googleTrustStoreIdentity.matches(identity.lowercase(Locale.ROOT))) {
            verifyGoogleTrustStore(identity, bytes)
            return
        }
        val reviewedFixture = if (archiveSha256 == null) {
            null
        } else {
            fixtureHits.keys.singleOrNull { fixture ->
                archiveIdentity.substringAfter("!/") == fixture.artifactPath &&
                    archiveSha256 == fixture.artifactSha256 &&
                    entryName == fixture.entryName
            }
        }
        if (reviewedFixture != null) {
            fixtureHits[reviewedFixture] = fixtureHits.getValue(reviewedFixture) + 1
            return
        }
        val rawText = bytes.toString(Charsets.ISO_8859_1)
        val text = rawText.lowercase(Locale.ROOT)
        require(forbiddenBodyTokens.none(text::contains)) { "archive entry contains sensitive material: $identity" }
        require(!containsPrivateKey(rawText)) { "archive entry contains sensitive material: $identity" }
        require(!standaloneBrand.containsMatchIn(rawText) && !containsAbsoluteUserPath(rawText)) {
            "archive entry contains a sensitive identity or absolute user path: $identity"
        }
    }

    private fun verifyComment(identity: String, comment: String?) {
        if (!comment.isNullOrEmpty()) verifySensitiveBytes(identity, comment.toByteArray(Charsets.ISO_8859_1))
    }

    private fun verifySensitiveBytes(identity: String, bytes: ByteArray) {
        val rawText = bytes.toString(Charsets.ISO_8859_1)
        val text = rawText.lowercase(Locale.ROOT)
        require(forbiddenBodyTokens.none(text::contains) && !standaloneBrand.containsMatchIn(rawText)) {
            "archive comment contains sensitive identity: $identity"
        }
        require(!containsAbsoluteUserPath(rawText)) { "archive comment contains an absolute user path: $identity" }
        require(!containsPrivateKey(rawText)) { "archive comment contains sensitive material: $identity" }
    }

    private fun verifyNestedCentralDirectory(bytes: ByteArray, identity: String): List<String> {
        val eocd = findEndOfCentralDirectory(bytes)
        val archiveCommentLength = littleEndianU16(bytes, eocd + 20)
        verifySensitiveBytes("$identity#comment", bytes.copyOfRange(eocd + 22, eocd + 22 + archiveCommentLength))
        val entryCount = littleEndianU16(bytes, eocd + 10)
        var cursor = littleEndianU32(bytes, eocd + 16).toInt()
        return List(entryCount) {
            require(littleEndianU32(bytes, cursor) == 0x02014b50L) {
                "nested archive central directory is invalid at $identity"
            }
            val nameLength = littleEndianU16(bytes, cursor + 28)
            val extraLength = littleEndianU16(bytes, cursor + 30)
            val commentLength = littleEndianU16(bytes, cursor + 32)
            val nameStart = cursor + 46
            val extraStart = nameStart + nameLength
            val commentStart = extraStart + extraLength
            require(commentStart + commentLength <= bytes.size) {
                "nested archive comment escapes the central directory at $identity"
            }
            val entryName = bytes.copyOfRange(nameStart, extraStart).toString(Charsets.UTF_8)
            verifyName("$identity!/$entryName")
            verifySensitiveBytes(
                "$identity!/$entryName#comment",
                bytes.copyOfRange(commentStart, commentStart + commentLength),
            )
            cursor = commentStart + commentLength
            entryName
        }
    }

    private fun findEndOfCentralDirectory(bytes: ByteArray): Int {
        val minimum = maxOf(0, bytes.size - 65_557)
        for (index in bytes.size - 22 downTo minimum) {
            if (littleEndianU32(bytes, index) == 0x06054b50L) {
                val commentLength = littleEndianU16(bytes, index + 20)
                if (index + 22 + commentLength == bytes.size) return index
            }
        }
        throw IllegalArgumentException("nested archive has no valid end-of-central-directory record")
    }

    private fun littleEndianU16(bytes: ByteArray, offset: Int): Int {
        require(offset >= 0 && offset + 2 <= bytes.size) { "ZIP field is outside the archive" }
        return (bytes[offset].toInt() and 0xff) or ((bytes[offset + 1].toInt() and 0xff) shl 8)
    }

    private fun littleEndianU32(bytes: ByteArray, offset: Int): Long {
        require(offset >= 0 && offset + 4 <= bytes.size) { "ZIP field is outside the archive" }
        return (bytes[offset].toLong() and 0xff) or
            ((bytes[offset + 1].toLong() and 0xff) shl 8) or
            ((bytes[offset + 2].toLong() and 0xff) shl 16) or
            ((bytes[offset + 3].toLong() and 0xff) shl 24)
    }

    private fun verifyGoogleTrustStore(identity: String, bytes: ByteArray) {
        val type = if (identity.lowercase(Locale.ROOT).endsWith(".p12")) "PKCS12" else "JKS"
        val store = runCatching {
            KeyStore.getInstance(type).also { keyStore ->
                keyStore.load(ByteArrayInputStream(bytes), "notasecret".toCharArray())
            }
        }.getOrElse { failure ->
            throw IllegalArgumentException("vendor certificate trust store is unreadable: $identity", failure)
        }
        val aliases = buildList {
            val entries = store.aliases()
            while (entries.hasMoreElements()) add(entries.nextElement())
        }
        require(aliases.isNotEmpty()) { "vendor certificate trust store is empty: $identity" }
        require(aliases.all { alias -> store.isCertificateEntry(alias) && !store.isKeyEntry(alias) }) {
            "vendor certificate trust store contains key material: $identity"
        }
    }

    private fun sha256(bytes: ByteArray): String = MessageDigest.getInstance("SHA-256")
        .digest(bytes)
        .joinToString("") { byte -> "%02x".format(byte) }

    private fun containsPrivateKey(text: String): Boolean = privateKeyBlock.findAll(text).any { match ->
        val payload = match.groupValues[2].filterNot(Char::isWhitespace)
        val der = runCatching { Base64.getDecoder().decode(payload) }.getOrNull()
        der != null && der.size >= 48 && der.first() == 0x30.toByte()
    }

    private fun containsAbsoluteUserPath(text: String): Boolean =
        macUserPath.containsMatchIn(text) || windowsUserPath.containsMatchIn(text)
}
