package com.holin.buildsupport

import java.nio.file.Files
import java.nio.file.Path
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.MessageDigest
import java.util.Base64
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509TrustManager
import kotlin.io.path.createDirectories
import kotlin.io.path.writeBytes
import kotlin.test.Test
import kotlin.test.assertContains
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import org.junit.jupiter.api.io.TempDir

class PortableBuildSupportTest {
    @TempDir
    lateinit var temporary: Path

    @Test
    fun `graph normalization flattens metadata nodes deterministically and rejects cycles`() {
        val graph = linkedMapOf("metadata-a" to setOf("metadata-b"), "metadata-b" to setOf("artifact-a"))

        assertEquals(
            listOf("artifact-a", "artifact-b"),
            OfflineGraphNormalizer.concreteClosure(
                linkedSetOf("artifact-b", "metadata-a"),
                graph,
                linkedSetOf("artifact-b", "artifact-a"),
            ),
        )
        assertFailsWith<IllegalArgumentException> {
            OfflineGraphNormalizer.concreteClosure(
                listOf("metadata-a"),
                mapOf("metadata-a" to setOf("metadata-b"), "metadata-b" to setOf("metadata-a")),
                emptySet(),
            )
        }
    }

    @Test
    fun `verification metadata covers multiple repositories with exact artifact checksums`() {
        val portable = repository("portable", "com/holin/plugin/plugin/1.0/plugin-1.0.jar", byteArrayOf(1, 2, 3))
        val toolchain = repository("toolchain", "com/android/tools/gradle/8.0/gradle-8.0.jar", byteArrayOf(4, 5, 6))

        val metadata = PortableVerificationMetadata.render(listOf(portable, toolchain))

        assertContains(metadata, "group=\"com.holin.plugin\" name=\"plugin\" version=\"1.0\"")
        assertContains(metadata, "group=\"com.android.tools\" name=\"gradle\" version=\"8.0\"")
        assertContains(metadata, "<verify-metadata>true</verify-metadata>")
    }

    @Test
    fun `checksum coverage rejects an unlisted archive entry`() {
        ArchiveChecksumCoverage.requireExhaustive(
            listOf("SHA256SUMS", "repository/plugin.jar"),
            setOf("repository/plugin.jar"),
        )

        assertFailsWith<IllegalArgumentException> {
            ArchiveChecksumCoverage.requireExhaustive(
                listOf("SHA256SUMS", "repository/plugin.jar", "unlisted.txt"),
                setOf("repository/plugin.jar"),
            )
        }
    }

    @Test
    fun `recursive archive scanner rejects file URI user paths in names bodies and comments`() {
        val body = zip(
            "file-uri-body.zip",
            mapOf("body.bin" to byteArrayOf(0) + "file:///Users/vendor/build".toByteArray()),
        )
        assertFailsWith<IllegalArgumentException> { RecursiveArchiveSensitivityScanner.verify(body) }

        val name = zip(
            "file-uri-name.zip",
            mapOf("file:///private/Users/vendor/build.txt" to "neutral".toByteArray()),
        )
        assertFailsWith<IllegalArgumentException> { RecursiveArchiveSensitivityScanner.verify(name) }

        val archiveComment = zip(
            "file-uri-archive-comment.zip",
            mapOf("safe.txt" to "neutral".toByteArray()),
            "file:////Users/vendor/build",
        )
        assertFailsWith<IllegalArgumentException> {
            RecursiveArchiveSensitivityScanner.verify(archiveComment)
        }

        val entryComment = zipWithEntryComment(
            "file-uri-entry-comment.zip",
            "safe.txt",
            "neutral".toByteArray(),
            "file:///Users/vendor/build",
        )
        assertFailsWith<IllegalArgumentException> {
            RecursiveArchiveSensitivityScanner.verify(entryComment)
        }
    }

    @Test
    fun `recursive archive scanner rejects a standalone former user name in names bodies and comments`() {
        val body = zip(
            "former-user-body.zip",
            mapOf("body.bin" to FORMER_USER_NAME.toByteArray()),
        )
        assertFailsWith<IllegalArgumentException> { RecursiveArchiveSensitivityScanner.verify(body) }

        val name = zip(
            "former-user-name.zip",
            mapOf("$FORMER_USER_NAME.txt" to "neutral".toByteArray()),
        )
        assertFailsWith<IllegalArgumentException> { RecursiveArchiveSensitivityScanner.verify(name) }

        val comment = zip(
            "former-user-comment.zip",
            mapOf("safe.txt" to "neutral".toByteArray()),
            FORMER_USER_NAME,
        )
        assertFailsWith<IllegalArgumentException> { RecursiveArchiveSensitivityScanner.verify(comment) }
    }

    @Test
    fun `recursive archive scanner rejects mismatched local and central entry names`() {
        listOf("NeutralApp.txt", "different0.txt").forEachIndexed { index, centralName ->
            val nested = zipWithCentralDirectoryName(
                "mismatched-names-$index.zip",
                "neutral000.txt",
                centralName,
            )
            val outer = zip(
                "mismatched-names-outer-$index.zip",
                mapOf("nested.zip" to Files.readAllBytes(nested)),
            )

            assertFailsWith<IllegalArgumentException> {
                RecursiveArchiveSensitivityScanner.verify(outer)
            }
        }
    }

    @Test
    fun `recursive archive scanner rejects a former app brand entry name`() {
        val entryName = "$FORMER_APP_BRAND.txt"
        val archive = zip(
            "former-brand-entry-name.zip",
            mapOf(entryName to "neutral".toByteArray()),
        )

        val failure = assertFailsWith<IllegalArgumentException> {
            RecursiveArchiveSensitivityScanner.verify(archive)
        }

        assertContains(failure.message.orEmpty(), "archive contains sensitive identity or path")
        assertContains(failure.message.orEmpty(), entryName)
    }

    @Test
    fun `recursive archive scanner rejects sensitive nested names and bodies`() {
        val safeNested = zipBytes(mapOf("safe.txt" to "neutral".toByteArray()))
        val safe = zip("safe.zip", mapOf("nested.jar" to safeNested))
        RecursiveArchiveSensitivityScanner.verify(safe)

        val nestedComment = zip(
            "nested-comment.zip",
            mapOf("nested.jar" to zipBytes(mapOf("safe.txt" to "neutral".toByteArray()), FORMER_APP_BRAND)),
        )
        assertFailsWith<IllegalArgumentException> { RecursiveArchiveSensitivityScanner.verify(nestedComment) }

        val archiveComment = zip(
            "archive-comment.zip",
            mapOf("safe.txt" to "neutral".toByteArray()),
            FORMER_APP_BRAND,
        )
        assertFailsWith<IllegalArgumentException> { RecursiveArchiveSensitivityScanner.verify(archiveComment) }

        val entryComment = zipWithEntryComment(
            "entry-comment.zip",
            "safe.txt",
            "neutral".toByteArray(),
            FORMER_APP_BRAND,
        )
        assertFailsWith<IllegalArgumentException> { RecursiveArchiveSensitivityScanner.verify(entryComment) }

        val urlRoute = zip(
            "url-route.zip",
            mapOf("api.proto" to "get: /v1/users/{user_id}/messages".toByteArray()),
        )
        RecursiveArchiveSensitivityScanner.verify(urlRoute)

        val body = zip("body.zip", mapOf("nested.jar" to zipBytes(mapOf("note.txt" to "/Users/private".toByteArray()))))
        assertFailsWith<IllegalArgumentException> { RecursiveArchiveSensitivityScanner.verify(body) }

        val windowsBody = zip(
            "windows-body.zip",
            mapOf("note.txt" to "C:\\Users\\private\\project".toByteArray()),
        )
        assertFailsWith<IllegalArgumentException> { RecursiveArchiveSensitivityScanner.verify(windowsBody) }

        val binaryBrand = zip(
            "binary-brand.zip",
            mapOf("native.dylib" to byteArrayOf(0) + FORMER_APP_BRAND.toByteArray()),
        )
        assertFailsWith<IllegalArgumentException> { RecursiveArchiveSensitivityScanner.verify(binaryBrand) }

        val vendorIdentifier = zip(
            "vendor-identifier.zip",
            mapOf("CompilerArguments.class" to byteArrayOf(0) + VENDOR_IDENTIFIER.toByteArray()),
            VENDOR_IDENTIFIER,
        )
        RecursiveArchiveSensitivityScanner.verify(vendorIdentifier)

        val vendorIdentifierName = zip(
            "vendor-identifier-name.zip",
            mapOf("$VENDOR_IDENTIFIER.class" to "neutral".toByteArray()),
        )
        RecursiveArchiveSensitivityScanner.verify(vendorIdentifierName)

        val binaryUserPath = zip(
            "binary-user-path.zip",
            mapOf("native.dylib" to byteArrayOf(0) + "/Users/vendor/build".toByteArray()),
        )
        assertFailsWith<IllegalArgumentException> { RecursiveArchiveSensitivityScanner.verify(binaryUserPath) }

        val lowercaseUrlPath = zip(
            "binary-lowercase-url-path.zip",
            mapOf("native.dylib" to byteArrayOf(0) + "/v1/users/vendor/messages".toByteArray()),
        )
        RecursiveArchiveSensitivityScanner.verify(lowercaseUrlPath)

        val userBinary = zip(
            "user-binary.zip",
            mapOf("native.dylib" to byteArrayOf(0) + FORMER_USER_PATH.toByteArray()),
        )
        assertFailsWith<IllegalArgumentException> { RecursiveArchiveSensitivityScanner.verify(userBinary) }

        val projectBinary = zip(
            "project-binary.zip",
            mapOf("classes.bin" to byteArrayOf(0) + FORMER_APP_PACKAGE.toByteArray()),
        )
        assertFailsWith<IllegalArgumentException> { RecursiveArchiveSensitivityScanner.verify(projectBinary) }

        val vendorBrand = zip(
            "vendor-brand.zip",
            mapOf("classes.bin" to byteArrayOf(0) + FORMER_VENDOR_BRAND.toByteArray()),
        )
        assertFailsWith<IllegalArgumentException> { RecursiveArchiveSensitivityScanner.verify(vendorBrand) }

        val vendorTrustStore = zip(
            "vendor-trust-store.zip",
            mapOf(
                "google-api-client-1.34.0.jar" to zipBytes(
                    mapOf(
                        "com/google/api/client/googleapis/google.p12" to trustedCertificateStore("PKCS12"),
                        "com/google/api/client/googleapis/google.jks" to trustedCertificateStore("JKS"),
                    ),
                ),
            ),
        )
        RecursiveArchiveSensitivityScanner.verify(vendorTrustStore)

        val key = zip("key.zip", mapOf("credentials/fixture.p12" to byteArrayOf(1, 2, 3)))
        assertFailsWith<IllegalArgumentException> { RecursiveArchiveSensitivityScanner.verify(key) }
    }

    @Test
    fun `recursive archive scanner pins reviewed fixture by artifact path hash and entry`() {
        val fixtureEntry = "com/google/api/client/testing/json/webtoken/TestCertificates.class"
        val jarBytes = zipBytes(mapOf(fixtureEntry to privateKeyPem()))
        val artifactPath = "matrix/agp-test/gradle/gradle-test/lib/plugins/google-http-client-test.jar"
        val reviewedFixture = ReviewedPublicFixture(artifactPath, sha256(jarBytes), fixtureEntry)
        val reviewed = zip("reviewed-google-fixture.zip", mapOf(artifactPath to jarBytes))

        RecursiveArchiveSensitivityScanner.verify(reviewed, listOf(reviewedFixture))

        val nearPath = zip("near-path-google-fixture.zip", mapOf("matrix/$artifactPath" to jarBytes))
        assertFailsWith<IllegalArgumentException> {
            RecursiveArchiveSensitivityScanner.verify(nearPath, listOf(reviewedFixture))
        }
        assertFailsWith<IllegalArgumentException> {
            RecursiveArchiveSensitivityScanner.verify(
                reviewed,
                listOf(ReviewedPublicFixture(artifactPath, "00", fixtureEntry)),
            )
        }
        val wrongEntryJar = zipBytes(mapOf("com/google/api/client/testing/Other.class" to privateKeyPem()))
        val wrongEntry = zip("wrong-entry-google-fixture.zip", mapOf(artifactPath to wrongEntryJar))
        assertFailsWith<IllegalArgumentException> {
            RecursiveArchiveSensitivityScanner.verify(
                wrongEntry,
                listOf(ReviewedPublicFixture(artifactPath, sha256(wrongEntryJar), fixtureEntry)),
            )
        }
        val stale = zip("stale-google-fixture.zip", mapOf("safe.txt" to "neutral".toByteArray()))
        assertFailsWith<IllegalArgumentException> {
            RecursiveArchiveSensitivityScanner.verify(stale, listOf(reviewedFixture))
        }
        val nestedOnly = zip(
            "nested-only-google-fixture.zip",
            mapOf("nested.zip" to zipBytes(mapOf(artifactPath to jarBytes))),
        )
        assertFailsWith<IllegalArgumentException> {
            RecursiveArchiveSensitivityScanner.verify(nestedOnly, listOf(reviewedFixture))
        }
        val duplicate = zip(
            "duplicate-google-fixture.zip",
            mapOf(
                artifactPath to jarBytes,
                "nested.zip" to zipBytes(mapOf(artifactPath to jarBytes)),
            ),
        )
        assertFailsWith<IllegalArgumentException> {
            RecursiveArchiveSensitivityScanner.verify(duplicate, listOf(reviewedFixture))
        }
    }

    @Test
    fun `recursive archive scanner distinguishes parser markers from embedded PEM private keys`() {
        val parserMarkers = zip(
            "parser-markers.zip",
            mapOf(
                "KeyParser.class" to (
                    byteArrayOf(0) +
                        "-----BEGIN PRIVATE KEY-----\u0000-----END PRIVATE KEY-----".toByteArray()
                    ),
            ),
        )

        RecursiveArchiveSensitivityScanner.verify(parserMarkers)

        val embeddedKey = zip(
            "embedded-key.zip",
            mapOf("credentials.txt" to privateKeyPem()),
        )
        assertFailsWith<IllegalArgumentException> {
            RecursiveArchiveSensitivityScanner.verify(embeddedKey)
        }
    }

    private fun repository(name: String, relative: String, bytes: ByteArray): Path =
        temporary.resolve(name).also { root ->
            root.resolve(relative).also { file ->
                file.parent.createDirectories()
                file.writeBytes(bytes)
            }
        }

    private fun zip(name: String, entries: Map<String, ByteArray>, comment: String? = null): Path =
        temporary.resolve(name).also { output -> Files.write(output, zipBytes(entries, comment)) }

    private fun zipWithEntryComment(name: String, entryName: String, bytes: ByteArray, comment: String): Path =
        temporary.resolve(name).also { output ->
            val stream = java.io.ByteArrayOutputStream()
            ZipOutputStream(stream).use { zip ->
                zip.putNextEntry(ZipEntry(entryName).also { entry -> entry.comment = comment })
                zip.write(bytes)
                zip.closeEntry()
            }
            Files.write(output, stream.toByteArray())
        }

    private fun zipWithCentralDirectoryName(name: String, localName: String, centralName: String): Path {
        val localNameBytes = localName.toByteArray()
        val centralNameBytes = centralName.toByteArray()
        require(localNameBytes.size == centralNameBytes.size)
        val bytes = zipBytes(mapOf(localName to "neutral".toByteArray()))
        val signature = byteArrayOf(0x50, 0x4b, 0x01, 0x02)
        val centralDirectory = bytes.indices.first { index ->
            index + signature.size <= bytes.size &&
                signature.indices.all { offset -> bytes[index + offset] == signature[offset] }
        }
        centralNameBytes.copyInto(bytes, centralDirectory + 46)
        return temporary.resolve(name).also { output -> Files.write(output, bytes) }
    }

    private fun zipBytes(entries: Map<String, ByteArray>, comment: String? = null): ByteArray {
        val output = java.io.ByteArrayOutputStream()
        ZipOutputStream(output).use { zip ->
            if (comment != null) zip.setComment(comment)
            entries.forEach { (name, bytes) ->
                zip.putNextEntry(ZipEntry(name))
                zip.write(bytes)
                zip.closeEntry()
            }
        }
        return output.toByteArray()
    }

    private fun trustedCertificateStore(type: String): ByteArray {
        val trustManagers = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
        trustManagers.init(null as KeyStore?)
        val certificate = trustManagers.trustManagers.filterIsInstance<X509TrustManager>()
            .flatMap { manager -> manager.acceptedIssuers.asList() }
            .first()
        val store = KeyStore.getInstance(type)
        store.load(null, null)
        store.setCertificateEntry("trusted", certificate)
        return java.io.ByteArrayOutputStream().use { output ->
            store.store(output, "notasecret".toCharArray())
            output.toByteArray()
        }
    }

    private fun sha256(bytes: ByteArray): String = MessageDigest.getInstance("SHA-256")
        .digest(bytes)
        .joinToString("") { byte -> "%02x".format(byte) }

    private companion object {
        val FORMER_APP_BRAND = listOf("single", "link").joinToString("")
        val FORMER_APP_PACKAGE = "com.$FORMER_APP_BRAND.match"
        val FORMER_VENDOR_BRAND = "joy" + "happier"
        val FORMER_USER_NAME = "Zhu" + "anz1"
        val FORMER_USER_PATH = listOf("/Users/", "Zhu", "anz1/build").joinToString("")
        val VENDOR_IDENTIFIER = "single" + "LinkerArguments"
    }

    private fun privateKeyPem(): ByteArray {
        val generator = KeyPairGenerator.getInstance("EC")
        generator.initialize(256)
        val payload = Base64.getMimeEncoder(64, "\n".toByteArray())
            .encodeToString(generator.generateKeyPair().private.encoded)
        return "-----BEGIN PRIVATE KEY-----\n$payload\n-----END PRIVATE KEY-----\n".toByteArray()
    }
}
