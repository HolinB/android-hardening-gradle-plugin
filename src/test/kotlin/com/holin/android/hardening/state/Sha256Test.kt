package com.holin.android.hardening.state

import java.nio.file.Files
import kotlin.io.path.createDirectory
import kotlin.io.path.createSymbolicLinkPointingTo
import kotlin.io.path.writeText
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotEquals
import org.junit.jupiter.api.io.TempDir
import java.nio.file.Path

class Sha256Test {
    @TempDir
    lateinit var root: Path

    @Test
    fun `standard SHA-256 vectors are lowercase and complete`() {
        assertEquals("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", Sha256.hex(byteArrayOf()))
        assertEquals("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", Sha256.hex("abc".toByteArray()))
    }

    @Test
    fun `HMAC-SHA-256 matches the RFC 4231 vector`() {
        assertEquals(
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
            HmacSha256.hex(ByteArray(20) { 0x0b }, "Hi There".toByteArray()),
        )
    }

    @Test
    fun `canonical payload has an explicit domain even when empty`() {
        val empty = root.resolve("empty").createDirectory()

        assertNotEquals(Sha256.hex(byteArrayOf()), Sha256.canonicalPayload(empty))
        assertNotEquals(
            Sha256.canonicalPayload(empty, CanonicalContentDomain.LEGACY_V1),
            Sha256.canonicalPayload(empty, CanonicalContentDomain.HOLIN_1_2),
        )
    }

    @Test
    fun `canonical payload hash is path sorted and length prefixed`() {
        val first = root.resolve("first").createDirectory()
        first.resolve("b.txt").writeText("two")
        first.resolve("a.txt").writeText("one")
        val second = root.resolve("second").createDirectory()
        second.resolve("a.txt").writeText("one")
        second.resolve("b.txt").writeText("two")

        assertEquals(Sha256.canonicalPayload(first), Sha256.canonicalPayload(second))
    }

    @Test
    fun `canonical payload includes empty directory entries`() {
        val first = root.resolve("first-with-directory").createDirectory()
        first.resolve("empty").createDirectory()
        val second = root.resolve("second-without-directory").createDirectory()

        assertNotEquals(Sha256.canonicalPayload(first), Sha256.canonicalPayload(second))
    }

    @Test
    fun `canonical payload rejects symlinks`() {
        val payload = root.resolve("payload").createDirectory()
        val outside = Files.writeString(root.resolve("outside.txt"), "secret")
        payload.resolve("link").createSymbolicLinkPointingTo(outside)

        assertFailsWith<IllegalArgumentException> { Sha256.canonicalPayload(payload) }
    }
}
