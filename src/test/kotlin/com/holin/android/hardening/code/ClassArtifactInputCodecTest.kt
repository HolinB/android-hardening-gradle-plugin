package com.holin.android.hardening.code

import java.nio.file.Path
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class ClassArtifactInputCodecTest {
    @Test
    fun `round trips owned and external artifact metadata with normalized absolute paths`() {
        val relative = Path.of("build", "classes.jar")
        val owned = ClassArtifactInput("project :app", ":app", relative)
        val external = ClassArtifactInput("android.jar", null, relative)

        assertEquals(
            owned.copy(file = relative.toAbsolutePath().normalize()),
            ClassArtifactInputCodec.decode(ClassArtifactInputCodec.encode(owned)),
        )
        assertEquals(
            external.copy(file = relative.toAbsolutePath().normalize()),
            ClassArtifactInputCodec.decode(ClassArtifactInputCodec.encode(external)),
        )
    }

    @Test
    fun `rejects malformed artifact metadata`() {
        assertFailsWith<IllegalArgumentException> { ClassArtifactInputCodec.decode("") }
        assertFailsWith<IllegalArgumentException> { ClassArtifactInputCodec.decode("YQ.Yg") }
        assertFailsWith<IllegalArgumentException> { ClassArtifactInputCodec.decode("YQ.Yg.Yw.ZA") }
        assertFailsWith<IllegalArgumentException> { ClassArtifactInputCodec.decode("%%..%%") }
    }
}
