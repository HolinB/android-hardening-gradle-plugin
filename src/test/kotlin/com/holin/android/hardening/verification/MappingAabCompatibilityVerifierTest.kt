package com.holin.android.hardening.verification

import com.android.tools.smali.dexlib2.AccessFlags
import com.android.tools.smali.dexlib2.Opcodes
import com.android.tools.smali.dexlib2.immutable.ImmutableClassDef
import com.android.tools.smali.dexlib2.immutable.ImmutableDexFile
import com.android.tools.smali.dexlib2.immutable.ImmutableField
import com.android.tools.smali.dexlib2.immutable.ImmutableMethod
import com.android.tools.smali.dexlib2.immutable.ImmutableMethodParameter
import com.android.tools.smali.dexlib2.writer.io.MemoryDataStore
import com.android.tools.smali.dexlib2.writer.pool.DexPool
import java.nio.file.Files
import java.nio.file.Path
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class MappingAabCompatibilityVerifierTest {
    @Test
    fun `AAB present class mapping change is rejected`() {
        val result = verify(
            mapping(
                "com.example.Present -> a.b:",
                "    int value -> c",
                "    void run() -> d",
            ),
            mapping(
                "com.example.Present -> x.y:",
                "    int value -> c",
                "    void run() -> d",
            ),
        )

        assertFalse(result.verified)
        assertTrue(result.violations.any { violation -> violation.contains("CLASS") && violation.contains("com.example.Present") })
    }

    @Test
    fun `AAB present field mapping change is rejected`() {
        val result = verify(
            mapping(
                "com.example.Present -> a.b:",
                "    int value -> c",
                "    void run() -> d",
            ),
            mapping(
                "com.example.Present -> a.b:",
                "    int value -> x",
                "    void run() -> d",
            ),
        )

        assertFalse(result.verified)
        assertTrue(result.violations.any { violation -> violation.contains("FIELD") && violation.contains("value") })
    }

    @Test
    fun `AAB present method mapping change is rejected`() {
        val result = verify(
            mapping(
                "com.example.Present -> a.b:",
                "    int value -> c",
                "    void run() -> d",
            ),
            mapping(
                "com.example.Present -> a.b:",
                "    int value -> c",
                "    void run() -> x",
            ),
        )

        assertFalse(result.verified)
        assertTrue(result.violations.any { violation -> violation.contains("METHOD") && violation.contains("run") })
    }

    @Test
    fun `mapping entries absent from the AAB may be removed`() {
        val previous = mapping(
            "com.example.Present -> a.b:",
            "    int value -> c",
            "    void run() -> d",
            "com.example.Removed -> r.s:",
            "    int gone -> t",
            "    void gone() -> u",
        )
        val candidate = mapping(
            "com.example.Present -> a.b:",
            "    int value -> c",
            "    void run() -> d",
        )

        val result = verify(previous, candidate)

        assertTrue(result.verified, result.violations.joinToString())
        assertEquals(3, result.removedSymbolCount)
    }

    private fun verify(
        previous: ParsedR8Mapping,
        candidate: ParsedR8Mapping,
    ): MappingAabCompatibilityResult = MappingAabCompatibilityVerifier().verify(
        aab(
            dex(
                ImmutableClassDef(
                    "La/b;",
                    AccessFlags.PUBLIC.value,
                    "Ljava/lang/Object;",
                    emptyList(),
                    null,
                    emptySet(),
                    listOf(
                        ImmutableField(
                            "La/b;",
                            "c",
                            "I",
                            AccessFlags.PUBLIC.value,
                            null,
                            emptySet(),
                            emptySet(),
                        ),
                    ),
                    listOf(
                        ImmutableMethod(
                            "La/b;",
                            "d",
                            emptyList<ImmutableMethodParameter>(),
                            "V",
                            AccessFlags.PUBLIC.value or AccessFlags.ABSTRACT.value,
                            emptySet(),
                            emptySet(),
                            null,
                        ),
                    ),
                ),
            ),
        ),
        previous,
        candidate,
    )

    private fun mapping(vararg lines: String): ParsedR8Mapping = R8MappingParser().parse(
        buildString {
            appendLine("# compiler: R8")
            appendLine("# compiler_version: 8.13.19")
            lines.forEach(::appendLine)
        },
        null,
    )

    private fun dex(vararg classes: ImmutableClassDef): ByteArray {
        val store = MemoryDataStore()
        DexPool.writeTo(store, ImmutableDexFile(Opcodes.getDefault(), classes.toList()))
        return store.data
    }

    private fun aab(dex: ByteArray): Path = Files.createTempFile("mapping-compatibility", ".aab").also { path ->
        ZipOutputStream(Files.newOutputStream(path)).use { output ->
            output.putNextEntry(ZipEntry("base/dex/classes.dex"))
            output.write(dex)
            output.closeEntry()
        }
    }
}
