package com.holin.android.hardening.verification

import com.android.tools.smali.dexlib2.AccessFlags
import com.android.tools.smali.dexlib2.Opcodes
import com.android.tools.smali.dexlib2.immutable.ImmutableClassDef
import com.android.tools.smali.dexlib2.immutable.ImmutableDexFile
import com.android.tools.smali.dexlib2.immutable.ImmutableField
import com.android.tools.smali.dexlib2.writer.io.MemoryDataStore
import com.android.tools.smali.dexlib2.writer.pool.DexPool
import com.holin.android.hardening.code.CodeSymbolKey
import com.holin.android.hardening.code.CodeSymbolKind
import com.holin.android.hardening.code.POTENTIAL_BEAN_FIELD_POLICY_VERSION
import com.holin.android.hardening.code.PotentialBeanField
import com.holin.android.hardening.code.PotentialBeanFieldManifest
import com.holin.android.hardening.code.PotentialBeanFieldManifestCodec
import java.nio.file.Files
import java.nio.file.Path
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class PotentialBeanFieldDexVerifierTest {
    @Test
    fun `unchanged protected fields verify with module counts`() {
        val field = beanField("com/example/Bean", "displayName", "Ljava/lang/String;")
        val aab = aab(
            "base/dex/classes.dex" to dex(
                clazz("Lcom/example/Bean;", immutableField("Lcom/example/Bean;", "displayName", "Ljava/lang/String;")),
            ),
        )

        val result = PotentialBeanFieldDexVerifier().verify(aab, mapping(), manifest(field))

        assertTrue(result.verified)
        assertEquals(POTENTIAL_BEAN_FIELD_POLICY_VERSION, result.policyVersion)
        assertEquals(OWNED_MODULES.associateWith { module -> if (module == ":app") 1 else 0 }, result.moduleFieldCounts)
        assertEquals(1, result.protectedFieldCount)
        assertEquals(1, result.survivingOwnerCount)
        assertEquals(0, result.shrunkOwnerCount)
        assertEquals(emptyList(), result.violations)
    }

    @Test
    fun `renamed protected field is rejected even when mapping names it`() {
        val field = beanField("com/example/Bean", "displayName", "Ljava/lang/String;")
        val aab = aab(
            "base/dex/classes.dex" to dex(
                clazz("La/b;", immutableField("La/b;", "x", "Ljava/lang/String;")),
            ),
        )
        val mapping = mapping(
            "com.example.Bean -> a.b:",
            "    java.lang.String displayName -> x",
        )

        val result = PotentialBeanFieldDexVerifier().verify(aab, mapping, manifest(field))

        assertFalse(result.verified)
        assertTrue(result.violations.any { it.contains("displayName") && it.contains("mapped to x") })
        assertTrue(result.violations.any { it.contains("required final field") })
    }

    @Test
    fun `missing field on surviving owner is rejected`() {
        val field = beanField("com/example/Bean", "displayName", "Ljava/lang/String;")
        val aab = aab("base/dex/classes.dex" to dex(clazz("Lcom/example/Bean;")))

        val result = PotentialBeanFieldDexVerifier().verify(aab, mapping(), manifest(field))

        assertEquals(1, result.survivingOwnerCount)
        assertEquals(0, result.shrunkOwnerCount)
        assertTrue(result.violations.single().contains("required final field"))
    }

    @Test
    fun `owner absent under both original and mapped descriptors is counted as shrunk`() {
        val field = beanField("com/example/Bean", "displayName", "Ljava/lang/String;")
        val aab = aab("base/dex/classes.dex" to dex(clazz("Lother/Present;")))
        val mapping = mapping("com.example.Bean -> a.b:")

        val result = PotentialBeanFieldDexVerifier().verify(aab, mapping, manifest(field))

        assertTrue(result.verified)
        assertEquals(0, result.survivingOwnerCount)
        assertEquals(1, result.shrunkOwnerCount)
    }

    @Test
    fun `original owner cannot substitute for a distinct mapped final owner`() {
        val field = beanField("com/example/Bean", "displayName", "Ljava/lang/String;")
        val aab = aab(
            "base/dex/classes.dex" to dex(
                clazz(
                    "Lcom/example/Bean;",
                    immutableField("Lcom/example/Bean;", "displayName", "Ljava/lang/String;"),
                ),
            ),
        )
        val mapping = mapping("com.example.Bean -> a.b:")

        val result = PotentialBeanFieldDexVerifier().verify(aab, mapping, manifest(field))

        assertFalse(result.verified)
        assertEquals(1, result.survivingOwnerCount)
        assertEquals(0, result.shrunkOwnerCount)
        assertTrue(result.violations.any { it.contains("mapped final owner La/b; is missing") })
    }

    @Test
    fun `field descriptor maps every owned object component`() {
        val field = beanField("com/example/Bean", "payloads", "[[Lcom/example/Payload;")
        val aab = aab(
            "base/dex/classes.dex" to dex(
                clazz("La/b;", immutableField("La/b;", "payloads", "[[Lc/d;")),
                clazz("Lc/d;"),
            ),
        )
        val mapping = mapping(
            "com.example.Bean -> a.b:",
            "    com.example.Payload[][] payloads -> payloads",
            "com.example.Payload -> c.d:",
        )

        val result = PotentialBeanFieldDexVerifier().verify(aab, mapping, manifest(field))

        assertTrue(result.verified, result.violations.joinToString())
    }

    @Test
    fun `duplicate class definitions across dex entries are violations`() {
        val field = beanField("com/example/Bean", "displayName", "Ljava/lang/String;")
        val bean = clazz(
            "Lcom/example/Bean;",
            immutableField("Lcom/example/Bean;", "displayName", "Ljava/lang/String;"),
        )
        val aab = aab(
            "base/dex/classes.dex" to dex(bean),
            "base/dex/classes2.dex" to dex(bean),
        )

        val result = PotentialBeanFieldDexVerifier().verify(aab, mapping(), manifest(field))

        assertFalse(result.verified)
        assertTrue(result.violations.any { it.contains("duplicate class descriptor Lcom/example/Bean;") })
    }

    @Test
    fun `malformed manifest is rejected before dex verification`() {
        val encoded = PotentialBeanFieldManifestCodec().encode(manifest(beanField()))
        val malformed = encoded.replace("\"policyVersion\":1", "\"policyVersion\":2")

        assertFailsWith<IllegalArgumentException> {
            PotentialBeanFieldManifestCodec().decode(malformed)
        }
    }

    @Test
    fun `malformed AAB ZIP is rejected`() {
        val malformed = Files.createTempFile("field-verifier-malformed", ".aab")
        Files.write(malformed, "not-a-zip".toByteArray())

        assertFailsWith<IllegalArgumentException> {
            PotentialBeanFieldDexVerifier().verify(malformed, mapping(), manifest(beanField()))
        }
    }

    @Test
    fun `malformed base DEX is rejected`() {
        val malformed = aab("base/dex/classes.dex" to "not-a-dex".toByteArray())

        assertFailsWith<IllegalArgumentException> {
            PotentialBeanFieldDexVerifier().verify(malformed, mapping(), manifest(beanField()))
        }
    }

    @Test
    fun `AAB without base DEX is rejected`() {
        val malformed = aab("base/manifest/AndroidManifest.xml" to "manifest".toByteArray())

        assertFailsWith<IllegalArgumentException> {
            PotentialBeanFieldDexVerifier().verify(malformed, mapping(), manifest(beanField()))
        }
    }

    @Test
    fun `multidex scans only base dex entries`() {
        val first = beanField("com/example/First", "value", "I")
        val second = beanField("com/example/Second", "name", "Ljava/lang/String;")
        val aab = aab(
            "base/dex/classes.dex" to dex(
                clazz("Lcom/example/First;", immutableField("Lcom/example/First;", "value", "I")),
            ),
            "base/dex/classes2.dex" to dex(
                clazz("Lcom/example/Second;", immutableField("Lcom/example/Second;", "name", "Ljava/lang/String;")),
            ),
            "feature/dex/classes.dex" to dex(
                clazz("Lcom/example/Second;", immutableField("Lcom/example/Second;", "renamed", "Ljava/lang/String;")),
            ),
        )

        val result = PotentialBeanFieldDexVerifier().verify(aab, mapping(), manifest(first, second))

        assertTrue(result.verified, result.violations.joinToString())
        assertEquals(2, result.protectedFieldCount)
        assertEquals(2, result.survivingOwnerCount)
    }

    private fun mapping(vararg lines: String): ParsedR8Mapping = R8MappingParser().parse(
        buildString {
            appendLine("# compiler: R8")
            appendLine("# compiler_version: 8.13.19")
            lines.forEach(::appendLine)
        },
        null,
    )

    private fun manifest(vararg fields: PotentialBeanField): PotentialBeanFieldManifest {
        val codec = PotentialBeanFieldManifestCodec()
        return PotentialBeanFieldManifest(
            1,
            POTENTIAL_BEAN_FIELD_POLICY_VERSION,
            "demoDebug",
            7,
            "a".repeat(64),
            codec.inventorySha256(fields.toList()),
            OWNED_MODULES,
            fields.toList(),
            2,
        )
    }

    private companion object {
        val OWNED_MODULES = setOf(":app", ":core", ":compress", ":selector", ":ucrop")
    }

    private fun beanField(
        owner: String = "com/example/Bean",
        name: String = "displayName",
        descriptor: String = "Ljava/lang/String;",
    ) = PotentialBeanField(
        ":app",
        CodeSymbolKey(CodeSymbolKind.FIELD, owner, name, descriptor),
        AccessFlags.PUBLIC.value,
    )

    private fun clazz(type: String, vararg fields: ImmutableField) = ImmutableClassDef(
        type,
        AccessFlags.PUBLIC.value,
        "Ljava/lang/Object;",
        emptyList(),
        null,
        emptySet(),
        fields.toList(),
        emptyList(),
    )

    private fun immutableField(owner: String, name: String, type: String) = ImmutableField(
        owner,
        name,
        type,
        AccessFlags.PUBLIC.value,
        null,
        emptySet(),
        emptySet(),
    )

    private fun dex(vararg classes: ImmutableClassDef): ByteArray {
        val store = MemoryDataStore()
        DexPool.writeTo(store, ImmutableDexFile(Opcodes.getDefault(), classes.toList()))
        return store.data
    }

    private fun aab(vararg entries: Pair<String, ByteArray>): Path = Files.createTempFile("field-verifier", ".aab").also { path ->
        ZipOutputStream(Files.newOutputStream(path)).use { output ->
            entries.forEach { (name, bytes) ->
                output.putNextEntry(ZipEntry(name))
                output.write(bytes)
                output.closeEntry()
            }
        }
    }
}
