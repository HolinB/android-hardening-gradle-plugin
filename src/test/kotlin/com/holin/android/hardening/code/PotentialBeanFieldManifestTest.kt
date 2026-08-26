package com.holin.android.hardening.code

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import org.objectweb.asm.Opcodes

class PotentialBeanFieldManifestTest {
    @Test
    fun `codec round trips repeated field names deterministically and binds inventory hash`() {
        val fields = listOf(
            beanField(":core", "com/example/Profile", "id", "J", Opcodes.ACC_PRIVATE),
            beanField(":app", "com/example/Order", "id", "J", Opcodes.ACC_FINAL),
        )
        val codec = PotentialBeanFieldManifestCodec()
        val manifest = manifest(fields, codec.inventorySha256(fields))

        val encoded = codec.encode(manifest)
        val decoded = codec.decode(encoded)

        assertEquals(manifest, decoded)
        assertEquals(encoded, codec.encode(decoded))
        assertEquals(listOf(":app", ":core"), decoded.fields.map(PotentialBeanField::modulePath))
        assertEquals(2, decoded.fields.map(PotentialBeanField::key).distinct().size)
        assertTrue(encoded.endsWith('\n'))
    }

    @Test
    fun `codec rejects unknown keys duplicates unsupported versions and hash mismatch`() {
        val field = beanField(":app", "com/example/Profile", "id", "J", 0)
        val codec = PotentialBeanFieldManifestCodec()
        val valid = codec.encode(manifest(listOf(field), codec.inventorySha256(listOf(field))))

        listOf(
            valid.replace("\"variant\":", "\"unknown\":0,\"variant\":"),
            valid.replace("\"schemaVersion\":1", "\"schemaVersion\":2"),
            valid.replace("\"policyVersion\":1", "\"policyVersion\":2"),
            valid.replace("\"inventorySha256\":\"${codec.inventorySha256(listOf(field))}\"", "\"inventorySha256\":\"${"f".repeat(64)}\""),
            valid.replace(",\"retiredLegacyFieldAssignmentCount\":0", ""),
            valid.replace("\"access\":0", "\"access\":0.5"),
            valid.replace("\"retiredLegacyFieldAssignmentCount\":0", "\"retiredLegacyFieldAssignmentCount\":0.5"),
        ).forEach { corrupted ->
            assertFailsWith<IllegalArgumentException> { codec.decode(corrupted) }
        }

        val duplicated = valid.replace("\"fields\":[", "\"fields\":[{" +
            "\"modulePath\":\":app\",\"owner\":\"com/example/Profile\",\"name\":\"id\"," +
            "\"descriptor\":\"J\",\"access\":0},")
        assertFailsWith<IllegalArgumentException> { codec.decode(duplicated) }
    }

    @Test
    fun `manifest rejects malformed descriptors and disallowed flags`() {
        val codec = PotentialBeanFieldManifestCodec()
        listOf(
            beanField(":app", "com/example/Profile", "id", "Jpayload", 0),
            beanField(":app", "com/example/Profile", "id", "J", Opcodes.ACC_STATIC),
            beanField(":app", "com/example/Profile", "id", "J", Opcodes.ACC_TRANSIENT),
            beanField(":app", "com/example/Profile", "id", "J", Opcodes.ACC_SYNTHETIC),
        ).forEach { field ->
            assertFailsWith<IllegalArgumentException> {
                manifest(listOf(field), codec.inventorySha256(listOf(field)))
            }
        }
        assertEquals(
            ":feature:checkout",
            PotentialBeanField(
                ":feature:checkout",
                CodeSymbolKey(CodeSymbolKind.FIELD, "third/Dependency", "id", "J"),
                0,
            ).modulePath,
        )
    }

    private fun manifest(
        fields: Collection<PotentialBeanField>,
        inventorySha256: String,
    ) = PotentialBeanFieldManifest(
        1,
        POTENTIAL_BEAN_FIELD_POLICY_VERSION,
        "demoDebug",
        3,
        "a".repeat(64),
        inventorySha256,
        setOf(":app", ":core", ":compress", ":selector", ":ucrop"),
        fields,
        0,
    )

    private fun beanField(module: String, owner: String, name: String, descriptor: String, access: Int) =
        PotentialBeanField(module, CodeSymbolKey(CodeSymbolKind.FIELD, owner, name, descriptor), access)
}
