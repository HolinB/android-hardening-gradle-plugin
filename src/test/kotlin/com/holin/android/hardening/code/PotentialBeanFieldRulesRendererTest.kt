package com.holin.android.hardening.code

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import org.objectweb.asm.Opcodes

class PotentialBeanFieldRulesRendererTest {
    @Test
    fun `renderer emits sorted exact owner field and descriptor rules`() {
        val order = field(":app", "com/example/Order", "id", "J", Opcodes.ACC_PRIVATE)
        val status = field(":app", "com/example/Order", "status", "Ljava/lang/String;", Opcodes.ACC_FINAL)
        val profile = field(":core", "com/example/Profile", "id", "J", 0)

        val rules = PotentialBeanFieldRulesRenderer().render(
            listOf(profile, status, order),
            setOf("com/example/Profile", "com/example/Order"),
        )

        assertEquals(
            """
            -keepattributes RuntimeVisibleAnnotations,RuntimeInvisibleAnnotations,AnnotationDefault
            -keep,allowoptimization,allowobfuscation class com.example.Order
            -keepclassmembers class com.example.Order {
                long id;
                java.lang.String status;
            }
            -keep,allowoptimization,allowobfuscation class com.example.Profile
            -keepclassmembers class com.example.Profile {
                long id;
            }

            """.trimIndent(),
            rules,
        )
        assertFalse(rules.contains('*'))
        assertFalse(rules.contains("**"))
        assertFalse(rules.contains("allowshrinking"))
        assertEquals(2, rules.lineSequence().count { line ->
            line.startsWith("-keep,allowoptimization,allowobfuscation class ")
        })
    }

    @Test
    fun `renderer rejects dependency owners duplicate keys and disallowed field flags`() {
        val owned = field(":app", "com/example/Profile", "id", "J", 0)
        val dependency = field(":app", "third/Dependency", "token", "Ljava/lang/String;", 0)

        assertFailsWith<IllegalArgumentException> {
            PotentialBeanFieldRulesRenderer().render(listOf(dependency), setOf("com/example/Profile"))
        }
        assertFailsWith<IllegalArgumentException> {
            PotentialBeanFieldRulesRenderer().render(listOf(owned, owned), setOf("com/example/Profile"))
        }
        assertFailsWith<IllegalArgumentException> {
            PotentialBeanFieldRulesRenderer().render(
                listOf(field(":app", "com/example/Profile", "cache", "I", Opcodes.ACC_TRANSIENT)),
                setOf("com/example/Profile"),
            )
        }
    }

    private fun field(module: String, owner: String, name: String, descriptor: String, access: Int) =
        PotentialBeanField(module, CodeSymbolKey(CodeSymbolKind.FIELD, owner, name, descriptor), access)
}
