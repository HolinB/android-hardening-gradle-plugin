package com.holin.android.hardening.code

import java.nio.file.Path
import kotlin.test.Test
import kotlin.test.assertEquals
import org.objectweb.asm.Opcodes

class PotentialBeanFieldPolicyTest {
    @Test
    fun `policy protects every ordinary owned instance field and only those fields`() {
        val owner = "com/example/Profile"
        val ordinary = field(owner, "id", "J", Opcodes.ACC_PRIVATE)
        val finalField = field(owner, "displayName", "Ljava/lang/String;", Opcodes.ACC_FINAL)
        val staticField = field(owner, "CREATOR", "Ljava/lang/Object;", Opcodes.ACC_STATIC)
        val transientField = field(owner, "scratch", "I", Opcodes.ACC_TRANSIENT)
        val syntheticField = field(owner, "this${'$'}0", "Lcom/example/Outer;", Opcodes.ACC_SYNTHETIC)
        val bytecode = inventory(
            listOf(type(owner, modulePath = ":app", fields = listOf(
                ordinary, finalField, staticField, transientField, syntheticField,
            ))),
            listOf(type("third/Dependency", owned = false, fields = listOf(
                field("third/Dependency", "token", "Ljava/lang/String;", 0),
            ))),
        )

        val fields = PotentialBeanFieldPolicy().inventory(bytecode)

        assertEquals(setOf(fieldKey(ordinary), fieldKey(finalField)), fields.mapTo(linkedSetOf()) { it.key })
        assertEquals(setOf(":app"), fields.mapTo(linkedSetOf()) { it.modulePath })
    }

    @Test
    fun `policy inventories ordinary fields from every owned module`() {
        val portableModules = setOf(":mobile", ":core", ":media")
        val owned = portableModules.sorted().mapIndexed { index, modulePath ->
            val owner = "com/example/Owned$index"
            type(owner, modulePath = modulePath, fields = listOf(field(owner, "id", "J", 0)))
        }

        val fields = PotentialBeanFieldPolicy().inventory(inventory(owned, emptyList()))

        assertEquals(portableModules, fields.mapTo(linkedSetOf()) { it.modulePath })
        assertEquals(owned.map { fieldKey(it.fields.single()) }.toSet(), fields.mapTo(linkedSetOf()) { it.key })
    }

    @Test
    fun `policy keeps same field name in different owners as separate entries`() {
        val firstOwner = "com/example/FirstProfile"
        val secondOwner = "com/example/SecondProfile"
        val first = field(firstOwner, "id", "J", 0)
        val second = field(secondOwner, "id", "J", 0)

        val fields = PotentialBeanFieldPolicy().inventory(
            inventory(
                listOf(
                    type(firstOwner, modulePath = ":app", fields = listOf(first)),
                    type(secondOwner, modulePath = ":core", fields = listOf(second)),
                ),
                emptyList(),
            ),
        )

        assertEquals(setOf(fieldKey(first), fieldKey(second)), fields.mapTo(linkedSetOf()) { it.key })
    }

    private fun inventory(owned: List<BytecodeClass>, external: List<BytecodeClass>): BytecodeInventory {
        val all = (owned + external).associateBy(BytecodeClass::internalName)
        return BytecodeInventory(owned.associateBy(BytecodeClass::internalName), all)
    }

    private fun type(
        name: String,
        modulePath: String? = ":app",
        owned: Boolean = true,
        fields: List<BytecodeField> = emptyList(),
    ) = BytecodeClass(
        name,
        if (owned) modulePath else null,
        "Profile.kt",
        if (owned) Path.of("/repo/app/src/main/java/com/example/Profile.kt") else null,
        Opcodes.ACC_PUBLIC,
        "java/lang/Object",
        emptyList(),
        emptySet(),
        fields,
        emptyList(),
    )

    private fun field(owner: String, name: String, descriptor: String, access: Int) =
        BytecodeField(owner, name, descriptor, access, emptySet())
}
