package com.holin.android.hardening.code

import kotlin.test.Test
import kotlin.test.assertEquals
import org.objectweb.asm.Opcodes

class R8HierarchyKeepContractAnalyzerTest {
    @Test
    fun `allowobfuscation and unmatched access do not create class exclusions`() {
        val publicOwner = type(
            "com/example/PublicOwner",
            ":app",
            "external/Base",
            Opcodes.ACC_PUBLIC,
        )
        val packageOwner = type(
            "com/example/PackageOwner",
            ":app",
            "external/Base",
            0,
        )
        val externalBase = type("external/Base", null, "java/lang/Object", Opcodes.ACC_PUBLIC)
        val inventory = BytecodeInventory(
            listOf(publicOwner, packageOwner).associateBy(BytecodeClass::internalName),
            listOf(publicOwner, packageOwner, externalBase).associateBy(BytecodeClass::internalName),
        )

        val exclusions = R8HierarchyKeepContractAnalyzer().exclusions(
            inventory,
            """
            -keep,allowobfuscation public class * extends external.Base
            -keep private class * extends external.Base
            """.trimIndent(),
        )

        assertEquals(emptyList(), exclusions)
    }

    @Test
    fun `interface extends keep names contract follows transitive interface ancestry`() {
        val externalContract = type(
            "external/Contract",
            null,
            null,
            Opcodes.ACC_PUBLIC or Opcodes.ACC_INTERFACE or Opcodes.ACC_ABSTRACT,
        )
        val ownedParent = type(
            "com/example/Parent",
            ":app",
            null,
            Opcodes.ACC_PUBLIC or Opcodes.ACC_INTERFACE or Opcodes.ACC_ABSTRACT,
            listOf(externalContract.internalName),
        )
        val ownedChild = type(
            "com/example/Child",
            ":app",
            null,
            Opcodes.ACC_PUBLIC or Opcodes.ACC_INTERFACE or Opcodes.ACC_ABSTRACT,
            listOf(ownedParent.internalName),
        )
        val inventory = BytecodeInventory(
            listOf(ownedParent, ownedChild).associateBy(BytecodeClass::internalName),
            listOf(externalContract, ownedParent, ownedChild).associateBy(BytecodeClass::internalName),
        )

        val exclusions = R8HierarchyKeepContractAnalyzer().exclusions(
            inventory,
            "-keepnames public interface * extends external.Contract\n",
        )

        assertEquals(
            setOf(classKey(ownedParent), classKey(ownedChild)),
            exclusions.mapTo(linkedSetOf(), CodeExclusion::key),
        )
    }

    @Test
    fun `class extends contract also matches an implemented nested interface`() {
        val listener = type(
            "com/chad/library/adapter4/BaseMultiItemAdapter${'$'}OnMultiItemAdapterListener",
            null,
            "java/lang/Object",
            Opcodes.ACC_PUBLIC or Opcodes.ACC_INTERFACE or Opcodes.ACC_ABSTRACT,
        )
        val anonymousListener = type(
            "com/example/OwnedAdapter${'$'}1",
            ":app",
            "java/lang/Object",
            Opcodes.ACC_PUBLIC or Opcodes.ACC_FINAL,
            listOf(listener.internalName),
        )
        val inventory = BytecodeInventory(
            mapOf(anonymousListener.internalName to anonymousListener),
            listOf(listener, anonymousListener).associateBy(BytecodeClass::internalName),
        )

        val exclusions = R8HierarchyKeepContractAnalyzer().exclusions(
            inventory,
            "-keep public class * extends com.chad.library.adapter4.*\n",
        )

        assertEquals(listOf(classKey(anonymousListener)), exclusions.map(CodeExclusion::key))
    }

    private fun type(
        internalName: String,
        modulePath: String?,
        superName: String?,
        access: Int,
        interfaces: List<String> = emptyList(),
    ) = BytecodeClass(
        internalName,
        modulePath,
        null,
        null,
        access,
        superName,
        interfaces,
        emptySet(),
        emptyList(),
        emptyList(),
    )
}
