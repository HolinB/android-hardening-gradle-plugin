package com.holin.android.hardening.dex

import com.android.tools.smali.dexlib2.AccessFlags
import com.android.tools.smali.dexlib2.Opcodes
import com.android.tools.smali.dexlib2.Opcode
import com.android.tools.smali.dexlib2.dexbacked.DexBackedDexFile
import com.android.tools.smali.dexlib2.immutable.ImmutableClassDef
import com.android.tools.smali.dexlib2.immutable.ImmutableMethod
import com.android.tools.smali.dexlib2.immutable.ImmutableMethodImplementation
import com.android.tools.smali.dexlib2.immutable.instruction.ImmutableInstruction10x
import com.android.tools.smali.dexlib2.immutable.instruction.ImmutableInstruction35c
import com.android.tools.smali.dexlib2.immutable.reference.ImmutableMethodReference
import com.android.tools.smali.dexlib2.writer.io.MemoryDataStore
import com.android.tools.smali.dexlib2.writer.pool.DexPool
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class DexClassAccessCompatibilityTest {
    @Test
    fun `classifies only invoke opcodes as method calls`() {
        assertTrue(DexClassAccessCompatibility.isInvokeInstruction(Opcode.INVOKE_STATIC))
        assertTrue(DexClassAccessCompatibility.isInvokeInstruction(Opcode.INVOKE_STATIC_RANGE))
        assertTrue(DexClassAccessCompatibility.isInvokeInstruction(Opcode.INVOKE_POLYMORPHIC))
        assertTrue(DexClassAccessCompatibility.isInvokeInstruction(Opcode.INVOKE_CUSTOM_RANGE))
        assertFalse(DexClassAccessCompatibility.isInvokeInstruction(Opcode.CONST_METHOD_HANDLE))
        assertFalse(DexClassAccessCompatibility.isInvokeInstruction(Opcode.RETURN_VOID))
    }

    @Test
    fun `transformer publicizes a planned compatibility owner outside diversification ownership`() {
        val target = classDef(
            TARGET,
            AccessFlags.FINAL.value,
            listOf(
                method(
                    TARGET,
                    "work",
                    AccessFlags.PRIVATE.value or AccessFlags.STATIC.value,
                    listOf(ImmutableInstruction10x(Opcode.RETURN_VOID)),
                ),
            ),
        )
        val caller = callingClass(CALLER, TARGET, "work")

        val result = SafeDexTransformer().transform(
            dex(caller, target),
            DexTransformRequest(
                ownedDescriptorPrefixes = emptySet(),
                ownedDescriptors = setOf(CALLER),
                salt = "access-compatibility".encodeToByteArray(),
                enforceMaximumGrowth = false,
                selectionRate = 0.0,
                publicClassDescriptors = setOf(TARGET),
            ),
        )

        val outputClass = DexBackedDexFile.fromInputStream(null, result.dexBytes.inputStream()).classes
            .single { it.type == TARGET }
        assertTrue(AccessFlags.PUBLIC.isSet(outputClass.accessFlags))
        assertEquals(setOf(TARGET), result.report.publicizedClassDescriptors)
        assertEquals(1, result.report.ownedMethodCount)
    }

    @Test
    fun `finds an owned package-private bridge owner referenced from another package across dex files`() {
        val target = classDef(
            TARGET,
            AccessFlags.FINAL.value,
            listOf(
                method(
                    TARGET,
                    "bridge",
                    AccessFlags.PUBLIC.value or AccessFlags.STATIC.value or AccessFlags.SYNTHETIC.value,
                    listOf(ImmutableInstruction10x(Opcode.RETURN_VOID)),
                ),
            ),
        )
        val caller = classDef(
            CALLER,
            AccessFlags.PUBLIC.value or AccessFlags.FINAL.value,
            listOf(
                method(
                    CALLER,
                    "run",
                    AccessFlags.PUBLIC.value or AccessFlags.STATIC.value,
                    listOf(
                        ImmutableInstruction35c(
                            Opcode.INVOKE_STATIC,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            ImmutableMethodReference(TARGET, "bridge", emptyList<String>(), "V"),
                        ),
                        ImmutableInstruction10x(Opcode.RETURN_VOID),
                    ),
                ),
            ),
        )

        val result = DexClassAccessCompatibility.requiredPublicClassDescriptors(
            listOf(dex(caller), dex(target)),
            setOf(TARGET),
        )

        assertEquals(setOf(TARGET), result)
    }

    @Test
    fun `ignores same-package calls public owners ordinary methods and unowned targets`() {
        val packagePrivateTarget = classDef(
            TARGET,
            AccessFlags.FINAL.value,
            listOf(
                method(
                    TARGET,
                    "ordinary",
                    AccessFlags.PUBLIC.value or AccessFlags.STATIC.value,
                    listOf(ImmutableInstruction10x(Opcode.RETURN_VOID)),
                ),
            ),
        )
        val publicTarget = classDef(
            PUBLIC_TARGET,
            AccessFlags.PUBLIC.value or AccessFlags.FINAL.value,
            listOf(
                method(
                    PUBLIC_TARGET,
                    "bridge",
                    AccessFlags.PUBLIC.value or AccessFlags.STATIC.value or AccessFlags.SYNTHETIC.value,
                    listOf(ImmutableInstruction10x(Opcode.RETURN_VOID)),
                ),
            ),
        )
        val samePackageCaller = callingClass("Lrenamed/Caller;", TARGET, "ordinary")
        val externalCaller = callingClass(CALLER, PUBLIC_TARGET, "bridge")

        assertEquals(
            emptySet(),
            DexClassAccessCompatibility.requiredPublicClassDescriptors(
                listOf(dex(packagePrivateTarget, publicTarget, samePackageCaller, externalCaller)),
                setOf(PUBLIC_TARGET),
            ),
        )
    }

    private fun callingClass(type: String, target: String, methodName: String): ImmutableClassDef = classDef(
        type,
        AccessFlags.PUBLIC.value or AccessFlags.FINAL.value,
        listOf(
            method(
                type,
                "run",
                AccessFlags.PUBLIC.value or AccessFlags.STATIC.value,
                listOf(
                    ImmutableInstruction35c(
                        Opcode.INVOKE_STATIC,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        ImmutableMethodReference(target, methodName, emptyList<String>(), "V"),
                    ),
                    ImmutableInstruction10x(Opcode.RETURN_VOID),
                ),
            ),
        ),
    )

    private fun method(
        owner: String,
        name: String,
        accessFlags: Int,
        instructions: List<com.android.tools.smali.dexlib2.iface.instruction.Instruction>,
    ): ImmutableMethod = ImmutableMethod(
        owner,
        name,
        emptyList(),
        "V",
        accessFlags,
        emptySet(),
        emptySet(),
        ImmutableMethodImplementation(0, instructions, emptyList(), emptyList()),
    )

    private fun classDef(type: String, accessFlags: Int, methods: List<ImmutableMethod>): ImmutableClassDef =
        ImmutableClassDef(
            type,
            accessFlags,
            "Ljava/lang/Object;",
            emptyList(),
            null,
            emptySet(),
            emptyList(),
            methods,
        )

    private fun dex(vararg classes: ImmutableClassDef): ByteArray {
        val pool = DexPool(Opcodes.getDefault())
        classes.forEach(pool::internClass)
        val store = MemoryDataStore()
        pool.writeTo(store)
        return store.data.copyOf(store.size)
    }

    private companion object {
        const val TARGET = "Lrenamed/ContinuationAlias;"
        const val PUBLIC_TARGET = "Lrenamed/PublicContinuation;"
        const val CALLER = "Lfixture/a;"
    }
}
