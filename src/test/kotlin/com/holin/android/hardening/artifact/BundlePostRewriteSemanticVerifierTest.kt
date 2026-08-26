package com.holin.android.hardening.artifact

import com.android.aapt.Resources
import com.android.tools.smali.dexlib2.AccessFlags
import com.android.tools.smali.dexlib2.Opcode
import com.android.tools.smali.dexlib2.Opcodes
import com.android.tools.smali.dexlib2.dexbacked.DexBackedDexFile
import com.android.tools.smali.dexlib2.iface.instruction.Instruction
import com.android.tools.smali.dexlib2.iface.instruction.OneRegisterInstruction
import com.android.tools.smali.dexlib2.immutable.ImmutableClassDef
import com.android.tools.smali.dexlib2.immutable.ImmutableDexFile
import com.android.tools.smali.dexlib2.immutable.ImmutableExceptionHandler
import com.android.tools.smali.dexlib2.immutable.ImmutableMethod
import com.android.tools.smali.dexlib2.immutable.ImmutableMethodImplementation
import com.android.tools.smali.dexlib2.immutable.ImmutableMethodParameter
import com.android.tools.smali.dexlib2.immutable.ImmutableTryBlock
import com.android.tools.smali.dexlib2.immutable.debug.ImmutableLineNumber
import com.android.tools.smali.dexlib2.immutable.instruction.ImmutableInstruction10x
import com.android.tools.smali.dexlib2.immutable.instruction.ImmutableInstruction10t
import com.android.tools.smali.dexlib2.immutable.instruction.ImmutableInstruction11x
import com.android.tools.smali.dexlib2.immutable.instruction.ImmutableInstruction11n
import com.android.tools.smali.dexlib2.immutable.instruction.ImmutableInstruction12x
import com.android.tools.smali.dexlib2.immutable.instruction.ImmutableInstruction20t
import com.android.tools.smali.dexlib2.immutable.instruction.ImmutableInstruction21c
import com.android.tools.smali.dexlib2.immutable.instruction.ImmutableInstruction21t
import com.android.tools.smali.dexlib2.immutable.instruction.ImmutableInstruction30t
import com.android.tools.smali.dexlib2.immutable.instruction.ImmutableInstruction23x
import com.android.tools.smali.dexlib2.immutable.instruction.ImmutableInstruction31t
import com.android.tools.smali.dexlib2.immutable.instruction.ImmutableInstruction31c
import com.android.tools.smali.dexlib2.immutable.instruction.ImmutablePackedSwitchPayload
import com.android.tools.smali.dexlib2.immutable.instruction.ImmutableSparseSwitchPayload
import com.android.tools.smali.dexlib2.immutable.instruction.ImmutableSwitchElement
import com.android.tools.smali.dexlib2.immutable.reference.ImmutableStringReference
import com.android.tools.smali.dexlib2.immutable.value.ImmutableBooleanEncodedValue
import com.android.tools.smali.dexlib2.immutable.value.ImmutableIntEncodedValue
import com.android.tools.smali.dexlib2.writer.io.MemoryDataStore
import com.android.tools.smali.dexlib2.writer.pool.DexPool
import com.holin.android.hardening.dex.DexTransformRequest
import com.holin.android.hardening.dex.MethodEligibilityReason
import com.holin.android.hardening.dex.NopWeaveResult
import com.holin.android.hardening.dex.NormalizedOpcodeSimHash
import com.holin.android.hardening.dex.SafeDexTransformer
import com.holin.android.hardening.dex.SafeUnreachablePayloadContract
import com.holin.android.hardening.dex.SafeNopWeaver
import com.holin.android.hardening.resources.ImageIneligibilityReason
import com.holin.android.hardening.resources.ImageTransformStatus
import com.holin.android.hardening.resources.ProtoResourceDiversifier
import com.holin.android.hardening.resources.ResourceType
import com.holin.android.hardening.state.Sha256
import java.awt.image.BufferedImage
import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.file.Files
import java.nio.file.Path
import java.security.MessageDigest
import java.util.zip.Adler32
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream
import javax.imageio.ImageIO
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.test.assertTrue
import org.junit.jupiter.api.io.TempDir

class BundlePostRewriteSemanticVerifierTest {
    @TempDir
    lateinit var temporary: Path

    @Test
    fun `static encoded defaults are equivalent to omitted DEX initial values`() {
        val static = AccessFlags.STATIC.value

        assertTrue(
            equivalentDexFieldInitialValue(
                "Z",
                static,
                ImmutableBooleanEncodedValue.FALSE_VALUE,
                null,
            ),
        )
        assertTrue(
            equivalentDexFieldInitialValue(
                "I",
                static,
                ImmutableIntEncodedValue(0),
                null,
            ),
        )
        assertTrue(
            !equivalentDexFieldInitialValue(
                "Z",
                static,
                ImmutableBooleanEncodedValue.TRUE_VALUE,
                null,
            ),
        )
        assertTrue(
            !equivalentDexFieldInitialValue(
                "I",
                0,
                ImmutableIntEncodedValue(0),
                null,
            ),
        )
    }

    @Test
    fun `independent verifier accepts safe NOP weaving and rejects non NOP opcode tampering`() {
        val originalDex = dex(Opcode.ADD_INT, includeNop = false)
        val transformation = SafeDexTransformer().transform(
            originalDex,
            DexTransformRequest(
                ownedDescriptorPrefixes = emptySet(),
                ownedDescriptors = setOf(OWNED_CLASS),
                salt = "post-rewrite-test".encodeToByteArray(),
                minimumCoverage = 0.0,
                minimumSimHashDistance = 4,
                maximumGrowthRatio = 1.0,
                selectionRate = 1.0,
            ),
        )
        val transformedDex = transformation.dexBytes
        val ordinary = zip("ordinary.aab", DEX_PATH to originalDex)
        val rewritten = zip("rewritten.aab", DEX_PATH to transformedDex)
        val manifest = manifest(
            ordinary,
            DEX_PATH,
            originalDex,
            DEX_PATH,
            transformedDex,
            BundleSemanticVerifier.DEX_SEMANTICS,
            "post-rewrite-test".encodeToByteArray(),
        )
        val plan = plan(
            Sha256.file(ordinary),
            originalDex,
            transformedDex,
            dexMethod = transformation.report.methods.single().toPlannedDexMethod(),
            contentSalt = "post-rewrite-test".encodeToByteArray(),
        )

        assertEquals(
            1,
            BundlePostRewriteSemanticVerifier().verify(
                ordinary,
                rewritten,
                manifest,
                plan,
                "post-rewrite-test".encodeToByteArray(),
            ).size,
        )

        val tamperedDex = dex(Opcode.SUB_INT, includeNop = true)
        val tampered = zip("tampered.aab", DEX_PATH to tamperedDex)
        val tamperedManifest = manifest(
            ordinary,
            DEX_PATH,
            originalDex,
            DEX_PATH,
            tamperedDex,
            BundleSemanticVerifier.DEX_SEMANTICS,
        )
        val tamperedPlan = plan(Sha256.file(ordinary), originalDex, tamperedDex)
        assertFailsWith<IllegalArgumentException> {
            BundlePostRewriteSemanticVerifier().verify(ordinary, tampered, tamperedManifest, tamperedPlan)
        }
    }

    @Test
    fun `independent verifier accepts exact authorized diverse entry payload`() {
        val originalDex = dex(Opcode.ADD_INT, includeNop = false)
        val diversePayload = safeDiversePayload()
        val candidateDex = sumCandidateDex(diversePayload)

        assertEquals(1, verifySumCandidate("diverse-payload", originalDex, candidateDex).size)
    }

    @Test
    fun `independent verifier rejects a raw content salt that does not match the plan`() {
        val originalDex = dex(Opcode.ADD_INT, includeNop = false)
        val candidateDex = sumCandidateDex(safeDiversePayload())

        val failure = assertFailsWith<IllegalArgumentException> {
            verifySumCandidate(
                "wrong-raw-content-salt",
                originalDex,
                candidateDex,
                contentSalt = "wrong-raw-content-salt".encodeToByteArray(),
            )
        }

        assertEquals(CONTENT_SALT_PLAN_FAILURE, failure.message)
    }

    @Test
    fun `independent verifier rejects plan and manifest content salt hash mismatch`() {
        val originalDex = dex(Opcode.ADD_INT, includeNop = false)
        val candidateDex = sumCandidateDex(safeDiversePayload())

        val failure = assertFailsWith<IllegalArgumentException> {
            verifySumCandidate(
                "plan-manifest-content-salt-mismatch",
                originalDex,
                candidateDex,
                manifestContentSalt = "different-manifest-content-salt".encodeToByteArray(),
            )
        }

        assertEquals(CONTENT_SALT_AGREEMENT_FAILURE, failure.message)
    }

    @Test
    fun `independent verifier rejects forbidden opcode and wrong registers in authorized payload`() {
        val originalDex = dex(Opcode.ADD_INT, includeNop = false)
        val forbidden = safeDiversePayload().toMutableList().apply {
            this[6] = ImmutableInstruction12x(Opcode.DIV_INT_2ADDR, 0, 0)
        }
        val wrongRegister = safeDiversePayload().toMutableList().apply {
            this[1] = ImmutableInstruction12x(Opcode.MOVE, 1, 0)
        }

        listOf("forbidden-opcode" to forbidden, "wrong-register" to wrongRegister).forEach { (name, payload) ->
            assertFailsWith<IllegalArgumentException>(name) {
                verifySumCandidate(name, originalDex, sumCandidateDex(payload))
            }
        }
    }

    @Test
    fun `independent verifier rejects safe arithmetic in an unreported entry detour`() {
        val originalDex = dex(Opcode.ADD_INT, includeNop = false)
        val candidateDex = sumCandidateDex(safeDiversePayload())

        assertFailsWith<IllegalArgumentException> {
            verifySumCandidate("unreported-safe-payload", originalDex, candidateDex, authorized = false)
        }
    }

    @Test
    fun `independent verifier rejects safe arithmetic in live code after the entry target`() {
        val originalDex = dex(Opcode.ADD_INT, includeNop = false)
        val candidateDex = sumCandidateDex(
            payload = safeDiversePayload(),
            livePrefix = listOf(ImmutableInstruction12x(Opcode.NEG_INT, 0, 0)),
        )

        assertFailsWith<IllegalArgumentException> {
            verifySumCandidate("live-safe-arithmetic", originalDex, candidateDex)
        }
    }

    @Test
    fun `independent verifier accepts exact planned opaque diamond`() {
        assertEquals(
            1,
            verifyOpaqueDiamondCandidate(
                name = "opaqueAccepted",
                candidateInstructions = opaqueDiamondInstructions(receiverRegister = 1),
                plannedDiamondCount = 1,
            ).size,
        )
    }

    @Test
    fun `independent verifier accepts exact marker bearing opaque payload`() {
        assertEquals(
            1,
            verifyOpaqueDiamondCandidate(
                name = "opaqueMarkersAccepted",
                candidateInstructions = opaqueMarkerDiamondInstructions(receiverRegister = 1),
                plannedDiamondCount = 1,
            ).size,
        )
    }

    @Test
    fun `independent verifier rejects marker set derived for another method`() {
        val name = "opaqueMarkerMethodSwap"
        val otherMethodId = "$OWNED_CLASS->otherMarkerMethod()V"
        val swappedPayload = opaqueMarkerPayload(
            SafeUnreachablePayloadContract.markerValues(VERIFIER_CONTENT_SALT, otherMethodId),
        )

        val failure = assertFailsWith<IllegalArgumentException> {
            verifyOpaqueDiamondCandidate(
                name = name,
                candidateInstructions = opaqueMarkerDiamondInstructions(receiverRegister = 1, payload = swappedPayload),
                plannedDiamondCount = 1,
                bindMarkerValues = false,
            )
        }
        assertTrue(failure.message.orEmpty().contains(EXACT_MARKER_FAILURE), failure.message)
    }

    @Test
    fun `independent verifier rejects well formed substituted marker values`() {
        val name = "opaqueMarkerSubstitution"
        val methodId = "$OWNED_CLASS->$name()V"
        val substituted = SafeUnreachablePayloadContract.markerValues(VERIFIER_CONTENT_SALT, methodId).map { value ->
            if (value.isEmpty()) value else value.dropLast(1) + if (value.last() == '0') '1' else '0'
        }

        val failure = assertFailsWith<IllegalArgumentException> {
            verifyOpaqueDiamondCandidate(
                name = name,
                candidateInstructions = opaqueMarkerDiamondInstructions(
                    receiverRegister = 1,
                    payload = opaqueMarkerPayload(substituted),
                ),
                plannedDiamondCount = 1,
                bindMarkerValues = false,
            )
        }
        assertTrue(failure.message.orEmpty().contains(EXACT_MARKER_FAILURE), failure.message)
    }

    @Test
    fun `independent verifier rejects malformed marker payload mutations`() {
        val valid = opaqueMarkerPayload()
        val mutations = listOf(
            "missing" to valid.filterIndexed { index, _ -> index != 1 },
            "duplicate" to valid.toMutableList().apply { this[3] = this[2] },
            "wrongCategory" to valid.toMutableList().apply {
                this[3] = ImmutableInstruction31c(
                    Opcode.CONST_STRING_JUMBO,
                    0,
                    ImmutableStringReference("SLH1M:" + "a".repeat(2)),
                )
            },
            "wrongRegister" to valid.toMutableList().apply {
                this[3] = ImmutableInstruction31c(
                    Opcode.CONST_STRING_JUMBO,
                    1,
                    ImmutableStringReference("SLH1M:" + "a".repeat(3)),
                )
            },
            "nonJumbo" to valid.toMutableList().apply {
                this[3] = ImmutableInstruction21c(
                    Opcode.CONST_STRING,
                    0,
                    ImmutableStringReference("SLH1M:" + "a".repeat(3)),
                )
            },
            "arbitrary" to valid + ImmutableInstruction31c(
                Opcode.CONST_STRING_JUMBO,
                0,
                ImmutableStringReference("arbitrary"),
            ),
        )

        mutations.forEach { (name, payload) ->
            val failure = assertFailsWith<IllegalArgumentException>(name) {
                verifyOpaqueDiamondCandidate(
                    name = "markerMutation$name",
                    candidateInstructions = opaqueMarkerDiamondInstructions(receiverRegister = 1, payload = payload),
                    plannedDiamondCount = 1,
                    bindMarkerValues = false,
                )
            }
            assertTrue(failure.message.orEmpty().contains("malformed dead payload"), "$name: ${failure.message}")
        }
    }

    @Test
    fun `independent verifier rejects marker instruction on live path`() {
        val originalDex = dex(Opcode.ADD_INT, includeNop = false)
        val candidateDex = sumCandidateDex(
            payload = safeDiversePayload(),
            livePrefix = listOf(
                ImmutableInstruction31c(
                    Opcode.CONST_STRING_JUMBO,
                    0,
                    ImmutableStringReference("SLH1Sabc"),
                ),
            ),
        )

        assertFailsWith<IllegalArgumentException> {
            verifySumCandidate("live-string-marker", originalDex, candidateDex)
        }
    }

    @Test
    fun `independent verifier accepts production opaque diamond output and persisted count`() {
        val name = "opaqueProducer"
        val originalDex = methodDex(
            name,
            opaqueOriginalInstructions(),
            registerCount = 2,
            parameterTypes = emptyList(),
            returnType = "V",
            accessFlags = AccessFlags.PRIVATE.value,
        )
        val transformation = SafeDexTransformer().transform(
            originalDex,
            DexTransformRequest(
                ownedDescriptorPrefixes = emptySet(),
                ownedDescriptors = setOf(OWNED_CLASS),
                salt = "opaque-producer-verifier".encodeToByteArray(),
                minimumCoverage = 0.0,
                minimumSimHashDistance = 0,
                maximumGrowthRatio = 0.0,
                enforceMaximumGrowth = false,
                selectionRate = 1.0,
            ),
        )
        val methodReport = transformation.report.methods.single()
        val ordinary = zip("$name-ordinary.aab", DEX_PATH to originalDex)
        val rewritten = zip("$name-rewritten.aab", DEX_PATH to transformation.dexBytes)
        val manifest = manifest(
            ordinary,
            DEX_PATH,
            originalDex,
            DEX_PATH,
            transformation.dexBytes,
            BundleSemanticVerifier.DEX_SEMANTICS,
            "opaque-producer-verifier".encodeToByteArray(),
        )
        val semanticPlan = plan(
            Sha256.file(ordinary),
            originalDex,
            transformation.dexBytes,
            dexMethod = methodReport.toPlannedDexMethod(),
            minimumSimHashDistance = 0,
            contentSalt = "opaque-producer-verifier".encodeToByteArray(),
        )

        assertEquals(1, methodReport.insertedOpaqueDiamondCount)
        assertEquals(0, methodReport.insertedRelayInstructionCount)
        assertEquals(1, semanticPlan.dex.entries.single().transformedMethods.single().opaqueDiamondCount)
        assertEquals(
            1,
            BundlePostRewriteSemanticVerifier().verify(
                ordinary,
                rewritten,
                manifest,
                semanticPlan,
                "opaque-producer-verifier".encodeToByteArray(),
            ).size,
        )
    }

    @Test
    fun `independent verifier rejects malformed or mismatched opaque diamonds`() {
        val valid = opaqueDiamondInstructions(receiverRegister = 1)
        val cases = listOf(
            Triple("wrongReceiver", "wrong conditional or receiver", valid.toMutableList().apply {
                this[0] = ImmutableInstruction21t(Opcode.IF_EQZ, 0, 5)
            }),
            Triple("oneSidedContinuation", "one-sided or invalid continuation", valid.toMutableList().apply {
                this[2] = ImmutableInstruction30t(Opcode.GOTO_32, 10)
            }),
            Triple("branchIntoPayload", "branch enters an opaque entry diamond protected span", valid.toMutableList().apply {
                this[lastIndex - 1] = ImmutableInstruction30t(Opcode.GOTO_32, -19)
            }),
            Triple("malformedPayload", "malformed dead payload", valid.toMutableList().apply {
                this[5] = ImmutableInstruction12x(Opcode.DIV_INT_2ADDR, 0, 0)
            }),
        )
        cases.forEach { (name, expectedMessage, instructions) ->
            val failure = assertFailsWith<IllegalArgumentException>(name) {
                verifyOpaqueDiamondCandidate(name, instructions, plannedDiamondCount = 1)
            }
            assertTrue(failure.message.orEmpty().contains(expectedMessage), "$name: ${failure.message}")
        }
        assertFailsWith<IllegalArgumentException>("countMismatch") {
            verifyOpaqueDiamondCandidate("countMismatch", valid, plannedDiamondCount = 2)
        }
        assertFailsWith<IllegalArgumentException>("unplannedIdenticalPrefix") {
            verifyOpaqueDiamondCandidate("unplannedIdenticalPrefix", valid, plannedDiamondCount = 0)
        }
    }

    @Test
    fun `independent verifier rejects two planned diamonds for a short method`() {
        assertFailsWith<IllegalArgumentException>("two planned diamonds for a short method") {
            verifyOpaqueDiamondCandidate(
                name = "twoDiamonds",
                candidateInstructions = opaqueDiamondInstructions(receiverRegister = 1, diamondCount = 2),
                plannedDiamondCount = 2,
            )
        }
    }

    @Test
    fun `independent verifier rejects GOTO fallback for a representable instance method`() {
        assertFailsWith<IllegalArgumentException>("GOTO fallback for a representable instance method") {
            verifyOpaqueDiamondCandidate(
                name = "representableFallback",
                candidateInstructions = opaqueFallbackInstructions(),
                plannedDiamondCount = 0,
            )
        }
    }

    @Test
    fun `independent verifier rejects an unowned planned method`() {
        assertFailsWith<IllegalArgumentException>("unowned method") {
            verifyOpaqueDiamondCandidate(
                name = "unowned",
                candidateInstructions = opaqueDiamondInstructions(receiverRegister = 1),
                plannedDiamondCount = 1,
                owner = "Lthird/party/Unowned;",
            )
        }
    }

    @Test
    fun `independent verifier rejects a synthetic planned method`() {
        assertFailsWith<IllegalArgumentException>("synthetic method") {
            verifyOpaqueDiamondCandidate(
                name = "synthetic",
                candidateInstructions = opaqueDiamondInstructions(receiverRegister = 1),
                plannedDiamondCount = 1,
                accessFlags = AccessFlags.PRIVATE.value or AccessFlags.SYNTHETIC.value,
            )
        }
    }

    @Test
    fun `independent verifier rejects an external-contract planned method`() {
        val externalContractMethodId = "$OWNED_CLASS->externalContract()V"
        assertFailsWith<IllegalArgumentException>(externalContractMethodId) {
            verifyOpaqueDiamondCandidate(
                name = "externalContract",
                candidateInstructions = opaqueDiamondInstructions(receiverRegister = 1),
                plannedDiamondCount = 1,
                dexScope = dexScope(externalContractMethodIds = setOf(externalContractMethodId)),
            )
        }
    }

    @Test
    fun `independent verifier rejects a backward goto into ignored entry payload`() {
        val failure = assertFailsWith<IllegalArgumentException> {
            verifyEntryPayloadInboundBranch(
                name = "payloadInboundGoto",
                originalInstructions = listOf(
                    ImmutableInstruction11n(Opcode.CONST_4, 0, 0),
                    ImmutableInstruction10t(Opcode.GOTO, -1),
                    ImmutableInstruction10x(Opcode.RETURN_VOID),
                ),
                candidateInstructions = entryPayloadInboundCandidate(conditional = false),
            )
        }

        assertTrue(failure.message.orEmpty().contains("live branch targets ignored entry payload"))
    }

    @Test
    fun `independent verifier rejects a backward conditional into ignored entry payload`() {
        val failure = assertFailsWith<IllegalArgumentException> {
            verifyEntryPayloadInboundBranch(
                name = "payloadInboundConditional",
                originalInstructions = listOf(
                    ImmutableInstruction11n(Opcode.CONST_4, 0, 0),
                    ImmutableInstruction21t(Opcode.IF_EQZ, 0, -1),
                    ImmutableInstruction10x(Opcode.RETURN_VOID),
                ),
                candidateInstructions = entryPayloadInboundCandidate(conditional = true),
            )
        }

        assertTrue(failure.message.orEmpty().contains("live branch targets ignored entry payload"))
    }

    @Test
    fun `independent verifier rejects exact reachable relay source suffix and continuation`() {
        assertFailsWith<IllegalArgumentException> {
            verifyRelayCandidate(
                name = "exactRelay",
                candidateInstructions = exactRelayCandidate(),
            )
        }
    }

    @Test
    fun `independent verifier rejects an exact relay pair in a dead block`() {
        val original = listOf(
            ImmutableInstruction10t(Opcode.GOTO, 3),
            ImmutableInstruction11n(Opcode.CONST_4, 0, 0),
            ImmutableInstruction12x(Opcode.NEG_INT, 0, 0),
            ImmutableInstruction10x(Opcode.RETURN_VOID),
        )
        val deadRelayCandidate = listOf(
            ImmutableInstruction10t(Opcode.GOTO, 6),
            ImmutableInstruction11n(Opcode.CONST_4, 0, 0),
            ImmutableInstruction30t(Opcode.GOTO_32, 6),
            ImmutableInstruction12x(Opcode.NEG_INT, 0, 0),
            ImmutableInstruction10x(Opcode.RETURN_VOID),
            ImmutableInstruction10x(Opcode.NOP),
            ImmutableInstruction30t(Opcode.GOTO_32, -3),
        )

        val failure = assertFailsWith<IllegalArgumentException> {
            verifyRelayCandidate(
                name = "deadRelaySource",
                originalInstructions = original,
                candidateInstructions = deadRelayCandidate,
            )
        }

        assertTrue(failure.message.orEmpty().contains("changed a non-NOP instruction or control-flow target"))
    }

    @Test
    fun `independent verifier rejects reachable relay sources with backward and conditional flow`() {
        val backwardOriginal = listOf(
            ImmutableInstruction11n(Opcode.CONST_4, 0, 0),
            ImmutableInstruction12x(Opcode.NEG_INT, 0, 0),
            ImmutableInstruction12x(Opcode.MOVE, 0, 0),
            ImmutableInstruction21t(Opcode.IF_NEZ, 0, -3),
            ImmutableInstruction10x(Opcode.RETURN_VOID),
        )
        val backwardCandidate = listOf(
            ImmutableInstruction11n(Opcode.CONST_4, 0, 0),
            ImmutableInstruction12x(Opcode.NEG_INT, 0, 0),
            ImmutableInstruction30t(Opcode.GOTO_32, 8),
            ImmutableInstruction12x(Opcode.MOVE, 0, 0),
            ImmutableInstruction21t(Opcode.IF_NEZ, 0, -6),
            ImmutableInstruction10x(Opcode.RETURN_VOID),
            ImmutableInstruction10x(Opcode.NOP),
            ImmutableInstruction30t(Opcode.GOTO_32, -5),
        )
        val conditionalOriginal = listOf(
            ImmutableInstruction11n(Opcode.CONST_4, 0, 0),
            ImmutableInstruction21t(Opcode.IF_EQZ, 0, 4),
            ImmutableInstruction12x(Opcode.NEG_INT, 0, 0),
            ImmutableInstruction12x(Opcode.MOVE, 0, 0),
            ImmutableInstruction10x(Opcode.RETURN_VOID),
        )
        val conditionalCandidate = listOf(
            ImmutableInstruction11n(Opcode.CONST_4, 0, 0),
            ImmutableInstruction21t(Opcode.IF_EQZ, 0, 7),
            ImmutableInstruction12x(Opcode.NEG_INT, 0, 0),
            ImmutableInstruction30t(Opcode.GOTO_32, 6),
            ImmutableInstruction12x(Opcode.MOVE, 0, 0),
            ImmutableInstruction10x(Opcode.RETURN_VOID),
            ImmutableInstruction10x(Opcode.NOP),
            ImmutableInstruction30t(Opcode.GOTO_32, -3),
        )

        assertFailsWith<IllegalArgumentException> {
            verifyRelayCandidate(
                name = "backwardReachableRelay",
                originalInstructions = backwardOriginal,
                candidateInstructions = backwardCandidate,
            )
        }
        assertFailsWith<IllegalArgumentException> {
            verifyRelayCandidate(
                name = "conditionalReachableRelay",
                originalInstructions = conditionalOriginal,
                candidateInstructions = conditionalCandidate,
            )
        }
    }

    @Test
    fun `weaver omits relays at an end debug boundary and serialized output passes independent verification`() {
        val name = "endDebugBoundary"
        val originalInstructions = relayOriginalInstructions()
        val originalCodeUnits = originalInstructions.sumOf(Instruction::getCodeUnits)
        val originalImplementation = ImmutableMethodImplementation(
            1,
            originalInstructions,
            emptyList(),
            listOf(ImmutableLineNumber(originalCodeUnits, 42)),
        )
        val candidate = assertIs<NopWeaveResult.Candidate>(
            SafeNopWeaver().weave(
                implementation = originalImplementation,
                salt = "end-debug-boundary".encodeToByteArray(),
                methodId = "$OWNED_CLASS->$name()V",
                detourPaddingNopCount = 1,
                expandConditionals = true,
            ),
        )

        assertEquals(0, candidate.insertedRelayInstructionCount)
        assertEquals(
            1,
            verifyRelayCandidate(
                name = name,
                originalInstructions = originalInstructions,
                candidateInstructions = candidate.implementation.instructions.toList(),
                contentSalt = "end-debug-boundary".encodeToByteArray(),
            ).size,
        )
    }

    @Test
    fun `production avoids relay sources after branch target NOP padding and passes independent verification`() {
        val name = "branchTargetNopPadding"
        val originalDex = relayMethodDex(
            name,
            listOf(
                ImmutableInstruction10t(Opcode.GOTO, 1),
                ImmutableInstruction10x(Opcode.NOP),
                ImmutableInstruction10x(Opcode.RETURN_VOID),
            ),
        )
        val transformation = SafeDexTransformer().transform(
            originalDex,
            DexTransformRequest(
                ownedDescriptorPrefixes = emptySet(),
                ownedDescriptors = setOf(OWNED_CLASS),
                salt = "branch-target-nop-padding".encodeToByteArray(),
                minimumCoverage = 0.0,
                minimumSimHashDistance = 0,
                maximumGrowthRatio = 0.0,
                enforceMaximumGrowth = false,
                selectionRate = 1.0,
            ),
        )

        assertEquals(0, transformation.report.methods.single().insertedRelayInstructionCount)
        assertEquals(
            1,
            verifyRelayScope(
                name = "branch-target-nop-padding",
                originalDex = originalDex,
                candidateDex = transformation.dexBytes,
                transformedMethodName = name,
                contentSalt = "branch-target-nop-padding".encodeToByteArray(),
            ).size,
        )
    }

    @Test
    fun `independent verifier rejects malformed reachable relay pairs and incoming edges`() {
        val ordinary = relayOriginalInstructions()
        val cases = linkedMapOf(
            "wrong-continuation" to exactRelayCandidate(relayOffset = -7),
            "non-goto32-source" to listOf(
                ImmutableInstruction11n(Opcode.CONST_4, 0, 0),
                ImmutableInstruction20t(Opcode.GOTO_16, 5),
                ImmutableInstruction12x(Opcode.NEG_INT, 0, 0),
                ImmutableInstruction10x(Opcode.RETURN_VOID),
                ImmutableInstruction10x(Opcode.NOP),
                ImmutableInstruction30t(Opcode.GOTO_32, -3),
            ),
            "non-goto32-relay" to listOf(
                ImmutableInstruction11n(Opcode.CONST_4, 0, 0),
                ImmutableInstruction30t(Opcode.GOTO_32, 6),
                ImmutableInstruction12x(Opcode.NEG_INT, 0, 0),
                ImmutableInstruction10x(Opcode.RETURN_VOID),
                ImmutableInstruction10x(Opcode.NOP),
                ImmutableInstruction20t(Opcode.GOTO_16, -3),
            ),
            "missing-source" to listOf(
                ImmutableInstruction11n(Opcode.CONST_4, 0, 0),
                ImmutableInstruction12x(Opcode.NEG_INT, 0, 0),
                ImmutableInstruction10x(Opcode.RETURN_VOID),
                ImmutableInstruction10x(Opcode.NOP),
                ImmutableInstruction30t(Opcode.GOTO_32, -3),
            ),
            "fallthrough-suffix" to listOf(
                ImmutableInstruction11n(Opcode.CONST_4, 0, 0),
                ImmutableInstruction30t(Opcode.GOTO_32, 5),
                ImmutableInstruction12x(Opcode.NEG_INT, 0, 0),
                ImmutableInstruction10x(Opcode.NOP),
                ImmutableInstruction30t(Opcode.GOTO_32, -2),
            ),
        )
        cases.forEach { (name, candidate) ->
            assertFailsWith<IllegalArgumentException>(name) {
                verifyRelayCandidate(name, ordinary, candidate)
            }
        }

        val fourInstructionOriginal = listOf(
            ImmutableInstruction11n(Opcode.CONST_4, 0, 0),
            ImmutableInstruction12x(Opcode.NEG_INT, 0, 0),
            ImmutableInstruction12x(Opcode.MOVE, 0, 0),
            ImmutableInstruction10x(Opcode.RETURN_VOID),
        )
        val duplicateAndChainCases = mapOf(
            "shared-relay" to listOf(
                ImmutableInstruction11n(Opcode.CONST_4, 0, 0),
                ImmutableInstruction30t(Opcode.GOTO_32, 10),
                ImmutableInstruction12x(Opcode.NEG_INT, 0, 0),
                ImmutableInstruction30t(Opcode.GOTO_32, 6),
                ImmutableInstruction12x(Opcode.MOVE, 0, 0),
                ImmutableInstruction10x(Opcode.RETURN_VOID),
                ImmutableInstruction10x(Opcode.NOP),
                ImmutableInstruction30t(Opcode.GOTO_32, -7),
            ),
            "relay-chain" to listOf(
                ImmutableInstruction11n(Opcode.CONST_4, 0, 0),
                ImmutableInstruction30t(Opcode.GOTO_32, 10),
                ImmutableInstruction12x(Opcode.NEG_INT, 0, 0),
                ImmutableInstruction30t(Opcode.GOTO_32, 9),
                ImmutableInstruction12x(Opcode.MOVE, 0, 0),
                ImmutableInstruction10x(Opcode.RETURN_VOID),
                ImmutableInstruction10x(Opcode.NOP),
                ImmutableInstruction30t(Opcode.GOTO_32, 3),
                ImmutableInstruction30t(Opcode.GOTO_32, -6),
            ),
        )
        duplicateAndChainCases.forEach { (name, candidate) ->
            assertFailsWith<IllegalArgumentException>(name) {
                verifyRelayCandidate(name, fourInstructionOriginal, candidate)
            }
        }

        val branchOriginal = listOf(
            ImmutableInstruction10t(Opcode.GOTO, 2),
            ImmutableInstruction11n(Opcode.CONST_4, 0, 0),
            ImmutableInstruction12x(Opcode.NEG_INT, 0, 0),
            ImmutableInstruction10x(Opcode.RETURN_VOID),
        )
        val incomingCases = mapOf(
            "incoming-source" to listOf(
                ImmutableInstruction10t(Opcode.GOTO, 2),
                ImmutableInstruction11n(Opcode.CONST_4, 0, 0),
                ImmutableInstruction30t(Opcode.GOTO_32, 6),
                ImmutableInstruction12x(Opcode.NEG_INT, 0, 0),
                ImmutableInstruction10x(Opcode.RETURN_VOID),
                ImmutableInstruction10x(Opcode.NOP),
                ImmutableInstruction30t(Opcode.GOTO_32, -3),
            ),
            "incoming-span-padding" to listOf(
                ImmutableInstruction10t(Opcode.GOTO, 5),
                ImmutableInstruction11n(Opcode.CONST_4, 0, 0),
                ImmutableInstruction30t(Opcode.GOTO_32, 7),
                ImmutableInstruction10x(Opcode.NOP),
                ImmutableInstruction12x(Opcode.NEG_INT, 0, 0),
                ImmutableInstruction10x(Opcode.RETURN_VOID),
                ImmutableInstruction10x(Opcode.NOP),
                ImmutableInstruction30t(Opcode.GOTO_32, -3),
            ),
            "unsafe-source-predecessor" to listOf(
                ImmutableInstruction10t(Opcode.GOTO, 4),
                ImmutableInstruction30t(Opcode.GOTO_32, 6),
                ImmutableInstruction12x(Opcode.NEG_INT, 0, 0),
                ImmutableInstruction10x(Opcode.RETURN_VOID),
                ImmutableInstruction10x(Opcode.NOP),
                ImmutableInstruction30t(Opcode.GOTO_32, -3),
            ),
        )
        incomingCases.forEach { (name, candidate) ->
            assertFailsWith<IllegalArgumentException>(name) {
                verifyRelayCandidate(name, branchOriginal, candidate)
            }
        }
    }

    @Test
    fun `independent verifier rejects debug and try boundaries in reachable relay suffix`() {
        assertFailsWith<IllegalArgumentException> {
            verifyRelayCandidate(
                name = "relay-debug-boundary",
                candidateInstructions = exactRelayCandidate(),
                candidateDebugLines = listOf(ImmutableLineNumber(7, 42)),
            )
        }
        assertFailsWith<IllegalArgumentException> {
            verifyRelayCandidate(
                name = "relay-try-boundary",
                candidateInstructions = exactRelayCandidate(),
                candidateTryBlocks = listOf(
                    ImmutableTryBlock(6, 1, listOf(ImmutableExceptionHandler(null, 5))),
                ),
            )
        }
    }

    @Test
    fun `relay shapes are rejected when inserted and preserved only when preexisting`() {
        val changedName = "changedRelay"
        val preexistingName = "preexistingRelayLike"
        val originalChanged = fixtureMethod(changedName, relayOriginalInstructions(), 1, emptyList(), "V")
        val candidateChanged = fixtureMethod(changedName, exactRelayCandidate(), 1, emptyList(), "V")
        val preexisting = fixtureMethod(preexistingName, exactRelayCandidate(), 1, emptyList(), "V")
        val acceptedOriginal = methodsDex(listOf(originalChanged, preexisting))
        val acceptedCandidate = methodsDex(listOf(candidateChanged, preexisting))

        assertFailsWith<IllegalArgumentException> {
            verifyRelayScope("preexisting-relay-like", acceptedOriginal, acceptedCandidate, changedName).size
        }

        val unreportedOriginal = methodsDex(
            listOf(
                originalChanged,
                fixtureMethod("excludedRelayLike", relayOriginalInstructions(), 1, emptyList(), "V"),
            ),
        )
        val unreportedCandidate = methodsDex(
            listOf(
                candidateChanged,
                fixtureMethod("excludedRelayLike", exactRelayCandidate(), 1, emptyList(), "V"),
            ),
        )
        assertFailsWith<IllegalArgumentException> {
            verifyRelayScope("unreported-relay-like", unreportedOriginal, unreportedCandidate, changedName)
        }

        val thirdParty = "Lthird/party/RelayLike;"
        val unownedOriginal = classesDex(
            listOf(
                fixtureClass(OWNED_CLASS, listOf(originalChanged)),
                fixtureClass(
                    thirdParty,
                    listOf(
                        fixtureMethod(
                            "unownedRelayLike",
                            relayOriginalInstructions(),
                            1,
                            emptyList(),
                            "V",
                            owner = thirdParty,
                        ),
                    ),
                ),
            ),
        )
        val unownedCandidate = classesDex(
            listOf(
                fixtureClass(OWNED_CLASS, listOf(candidateChanged)),
                fixtureClass(
                    thirdParty,
                    listOf(
                        fixtureMethod(
                            "unownedRelayLike",
                            exactRelayCandidate(),
                            1,
                            emptyList(),
                            "V",
                            owner = thirdParty,
                        ),
                    ),
                ),
            ),
        )
        assertFailsWith<IllegalArgumentException> {
            verifyRelayScope("unowned-relay-like", unownedOriginal, unownedCandidate, changedName)
        }
    }

    private fun relayOriginalInstructions(): List<Instruction> = listOf(
        ImmutableInstruction11n(Opcode.CONST_4, 0, 0),
        ImmutableInstruction12x(Opcode.NEG_INT, 0, 0),
        ImmutableInstruction10x(Opcode.RETURN_VOID),
    )

    private fun exactRelayCandidate(relayOffset: Int = -3): List<Instruction> = listOf(
        ImmutableInstruction11n(Opcode.CONST_4, 0, 0),
        ImmutableInstruction30t(Opcode.GOTO_32, 6),
        ImmutableInstruction12x(Opcode.NEG_INT, 0, 0),
        ImmutableInstruction10x(Opcode.RETURN_VOID),
        ImmutableInstruction10x(Opcode.NOP),
        ImmutableInstruction30t(Opcode.GOTO_32, relayOffset),
    )

    private fun verifyRelayCandidate(
        name: String,
        originalInstructions: List<Instruction> = relayOriginalInstructions(),
        candidateInstructions: List<Instruction>,
        candidateTryBlocks: List<ImmutableTryBlock> = emptyList(),
        candidateDebugLines: List<ImmutableLineNumber> = emptyList(),
        contentSalt: ByteArray = VERIFIER_CONTENT_SALT,
    ): List<BundleSemanticVerificationResult> {
        val originalDex = relayMethodDex(name, originalInstructions)
        val candidateDex = relayMethodDex(
            name,
            candidateInstructions,
            tryBlocks = candidateTryBlocks,
            debugLines = candidateDebugLines,
        )
        val ordinary = zip("$name-relay-ordinary.aab", DEX_PATH to originalDex)
        val rewritten = zip("$name-relay-rewritten.aab", DEX_PATH to candidateDex)
        val manifest = manifest(
            ordinary,
            DEX_PATH,
            originalDex,
            DEX_PATH,
            candidateDex,
            BundleSemanticVerifier.DEX_SEMANTICS,
            contentSalt,
        )
        val parsedOriginal = dexInstructions(originalDex, name)
        val parsedCandidate = dexInstructions(candidateDex, name)
        val methodPlan = PlannedDexMethod(
            "$OWNED_CLASS->$name()V",
            parsedOriginal.size,
            NormalizedOpcodeSimHash.distance(parsedOriginal, parsedCandidate),
        )
        val semanticPlan = plan(
            Sha256.file(ordinary),
            originalDex,
            candidateDex,
            dexMethod = methodPlan,
            minimumSimHashDistance = 0,
            contentSalt = contentSalt,
        )
        return BundlePostRewriteSemanticVerifier().verify(ordinary, rewritten, manifest, semanticPlan, contentSalt)
    }

    private fun verifyRelayScope(
        name: String,
        originalDex: ByteArray,
        candidateDex: ByteArray,
        transformedMethodName: String,
        contentSalt: ByteArray = VERIFIER_CONTENT_SALT,
    ): List<BundleSemanticVerificationResult> {
        val ordinary = zip("$name-ordinary.aab", DEX_PATH to originalDex)
        val rewritten = zip("$name-rewritten.aab", DEX_PATH to candidateDex)
        val manifest = manifest(
            ordinary,
            DEX_PATH,
            originalDex,
            DEX_PATH,
            candidateDex,
            BundleSemanticVerifier.DEX_SEMANTICS,
            contentSalt,
        )
        val originalInstructions = dexInstructions(originalDex, transformedMethodName)
        val candidateInstructions = dexInstructions(candidateDex, transformedMethodName)
        val methodPlan = PlannedDexMethod(
            "$OWNED_CLASS->$transformedMethodName()V",
            originalInstructions.size,
            NormalizedOpcodeSimHash.distance(originalInstructions, candidateInstructions),
        )
        val semanticPlan = plan(
            Sha256.file(ordinary),
            originalDex,
            candidateDex,
            dexMethod = methodPlan,
            minimumSimHashDistance = 0,
            contentSalt = contentSalt,
        )
        return BundlePostRewriteSemanticVerifier().verify(ordinary, rewritten, manifest, semanticPlan, contentSalt)
    }

    private fun safeDiversePayload(): List<Instruction> = listOf(
        ImmutableInstruction11n(Opcode.CONST_4, 0, 1),
        *SafeUnreachablePayloadContract.markerValues(VERIFIER_CONTENT_SALT, "$OWNED_CLASS->sum(II)I")
            .map { value ->
                ImmutableInstruction31c(Opcode.CONST_STRING_JUMBO, 0, ImmutableStringReference(value))
            }.toTypedArray(),
        ImmutableInstruction12x(Opcode.MOVE, 0, 0),
        ImmutableInstruction12x(Opcode.NEG_INT, 0, 0),
        ImmutableInstruction12x(Opcode.NOT_INT, 0, 0),
        ImmutableInstruction12x(Opcode.ADD_INT_2ADDR, 0, 0),
        ImmutableInstruction12x(Opcode.SUB_INT_2ADDR, 0, 0),
        ImmutableInstruction12x(Opcode.MUL_INT_2ADDR, 0, 0),
        ImmutableInstruction12x(Opcode.AND_INT_2ADDR, 0, 0),
        ImmutableInstruction12x(Opcode.OR_INT_2ADDR, 0, 0),
        ImmutableInstruction12x(Opcode.XOR_INT_2ADDR, 0, 0),
        ImmutableInstruction12x(Opcode.SHL_INT_2ADDR, 0, 0),
        ImmutableInstruction12x(Opcode.SHR_INT_2ADDR, 0, 0),
        ImmutableInstruction12x(Opcode.USHR_INT_2ADDR, 0, 0),
    )

    private fun entryPayloadInboundCandidate(conditional: Boolean): List<Instruction> = buildList {
        val payload = safeDiversePayload()
        val payloadCodeUnits = payload.sumOf(Instruction::getCodeUnits)
        add(ImmutableInstruction30t(Opcode.GOTO_32, 3 + payloadCodeUnits))
        addAll(payload)
        add(ImmutableInstruction11n(Opcode.CONST_4, 0, 0))
        if (conditional) {
            add(ImmutableInstruction21t(Opcode.IF_EQZ, 0, -(payloadCodeUnits + 1)))
        } else {
            add(ImmutableInstruction10t(Opcode.GOTO, -(payloadCodeUnits + 1)))
        }
        add(ImmutableInstruction10x(Opcode.NOP))
        add(ImmutableInstruction10x(Opcode.RETURN_VOID))
    }

    private fun sumCandidateDex(
        payload: List<Instruction>,
        livePrefix: List<Instruction> = emptyList(),
    ): ByteArray {
        val candidateInstructions = buildList {
            add(ImmutableInstruction30t(Opcode.GOTO_32, 3 + payload.sumOf(Instruction::getCodeUnits)))
            addAll(payload)
            addAll(livePrefix)
            add(com.android.tools.smali.dexlib2.immutable.instruction.ImmutableInstruction23x(Opcode.ADD_INT, 0, 0, 1))
            add(ImmutableInstruction10x(Opcode.NOP))
            add(ImmutableInstruction11x(Opcode.RETURN, 0))
        }
        return methodDex(
            "sum",
            candidateInstructions,
            registerCount = 2,
            parameterTypes = listOf("I", "I"),
            returnType = "I",
        )
    }

    private fun verifySumCandidate(
        name: String,
        originalDex: ByteArray,
        candidateDex: ByteArray,
        authorized: Boolean = true,
        contentSalt: ByteArray = VERIFIER_CONTENT_SALT,
        planContentSalt: ByteArray = VERIFIER_CONTENT_SALT,
        manifestContentSalt: ByteArray = VERIFIER_CONTENT_SALT,
    ): List<BundleSemanticVerificationResult> {
        val ordinary = zip("$name-ordinary.aab", DEX_PATH to originalDex)
        val rewritten = zip("$name-rewritten.aab", DEX_PATH to candidateDex)
        val manifest = manifest(
            ordinary,
            DEX_PATH,
            originalDex,
            DEX_PATH,
            candidateDex,
            BundleSemanticVerifier.DEX_SEMANTICS,
            manifestContentSalt,
        )
        val originalInstructions = dexInstructions(originalDex, "sum")
        val candidateInstructions = dexInstructions(candidateDex, "sum")
        val plannedMethod = PlannedDexMethod(
            "$OWNED_CLASS->sum(II)I",
            originalInstructions.size,
            NormalizedOpcodeSimHash.distance(originalInstructions, candidateInstructions),
        )
        val basePlan = plan(
            Sha256.file(ordinary),
            originalDex,
            candidateDex,
            dexMethod = plannedMethod,
            contentSalt = planContentSalt,
        )
        val baseEntry = basePlan.dex.entries.single()
        val semanticPlan = basePlan.copy(
            dex = basePlan.dex.copy(
                minimumSimHashDistance = 0,
                entries = if (authorized) {
                    listOf(baseEntry)
                } else {
                    listOf(
                        baseEntry.copy(
                            transformedMethodCount = 0,
                            transformedInstructionCount = 0,
                            transformedMethods = emptyList(),
                        ),
                    )
                },
            ),
        )
        return BundlePostRewriteSemanticVerifier().verify(ordinary, rewritten, manifest, semanticPlan, contentSalt)
    }

    private fun verifyEntryPayloadInboundBranch(
        name: String,
        originalInstructions: List<Instruction>,
        candidateInstructions: List<Instruction>,
    ): List<BundleSemanticVerificationResult> {
        val originalDex = methodDex(name, originalInstructions, 1, emptyList(), "V")
        val candidateDex = methodDex(
            name,
            bindMarkerValues(candidateInstructions, "$OWNED_CLASS->$name()V"),
            1,
            emptyList(),
            "V",
        )
        val ordinary = zip("$name-ordinary.aab", DEX_PATH to originalDex)
        val rewritten = zip("$name-rewritten.aab", DEX_PATH to candidateDex)
        val manifest = manifest(
            ordinary,
            DEX_PATH,
            originalDex,
            DEX_PATH,
            candidateDex,
            BundleSemanticVerifier.DEX_SEMANTICS,
        )
        val parsedOriginal = dexInstructions(originalDex, name)
        val parsedCandidate = dexInstructions(candidateDex, name)
        val methodPlan = PlannedDexMethod(
            "$OWNED_CLASS->$name()V",
            parsedOriginal.size,
            NormalizedOpcodeSimHash.distance(parsedOriginal, parsedCandidate),
        )
        val basePlan = plan(Sha256.file(ordinary), originalDex, candidateDex, dexMethod = methodPlan)
        val semanticPlan = basePlan.copy(dex = basePlan.dex.copy(minimumSimHashDistance = 0))
        return BundlePostRewriteSemanticVerifier().verify(ordinary, rewritten, manifest, semanticPlan)
    }

    private fun verifyOpaqueDiamondCandidate(
        name: String,
        candidateInstructions: List<Instruction>,
        plannedDiamondCount: Int,
        owner: String = OWNED_CLASS,
        accessFlags: Int = AccessFlags.PRIVATE.value,
        dexScope: DexSemanticVerificationScope = dexScope(),
        bindMarkerValues: Boolean = true,
    ): List<BundleSemanticVerificationResult> {
        val originalInstructions = opaqueOriginalInstructions()
        val originalDex = methodDex(
            name,
            originalInstructions,
            registerCount = 2,
            parameterTypes = emptyList(),
            returnType = "V",
            accessFlags = accessFlags,
            owner = owner,
        )
        val boundCandidateInstructions = if (bindMarkerValues) {
            bindMarkerValues(candidateInstructions, "$owner->$name()V")
        } else {
            candidateInstructions
        }
        val candidateDex = methodDex(
            name,
            boundCandidateInstructions,
            registerCount = 2,
            parameterTypes = emptyList(),
            returnType = "V",
            accessFlags = accessFlags,
            owner = owner,
        )
        val ordinary = zip("$name-opaque-ordinary.aab", DEX_PATH to originalDex)
        val rewritten = zip("$name-opaque-rewritten.aab", DEX_PATH to candidateDex)
        val manifest = manifest(
            ordinary,
            DEX_PATH,
            originalDex,
            DEX_PATH,
            candidateDex,
            BundleSemanticVerifier.DEX_SEMANTICS,
        )
        val parsedOriginal = dexInstructions(originalDex, name)
        val parsedCandidate = dexInstructions(candidateDex, name)
        val methodPlan = PlannedDexMethod(
            methodId = "$owner->$name()V",
            originalInstructionCount = parsedOriginal.size,
            simHashDistance = NormalizedOpcodeSimHash.distance(parsedOriginal, parsedCandidate),
            opaqueDiamondCount = plannedDiamondCount,
        )
        val semanticPlan = plan(
            Sha256.file(ordinary),
            originalDex,
            candidateDex,
            dexMethod = methodPlan,
            minimumSimHashDistance = 0,
        )
        return BundlePostRewriteSemanticVerifier().verify(
            ordinary,
            rewritten,
            manifest,
            semanticPlan,
            VERIFIER_CONTENT_SALT,
            dexScope,
        )
    }

    private fun opaqueOriginalInstructions(): List<Instruction> = buildList {
        repeat(11) { add(ImmutableInstruction12x(Opcode.MOVE_OBJECT, 0, 0)) }
        add(ImmutableInstruction10x(Opcode.RETURN_VOID))
    }

    private fun opaqueDiamondInstructions(receiverRegister: Int, diamondCount: Int = 1): List<Instruction> = buildList {
        repeat(diamondCount) {
            add(ImmutableInstruction21t(Opcode.IF_EQZ, receiverRegister, 5))
            add(ImmutableInstruction30t(Opcode.GOTO_32, 24))
            add(ImmutableInstruction30t(Opcode.GOTO_32, 21))
            addAll(opaqueSafePayload())
        }
        addAll(opaqueOriginalInstructions().take(6))
        add(ImmutableInstruction10x(Opcode.NOP))
        addAll(opaqueOriginalInstructions().drop(6))
    }

    private fun opaqueMarkerDiamondInstructions(
        receiverRegister: Int,
        payload: List<Instruction> = opaqueMarkerPayload(),
    ): List<Instruction> = buildList {
        addAll(opaqueDiamondWithPayload(receiverRegister, payload))
        addAll(opaqueOriginalInstructions().take(6))
        add(ImmutableInstruction10x(Opcode.NOP))
        addAll(opaqueOriginalInstructions().drop(6))
    }

    private fun opaqueDiamondWithPayload(receiverRegister: Int, payload: List<Instruction>): List<Instruction> = buildList {
        val payloadCodeUnits = payload.sumOf(Instruction::getCodeUnits)
        add(ImmutableInstruction21t(Opcode.IF_EQZ, receiverRegister, 5))
        add(ImmutableInstruction30t(Opcode.GOTO_32, 6 + payloadCodeUnits))
        add(ImmutableInstruction30t(Opcode.GOTO_32, 3 + payloadCodeUnits))
        addAll(payload)
    }

    private fun opaqueMarkerPayload(
        markerValues: List<String> = listOf(
            "",
            "SLH1Sabc",
            "SLH1M:" + "a".repeat(3),
            "SLH1L:" + "b".repeat(27),
            "SLH1V:" + "c".repeat(123),
        ),
    ): List<Instruction> = listOf(
        ImmutableInstruction11n(Opcode.CONST_4, 0, 0),
        *markerValues.map { value ->
            ImmutableInstruction31c(Opcode.CONST_STRING_JUMBO, 0, ImmutableStringReference(value))
        }.toTypedArray(),
        ImmutableInstruction12x(Opcode.NEG_INT, 0, 0),
        ImmutableInstruction12x(Opcode.XOR_INT_2ADDR, 0, 0),
    )

    private fun bindMarkerValues(instructions: List<Instruction>, methodId: String): List<Instruction> {
        val expected = SafeUnreachablePayloadContract.markerValues(VERIFIER_CONTENT_SALT, methodId)
        var markerIndex = 0
        return instructions.map { instruction ->
            if (instruction.opcode != Opcode.CONST_STRING_JUMBO) {
                instruction
            } else {
                ImmutableInstruction31c(
                    Opcode.CONST_STRING_JUMBO,
                    (instruction as OneRegisterInstruction).registerA,
                    ImmutableStringReference(expected[markerIndex++ % expected.size]),
                )
            }
        }
    }

    private fun opaqueFallbackInstructions(): List<Instruction> = buildList {
        add(ImmutableInstruction30t(Opcode.GOTO_32, 21))
        addAll(opaqueSafePayload())
        addAll(opaqueOriginalInstructions().take(6))
        add(ImmutableInstruction10x(Opcode.NOP))
        addAll(opaqueOriginalInstructions().drop(6))
    }

    private fun opaqueSafePayload(): List<Instruction> = opaqueMarkerPayload()

    @Test
    fun `independent verifier accepts inverse conditional plus goto32 expansion`() {
        val originalDex = conditionalDex()
        val transformation = SafeDexTransformer().transform(
            originalDex,
            DexTransformRequest(
                ownedDescriptorPrefixes = emptySet(),
                ownedDescriptors = setOf(OWNED_CLASS),
                salt = "conditional-semantic-verification".encodeToByteArray(),
                minimumCoverage = 0.0,
                minimumSimHashDistance = 4,
                maximumGrowthRatio = 1.0,
                selectionRate = 1.0,
            ),
        )
        val ordinary = zip("conditional-ordinary.aab", DEX_PATH to originalDex)
        val rewritten = zip("conditional-rewritten.aab", DEX_PATH to transformation.dexBytes)
        val manifest = manifest(
            ordinary,
            DEX_PATH,
            originalDex,
            DEX_PATH,
            transformation.dexBytes,
            BundleSemanticVerifier.DEX_SEMANTICS,
            "conditional-semantic-verification".encodeToByteArray(),
        )
        val plan = plan(
            Sha256.file(ordinary),
            originalDex,
            transformation.dexBytes,
            dexMethod = transformation.report.methods.single().toPlannedDexMethod(),
            contentSalt = "conditional-semantic-verification".encodeToByteArray(),
        )

        assertEquals(
            1,
            BundlePostRewriteSemanticVerifier().verify(
                ordinary,
                rewritten,
                manifest,
                plan,
                "conditional-semantic-verification".encodeToByteArray(),
            ).size,
        )
    }

    @Test
    fun `independent verifier preserves a preexisting inverse conditional goto32 pattern`() {
        val originalDex = preExpandedConditionalDex()
        val transformation = SafeDexTransformer().transform(
            originalDex,
            DexTransformRequest(
                ownedDescriptorPrefixes = emptySet(),
                ownedDescriptors = setOf(OWNED_CLASS),
                salt = "preexisting-conditional-pattern".encodeToByteArray(),
                minimumCoverage = 0.0,
                minimumSimHashDistance = 4,
                maximumGrowthRatio = 1.0,
                selectionRate = 1.0,
            ),
        )
        val ordinary = zip("preexisting-conditional-ordinary.aab", DEX_PATH to originalDex)
        val rewritten = zip("preexisting-conditional-rewritten.aab", DEX_PATH to transformation.dexBytes)
        val manifest = manifest(
            ordinary,
            DEX_PATH,
            originalDex,
            DEX_PATH,
            transformation.dexBytes,
            BundleSemanticVerifier.DEX_SEMANTICS,
            "preexisting-conditional-pattern".encodeToByteArray(),
        )
        val plan = plan(
            Sha256.file(ordinary),
            originalDex,
            transformation.dexBytes,
            dexMethod = transformation.report.methods.single().toPlannedDexMethod(),
            contentSalt = "preexisting-conditional-pattern".encodeToByteArray(),
        )

        assertEquals(
            1,
            BundlePostRewriteSemanticVerifier().verify(
                ordinary,
                rewritten,
                manifest,
                plan,
                "preexisting-conditional-pattern".encodeToByteArray(),
            ).size,
        )
    }

    @Test
    fun `conditional expansion does not hide a live safe-opcode fallthrough as entry payload`() {
        val originalDex = methodDex(
            "safeOpcodeFallthrough",
            listOf(
                ImmutableInstruction21t(Opcode.IF_EQZ, 0, 4),
                ImmutableInstruction11n(Opcode.CONST_4, 1, 1),
                ImmutableInstruction12x(Opcode.MOVE, 1, 1),
                ImmutableInstruction10x(Opcode.RETURN_VOID),
            ),
            registerCount = 2,
            parameterTypes = listOf("I"),
            returnType = "V",
        )
        val transformation = SafeDexTransformer().transform(
            originalDex,
            DexTransformRequest(
                ownedDescriptorPrefixes = emptySet(),
                ownedDescriptors = setOf(OWNED_CLASS),
                salt = "safe-opcode-fallthrough".encodeToByteArray(),
                minimumCoverage = 0.0,
                minimumSimHashDistance = 0,
                maximumGrowthRatio = 1.0,
                selectionRate = 1.0,
            ),
        )
        val ordinary = zip("safe-fallthrough-ordinary.aab", DEX_PATH to originalDex)
        val rewritten = zip("safe-fallthrough-rewritten.aab", DEX_PATH to transformation.dexBytes)
        val manifest = manifest(
            ordinary,
            DEX_PATH,
            originalDex,
            DEX_PATH,
            transformation.dexBytes,
            BundleSemanticVerifier.DEX_SEMANTICS,
            "safe-opcode-fallthrough".encodeToByteArray(),
        )
        val basePlan = plan(
            Sha256.file(ordinary),
            originalDex,
            transformation.dexBytes,
            dexMethod = transformation.report.methods.single().toPlannedDexMethod(),
            contentSalt = "safe-opcode-fallthrough".encodeToByteArray(),
        )
        val semanticPlan = basePlan.copy(dex = basePlan.dex.copy(minimumSimHashDistance = 0))

        assertEquals(
            1,
            BundlePostRewriteSemanticVerifier().verify(
                ordinary,
                rewritten,
                manifest,
                semanticPlan,
                "safe-opcode-fallthrough".encodeToByteArray(),
            ).size,
        )
    }

    @Test
    fun `conditional expansion verifier rejects an incoming branch retargeted to pre-goto nop`() {
        val originalDex = methodDex(
            "corrupted",
            listOf(
                ImmutableInstruction10t(Opcode.GOTO, 3),
                ImmutableInstruction21t(Opcode.IF_EQZ, 0, 4),
                ImmutableInstruction11n(Opcode.CONST_4, 0, 0),
                ImmutableInstruction11x(Opcode.RETURN, 0),
                ImmutableInstruction11n(Opcode.CONST_4, 0, 1),
                ImmutableInstruction11x(Opcode.RETURN, 0),
            ),
            registerCount = 1,
            parameterTypes = listOf("I"),
            returnType = "I",
        )
        val corruptedDex = methodDex(
            "corrupted",
            listOf(
                ImmutableInstruction30t(Opcode.GOTO_32, 4),
                ImmutableInstruction10x(Opcode.NOP),
                ImmutableInstruction10t(Opcode.GOTO, 3),
                ImmutableInstruction21t(Opcode.IF_NEZ, 0, 6),
                ImmutableInstruction10x(Opcode.NOP),
                ImmutableInstruction30t(Opcode.GOTO_32, 5),
                ImmutableInstruction11n(Opcode.CONST_4, 0, 0),
                ImmutableInstruction11x(Opcode.RETURN, 0),
                ImmutableInstruction11n(Opcode.CONST_4, 0, 1),
                ImmutableInstruction11x(Opcode.RETURN, 0),
            ),
            registerCount = 1,
            parameterTypes = listOf("I"),
            returnType = "I",
        )
        val ordinary = zip("incoming-goto-ordinary.aab", DEX_PATH to originalDex)
        val rewritten = zip("incoming-goto-rewritten.aab", DEX_PATH to corruptedDex)
        val manifest = manifest(
            ordinary,
            DEX_PATH,
            originalDex,
            DEX_PATH,
            corruptedDex,
            BundleSemanticVerifier.DEX_SEMANTICS,
        )
        val originalInstructions = dexInstructions(originalDex, "corrupted")
        val corruptedInstructions = dexInstructions(corruptedDex, "corrupted")
        val methodPlan = PlannedDexMethod(
            "$OWNED_CLASS->corrupted(I)I",
            originalInstructions.size,
            NormalizedOpcodeSimHash.distance(originalInstructions, corruptedInstructions),
        )
        val basePlan = plan(Sha256.file(ordinary), originalDex, corruptedDex, dexMethod = methodPlan)
        val semanticPlan = basePlan.copy(dex = basePlan.dex.copy(minimumSimHashDistance = 0))

        val failure = assertFailsWith<IllegalArgumentException> {
            BundlePostRewriteSemanticVerifier().verify(ordinary, rewritten, manifest, semanticPlan)
        }

        assertTrue(failure.message.orEmpty().contains("non-NOP instruction or control-flow target"))
    }

    @Test
    fun `conditional expansion verifier rejects a switch case retargeted to inserted goto`() {
        val originalDex = methodDex(
            "forgedSwitchEdge",
            listOf(
                ImmutableInstruction31t(Opcode.PACKED_SWITCH, 0, 10),
                ImmutableInstruction21t(Opcode.IF_EQZ, 1, 4),
                ImmutableInstruction11n(Opcode.CONST_4, 1, 0),
                ImmutableInstruction11x(Opcode.RETURN, 1),
                ImmutableInstruction11n(Opcode.CONST_4, 1, 1),
                ImmutableInstruction11x(Opcode.RETURN, 1),
                ImmutableInstruction10x(Opcode.NOP),
                ImmutablePackedSwitchPayload(listOf(ImmutableSwitchElement(0, 5))),
            ),
            registerCount = 2,
            parameterTypes = listOf("I", "I"),
            returnType = "I",
        )
        val forgedDex = methodDex(
            "forgedSwitchEdge",
            listOf(
                ImmutableInstruction30t(Opcode.GOTO_32, 5),
                ImmutableInstruction10x(Opcode.NOP),
                ImmutableInstruction10x(Opcode.NOP),
                ImmutableInstruction31t(Opcode.PACKED_SWITCH, 0, 12),
                ImmutableInstruction21t(Opcode.IF_NEZ, 1, 5),
                ImmutableInstruction30t(Opcode.GOTO_32, 5),
                ImmutableInstruction11n(Opcode.CONST_4, 1, 0),
                ImmutableInstruction11x(Opcode.RETURN, 1),
                ImmutableInstruction11n(Opcode.CONST_4, 1, 1),
                ImmutableInstruction11x(Opcode.RETURN, 1),
                ImmutablePackedSwitchPayload(listOf(ImmutableSwitchElement(0, 5))),
            ),
            registerCount = 2,
            parameterTypes = listOf("I", "I"),
            returnType = "I",
        )
        val ordinary = zip("switch-edge-ordinary.aab", DEX_PATH to originalDex)
        val rewritten = zip("switch-edge-rewritten.aab", DEX_PATH to forgedDex)
        val manifest = manifest(
            ordinary,
            DEX_PATH,
            originalDex,
            DEX_PATH,
            forgedDex,
            BundleSemanticVerifier.DEX_SEMANTICS,
        )
        val originalInstructions = dexInstructions(originalDex, "forgedSwitchEdge")
        val forgedInstructions = dexInstructions(forgedDex, "forgedSwitchEdge")
        val methodPlan = PlannedDexMethod(
            "$OWNED_CLASS->forgedSwitchEdge(II)I",
            originalInstructions.size,
            NormalizedOpcodeSimHash.distance(originalInstructions, forgedInstructions),
        )
        val basePlan = plan(Sha256.file(ordinary), originalDex, forgedDex, dexMethod = methodPlan)
        val semanticPlan = basePlan.copy(dex = basePlan.dex.copy(minimumSimHashDistance = 0))

        assertFailsWith<IllegalArgumentException> {
            BundlePostRewriteSemanticVerifier().verify(ordinary, rewritten, manifest, semanticPlan)
        }
    }

    @Test
    fun `independent verifier preserves an excluded switch beside legitimate conditional expansion`() {
        val switchMethod = fixtureMethod(
            "unchangedSwitch",
            listOf(
                ImmutableInstruction31t(Opcode.PACKED_SWITCH, 0, 4),
                ImmutableInstruction10x(Opcode.RETURN_VOID),
                ImmutablePackedSwitchPayload(listOf(ImmutableSwitchElement(0, 3))),
            ),
            registerCount = 1,
            parameterTypes = listOf("I"),
            returnType = "V",
        )
        val conditionalMethod = fixtureMethod(
            "legitimateConditional",
            listOf(
                ImmutableInstruction21t(Opcode.IF_EQZ, 0, 4),
                ImmutableInstruction11n(Opcode.CONST_4, 0, 0),
                ImmutableInstruction11x(Opcode.RETURN, 0),
                ImmutableInstruction11n(Opcode.CONST_4, 0, 1),
                ImmutableInstruction11x(Opcode.RETURN, 0),
            ),
            registerCount = 1,
            parameterTypes = listOf("I"),
            returnType = "I",
        )
        val originalDex = methodsDex(listOf(switchMethod, conditionalMethod))
        val transformation = SafeDexTransformer().transform(
            originalDex,
            DexTransformRequest(
                ownedDescriptorPrefixes = emptySet(),
                ownedDescriptors = setOf(OWNED_CLASS),
                salt = "legitimate-switch-and-conditional".encodeToByteArray(),
                minimumCoverage = 0.0,
                minimumSimHashDistance = 0,
                maximumGrowthRatio = 1.0,
                selectionRate = 1.0,
            ),
        )
        val ordinary = zip("legitimate-switch-ordinary.aab", DEX_PATH to originalDex)
        val rewritten = zip("legitimate-switch-rewritten.aab", DEX_PATH to transformation.dexBytes)
        val manifest = manifest(
            ordinary,
            DEX_PATH,
            originalDex,
            DEX_PATH,
            transformation.dexBytes,
            BundleSemanticVerifier.DEX_SEMANTICS,
            "legitimate-switch-and-conditional".encodeToByteArray(),
        )
        val transformedMethod = transformation.report.methods.single {
            it.methodId == "$OWNED_CLASS->legitimateConditional(I)I"
        }
        val basePlan = plan(
            Sha256.file(ordinary),
            originalDex,
            transformation.dexBytes,
            dexMethod = transformedMethod.toPlannedDexMethod(),
            contentSalt = "legitimate-switch-and-conditional".encodeToByteArray(),
        )
        val baseEntry = basePlan.dex.entries.single()
        val completeEntry = baseEntry.copy(
            ownedMethodCount = transformation.report.ownedMethodCount,
            eligibleMethodCount = transformation.report.eligibleMethodCount,
            transformedMethodCount = transformation.report.transformedMethodCount,
            ownedInstructionCount = transformation.report.ownedInstructionCount,
            eligibleInstructionCount = transformation.report.eligibleInstructionCount,
            transformedInstructionCount = transformation.report.transformedInstructionCount,
        )
        val completePlan = basePlan.copy(
            dex = basePlan.dex.copy(minimumSimHashDistance = 0, entries = listOf(completeEntry)),
        )

        assertEquals(
            1,
            BundlePostRewriteSemanticVerifier().verify(
                ordinary,
                rewritten,
                manifest,
                completePlan,
                "legitimate-switch-and-conditional".encodeToByteArray(),
            ).size,
        )
    }

    @Test
    fun `independent verifier preserves preexpanded conditional in unchanged excluded method`() {
        val excludedMethod = fixtureMethod(
            "excludedPreexpandedConditional",
            listOf(
                ImmutableInstruction21t(Opcode.IF_NEZ, 0, 5),
                ImmutableInstruction30t(Opcode.GOTO_32, 5),
                ImmutableInstruction11n(Opcode.CONST_4, 0, 0),
                ImmutableInstruction11x(Opcode.RETURN, 0),
                ImmutableInstruction11n(Opcode.CONST_4, 0, 1),
                ImmutableInstruction11x(Opcode.RETURN, 0),
            ),
            registerCount = 1,
            parameterTypes = listOf("I"),
            returnType = "I",
            accessFlags = AccessFlags.PRIVATE.value or AccessFlags.STATIC.value or AccessFlags.SYNCHRONIZED.value,
        )
        val transformedMethod = fixtureMethod(
            "legitimateConditionalBesideExcluded",
            listOf(
                ImmutableInstruction21t(Opcode.IF_EQZ, 0, 4),
                ImmutableInstruction11n(Opcode.CONST_4, 0, 0),
                ImmutableInstruction11x(Opcode.RETURN, 0),
                ImmutableInstruction11n(Opcode.CONST_4, 0, 1),
                ImmutableInstruction11x(Opcode.RETURN, 0),
            ),
            registerCount = 1,
            parameterTypes = listOf("I"),
            returnType = "I",
        )
        val originalDex = methodsDex(listOf(excludedMethod, transformedMethod))
        val transformation = SafeDexTransformer().transform(
            originalDex,
            DexTransformRequest(
                ownedDescriptorPrefixes = emptySet(),
                ownedDescriptors = setOf(OWNED_CLASS),
                salt = "excluded-preexpanded-conditional".encodeToByteArray(),
                minimumCoverage = 0.0,
                minimumSimHashDistance = 0,
                maximumGrowthRatio = 1.0,
                selectionRate = 1.0,
            ),
        )
        val ordinary = zip("excluded-conditional-ordinary.aab", DEX_PATH to originalDex)
        val rewritten = zip("excluded-conditional-rewritten.aab", DEX_PATH to transformation.dexBytes)
        val manifest = manifest(
            ordinary,
            DEX_PATH,
            originalDex,
            DEX_PATH,
            transformation.dexBytes,
            BundleSemanticVerifier.DEX_SEMANTICS,
            "excluded-preexpanded-conditional".encodeToByteArray(),
        )
        val transformedPlan = transformation.report.methods.single {
            it.methodId == "$OWNED_CLASS->legitimateConditionalBesideExcluded(I)I"
        }
        val basePlan = plan(
            Sha256.file(ordinary),
            originalDex,
            transformation.dexBytes,
            dexMethod = transformedPlan.toPlannedDexMethod(),
            contentSalt = "excluded-preexpanded-conditional".encodeToByteArray(),
        )
        val baseEntry = basePlan.dex.entries.single()
        val completePlan = basePlan.copy(
            dex = basePlan.dex.copy(
                minimumSimHashDistance = 0,
                entries = listOf(
                    baseEntry.copy(
                        ownedMethodCount = transformation.report.ownedMethodCount,
                        eligibleMethodCount = transformation.report.eligibleMethodCount,
                        transformedMethodCount = transformation.report.transformedMethodCount,
                        ownedInstructionCount = transformation.report.ownedInstructionCount,
                        eligibleInstructionCount = transformation.report.eligibleInstructionCount,
                        transformedInstructionCount = transformation.report.transformedInstructionCount,
                    ),
                ),
            ),
        )

        assertEquals(
            1,
            BundlePostRewriteSemanticVerifier().verify(
                ordinary,
                rewritten,
                manifest,
                completePlan,
                "excluded-preexpanded-conditional".encodeToByteArray(),
            ).size,
        )
    }

    @Test
    fun `independent verifier preserves preexisting entry detour in unchanged unowned method`() {
        val transformedMethod = fixtureMethod(
            "legitimateConditionalBesideUnowned",
            listOf(
                ImmutableInstruction21t(Opcode.IF_EQZ, 0, 4),
                ImmutableInstruction11n(Opcode.CONST_4, 0, 0),
                ImmutableInstruction11x(Opcode.RETURN, 0),
                ImmutableInstruction11n(Opcode.CONST_4, 0, 1),
                ImmutableInstruction11x(Opcode.RETURN, 0),
            ),
            registerCount = 1,
            parameterTypes = listOf("I"),
            returnType = "I",
        )
        val unownedClass = "Lthird/party/PreexistingEntryDetour;"
        val unownedMethod = fixtureMethod(
            "unchangedEntryDetour",
            listOf(
                ImmutableInstruction30t(Opcode.GOTO_32, 6),
                ImmutableInstruction10x(Opcode.NOP),
                ImmutableInstruction11n(Opcode.CONST_4, 0, 1),
                ImmutableInstruction12x(Opcode.MOVE, 0, 0),
                ImmutableInstruction10x(Opcode.RETURN_VOID),
            ),
            registerCount = 1,
            parameterTypes = emptyList(),
            returnType = "V",
            owner = unownedClass,
        )
        val originalDex = classesDex(
            listOf(
                fixtureClass(OWNED_CLASS, listOf(transformedMethod)),
                fixtureClass(unownedClass, listOf(unownedMethod)),
            ),
        )
        val transformation = SafeDexTransformer().transform(
            originalDex,
            DexTransformRequest(
                ownedDescriptorPrefixes = emptySet(),
                ownedDescriptors = setOf(OWNED_CLASS),
                salt = "unowned-entry-detour".encodeToByteArray(),
                minimumCoverage = 0.0,
                minimumSimHashDistance = 0,
                maximumGrowthRatio = 1.0,
                selectionRate = 1.0,
            ),
        )
        val ordinary = zip("unowned-entry-ordinary.aab", DEX_PATH to originalDex)
        val rewritten = zip("unowned-entry-rewritten.aab", DEX_PATH to transformation.dexBytes)
        val manifest = manifest(
            ordinary,
            DEX_PATH,
            originalDex,
            DEX_PATH,
            transformation.dexBytes,
            BundleSemanticVerifier.DEX_SEMANTICS,
            "unowned-entry-detour".encodeToByteArray(),
        )
        val transformedPlan = transformation.report.methods.single {
            it.methodId == "$OWNED_CLASS->legitimateConditionalBesideUnowned(I)I"
        }
        val basePlan = plan(
            Sha256.file(ordinary),
            originalDex,
            transformation.dexBytes,
            dexMethod = transformedPlan.toPlannedDexMethod(),
            contentSalt = "unowned-entry-detour".encodeToByteArray(),
        )
        val baseEntry = basePlan.dex.entries.single()
        val completePlan = basePlan.copy(
            dex = basePlan.dex.copy(
                minimumSimHashDistance = 0,
                entries = listOf(
                    baseEntry.copy(
                        ownedMethodCount = transformation.report.ownedMethodCount,
                        eligibleMethodCount = transformation.report.eligibleMethodCount,
                        transformedMethodCount = transformation.report.transformedMethodCount,
                        ownedInstructionCount = transformation.report.ownedInstructionCount,
                        eligibleInstructionCount = transformation.report.eligibleInstructionCount,
                        transformedInstructionCount = transformation.report.transformedInstructionCount,
                    ),
                ),
            ),
        )

        assertEquals(
            1,
            BundlePostRewriteSemanticVerifier().verify(
                ordinary,
                rewritten,
                manifest,
                completePlan,
                "unowned-entry-detour".encodeToByteArray(),
            ).size,
        )
    }

    @Test
    fun `independent verifier preserves a preexisting entry payload detour`() {
        val originalDex = methodDex(
            "preexistingEntryDetour",
            listOf(
                ImmutableInstruction30t(Opcode.GOTO_32, 6),
                ImmutableInstruction10x(Opcode.NOP),
                ImmutableInstruction11n(Opcode.CONST_4, 0, 1),
                ImmutableInstruction12x(Opcode.MOVE, 0, 0),
                ImmutableInstruction10x(Opcode.RETURN_VOID),
            ),
            registerCount = 1,
            parameterTypes = emptyList(),
            returnType = "V",
        )
        val transformation = SafeDexTransformer().transform(
            originalDex,
            DexTransformRequest(
                ownedDescriptorPrefixes = emptySet(),
                ownedDescriptors = setOf(OWNED_CLASS),
                salt = "preexisting-entry-detour".encodeToByteArray(),
                minimumCoverage = 0.0,
                minimumSimHashDistance = 0,
                maximumGrowthRatio = 1.0,
                selectionRate = 1.0,
            ),
        )
        val ordinary = zip("entry-detour-ordinary.aab", DEX_PATH to originalDex)
        val rewritten = zip("entry-detour-rewritten.aab", DEX_PATH to transformation.dexBytes)
        val manifest = manifest(
            ordinary,
            DEX_PATH,
            originalDex,
            DEX_PATH,
            transformation.dexBytes,
            BundleSemanticVerifier.DEX_SEMANTICS,
            "preexisting-entry-detour".encodeToByteArray(),
        )
        val basePlan = plan(
            Sha256.file(ordinary),
            originalDex,
            transformation.dexBytes,
            dexMethod = transformation.report.methods.single().toPlannedDexMethod(),
            contentSalt = "preexisting-entry-detour".encodeToByteArray(),
        )
        val semanticPlan = basePlan.copy(dex = basePlan.dex.copy(minimumSimHashDistance = 0))

        assertEquals(
            1,
            BundlePostRewriteSemanticVerifier().verify(
                ordinary,
                rewritten,
                manifest,
                semanticPlan,
                "preexisting-entry-detour".encodeToByteArray(),
            ).size,
        )
    }

    @Test
    fun `try block weaving preserves a preexisting conditional expansion pattern`() {
        val originalDex = methodDex(
            "preexistingTryConditional",
            listOf(
                ImmutableInstruction21t(Opcode.IF_NEZ, 0, 5),
                ImmutableInstruction30t(Opcode.GOTO_32, 5),
                ImmutableInstruction11n(Opcode.CONST_4, 0, 0),
                ImmutableInstruction11x(Opcode.RETURN, 0),
                ImmutableInstruction11n(Opcode.CONST_4, 0, 1),
                ImmutableInstruction11x(Opcode.RETURN, 0),
                ImmutableInstruction11x(Opcode.MOVE_EXCEPTION, 0),
                ImmutableInstruction11x(Opcode.RETURN, 0),
            ),
            registerCount = 1,
            parameterTypes = listOf("I"),
            returnType = "I",
            tryBlocks = listOf(ImmutableTryBlock(5, 1, listOf(ImmutableExceptionHandler(null, 9)))),
        )
        val transformation = SafeDexTransformer().transform(
            originalDex,
            DexTransformRequest(
                ownedDescriptorPrefixes = emptySet(),
                ownedDescriptors = setOf(OWNED_CLASS),
                salt = "preexisting-try-conditional".encodeToByteArray(),
                minimumCoverage = 0.0,
                minimumSimHashDistance = 0,
                maximumGrowthRatio = 1.0,
                selectionRate = 1.0,
            ),
        )
        val ordinary = zip("try-conditional-ordinary.aab", DEX_PATH to originalDex)
        val rewritten = zip("try-conditional-rewritten.aab", DEX_PATH to transformation.dexBytes)
        val manifest = manifest(
            ordinary,
            DEX_PATH,
            originalDex,
            DEX_PATH,
            transformation.dexBytes,
            BundleSemanticVerifier.DEX_SEMANTICS,
            "preexisting-try-conditional".encodeToByteArray(),
        )
        val basePlan = plan(
            Sha256.file(ordinary),
            originalDex,
            transformation.dexBytes,
            dexMethod = transformation.report.methods.single().toPlannedDexMethod(),
            contentSalt = "preexisting-try-conditional".encodeToByteArray(),
        )
        val semanticPlan = basePlan.copy(dex = basePlan.dex.copy(minimumSimHashDistance = 0))

        assertEquals(
            1,
            BundlePostRewriteSemanticVerifier().verify(
                ordinary,
                rewritten,
                manifest,
                semanticPlan,
                "preexisting-try-conditional".encodeToByteArray(),
            ).size,
        )
    }

    @Test
    fun `canonicalized dex accepts stable semantics without requiring NOP weaving`() {
        val transformedInput = dex(Opcode.ADD_INT, includeNop = false)
        val transformed = SafeDexTransformer().transform(
            transformedInput,
            DexTransformRequest(
                ownedDescriptorPrefixes = emptySet(),
                ownedDescriptors = setOf(OWNED_CLASS),
                salt = "canonicalized-closure".encodeToByteArray(),
                minimumCoverage = 0.0,
                minimumSimHashDistance = 4,
                maximumGrowthRatio = 1.0,
                selectionRate = 1.0,
            ),
        )
        val canonicalizedInput = invalidNoEligibleDex()
        val canonicalized = SafeDexTransformer().transform(
            canonicalizedInput,
            DexTransformRequest(
                ownedDescriptorPrefixes = emptySet(),
                ownedDescriptors = setOf(CANONICALIZED_CLASS),
                salt = "canonicalized-closure".encodeToByteArray(),
                minimumCoverage = 0.0,
                maximumGrowthRatio = 0.0,
                enforceMaximumGrowth = false,
                selectionRate = 1.0,
                allowNoEligibleMethodsSkip = true,
            ),
        )
        assertTrue(canonicalized.report.inputCanonicalized)
        val ordinary = zip(
            "canonicalized-ordinary.aab",
            DEX_PATH to transformedInput,
            CANONICALIZED_DEX_PATH to canonicalizedInput,
        )
        val rewritten = zip(
            "canonicalized-rewritten.aab",
            DEX_PATH to transformed.dexBytes,
            CANONICALIZED_DEX_PATH to canonicalized.dexBytes,
        )
        val manifest = BundleRewriteManifest(
            originalAabSha256 = Sha256.file(ordinary),
            contentSaltSha256 = Sha256.hex("canonicalized-closure".encodeToByteArray()),
            entries = listOf(
                BundleRewriteEntry.transformed(
                    DEX_PATH,
                    Sha256.hex(transformedInput),
                    DEX_PATH,
                    Sha256.hex(transformed.dexBytes),
                    BundleSemanticVerifier.DEX_SEMANTICS,
                ),
                BundleRewriteEntry.transformed(
                    CANONICALIZED_DEX_PATH,
                    Sha256.hex(canonicalizedInput),
                    CANONICALIZED_DEX_PATH,
                    Sha256.hex(canonicalized.dexBytes),
                    BundleSemanticVerifier.DEX_SEMANTICS,
                ),
            ),
        )
        val basePlan = plan(
            sourceHash = Sha256.file(ordinary),
            dexBefore = transformedInput,
            dexAfter = transformed.dexBytes,
            dexMethod = transformed.report.methods.single().toPlannedDexMethod(),
            contentSalt = "canonicalized-closure".encodeToByteArray(),
        )
        val canonicalizedEntry = PlannedDexEntry(
            path = CANONICALIZED_DEX_PATH,
            status = PlannedDexStatus.CANONICALIZED,
            inputSha256 = Sha256.hex(canonicalizedInput),
            outputSha256 = Sha256.hex(canonicalized.dexBytes),
            inputByteCount = canonicalizedInput.size.toLong(),
            outputByteCount = canonicalized.dexBytes.size.toLong(),
            ownedDescriptorCount = 1,
            ownedMethodCount = canonicalized.report.ownedMethodCount,
            eligibleMethodCount = 0,
            transformedMethodCount = 0,
            ownedInstructionCount = canonicalized.report.ownedInstructionCount,
            eligibleInstructionCount = 0,
            transformedInstructionCount = 0,
        )
        val completePlan = basePlan.copy(
            dex = basePlan.dex.copy(
                discoveredOwnedDescriptorCount = 2,
                boundaryAcceptedDescriptorCount = 2,
                entries = basePlan.dex.entries + canonicalizedEntry,
            ),
        )

        assertEquals(
            2,
            BundlePostRewriteSemanticVerifier().verify(
                ordinary,
                rewritten,
                manifest,
                completePlan,
                "canonicalized-closure".encodeToByteArray(),
            ).size,
        )
    }

    @Test
    fun `dex writer const string jumbo widening is not an unreported method change`() {
        val salt = "string-jumbo-writer-canonicalization".encodeToByteArray()
        val originalDex = classesDex(
            listOf(
                fixtureClass(
                    OWNED_CLASS,
                    listOf(
                        fixtureMethod(
                            name = "sum",
                            instructions = listOf(
                                ImmutableInstruction23x(Opcode.ADD_INT, 0, 0, 1),
                                ImmutableInstruction11x(Opcode.RETURN, 0),
                            ),
                            registerCount = 2,
                            parameterTypes = listOf("I", "I"),
                            returnType = "I",
                        ),
                    ),
                ),
                stringCarrierClass(Opcode.CONST_STRING),
            ),
        )
        val transformation = SafeDexTransformer().transform(
            originalDex,
            DexTransformRequest(
                ownedDescriptorPrefixes = emptySet(),
                ownedDescriptors = setOf(OWNED_CLASS),
                salt = salt,
                minimumCoverage = 0.0,
                minimumSimHashDistance = 4,
                maximumGrowthRatio = 0.0,
                enforceMaximumGrowth = false,
                selectionRate = 1.0,
            ),
        )
        val transformedOwnedClass = DexBackedDexFile.fromInputStream(null, transformation.dexBytes.inputStream())
            .classes.single { it.type == OWNED_CLASS }
            .let(ImmutableClassDef::of)
        val rewrittenDex = classesDex(
            listOf(
                transformedOwnedClass,
                stringCarrierClass(Opcode.CONST_STRING_JUMBO),
            ),
        )
        assertEquals(Opcode.CONST_STRING, dexInstructions(originalDex, "stringValue").first().opcode)
        assertEquals(Opcode.CONST_STRING_JUMBO, dexInstructions(rewrittenDex, "stringValue").first().opcode)

        val ordinary = zip("string-jumbo-ordinary.aab", DEX_PATH to originalDex)
        val rewritten = zip("string-jumbo-rewritten.aab", DEX_PATH to rewrittenDex)
        val manifest = manifest(
            ordinary,
            DEX_PATH,
            originalDex,
            DEX_PATH,
            rewrittenDex,
            BundleSemanticVerifier.DEX_SEMANTICS,
            salt,
        )
        val semanticPlan = plan(
            sourceHash = Sha256.file(ordinary),
            dexBefore = originalDex,
            dexAfter = rewrittenDex,
            dexMethod = transformation.report.methods.single { it.reason == MethodEligibilityReason.TRANSFORMED }
                .toPlannedDexMethod(),
            contentSalt = salt,
        )

        assertEquals(
            1,
            BundlePostRewriteSemanticVerifier().verify(
                ordinary,
                rewritten,
                manifest,
                semanticPlan,
                salt,
            ).size,
        )
    }

    @Test
    fun `dex writer goto widening preserves the logical target but rejects a changed target`() {
        val salt = "goto-writer-canonicalization".encodeToByteArray()
        val originalDex = classesDex(
            listOf(
                fixtureClass(
                    OWNED_CLASS,
                    listOf(
                        fixtureMethod(
                            name = "sum",
                            instructions = listOf(
                                ImmutableInstruction23x(Opcode.ADD_INT, 0, 0, 1),
                                ImmutableInstruction11x(Opcode.RETURN, 0),
                            ),
                            registerCount = 2,
                            parameterTypes = listOf("I", "I"),
                            returnType = "I",
                        ),
                    ),
                ),
                gotoCarrierClass(Opcode.GOTO),
            ),
        )
        val transformation = SafeDexTransformer().transform(
            originalDex,
            DexTransformRequest(
                ownedDescriptorPrefixes = emptySet(),
                ownedDescriptors = setOf(OWNED_CLASS),
                salt = salt,
                minimumCoverage = 0.0,
                minimumSimHashDistance = 4,
                maximumGrowthRatio = 0.0,
                enforceMaximumGrowth = false,
                selectionRate = 1.0,
            ),
        )
        val transformedOwnedClass = DexBackedDexFile.fromInputStream(null, transformation.dexBytes.inputStream())
            .classes.single { it.type == OWNED_CLASS }
            .let(ImmutableClassDef::of)
        val rewrittenDex = classesDex(
            listOf(
                transformedOwnedClass,
                gotoCarrierClass(Opcode.GOTO_16),
            ),
        )
        assertEquals(Opcode.GOTO, dexInstructions(originalDex, "gotoValue").first().opcode)
        assertEquals(Opcode.GOTO_16, dexInstructions(rewrittenDex, "gotoValue").first().opcode)

        val ordinary = zip("goto-ordinary.aab", DEX_PATH to originalDex)
        val rewritten = zip("goto-rewritten.aab", DEX_PATH to rewrittenDex)
        val manifest = manifest(
            ordinary,
            DEX_PATH,
            originalDex,
            DEX_PATH,
            rewrittenDex,
            BundleSemanticVerifier.DEX_SEMANTICS,
            salt,
        )
        val semanticPlan = plan(
            sourceHash = Sha256.file(ordinary),
            dexBefore = originalDex,
            dexAfter = rewrittenDex,
            dexMethod = transformation.report.methods.single { it.reason == MethodEligibilityReason.TRANSFORMED }
                .toPlannedDexMethod(),
            contentSalt = salt,
        )

        assertEquals(
            1,
            BundlePostRewriteSemanticVerifier().verify(
                ordinary,
                rewritten,
                manifest,
                semanticPlan,
                salt,
            ).size,
        )

        val changedTargetDex = classesDex(
            listOf(
                transformedOwnedClass,
                gotoCarrierClass(Opcode.GOTO_16, 3),
            ),
        )
        val changedTarget = zip("goto-changed-target.aab", DEX_PATH to changedTargetDex)
        val changedTargetManifest = manifest(
            ordinary,
            DEX_PATH,
            originalDex,
            DEX_PATH,
            changedTargetDex,
            BundleSemanticVerifier.DEX_SEMANTICS,
            salt,
        )
        val changedTargetPlan = plan(
            sourceHash = Sha256.file(ordinary),
            dexBefore = originalDex,
            dexAfter = changedTargetDex,
            dexMethod = transformation.report.methods.single { it.reason == MethodEligibilityReason.TRANSFORMED }
                .toPlannedDexMethod(),
            contentSalt = salt,
        )

        val failure = assertFailsWith<IllegalArgumentException> {
            BundlePostRewriteSemanticVerifier().verify(
                ordinary,
                changedTarget,
                changedTargetManifest,
                changedTargetPlan,
                salt,
            )
        }
        assertTrue(failure.message.orEmpty().contains("changed canonicalized instructions"))
    }

    @Test
    fun `dex writer payload alignment nop after jumbo widening is not an unreported method change`() {
        val salt = "string-jumbo-payload-alignment".encodeToByteArray()
        val originalDex = classesDex(
            listOf(
                fixtureClass(
                    OWNED_CLASS,
                    listOf(
                        fixtureMethod(
                            name = "sum",
                            instructions = listOf(
                                ImmutableInstruction23x(Opcode.ADD_INT, 0, 0, 1),
                                ImmutableInstruction11x(Opcode.RETURN, 0),
                            ),
                            registerCount = 2,
                            parameterTypes = listOf("I", "I"),
                            returnType = "I",
                        ),
                    ),
                ),
                stringSwitchCarrierClass(Opcode.CONST_STRING),
            ),
        )
        val transformation = SafeDexTransformer().transform(
            originalDex,
            DexTransformRequest(
                ownedDescriptorPrefixes = emptySet(),
                ownedDescriptors = setOf(OWNED_CLASS),
                salt = salt,
                minimumCoverage = 0.0,
                minimumSimHashDistance = 4,
                maximumGrowthRatio = 0.0,
                enforceMaximumGrowth = false,
                selectionRate = 1.0,
            ),
        )
        val transformedOwnedClass = DexBackedDexFile.fromInputStream(null, transformation.dexBytes.inputStream())
            .classes.single { it.type == OWNED_CLASS }
            .let(ImmutableClassDef::of)
        val rewrittenDex = classesDex(
            listOf(
                transformedOwnedClass,
                stringSwitchCarrierClass(Opcode.CONST_STRING_JUMBO),
            ),
        )
        assertEquals(
            listOf(Opcode.CONST_STRING, Opcode.PACKED_SWITCH, Opcode.RETURN_OBJECT, Opcode.PACKED_SWITCH_PAYLOAD),
            dexInstructions(originalDex, "stringSwitch").map(Instruction::getOpcode),
        )
        assertEquals(
            listOf(
                Opcode.CONST_STRING_JUMBO,
                Opcode.PACKED_SWITCH,
                Opcode.RETURN_OBJECT,
                Opcode.NOP,
                Opcode.PACKED_SWITCH_PAYLOAD,
            ),
            dexInstructions(rewrittenDex, "stringSwitch").map(Instruction::getOpcode),
        )

        val ordinary = zip("string-jumbo-switch-ordinary.aab", DEX_PATH to originalDex)
        val rewritten = zip("string-jumbo-switch-rewritten.aab", DEX_PATH to rewrittenDex)
        val manifest = manifest(
            ordinary,
            DEX_PATH,
            originalDex,
            DEX_PATH,
            rewrittenDex,
            BundleSemanticVerifier.DEX_SEMANTICS,
            salt,
        )
        val semanticPlan = plan(
            sourceHash = Sha256.file(ordinary),
            dexBefore = originalDex,
            dexAfter = rewrittenDex,
            dexMethod = transformation.report.methods.single { it.reason == MethodEligibilityReason.TRANSFORMED }
                .toPlannedDexMethod(),
            contentSalt = salt,
        )

        assertEquals(
            1,
            BundlePostRewriteSemanticVerifier().verify(
                ordinary,
                rewritten,
                manifest,
                semanticPlan,
                salt,
            ).size,
        )
    }

    @Test
    fun `independent verifier rejects packed and sparse cases retargeted from payload alignment nops`() {
        val ownedClass = fixtureClass(
            OWNED_CLASS,
            listOf(
                fixtureMethod(
                    name = "sum",
                    instructions = listOf(
                        ImmutableInstruction23x(Opcode.ADD_INT, 0, 0, 1),
                        ImmutableInstruction11x(Opcode.RETURN, 0),
                    ),
                    registerCount = 2,
                    parameterTypes = listOf("I", "I"),
                    returnType = "I",
                ),
            ),
        )
        listOf(Opcode.PACKED_SWITCH, Opcode.SPARSE_SWITCH).forEach { opcode ->
            val salt = "switch-case-alignment-${opcode.name}".encodeToByteArray()
            val originalDex = classesDex(
                listOf(ownedClass, switchCaseAlignmentCarrierClass(opcode, targetOffset = 3)),
            )
            val transformation = SafeDexTransformer().transform(
                originalDex,
                DexTransformRequest(
                    ownedDescriptorPrefixes = emptySet(),
                    ownedDescriptors = setOf(OWNED_CLASS),
                    salt = salt,
                    minimumCoverage = 0.0,
                    minimumSimHashDistance = 4,
                    maximumGrowthRatio = 0.0,
                    enforceMaximumGrowth = false,
                    selectionRate = 1.0,
                ),
            )
            val transformedOwnedClass = DexBackedDexFile.fromInputStream(null, transformation.dexBytes.inputStream())
                .classes.single { it.type == OWNED_CLASS }
                .let(ImmutableClassDef::of)
            val rewrittenDex = classesDex(
                listOf(transformedOwnedClass, switchCaseAlignmentCarrierClass(opcode, targetOffset = 4)),
            )
            val ordinary = zip("${opcode.name}-case-target-ordinary.aab", DEX_PATH to originalDex)
            val rewritten = zip("${opcode.name}-case-target-rewritten.aab", DEX_PATH to rewrittenDex)
            val manifest = manifest(
                ordinary,
                DEX_PATH,
                originalDex,
                DEX_PATH,
                rewrittenDex,
                BundleSemanticVerifier.DEX_SEMANTICS,
                salt,
            )
            val semanticPlan = plan(
                sourceHash = Sha256.file(ordinary),
                dexBefore = originalDex,
                dexAfter = rewrittenDex,
                dexMethod = transformation.report.methods.single { it.reason == MethodEligibilityReason.TRANSFORMED }
                    .toPlannedDexMethod(),
                contentSalt = salt,
            )

            assertFailsWith<IllegalArgumentException>(opcode.name) {
                BundlePostRewriteSemanticVerifier().verify(
                    ordinary,
                    rewritten,
                    manifest,
                    semanticPlan,
                    salt,
                )
            }
        }
    }

    @Test
    fun `dex writer switch element offsets after jumbo widening are not an unreported method change`() {
        val salt = "string-jumbo-switch-element-offsets".encodeToByteArray()
        val originalDex = classesDex(
            listOf(
                fixtureClass(
                    OWNED_CLASS,
                    listOf(
                        fixtureMethod(
                            "sum",
                            listOf(
                                ImmutableInstruction23x(Opcode.ADD_INT, 0, 0, 1),
                                ImmutableInstruction11x(Opcode.RETURN, 0),
                            ),
                            2,
                            listOf("I", "I"),
                            "I",
                        ),
                    ),
                ),
                stringAfterSwitchCarrierClass(Opcode.CONST_STRING),
            ),
        )
        val transformation = SafeDexTransformer().transform(
            originalDex,
            DexTransformRequest(
                emptySet(),
                setOf(OWNED_CLASS),
                salt,
                0.0,
                4,
                0.0,
                false,
                1.0,
            ),
        )
        val transformedOwnedClass = DexBackedDexFile.fromInputStream(null, transformation.dexBytes.inputStream())
            .classes.single { it.type == OWNED_CLASS }
            .let(ImmutableClassDef::of)
        val rewrittenDex = classesDex(
            listOf(
                transformedOwnedClass,
                stringAfterSwitchCarrierClass(Opcode.CONST_STRING_JUMBO),
            ),
        )
        assertEquals(
            listOf(Opcode.PACKED_SWITCH, Opcode.CONST_STRING, Opcode.RETURN_OBJECT, Opcode.PACKED_SWITCH_PAYLOAD),
            dexInstructions(originalDex, "stringAfterSwitch").map(Instruction::getOpcode),
        )
        assertEquals(
            listOf(
                Opcode.PACKED_SWITCH,
                Opcode.CONST_STRING_JUMBO,
                Opcode.RETURN_OBJECT,
                Opcode.NOP,
                Opcode.PACKED_SWITCH_PAYLOAD,
            ),
            dexInstructions(rewrittenDex, "stringAfterSwitch").map(Instruction::getOpcode),
        )

        val ordinary = zip("string-jumbo-switch-offsets-ordinary.aab", DEX_PATH to originalDex)
        val rewritten = zip("string-jumbo-switch-offsets-rewritten.aab", DEX_PATH to rewrittenDex)
        val manifest = manifest(
            ordinary,
            DEX_PATH,
            originalDex,
            DEX_PATH,
            rewrittenDex,
            BundleSemanticVerifier.DEX_SEMANTICS,
            salt,
        )
        val semanticPlan = plan(
            sourceHash = Sha256.file(ordinary),
            dexBefore = originalDex,
            dexAfter = rewrittenDex,
            dexMethod = transformation.report.methods.single { it.reason == MethodEligibilityReason.TRANSFORMED }
                .toPlannedDexMethod(),
            contentSalt = salt,
        )

        assertEquals(
            1,
            BundlePostRewriteSemanticVerifier().verify(
                ordinary,
                rewritten,
                manifest,
                semanticPlan,
                salt,
            ).size,
        )
    }

    @Test
    fun `debug line inside a multi code unit instruction retains its semantic instruction`() {
        val originalDex = dex(Opcode.ADD_INT, includeNop = false, debugLineAddress = 1)
        val transformation = SafeDexTransformer().transform(
            originalDex,
            DexTransformRequest(
                ownedDescriptorPrefixes = emptySet(),
                ownedDescriptors = setOf(OWNED_CLASS),
                salt = "interior-debug-line".encodeToByteArray(),
                minimumCoverage = 0.0,
                minimumSimHashDistance = 4,
                maximumGrowthRatio = 0.0,
                enforceMaximumGrowth = false,
                selectionRate = 1.0,
            ),
        )
        val ordinary = zip("debug-ordinary.aab", DEX_PATH to originalDex)
        val rewritten = zip("debug-rewritten.aab", DEX_PATH to transformation.dexBytes)
        val manifest = manifest(
            ordinary,
            DEX_PATH,
            originalDex,
            DEX_PATH,
            transformation.dexBytes,
            BundleSemanticVerifier.DEX_SEMANTICS,
            "interior-debug-line".encodeToByteArray(),
        )
        val plan = plan(
            Sha256.file(ordinary),
            originalDex,
            transformation.dexBytes,
            dexMethod = transformation.report.methods.single().toPlannedDexMethod(),
            contentSalt = "interior-debug-line".encodeToByteArray(),
        )

        assertEquals(
            1,
            BundlePostRewriteSemanticVerifier().verify(
                ordinary,
                rewritten,
                manifest,
                plan,
                "interior-debug-line".encodeToByteArray(),
            ).size,
        )
    }

    @Test
    fun `debug line on a nop retains its semantic boundary`() {
        val originalDex = dex(Opcode.ADD_INT, includeNop = true, debugLineAddress = 0)
        val transformation = SafeDexTransformer().transform(
            originalDex,
            DexTransformRequest(
                ownedDescriptorPrefixes = emptySet(),
                ownedDescriptors = setOf(OWNED_CLASS),
                salt = "nop-debug-line".encodeToByteArray(),
                minimumCoverage = 0.0,
                minimumSimHashDistance = 4,
                maximumGrowthRatio = 0.0,
                enforceMaximumGrowth = false,
                selectionRate = 1.0,
            ),
        )
        val ordinary = zip("nop-debug-ordinary.aab", DEX_PATH to originalDex)
        val rewritten = zip("nop-debug-rewritten.aab", DEX_PATH to transformation.dexBytes)
        val manifest = manifest(
            ordinary,
            DEX_PATH,
            originalDex,
            DEX_PATH,
            transformation.dexBytes,
            BundleSemanticVerifier.DEX_SEMANTICS,
            "nop-debug-line".encodeToByteArray(),
        )
        val plan = plan(
            Sha256.file(ordinary),
            originalDex,
            transformation.dexBytes,
            dexMethod = transformation.report.methods.single().toPlannedDexMethod(),
            contentSalt = "nop-debug-line".encodeToByteArray(),
        )

        assertEquals(
            1,
            BundlePostRewriteSemanticVerifier().verify(
                ordinary,
                rewritten,
                manifest,
                plan,
                "nop-debug-line".encodeToByteArray(),
            ).size,
        )
    }

    @Test
    fun `independent verifier rejects a forged transformed method SimHash distance`() {
        val originalDex = dex(Opcode.ADD_INT, includeNop = false)
        val transformation = SafeDexTransformer().transform(
            originalDex,
            DexTransformRequest(
                ownedDescriptorPrefixes = emptySet(),
                ownedDescriptors = setOf(OWNED_CLASS),
                salt = "simhash-tamper-test".encodeToByteArray(),
                minimumCoverage = 0.0,
                minimumSimHashDistance = 4,
                maximumGrowthRatio = 1.0,
                selectionRate = 1.0,
            ),
        )
        val ordinary = zip("simhash-ordinary.aab", DEX_PATH to originalDex)
        val rewritten = zip("simhash-rewritten.aab", DEX_PATH to transformation.dexBytes)
        val manifest = manifest(
            ordinary,
            DEX_PATH,
            originalDex,
            DEX_PATH,
            transformation.dexBytes,
            BundleSemanticVerifier.DEX_SEMANTICS,
        )
        val actual = transformation.report.methods.single().toPlannedDexMethod()
        val forgedDistance = if (actual.simHashDistance == 64) 63 else actual.simHashDistance + 1
        val forged = plan(
            Sha256.file(ordinary),
            originalDex,
            transformation.dexBytes,
            dexMethod = actual.copy(simHashDistance = forgedDistance),
        )

        val failure = assertFailsWith<IllegalArgumentException> {
            BundlePostRewriteSemanticVerifier().verify(ordinary, rewritten, manifest, forged)
        }

        assertTrue(failure.message.orEmpty().contains("SimHash distance"))
    }

    @Test
    fun `resource table verifier rejects changes outside declared name path and marker`() {
        val original = resourceTable(packageName = "com.example.demo.fixture", entryName = "hero")
        val unauthorized = resourceTable(packageName = "com.example.demo.changed", entryName = "hardened_hero")
        val transformed = ProtoResourceDiversifier().diversifyResourceTable(
            unauthorized,
            "resource-test-salt".encodeToByteArray(),
        )
        val ordinary = zip("resource-ordinary.aab", RESOURCES_PATH to original)
        val rewritten = zip("resource-rewritten.aab", RESOURCES_PATH to transformed)
        val manifest = manifest(
            ordinary,
            RESOURCES_PATH,
            original,
            RESOURCES_PATH,
            transformed,
            BundleSemanticVerifier.RESOURCE_SEMANTICS,
        )
        val plan = plan(
            sourceHash = Sha256.file(ordinary),
            dexBefore = byteArrayOf(1),
            dexAfter = byteArrayOf(2),
            resourceBefore = original,
            resourceAfter = transformed,
        )

        assertFailsWith<IllegalArgumentException> {
            BundlePostRewriteSemanticVerifier().verify(ordinary, rewritten, manifest, plan)
        }
    }

    @Test
    fun `image verifier rejects dimensions and alpha despite a successful planner claim`() {
        val original = png(32, 32, alpha = true)
        val transformed = png(31, 32, alpha = true)
        val oldPath = "base/res/drawable/hero.png"
        val newPath = "base/res/drawable/hardened_hero.png"
        val ordinary = zip("image-ordinary.aab", oldPath to original)
        val rewritten = zip("image-rewritten.aab", newPath to transformed)
        val manifest = manifest(
            ordinary,
            oldPath,
            original,
            newPath,
            transformed,
            BundleSemanticVerifier.RESOURCE_SEMANTICS,
        )
        val image = PlannedImageEntry(
            oldPath = oldPath,
            newPath = newPath,
            status = ImageTransformStatus.TRANSFORMED,
            reason = ImageIneligibilityReason.TRANSFORMED,
            originalSha256 = Sha256.hex(original),
            transformedSha256 = Sha256.hex(transformed),
            width = 32,
            height = 32,
            alphaPreserved = true,
            ssim = 0.999,
            pHashDistance = 11,
        )
        val plan = plan(
            sourceHash = Sha256.file(ordinary),
            dexBefore = byteArrayOf(1),
            dexAfter = byteArrayOf(2),
            resourceBefore = byteArrayOf(3),
            resourceAfter = byteArrayOf(4),
            images = listOf(image),
        )

        assertFailsWith<IllegalArgumentException> {
            BundlePostRewriteSemanticVerifier().verify(ordinary, rewritten, manifest, plan)
        }
    }

    @Test
    fun `dex verifier rejects plan entries outside the manifest and AAB closure`() {
        val originalDex = dex(Opcode.ADD_INT, includeNop = false)
        val transformation = SafeDexTransformer().transform(
            originalDex,
            DexTransformRequest(
                ownedDescriptorPrefixes = emptySet(),
                ownedDescriptors = setOf(OWNED_CLASS),
                salt = "closure-test".encodeToByteArray(),
                minimumCoverage = 0.0,
                minimumSimHashDistance = 4,
                maximumGrowthRatio = 1.0,
                selectionRate = 1.0,
            ),
        )
        val transformedDex = transformation.dexBytes
        val ordinary = zip("closure-ordinary.aab", DEX_PATH to originalDex)
        val rewritten = zip("closure-rewritten.aab", DEX_PATH to transformedDex)
        val manifest = manifest(
            ordinary,
            DEX_PATH,
            originalDex,
            DEX_PATH,
            transformedDex,
            BundleSemanticVerifier.DEX_SEMANTICS,
        )
        val valid = plan(
            Sha256.file(ordinary),
            originalDex,
            transformedDex,
            dexMethod = transformation.report.methods.single().toPlannedDexMethod(),
        )
        val extra = PlannedDexEntry(
            path = "base/dex/classes2.dex",
            status = PlannedDexStatus.WRITER_FLOOR_SKIPPED,
            inputSha256 = "c".repeat(64),
            outputSha256 = "c".repeat(64),
            inputByteCount = 100,
            outputByteCount = 100,
            ownedDescriptorCount = 1,
            ownedMethodCount = 1,
            eligibleMethodCount = 1,
            transformedMethodCount = 0,
            ownedInstructionCount = 1,
            eligibleInstructionCount = 1,
            transformedInstructionCount = 0,
        )
        val inconsistent = valid.copy(
            dex = valid.dex.copy(
                discoveredOwnedDescriptorCount = 2,
                boundaryAcceptedDescriptorCount = 2,
                entries = valid.dex.entries + extra,
            ),
        )

        assertFailsWith<IllegalArgumentException> {
            BundlePostRewriteSemanticVerifier().verify(ordinary, rewritten, manifest, inconsistent)
        }
    }

    private fun BundlePostRewriteSemanticVerifier.verify(
        ordinaryBundle: Path,
        rewrittenBundle: Path,
        manifest: BundleRewriteManifest,
        plan: HardenedBundlePlanReport,
        contentSalt: ByteArray = VERIFIER_CONTENT_SALT,
    ): List<BundleSemanticVerificationResult> = verify(
        ordinaryBundle,
        rewrittenBundle,
        manifest,
        plan,
        contentSalt,
        dexScope(),
    )

    private fun dexScope(
        ownedDescriptors: Set<String> = setOf(OWNED_CLASS, CANONICALIZED_CLASS),
        externalContractMethodIds: Set<String> = emptySet(),
    ) = DexSemanticVerificationScope(
        ownedDescriptors,
        setOf("Lcom/example/demo/match/junkcode/"),
        externalContractMethodIds,
    )

    private fun plan(
        sourceHash: String,
        dexBefore: ByteArray,
        dexAfter: ByteArray,
        resourceBefore: ByteArray = byteArrayOf(3),
        resourceAfter: ByteArray = byteArrayOf(4),
        images: List<PlannedImageEntry> = emptyList(),
        dexMethod: PlannedDexMethod = PlannedDexMethod("$OWNED_CLASS->sum(II)I", 2, 4),
        minimumSimHashDistance: Int = 4,
        contentSalt: ByteArray = VERIFIER_CONTENT_SALT,
    ) = HardenedBundlePlanReport(
        sourceAabSha256 = sourceHash,
        contentSaltSha256 = Sha256.hex(contentSalt),
        namespace = "com.example.demo.fixture",
        generation = 1,
        ownedModules = setOf(":app", ":core", ":compress", ":selector", ":ucrop"),
        dex = PlannedDexSummary(
            discoveredOwnedDescriptorCount = 1,
            boundaryAcceptedDescriptorCount = 1,
            boundaryFilteredDescriptorCount = 0,
            minimumCodeCoverage = 0.0,
            minimumSimHashDistance = minimumSimHashDistance,
            maximumGrowthRatio = 100.0,
            entries = listOf(
                PlannedDexEntry(
                    path = DEX_PATH,
                    status = PlannedDexStatus.TRANSFORMED,
                    inputSha256 = Sha256.hex(dexBefore),
                    outputSha256 = Sha256.hex(dexAfter),
                    inputByteCount = dexBefore.size.toLong(),
                    outputByteCount = dexAfter.size.toLong(),
                    ownedDescriptorCount = 1,
                    ownedMethodCount = 1,
                    eligibleMethodCount = 1,
                    transformedMethodCount = 1,
                    ownedInstructionCount = dexMethod.originalInstructionCount,
                    eligibleInstructionCount = dexMethod.originalInstructionCount,
                    transformedInstructionCount = dexMethod.originalInstructionCount,
                    transformedMethods = listOf(dexMethod),
                ),
            ),
        ),
        resources = PlannedResourceSummary(
            inventoryVariantCount = 1,
            renamedResourceCount = 1,
            renamedFileCount = 0,
            resourcesPbInputSha256 = Sha256.hex(resourceBefore),
            resourcesPbOutputSha256 = Sha256.hex(resourceAfter),
            minimumImageCoverage = 0.0,
            minimumImageSsim = 0.995,
            minimumImagePHashDistance = 11,
            eligibleImageCount = images.size,
            transformedImageCount = images.size,
            imageCoverage = 1.0,
            transformedPngCount = images.count { it.oldPath.endsWith(".png") },
            transformedWebpCount = images.count { it.oldPath.endsWith(".webp") },
            diversifiedProtoXmlCount = 0,
            renames = listOf(PlannedResourceRename(RESOURCE_ID, ResourceType.DRAWABLE, "hero", "hardened_hero", 0)),
            images = images,
        ),
    )

    private fun manifest(
        ordinary: Path,
        oldPath: String,
        before: ByteArray,
        newPath: String,
        after: ByteArray,
        verifier: BundleSemanticVerifier,
        contentSalt: ByteArray = VERIFIER_CONTENT_SALT,
    ) = BundleRewriteManifest(
        originalAabSha256 = Sha256.file(ordinary),
        contentSaltSha256 = Sha256.hex(contentSalt),
        entries = listOf(
            BundleRewriteEntry.transformed(oldPath, Sha256.hex(before), newPath, Sha256.hex(after), verifier),
        ),
    )

    private fun dex(
        operation: Opcode,
        includeNop: Boolean,
        debugLineAddress: Int? = null,
    ): ByteArray {
        val instructions = buildList {
            if (includeNop) add(ImmutableInstruction10x(Opcode.NOP))
            add(ImmutableInstruction23x(operation, 0, 0, 1))
            add(ImmutableInstruction11x(Opcode.RETURN, 0))
        }
        val method = ImmutableMethod(
            OWNED_CLASS,
            "sum",
            listOf(ImmutableMethodParameter("I", emptySet(), null), ImmutableMethodParameter("I", emptySet(), null)),
            "I",
            AccessFlags.PRIVATE.value or AccessFlags.STATIC.value,
            emptySet(),
            emptySet(),
            ImmutableMethodImplementation(
                2,
                instructions,
                emptyList(),
                debugLineAddress?.let { listOf(ImmutableLineNumber(it, 42)) }.orEmpty(),
            ),
        )
        val clazz = ImmutableClassDef(
            OWNED_CLASS,
            AccessFlags.PUBLIC.value,
            "Ljava/lang/Object;",
            emptyList(),
            null,
            emptySet(),
            emptyList(),
            listOf(method),
        )
        val store = MemoryDataStore()
        DexPool.writeTo(store, ImmutableDexFile(Opcodes.getDefault(), listOf(clazz)))
        return store.data
    }

    private fun conditionalDex(): ByteArray {
        val method = ImmutableMethod(
            OWNED_CLASS,
            "conditional",
            listOf(ImmutableMethodParameter("I", emptySet(), null)),
            "I",
            AccessFlags.PRIVATE.value or AccessFlags.STATIC.value,
            emptySet(),
            emptySet(),
            ImmutableMethodImplementation(
                1,
                listOf(
                    ImmutableInstruction21t(Opcode.IF_EQZ, 0, 4),
                    ImmutableInstruction11n(Opcode.CONST_4, 0, 0),
                    ImmutableInstruction11x(Opcode.RETURN, 0),
                    ImmutableInstruction11n(Opcode.CONST_4, 0, 1),
                    ImmutableInstruction11x(Opcode.RETURN, 0),
                ),
                emptyList(),
                listOf(ImmutableLineNumber(0, 10), ImmutableLineNumber(4, 20)),
            ),
        )
        val clazz = ImmutableClassDef(
            OWNED_CLASS,
            AccessFlags.PUBLIC.value,
            "Ljava/lang/Object;",
            emptyList(),
            null,
            emptySet(),
            emptyList(),
            listOf(method),
        )
        val store = MemoryDataStore()
        DexPool.writeTo(store, ImmutableDexFile(Opcodes.getDefault(), listOf(clazz)))
        return store.data
    }

    private fun preExpandedConditionalDex(): ByteArray {
        val method = ImmutableMethod(
            OWNED_CLASS,
            "preExpandedConditional",
            listOf(ImmutableMethodParameter("I", emptySet(), null)),
            "I",
            AccessFlags.PRIVATE.value or AccessFlags.STATIC.value,
            emptySet(),
            emptySet(),
            ImmutableMethodImplementation(
                1,
                listOf(
                    ImmutableInstruction21t(Opcode.IF_NEZ, 0, 5),
                    com.android.tools.smali.dexlib2.immutable.instruction.ImmutableInstruction30t(Opcode.GOTO_32, 5),
                    ImmutableInstruction11n(Opcode.CONST_4, 0, 0),
                    ImmutableInstruction11x(Opcode.RETURN, 0),
                    ImmutableInstruction11n(Opcode.CONST_4, 0, 1),
                    ImmutableInstruction11x(Opcode.RETURN, 0),
                ),
                emptyList(),
                emptyList(),
            ),
        )
        val clazz = ImmutableClassDef(
            OWNED_CLASS,
            AccessFlags.PUBLIC.value,
            "Ljava/lang/Object;",
            emptyList(),
            null,
            emptySet(),
            emptyList(),
            listOf(method),
        )
        val store = MemoryDataStore()
        DexPool.writeTo(store, ImmutableDexFile(Opcodes.getDefault(), listOf(clazz)))
        return store.data
    }

    private fun methodDex(
        name: String,
        instructions: List<Instruction>,
        registerCount: Int,
        parameterTypes: List<String>,
        returnType: String,
        tryBlocks: List<ImmutableTryBlock> = emptyList(),
        accessFlags: Int = AccessFlags.PRIVATE.value or AccessFlags.STATIC.value,
        owner: String = OWNED_CLASS,
    ): ByteArray = classesDex(
        listOf(
            fixtureClass(
                owner,
                listOf(
                    fixtureMethod(
                        name,
                        instructions,
                        registerCount,
                        parameterTypes,
                        returnType,
                        tryBlocks,
                        owner = owner,
                        accessFlags = accessFlags,
                    ),
                ),
            ),
        ),
    )

    private fun relayMethodDex(
        name: String,
        instructions: List<Instruction>,
        tryBlocks: List<ImmutableTryBlock> = emptyList(),
        debugLines: List<ImmutableLineNumber> = emptyList(),
    ): ByteArray {
        val method = ImmutableMethod(
            OWNED_CLASS,
            name,
            emptyList(),
            "V",
            AccessFlags.PRIVATE.value or AccessFlags.STATIC.value,
            emptySet(),
            emptySet(),
            ImmutableMethodImplementation(1, instructions, tryBlocks, debugLines),
        )
        return methodsDex(listOf(method))
    }

    private fun fixtureMethod(
        name: String,
        instructions: List<Instruction>,
        registerCount: Int,
        parameterTypes: List<String>,
        returnType: String,
        tryBlocks: List<ImmutableTryBlock> = emptyList(),
        owner: String = OWNED_CLASS,
        accessFlags: Int = AccessFlags.PRIVATE.value or AccessFlags.STATIC.value,
    ) = ImmutableMethod(
        owner,
        name,
        parameterTypes.map { ImmutableMethodParameter(it, emptySet(), null) },
        returnType,
        accessFlags,
        emptySet(),
        emptySet(),
        ImmutableMethodImplementation(registerCount, instructions, tryBlocks, emptyList()),
    )

    private fun fixtureClass(type: String, methods: List<ImmutableMethod>) =
        ImmutableClassDef(
            type,
            AccessFlags.PUBLIC.value,
            "Ljava/lang/Object;",
            emptyList(),
            null,
            emptySet(),
            emptyList(),
            methods,
        )

    private fun stringCarrierClass(opcode: Opcode): ImmutableClassDef {
        val stringInstruction = when (opcode) {
            Opcode.CONST_STRING -> ImmutableInstruction21c(
                opcode,
                0,
                ImmutableStringReference("timestamp is not ISO format "),
            )
            Opcode.CONST_STRING_JUMBO -> ImmutableInstruction31c(
                opcode,
                0,
                ImmutableStringReference("timestamp is not ISO format "),
            )
            else -> error("unsupported string opcode: $opcode")
        }
        return fixtureClass(
            "Lthird/party/StringCarrier;",
            listOf(
                fixtureMethod(
                    name = "stringValue",
                    instructions = listOf(stringInstruction, ImmutableInstruction11x(Opcode.RETURN_OBJECT, 0)),
                    registerCount = 1,
                    parameterTypes = emptyList(),
                    returnType = "Ljava/lang/String;",
                    owner = "Lthird/party/StringCarrier;",
                ),
            ),
        )
    }

    private fun gotoCarrierClass(opcode: Opcode, codeOffset: Int = if (opcode == Opcode.GOTO) 3 else 4): ImmutableClassDef {
        val gotoInstruction = when (opcode) {
            Opcode.GOTO -> ImmutableInstruction10t(opcode, codeOffset)
            Opcode.GOTO_16 -> ImmutableInstruction20t(opcode, codeOffset)
            else -> error("unsupported goto opcode: $opcode")
        }
        return fixtureClass(
            "Lthird/party/GotoCarrier;",
            listOf(
                fixtureMethod(
                    name = "gotoValue",
                    instructions = listOf(
                        gotoInstruction,
                        ImmutableInstruction11n(Opcode.CONST_4, 0, 0),
                        ImmutableInstruction11x(Opcode.RETURN, 0),
                        ImmutableInstruction11n(Opcode.CONST_4, 0, 1),
                        ImmutableInstruction11x(Opcode.RETURN, 0),
                    ),
                    registerCount = 1,
                    parameterTypes = emptyList(),
                    returnType = "I",
                    owner = "Lthird/party/GotoCarrier;",
                ),
            ),
        )
    }

    private fun stringSwitchCarrierClass(opcode: Opcode): ImmutableClassDef {
        val stringInstruction = when (opcode) {
            Opcode.CONST_STRING -> ImmutableInstruction21c(
                opcode,
                0,
                ImmutableStringReference("values="),
            )
            Opcode.CONST_STRING_JUMBO -> ImmutableInstruction31c(
                opcode,
                0,
                ImmutableStringReference("values="),
            )
            else -> error("unsupported string opcode: $opcode")
        }
        val payloadOffset = if (opcode == Opcode.CONST_STRING) 4 else 5
        return fixtureClass(
            "Lthird/party/StringSwitchCarrier;",
            listOf(
                fixtureMethod(
                    name = "stringSwitch",
                    instructions = buildList {
                        add(stringInstruction)
                        add(ImmutableInstruction31t(Opcode.PACKED_SWITCH, 1, payloadOffset))
                        add(ImmutableInstruction11x(Opcode.RETURN_OBJECT, 0))
                        if (opcode == Opcode.CONST_STRING_JUMBO) add(ImmutableInstruction10x(Opcode.NOP))
                        add(ImmutablePackedSwitchPayload(listOf(ImmutableSwitchElement(0, 3))))
                    },
                    registerCount = 2,
                    parameterTypes = listOf("I"),
                    returnType = "Ljava/lang/String;",
                    owner = "Lthird/party/StringSwitchCarrier;",
                ),
            ),
        )
    }

    private fun stringAfterSwitchCarrierClass(opcode: Opcode): ImmutableClassDef {
        val stringInstruction = when (opcode) {
            Opcode.CONST_STRING -> ImmutableInstruction21c(
                opcode,
                0,
                ImmutableStringReference("unexpected"),
            )
            Opcode.CONST_STRING_JUMBO -> ImmutableInstruction31c(
                opcode,
                0,
                ImmutableStringReference("unexpected"),
            )
            else -> error("unsupported string opcode: $opcode")
        }
        val jumbo = opcode == Opcode.CONST_STRING_JUMBO
        return fixtureClass(
            "Lthird/party/StringAfterSwitchCarrier;",
            listOf(
                fixtureMethod(
                    name = "stringAfterSwitch",
                    instructions = buildList {
                        add(ImmutableInstruction31t(Opcode.PACKED_SWITCH, 1, if (jumbo) 8 else 6))
                        add(stringInstruction)
                        add(ImmutableInstruction11x(Opcode.RETURN_OBJECT, 0))
                        if (jumbo) add(ImmutableInstruction10x(Opcode.NOP))
                        add(
                            ImmutablePackedSwitchPayload(
                                listOf(
                                    ImmutableSwitchElement(0, 3),
                                    ImmutableSwitchElement(1, if (jumbo) 6 else 5),
                                ),
                            ),
                        )
                    },
                    registerCount = 2,
                    parameterTypes = listOf("I"),
                    returnType = "Ljava/lang/String;",
                    owner = "Lthird/party/StringAfterSwitchCarrier;",
                ),
            ),
        )
    }

    private fun switchCaseAlignmentCarrierClass(opcode: Opcode, targetOffset: Int): ImmutableClassDef {
        val payload = when (opcode) {
            Opcode.PACKED_SWITCH -> ImmutablePackedSwitchPayload(
                listOf(ImmutableSwitchElement(0, targetOffset)),
            )
            Opcode.SPARSE_SWITCH -> ImmutableSparseSwitchPayload(
                listOf(ImmutableSwitchElement(0, targetOffset)),
            )
            else -> error("unsupported switch opcode: $opcode")
        }
        return fixtureClass(
            "Lthird/party/SwitchCaseAlignmentCarrier;",
            listOf(
                fixtureMethod(
                    name = "caseTarget",
                    instructions = listOf(
                        ImmutableInstruction11n(Opcode.CONST_4, 0, 0),
                        ImmutableInstruction10x(Opcode.NOP),
                        ImmutableInstruction31t(opcode, 0, 4),
                        ImmutableInstruction10x(Opcode.NOP),
                        payload,
                    ),
                    registerCount = 1,
                    parameterTypes = emptyList(),
                    returnType = "V",
                    owner = "Lthird/party/SwitchCaseAlignmentCarrier;",
                ),
            ),
        )
    }

    private fun methodsDex(methods: List<ImmutableMethod>): ByteArray =
        classesDex(listOf(fixtureClass(OWNED_CLASS, methods)))

    private fun classesDex(classes: List<ImmutableClassDef>): ByteArray {
        val store = MemoryDataStore()
        DexPool.writeTo(store, ImmutableDexFile(Opcodes.getDefault(), classes))
        return store.data
    }

    private fun dexInstructions(bytes: ByteArray, name: String): List<Instruction> =
        DexBackedDexFile.fromInputStream(null, bytes.inputStream())
            .classes.flatMap { it.methods }
            .single { it.name == name }
            .implementation!!.instructions.toList()

    private fun invalidNoEligibleDex(): ByteArray {
        val implementation = ImmutableMethodImplementation(
            0,
            listOf(ImmutableInstruction10x(Opcode.RETURN_VOID)),
            emptyList(),
            emptyList(),
        )
        fun method(owner: String, name: String, flags: Int) = ImmutableMethod(
            owner,
            name,
            emptyList(),
            "V",
            flags,
            emptySet(),
            emptySet(),
            implementation,
        )
        val classes = listOf(
            ImmutableClassDef(
                CANONICALIZED_CLASS,
                AccessFlags.PUBLIC.value,
                "Ljava/lang/Object;",
                emptyList(),
                null,
                emptySet(),
                emptyList(),
                listOf(
                    method(
                        CANONICALIZED_CLASS,
                        "<clinit>",
                        AccessFlags.STATIC.value or AccessFlags.CONSTRUCTOR.value,
                    ),
                ),
            ),
            ImmutableClassDef(
                "Lthird/party/CanonicalizationFixture;",
                AccessFlags.PUBLIC.value,
                "Ljava/lang/Object;",
                emptyList(),
                null,
                emptySet(),
                emptyList(),
                listOf(
                    method("Lthird/party/CanonicalizationFixture;", "alpha", AccessFlags.STATIC.value),
                    method("Lthird/party/CanonicalizationFixture;", "beta", AccessFlags.STATIC.value),
                ),
            ),
        )
        val store = MemoryDataStore()
        DexPool.writeTo(store, ImmutableDexFile(Opcodes.getDefault(), classes))
        val bytes = store.data
        val buffer = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN)
        val methodIdsSize = buffer.getInt(0x58)
        val methodIdsOffset = buffer.getInt(0x5c)
        val sourceOffset = methodIdsOffset + (methodIdsSize - 2) * METHOD_ID_ITEM_SIZE
        bytes.copyInto(
            destination = bytes,
            destinationOffset = sourceOffset + METHOD_ID_ITEM_SIZE,
            startIndex = sourceOffset,
            endIndex = sourceOffset + METHOD_ID_ITEM_SIZE,
        )
        MessageDigest.getInstance("SHA-1")
            .digest(bytes.copyOfRange(32, bytes.size))
            .copyInto(bytes, 12)
        buffer.putInt(
            8,
            Adler32().apply { update(bytes, 12, bytes.size - 12) }.value.toInt(),
        )
        return bytes
    }

    private fun com.holin.android.hardening.dex.MethodTransformationReport.toPlannedDexMethod() =
        PlannedDexMethod(methodId, oldInstructionCount, simHashDistance, insertedOpaqueDiamondCount)

    private fun resourceTable(packageName: String, entryName: String): ByteArray =
        Resources.ResourceTable.newBuilder().addPackage(
            Resources.Package.newBuilder()
                .setPackageId(Resources.PackageId.newBuilder().setId(0x7f))
                .setPackageName(packageName)
                .addType(
                    Resources.Type.newBuilder()
                        .setTypeId(Resources.TypeId.newBuilder().setId(2))
                        .setName("drawable")
                        .addEntry(
                            Resources.Entry.newBuilder()
                                .setEntryId(Resources.EntryId.newBuilder().setId(1))
                                .setName(entryName),
                        ),
                ),
        ).build().toByteArray()

    private fun png(width: Int, height: Int, alpha: Boolean): ByteArray {
        val image = BufferedImage(width, height, if (alpha) BufferedImage.TYPE_INT_ARGB else BufferedImage.TYPE_INT_RGB)
        for (y in 0 until height) for (x in 0 until width) {
            image.setRGB(x, y, ((if (alpha) 128 else 255) shl 24) or ((x * 17 and 0xff) shl 16) or (y * 19 and 0xff))
        }
        return ByteArrayOutputStream().use { output ->
            check(ImageIO.write(image, "png", output))
            output.toByteArray()
        }
    }

    private fun zip(name: String, vararg entries: Pair<String, ByteArray>): Path = temporary.resolve(name).also { path ->
        ZipOutputStream(Files.newOutputStream(path)).use { output ->
            entries.forEach { (entryName, bytes) ->
                output.putNextEntry(ZipEntry(entryName))
                output.write(bytes)
                output.closeEntry()
            }
        }
    }

    private companion object {
        val VERIFIER_CONTENT_SALT = "bundle-post-rewrite-semantic-verifier".encodeToByteArray()
        const val CONTENT_SALT_AGREEMENT_FAILURE =
            "semantic verification plan and manifest content salt hashes differ"
        const val CONTENT_SALT_PLAN_FAILURE = "semantic verification content salt does not match the plan"
        const val EXACT_MARKER_FAILURE = "marker values do not match content salt and method id"
        const val OWNED_CLASS = "Lcom/example/demo/fixture/Calculator;"
        const val CANONICALIZED_CLASS = "Lcom/example/demo/fixture/Canonicalized;"
        const val DEX_PATH = "base/dex/classes.dex"
        const val CANONICALIZED_DEX_PATH = "base/dex/classes2.dex"
        const val METHOD_ID_ITEM_SIZE = 8
        const val RESOURCES_PATH = "base/resources.pb"
        const val RESOURCE_ID = 0x7f020001
    }
}
