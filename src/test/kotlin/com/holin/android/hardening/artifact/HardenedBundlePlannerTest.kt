package com.holin.android.hardening.artifact

import com.android.aapt.Resources
import com.android.tools.smali.dexlib2.AccessFlags
import com.android.tools.smali.dexlib2.Opcode
import com.android.tools.smali.dexlib2.Opcodes
import com.android.tools.smali.dexlib2.dexbacked.DexBackedDexFile
import com.android.tools.smali.dexlib2.immutable.ImmutableClassDef
import com.android.tools.smali.dexlib2.immutable.ImmutableDexFile
import com.android.tools.smali.dexlib2.immutable.ImmutableMethod
import com.android.tools.smali.dexlib2.immutable.ImmutableMethodImplementation
import com.android.tools.smali.dexlib2.immutable.instruction.ImmutableInstruction10x
import com.android.tools.smali.dexlib2.immutable.instruction.ImmutableInstruction35c
import com.android.tools.smali.dexlib2.immutable.reference.ImmutableMethodReference
import com.android.tools.smali.dexlib2.writer.io.MemoryDataStore
import com.android.tools.smali.dexlib2.writer.pool.DexPool
import com.holin.android.hardening.testHardeningOwnership
import com.holin.android.hardening.HardcodedReferenceKind
import com.holin.android.hardening.HardeningOwnership
import com.holin.android.hardening.ImageFormat
import com.holin.android.hardening.naming.PseudowordRegistry
import com.holin.android.hardening.naming.AliasRequest
import com.holin.android.hardening.naming.RegistryKey
import com.holin.android.hardening.naming.SymbolKind
import com.holin.android.hardening.resources.ImageIneligibilityReason
import com.holin.android.hardening.resources.ImageTransformStatus
import com.holin.android.hardening.resources.ResourceType
import com.holin.android.hardening.state.Sha256
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.file.Files
import java.nio.file.Path
import java.security.MessageDigest
import java.util.zip.Adler32
import java.util.zip.ZipEntry
import java.util.zip.ZipFile
import java.util.zip.ZipOutputStream
import java.awt.image.BufferedImage
import java.io.ByteArrayOutputStream
import javax.imageio.ImageIO
import kotlin.io.path.createDirectories
import kotlin.io.path.writeBytes
import kotlin.io.path.writeText
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue
import org.junit.jupiter.api.io.TempDir

class HardenedBundlePlannerTest {
    @TempDir
    lateinit var repository: Path

    @Test
    fun `planner protects exactly enabled in scope hardcoded resource findings`() {
        fixtureRepository()
        repository.resolve("app/src/main/java/com/example/demo/match/Calculator.kt").writeText(
            """
            package com.example.demo.match

            class Calculator {
                fun resolve(resources: android.content.res.Resources): Int =
                    resources.getIdentifier("home", "layout", "com.example.demo.app") +
                        resources.getIdentifier("other", "layout", "android") +
                        resources.getIdentifier("other", "layout", "com.other")
            }
            """.trimIndent(),
        )
        repository.resolve("app/src/main/res/layout/other.xml").writeText("<FrameLayout/>")
        val ordinary = repository.resolve("hardcoded-resource.aab")
        zip(
            ordinary,
            mapOf(
                "base/dex/classes.dex" to dex(OWNED_DESCRIPTOR),
                "base/resources.pb" to resourcesTableWithOtherLayout(),
                "base/res/layout/home.xml" to compiledXml(),
                "base/res/layout/other.xml" to compiledXml(),
                "base/res/drawable/icon_notification.png" to byteArrayOf(2),
            ),
        )
        val seed = ByteArray(32) { 31 }
        val defaults = HardeningOwnership.HardcodedReferenceScope.defaults()
        val disabled = HardeningOwnership.HardcodedReferenceScope.resolve(
            defaults.kinds - HardcodedReferenceKind.RESOURCE_NAME,
            defaults.includeGlobs,
            defaults.excludeGlobs,
            true,
            false,
        )
        val excluded = HardeningOwnership.HardcodedReferenceScope.resolve(
            defaults.kinds,
            defaults.includeGlobs,
            defaults.excludeGlobs + "src/main/java/com/example/demo/match/Calculator.kt",
            true,
            false,
        )
        fun plan(scope: HardeningOwnership.HardcodedReferenceScope): HardenedBundlePlan {
            val ownership = testHardeningOwnership(
                repository,
                OWNED_MODULES,
                OWNED_MODULES.associateWith { setOf("main") },
                setOf("com.example.junkcode"),
                emptySet(),
                scope,
            )
            return HardenedBundlePlanner().plan(
                request(ordinary, seed, PseudowordRegistry(seed).snapshot(1), ownership),
            )
        }

        val enabledPlan = plan(defaults)
        val disabledPlan = plan(disabled)
        val excludedPlan = plan(excluded)

        assertEquals(setOf("other"), enabledPlan.report.resources.renames.map { it.oldName }.toSet())
        assertEquals(setOf("home", "other"), disabledPlan.report.resources.renames.map { it.oldName }.toSet())
        assertEquals(setOf("home", "other"), excludedPlan.report.resources.renames.map { it.oldName }.toSet())
    }

    @Test
    fun `access-only dex plan entry does not claim mixed classes as diversification owned`() {
        val entry = PlannedDexEntry(
            "base/dex/classes2.dex",
            PlannedDexStatus.TRANSFORMED,
            "a".repeat(64),
            "b".repeat(64),
            100,
            101,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            setOf("La/mixed/Continuation;"),
        )

        assertEquals(0, entry.ownedDescriptorCount)
        assertEquals(setOf("La/mixed/Continuation;"), entry.publicizedClassDescriptors)
    }

    @Test
    fun `resource planning preserves class member and package registry assignments`() {
        fixtureRepository()
        val ordinary = repository.resolve("ordinary.aab")
        zip(
            ordinary,
            mapOf(
                "base/dex/classes.dex" to dex(OWNED_DESCRIPTOR),
                "base/resources.pb" to resourcesTable(),
                "base/res/layout/home.xml" to compiledXml(),
                "base/res/drawable/icon_notification.png" to byteArrayOf(2),
            ),
        )
        val seed = ByteArray(32) { 17 }
        val registry = PseudowordRegistry(seed)
        val codeRequests = listOf(
            AliasRequest(RegistryKey("com/example/Calculator", SymbolKind.CLASS, "com/example"), "code-class:com/example"),
            AliasRequest(RegistryKey("com/example/Calculator#calculate()V", SymbolKind.MEMBER, "()V"), "code-member"),
            AliasRequest(RegistryKey("com/example", SymbolKind.PACKAGE, "com"), "code-package:com"),
        )
        val retiredClass = AliasRequest(
            RegistryKey("com/example/Retired", SymbolKind.CLASS, "com/example"),
            "code-class:com/example",
        )
        registry.reconcileScoped(
            codeRequests + retiredClass,
            1,
            setOf(SymbolKind.CLASS, SymbolKind.MEMBER, SymbolKind.PACKAGE),
        )
        registry.reconcileScoped(codeRequests, 1, setOf(SymbolKind.CLASS, SymbolKind.MEMBER, SymbolKind.PACKAGE))
        val before = registry.snapshot(1)

        val plan = HardenedBundlePlanner().plan(request(ordinary, seed, registry.snapshot(1)))

        assertEquals(
            before.assignments.filter { it.key.kind != SymbolKind.RESOURCE },
            plan.updatedRegistry.assignments.filter { it.key.kind != SymbolKind.RESOURCE },
        )
        assertEquals(
            before.tombstones.filter { it.kind != SymbolKind.RESOURCE },
            plan.updatedRegistry.tombstones.filter { it.kind != SymbolKind.RESOURCE },
        )
    }

    @Test
    fun `plans exact owned dex and resource rewrites without touching the source bundle`() {
        fixtureRepository()
        val ordinary = repository.resolve("ordinary.aab")
        val originalDex = dex(OBFUSCATED_OWNED_DESCRIPTOR)
        val resources = resourcesTable()
        zip(
            ordinary,
            mapOf(
                "base/dex/classes.dex" to originalDex,
                "base/resources.pb" to resources,
                "base/res/layout/home.xml" to compiledXml(),
                "base/res/drawable/icon_notification.png" to "not-a-real-png".toByteArray(),
                "base/manifest/AndroidManifest.xml" to "manifest".toByteArray(),
            ),
        )
        val sourceHash = Sha256.file(ordinary)
        val seed = ByteArray(32) { (it + 1).toByte() }
        val registry = PseudowordRegistry(seed).snapshot(1)

        val plan = HardenedBundlePlanner().plan(
            HardenedBundlePlanRequest(
                ordinary,
                repository,
                "com.example.demo.match.Calculator -> a.b:\n",
                "com.example.demo.match",
                "com.example.demo.app",
                seed,
                registry,
                1,
                "fresh-content-salt".toByteArray(),
                0.50,
                4,
                1.0,
                true,
                0.90,
                0.995,
                11,
                ":app",
                testHardeningOwnership(repository, OWNED_MODULES),
            ),
        )

        assertEquals(sourceHash, Sha256.file(ordinary), "the planner must be read-only")
        assertNotEquals(plan.ownedArtifactInventory, plan.ownedArtifactAnalysisInventory)
        val byOldPath = plan.replacements.associateBy(BundleEntryReplacement::oldPath)
        assertEquals(
            setOf(
                "base/dex/classes.dex",
                "base/resources.pb",
                "base/res/layout/home.xml",
                "base/res/drawable/icon_notification.png",
            ),
            byOldPath.keys,
        )
        assertEquals(BundleSemanticVerifier.DEX_SEMANTICS, byOldPath.getValue("base/dex/classes.dex").semanticVerifier)
        assertEquals(
            BundleSemanticVerifier.RESOURCE_SEMANTICS,
            byOldPath.getValue("base/resources.pb").semanticVerifier,
        )
        assertEquals(
            BundleSemanticVerifier.RESOURCE_SEMANTICS,
            byOldPath.getValue("base/res/layout/home.xml").semanticVerifier,
        )
        assertFalse(byOldPath.getValue("base/dex/classes.dex").bytes.contentEquals(originalDex))
        assertNotEquals("base/res/layout/home.xml", byOldPath.getValue("base/res/layout/home.xml").newPath)
        assertTrue(byOldPath.getValue("base/res/layout/home.xml").newPath.startsWith("base/res/layout/sl_layout_"))
        val notificationReplacement = byOldPath.getValue("base/res/drawable/icon_notification.png")
        assertTrue(notificationReplacement.newPath.startsWith("base/res/drawable/sl_drawable_"))
        assertEquals(null, notificationReplacement.semanticVerifier)
        assertEquals("not-a-real-png", notificationReplacement.bytes.toString(Charsets.UTF_8))
        assertEquals(setOf(OBFUSCATED_OWNED_DESCRIPTOR), plan.ownedArtifactInventory.ownedDescriptors)
        assertEquals(plan.ownedArtifactInventory.ownedDescriptors, plan.dexVerificationScope.ownedDescriptors)
        assertEquals(
            setOf("Lcom/example/junkcode/"),
            plan.dexVerificationScope.deniedDescriptorPrefixes,
        )
        assertTrue(plan.dexVerificationScope.externalContractMethodIds.isEmpty())
        assertEquals(
            setOf("home.xml", "icon_notification.png"),
            plan.ownedArtifactInventory.ordinaryOwnedResources.values.mapTo(linkedSetOf()) { it.entryName },
        )
        assertTrue(
            plan.ownedArtifactInventory.hardenedOwnedResources.values.any { location ->
                location.entryName.startsWith("sl_layout_") && location.entryName.endsWith(".xml")
            },
        )
        val notificationKey = plan.ownedArtifactInventory.ordinaryOwnedResources.keys.single { it.resourceId == 0x7f020001 }
        assertEquals(
            "base/res/drawable/icon_notification.png",
            plan.ownedArtifactInventory.hardenedOwnedResources.getValue(notificationKey).aabPath,
        )
        assertEquals(
            notificationReplacement.newPath,
            plan.ownedArtifactAnalysisInventory.hardenedOwnedResources.getValue(notificationKey).aabPath,
        )
        plan.ownedArtifactInventory.ordinaryOwnedResources.forEach { (key, ordinaryLocation) ->
            val hardenedLocation = plan.ownedArtifactInventory.hardenedOwnedResources.getValue(key)
            assertEquals(ordinaryLocation.semanticHash, hardenedLocation.semanticHash)
            assertEquals(ordinaryLocation.aabPath.removePrefix("base/"), ordinaryLocation.apkPath)
            assertEquals(hardenedLocation.aabPath.removePrefix("base/"), hardenedLocation.apkPath)
        }

        assertEquals(1, plan.report.dex.transformedDexCount)
        assertEquals(4, plan.report.dex.minimumSimHashDistance)
        val transformedMethods = plan.report.dex.entries.single().transformedMethods
        assertEquals(1, transformedMethods.size)
        assertTrue(transformedMethods.single().methodId.contains("->"))
        assertTrue(transformedMethods.single().simHashDistance >= 4)
        assertEquals(1, plan.report.dex.discoveredOwnedDescriptorCount)
        assertEquals(1, plan.report.dex.boundaryAcceptedDescriptorCount)
        assertEquals(0, plan.report.dex.boundaryFilteredDescriptorCount)
        assertEquals(1, plan.report.resources.renamedResourceCount)
        assertEquals(1, plan.report.resources.diversifiedProtoXmlCount)
        assertEquals(1.0, plan.report.resources.imageCoverage)
        assertEquals(0L, plan.report.resources.eligibleImageBytes)
        assertEquals(0L, plan.report.resources.transformedImageBytes)
        assertEquals(1.0, plan.report.resources.imageByteCoverage)
        assertEquals(
            ImageIneligibilityReason.NOTIFICATION_ICON,
            plan.report.resources.images.single().reason,
        )
        assertEquals(OWNED_MODULES, plan.report.ownedModules)
        assertEquals(2, plan.updatedRegistry.assignments.count { it.key.kind == SymbolKind.RESOURCE })
        assertTrue(plan.report.contentSaltSha256.matches(Regex("[0-9a-f]{64}")))
        assertFalse(plan.report.toString().contains("fresh-content-salt"))

    }

    @Test
    fun `publicizes a mapped package-private bridge owner referenced from another package`() {
        fixtureRepository()
        secondOwnedSource()
        val ordinary = repository.resolve("access-ordinary.aab")
        zip(
            ordinary,
            mapOf(
                "base/dex/classes.dex" to dexWithCrossPackageBridge(),
                "base/resources.pb" to resourcesTable(),
                "base/res/layout/home.xml" to compiledXml(),
                "base/res/drawable/icon_notification.png" to byteArrayOf(2),
            ),
        )
        val seed = ByteArray(32) { 29 }

        val plan = HardenedBundlePlanner().plan(
            request(ordinary, seed, PseudowordRegistry(seed).snapshot(1)).copy(
                r8MappingText =
                    "com.example.demo.match.Calculator -> a.b:\n" +
                        "    1:2:void third.party.Library.merged():3:4 -> merged\n" +
                        "com.example.demo.match.Second -> com.example.demo.match.a:\n",
            ),
        )

        val dexReplacement = plan.replacements.single { it.oldPath == "base/dex/classes.dex" }
        val target = DexBackedDexFile.fromInputStream(null, dexReplacement.bytes.inputStream()).classes
            .single { it.type == OBFUSCATED_OWNED_DESCRIPTOR }
        assertTrue(AccessFlags.PUBLIC.isSet(target.accessFlags))
        assertEquals(
            setOf(OBFUSCATED_OWNED_DESCRIPTOR),
            plan.report.dex.entries.single().publicizedClassDescriptors,
        )

        val rewritten = repository.resolve("access-rewritten.aab")
        val rewrite = BundleZipRewriter().rewrite(
            ordinary,
            rewritten,
            plan.report.contentSaltSha256,
            plan.replacements,
        )
        val verification = BundlePostRewriteSemanticVerifier().verify(
            ordinaryBundle = ordinary,
            rewrittenBundle = rewritten,
            manifest = rewrite.manifest,
            plan = plan.report,
            contentSalt = "content-salt".toByteArray(),
            dexScope = plan.dexVerificationScope,
        )
        assertTrue(verification.any { result ->
            result.oldPath == "base/dex/classes.dex" && result.successful
        })

        val forgedPlan = plan.report.copy(
            dex = plan.report.dex.copy(
                entries = plan.report.dex.entries.map { entry ->
                    entry.copy(publicizedClassDescriptors = emptySet())
                },
            ),
        )
        val failure = assertFailsWith<IllegalArgumentException> {
            BundlePostRewriteSemanticVerifier().verify(
                ordinary,
                rewritten,
                rewrite.manifest,
                forgedPlan,
                "content-salt".toByteArray(),
                plan.dexVerificationScope,
            )
        }
        assertTrue(
            failure.message.orEmpty().contains(
                "DEX access compatibility plan differs from the ordinary multidex reference closure",
            ),
        )
    }

    @Test
    fun `diversifies owned sfnt font containers without changing their semantics`() {
        fixtureRepository()
        val font = sfntFont()
        repository.resolve("app/src/main/res/font/brand.ttf").also {
            it.parent.createDirectories()
            it.writeBytes(font)
        }
        val ordinary = repository.resolve("font-ordinary.aab")
        zip(
            ordinary,
            mapOf(
                "base/dex/classes.dex" to dex(OWNED_DESCRIPTOR),
                "base/resources.pb" to resourcesTableWithFont(),
                "base/res/layout/home.xml" to compiledXml(),
                "base/res/drawable/icon_notification.png" to byteArrayOf(2),
                "base/res/font/brand.ttf" to font,
            ),
        )
        val seed = ByteArray(32) { 18 }
        val registry = PseudowordRegistry(seed).snapshot(1)

        val first = HardenedBundlePlanner().plan(request(ordinary, seed, registry))
        val repeated = HardenedBundlePlanner().plan(request(ordinary, seed, registry))
        val changedSalt = HardenedBundlePlanner().plan(
            request(ordinary, seed, registry).copy(contentSalt = "different-content-salt".toByteArray()),
        )
        val firstFont = first.replacements.single { it.oldPath == "base/res/font/brand.ttf" }
        val repeatedFont = repeated.replacements.single { it.oldPath == "base/res/font/brand.ttf" }
        val changedFont = changedSalt.replacements.single { it.oldPath == "base/res/font/brand.ttf" }

        assertFalse(font.contentEquals(firstFont.bytes))
        assertTrue(firstFont.bytes.contentEquals(repeatedFont.bytes))
        assertFalse(firstFont.bytes.contentEquals(changedFont.bytes))
        assertEquals(BundleSemanticVerifier.RESOURCE_SEMANTICS, firstFont.semanticVerifier)

        val rewritten = repository.resolve("font-rewritten.aab")
        val rewrite = BundleZipRewriter().rewrite(
            ordinary,
            rewritten,
            first.report.contentSaltSha256,
            first.replacements,
        )
        val semanticResults = BundlePostRewriteSemanticVerifier().verify(
            ordinary,
            rewritten,
            rewrite.manifest,
            first.report,
            "content-salt".toByteArray(),
            first.dexVerificationScope,
        )
        assertTrue(semanticResults.any { it.oldPath == "base/res/font/brand.ttf" && it.successful })
        BundleRewriteVerifier().verify(ordinary, rewritten, rewrite.manifest, semanticResults)

        val tamperedFont = firstFont.bytes.copyOf().also { bytes ->
            bytes[bytes.lastIndex] = (bytes.last().toInt() xor 0x01).toByte()
        }
        val tamperedReplacements = first.replacements.map { replacement ->
            if (replacement.oldPath == "base/res/font/brand.ttf") {
                replacement.copy(bytes = tamperedFont)
            } else {
                replacement
            }
        }
        val tampered = repository.resolve("font-tampered.aab")
        val tamperedRewrite = BundleZipRewriter().rewrite(
            ordinary,
            tampered,
            first.report.contentSaltSha256,
            tamperedReplacements,
        )
        assertFailsWith<IllegalArgumentException> {
            BundlePostRewriteSemanticVerifier().verify(
                ordinary,
                tampered,
                tamperedRewrite.manifest,
                first.report,
                "content-salt".toByteArray(),
                first.dexVerificationScope,
            )
        }
    }

    @Test
    fun `rejects malformed owned sfnt fonts instead of publishing unverified bytes`() {
        fixtureRepository()
        repository.resolve("app/src/main/res/font/brand.ttf").also {
            it.parent.createDirectories()
            it.writeBytes("not-an-sfnt-font".toByteArray())
        }
        val ordinary = repository.resolve("invalid-font-ordinary.aab")
        zip(
            ordinary,
            mapOf(
                "base/dex/classes.dex" to dex(OWNED_DESCRIPTOR),
                "base/resources.pb" to resourcesTableWithFont(),
                "base/res/layout/home.xml" to compiledXml(),
                "base/res/drawable/icon_notification.png" to byteArrayOf(2),
                "base/res/font/brand.ttf" to "not-an-sfnt-font".toByteArray(),
            ),
        )
        val seed = ByteArray(32) { 19 }

        val failure = assertFailsWith<IllegalArgumentException> {
            HardenedBundlePlanner().plan(request(ordinary, seed, PseudowordRegistry(seed).snapshot(1)))
        }

        assertTrue(failure.message.orEmpty().contains("SFNT"))
    }

    @Test
    fun `notification physical paths are stable across salts and preserve qualifier bytes and semantics`() {
        fixtureRepository()
        repository.resolve("app/src/main/res/drawable-land/icon_notification.png").also {
            it.parent.createDirectories()
            it.writeBytes(byteArrayOf(4, 5, 6))
        }
        val ordinary = repository.resolve("ordinary.aab")
        val defaultBytes = byteArrayOf(1, 2, 3)
        val landBytes = byteArrayOf(4, 5, 6)
        zip(
            ordinary,
            mapOf(
                "base/dex/classes.dex" to dex(OWNED_DESCRIPTOR),
                "base/resources.pb" to resourcesTableWithNotificationQualifiers(),
                "base/res/layout/home.xml" to compiledXml(),
                "base/res/drawable/icon_notification.png" to defaultBytes,
                "base/res/drawable-land/icon_notification.png" to landBytes,
            ),
        )
        val seed = ByteArray(32) { 23 }
        val registry = PseudowordRegistry(seed).snapshot(1)

        val first = HardenedBundlePlanner().plan(request(ordinary, seed, registry))
        val second = HardenedBundlePlanner().plan(
            request(ordinary, seed, registry).copy(contentSalt = "different-content-salt".toByteArray()),
        )
        val oldPaths = setOf(
            "base/res/drawable/icon_notification.png",
            "base/res/drawable-land/icon_notification.png",
        )
        val firstNotification = first.replacements.filter { it.oldPath in oldPaths }.sortedBy { it.oldPath }
        val secondNotification = second.replacements.filter { it.oldPath in oldPaths }.sortedBy { it.oldPath }

        assertEquals(2, firstNotification.size)
        assertEquals(
            1,
            firstNotification.map { it.newPath.substringAfterLast('/').substringBefore('.') }.distinct().size,
        )
        assertEquals(firstNotification.map { it.newPath }, secondNotification.map { it.newPath })
        assertEquals(
            mapOf(
                "base/res/drawable/icon_notification.png" to defaultBytes.toList(),
                "base/res/drawable-land/icon_notification.png" to landBytes.toList(),
            ),
            firstNotification.associate { it.oldPath to it.bytes.toList() },
        )
        assertTrue(firstNotification.all { it.semanticVerifier == null })
        assertEquals(1, first.report.resources.renamedResourceCount)
        assertTrue(first.report.resources.renames.none { it.oldName == "icon_notification" })
        assertTrue(first.report.resources.images.filter { it.oldPath in oldPaths }.all {
            it.reason == ImageIneligibilityReason.NOTIFICATION_ICON && it.status == ImageTransformStatus.EXCLUDED
        })

        val notificationKeys = first.ownedArtifactInventory.ordinaryOwnedResources.keys.filter { it.resourceId == 0x7f020001 }
        assertEquals(2, notificationKeys.size)
        notificationKeys.forEach { key ->
            val identity = first.ownedArtifactInventory.hardenedOwnedResources.getValue(key)
            val analysis = first.ownedArtifactAnalysisInventory.hardenedOwnedResources.getValue(key)
            assertEquals(first.ownedArtifactInventory.ordinaryOwnedResources.getValue(key), identity)
            assertEquals(identity.semanticHash, analysis.semanticHash)
            assertNotEquals(identity.aabPath, analysis.aabPath)
            assertEquals(analysis.aabPath.substringAfterLast('/'), analysis.entryName)
            assertEquals(analysis.aabPath.removePrefix("base/"), analysis.apkPath)
            assertTrue(analysis.entryName.startsWith("sl_drawable_") && analysis.entryName.endsWith(".png"))
        }
        assertEquals(
            first.updatedRegistry.assignments.filter { it.key.kind == SymbolKind.RESOURCE }.associate { it.key to it.alias },
            second.updatedRegistry.assignments.filter { it.key.kind == SymbolKind.RESOURCE }.associate { it.key to it.alias },
        )

        val rewritten = repository.resolve("rewritten.aab")
        val rewrite = BundleZipRewriter().rewrite(
            ordinary,
            rewritten,
            first.report.contentSaltSha256,
            first.replacements,
        )
        val semanticResults = BundlePostRewriteSemanticVerifier().verify(
            ordinary,
            rewritten,
            rewrite.manifest,
            first.report,
            "content-salt".toByteArray(),
            first.dexVerificationScope,
        )
        BundleRewriteVerifier().verify(ordinary, rewritten, rewrite.manifest, semanticResults)
        ZipFile(rewritten.toFile()).use { archive ->
            firstNotification.forEach { replacement ->
                val bytes = archive.getInputStream(requireNotNull(archive.getEntry(replacement.newPath))).use { it.readBytes() }
                assertEquals(replacement.bytes.toList(), bytes.toList())
            }
            assertTrue(oldPaths.none { archive.getEntry(it) != null })
            val table = Resources.ResourceTable.parseFrom(
                archive.getInputStream(requireNotNull(archive.getEntry("base/resources.pb"))).use { it.readBytes() },
            )
            val notification = table.getPackage(0).typeList.single { it.name == "drawable" }.entryList.single()
            assertEquals("icon_notification", notification.name)
            assertEquals(1, notification.entryId.id)
            assertEquals(setOf(0, 2), notification.configValueList.map { it.config.orientationValue }.toSet())
        }
    }

    @Test
    fun `planner does not resize notification jpeg when image scope is enabled`() {
        fixtureRepository()
        Files.delete(repository.resolve("app/src/main/res/drawable/icon_notification.png"))
        val jpeg = encodedImage(2, 2, "jpeg")
        repository.resolve("app/src/main/res/drawable/icon_notification.jpg").writeBytes(jpeg)
        val ordinary = repository.resolve("notification-jpeg-ordinary.aab")
        zip(
            ordinary,
            mapOf(
                "base/dex/classes.dex" to dex(OWNED_DESCRIPTOR),
                "base/resources.pb" to resourcesTable("jpg"),
                "base/res/layout/home.xml" to compiledXml(),
                "base/res/drawable/icon_notification.jpg" to jpeg,
            ),
        )
        val seed = ByteArray(32) { 27 }
        val plan = HardenedBundlePlanner().plan(
            request(
                ordinary,
                seed,
                PseudowordRegistry(seed).snapshot(1),
                notificationJpegOwnership(),
                null,
                0.0,
            ),
        )

        val image = plan.report.resources.images.single()
        assertEquals(ImageTransformStatus.INELIGIBLE, image.status)
        assertEquals(ImageIneligibilityReason.UNSUPPORTED_FORMAT, image.reason)
        assertFalse(image.dimensionChanged)
        assertEquals(null, image.transformedSha256)
        val replacement = plan.replacements.single { it.oldPath == "base/res/drawable/icon_notification.jpg" }
        assertTrue(replacement.bytes.contentEquals(jpeg))
    }

    @Test
    fun `fails closed when the exact owned dex inventory produces no effective transform`() {
        fixtureRepository()
        val ordinary = repository.resolve("ordinary.aab")
        zip(
            ordinary,
            mapOf(
                "base/dex/classes.dex" to dex("Lthird/party/OnlyClass;"),
                "base/resources.pb" to resourcesTable(),
                "base/res/layout/home.xml" to compiledXml(),
                "base/res/drawable/icon_notification.png" to byteArrayOf(2),
            ),
        )
        val seed = ByteArray(32) { 7 }

        val failure = assertFailsWith<IllegalArgumentException> {
            HardenedBundlePlanner().plan(
                request(ordinary, seed, PseudowordRegistry(seed).snapshot(1)),
            )
        }

        assertTrue(failure.message.orEmpty().contains("DEX", ignoreCase = true))
        assertFalse(Files.exists(repository.resolve("hardened.aab")))
    }

    @Test
    fun `strict report codec round trips and rejects schema drift secrets and invalid metrics`() {
        fixtureRepository()
        val ordinary = repository.resolve("ordinary.aab")
        zip(
            ordinary,
            mapOf(
                "base/dex/classes.dex" to dex(OWNED_DESCRIPTOR),
                "base/resources.pb" to resourcesTable(),
                "base/res/layout/home.xml" to compiledXml(),
                "base/res/drawable/icon_notification.png" to byteArrayOf(2),
            ),
        )
        val seed = ByteArray(32) { 9 }
        val rawFixedSeed = "planner raw fixed seed must not be serialized"
        val fixedSeedHash = Sha256.hex(rawFixedSeed.toByteArray())
        val plan = HardenedBundlePlanner().plan(
            request(
                ordinary,
                seed,
                PseudowordRegistry(seed).snapshot(1),
                testHardeningOwnership(repository, OWNED_MODULES),
                fixedSeedHash,
            ),
        )

        val encoded = HardenedBundlePlanReportCodec.encode(plan.report)

        assertEquals(plan.report, HardenedBundlePlanReportCodec.decode(encoded))
        assertTrue(plan.report.fixedSeedProvided)
        assertEquals(fixedSeedHash, plan.report.fixedSeedHash)
        assertTrue(encoded.contains("\"fixedSeedProvided\":true"))
        assertTrue(encoded.contains("\"fixedSeedHash\":\"$fixedSeedHash\""))
        assertTrue(encoded.contains("\"eligibleImageBytes\":0"))
        assertTrue(encoded.contains("\"transformedImageBytes\":0"))
        assertTrue(encoded.contains("\"imageByteCoverage\":1.0"))
        assertTrue(encoded.contains("\"writerFloorSkippedDexPaths\":[]"))
        assertTrue(encoded.contains("\"minimumSimHashDistance\":4"))
        assertTrue(encoded.contains("\"transformedMethods\":[{"))
        assertFalse(encoded.contains("stable-mapping-secret"))
        assertFalse(encoded.contains(rawFixedSeed))
        assertFalse(encoded.contains(seed.joinToString()))
        assertFailsWith<IllegalArgumentException> {
            HardenedBundlePlanReportCodec.decode(
                encoded.replace("\"fixedSeedProvided\":true", "\"fixedSeedProvided\":false"),
            )
        }
        assertFailsWith<IllegalArgumentException> {
            HardenedBundlePlanReportCodec.decode(
                encoded.replace("\"fixedSeedHash\":\"$fixedSeedHash\"", "\"fixedSeedHash\":null"),
            )
        }
        assertFailsWith<IllegalArgumentException> {
            HardenedBundlePlanReportCodec.decode(encoded.replace(fixedSeedHash, fixedSeedHash.uppercase()))
        }
        assertFailsWith<IllegalArgumentException> {
            HardenedBundlePlanReportCodec.decode(encoded.replaceFirst("{", "{\"unknown\":true,"))
        }
        assertFailsWith<IllegalArgumentException> {
            HardenedBundlePlanReportCodec.decode(encoded.replaceFirst("\"schemaVersion\":1", "\"schemaVersion\":1,\"schemaVersion\":1"))
        }
        assertFailsWith<IllegalArgumentException> {
            HardenedBundlePlanReportCodec.decode(encoded.replace("\"minimumCodeCoverage\":0.5", "\"minimumCodeCoverage\":1.5"))
        }
        val recordedDistance = plan.report.dex.entries.single().transformedMethods.single().simHashDistance
        assertFailsWith<IllegalArgumentException> {
            HardenedBundlePlanReportCodec.decode(
                encoded.replaceFirst("\"simHashDistance\":$recordedDistance", "\"simHashDistance\":3"),
            )
        }
        assertFailsWith<IllegalArgumentException> {
            HardenedBundlePlanReportCodec.decode(encoded.replaceFirst("\"schemaVersion\":1", "\"schemaVersion\":2"))
        }
    }

    @Test
    fun `schema one report without 1 3 image fields remains readable`() {
        fixtureRepository()
        val ordinary = repository.resolve("ordinary.aab")
        zip(
            ordinary,
            mapOf(
                "base/dex/classes.dex" to dex(OWNED_DESCRIPTOR),
                "base/resources.pb" to resourcesTable(),
                "base/res/layout/home.xml" to compiledXml(),
                "base/res/drawable/icon_notification.png" to byteArrayOf(2),
            ),
        )
        val seed = ByteArray(32) { 21 }
        val report = HardenedBundlePlanner().plan(
            request(ordinary, seed, PseudowordRegistry(seed).snapshot(1)),
        ).report
        val encoded = HardenedBundlePlanReportCodec.encode(report)
            .replace("\"transformedJpegCount\":0,", "")
            .replace(",\"originalWidth\":null,\"originalHeight\":null,\"dimensionChanged\":false,\"resizeFallback\":false,\"resizeFallbackReason\":null", "")

        val decoded = HardenedBundlePlanReportCodec.decode(encoded)

        assertEquals(report.resources.transformedJpegCount, decoded.resources.transformedJpegCount)
        assertEquals(report.resources.images.map { it.oldPath }, decoded.resources.images.map { it.oldPath })
        assertTrue(decoded.resources.images.all { !it.dimensionChanged && !it.resizeFallback })
    }

    @Test
    fun `writer floor skipped dex remains in aggregate coverage and byte accounting`() {
        fixtureRepository()
        secondOwnedSource()
        val ordinary = repository.resolve("ordinary.aab")
        val transformableDex = dex(OWNED_DESCRIPTOR, sourceFile = "large-" + "x".repeat(10_000))
        val skippedDex = dex(SECOND_OWNED_DESCRIPTOR)
        zip(
            ordinary,
            mapOf(
                "base/dex/classes.dex" to transformableDex,
                "base/dex/classes2.dex" to skippedDex,
                "base/resources.pb" to resourcesTable(),
                "base/res/layout/home.xml" to compiledXml(),
                "base/res/drawable/icon_notification.png" to byteArrayOf(2),
            ),
        )
        val seed = ByteArray(32) { 11 }

        val plan = HardenedBundlePlanner().plan(
            request(ordinary, seed, PseudowordRegistry(seed).snapshot(1)).copy(
                r8MappingText = twoClassMapping(),
                maximumDexGrowthRatio = 0.01,
            ),
        )

        val dex = plan.report.dex
        assertEquals(listOf("base/dex/classes2.dex"), dex.writerFloorSkippedDexPaths)
        assertEquals(
            listOf("base/dex/classes.dex", "base/dex/classes2.dex"),
            dex.entries.map(PlannedDexEntry::path),
        )
        assertEquals(
            PlannedDexStatus.WRITER_FLOOR_SKIPPED,
            dex.entries.single { it.path == "base/dex/classes2.dex" }.status,
        )
        assertEquals(1, dex.transformedDexCount)
        assertEquals(0.5, dex.eligibleMethodCoverage)
        assertEquals(0.5, dex.eligibleInstructionCoverage)
        assertEquals(transformableDex.size.toLong() + skippedDex.size, dex.totalInputBytes)
        val rewrittenDexSize = plan.replacements.single { it.oldPath == "base/dex/classes.dex" }.bytes.size
        assertEquals(rewrittenDexSize.toLong() + skippedDex.size, dex.totalOutputBytes)
        assertTrue(plan.replacements.none { it.oldPath == "base/dex/classes2.dex" })

        val rewritten = repository.resolve("rewritten.aab")
        val rewrite = BundleZipRewriter().rewrite(
            ordinary,
            rewritten,
            plan.report.contentSaltSha256,
            plan.replacements,
        )
        val semanticResults = BundlePostRewriteSemanticVerifier().verify(
            ordinaryBundle = ordinary,
            rewrittenBundle = rewritten,
            manifest = rewrite.manifest,
            plan = plan.report,
            contentSalt = "content-salt".toByteArray(),
            dexScope = plan.dexVerificationScope,
        )
        BundleRewriteVerifier().verify(ordinary, rewritten, rewrite.manifest, semanticResults)

        val roundTripped = HardenedBundlePlanReportCodec.decode(HardenedBundlePlanReportCodec.encode(plan.report))
        assertEquals(dex.writerFloorSkippedDexPaths, roundTripped.dex.writerFloorSkippedDexPaths)
    }

    @Test
    fun `dex with no eligible methods is preserved without diluting aggregate coverage`() {
        fixtureRepository()
        secondOwnedSource()
        val ordinary = repository.resolve("ordinary.aab")
        val transformableDex = dex(OWNED_DESCRIPTOR)
        val noEligibleDex = classInitializerDex(SECOND_OWNED_DESCRIPTOR)
        zip(
            ordinary,
            mapOf(
                "base/dex/classes.dex" to transformableDex,
                "base/dex/classes2.dex" to noEligibleDex,
                "base/resources.pb" to resourcesTable(),
                "base/res/layout/home.xml" to compiledXml(),
                "base/res/drawable/icon_notification.png" to byteArrayOf(2),
            ),
        )
        val seed = ByteArray(32) { 14 }

        val plan = HardenedBundlePlanner().plan(
            request(ordinary, seed, PseudowordRegistry(seed).snapshot(1)).copy(
                r8MappingText = twoClassMapping(),
                enforceMaximumDexGrowth = false,
                maximumDexGrowthRatio = 0.0,
            ),
        )

        val dex = plan.report.dex
        val skipped = dex.entries.single { it.path == "base/dex/classes2.dex" }
        assertEquals(PlannedDexStatus.NO_ELIGIBLE_METHODS_SKIPPED, skipped.status)
        assertEquals(listOf("base/dex/classes2.dex"), dex.noEligibleMethodsSkippedDexPaths)
        assertTrue(dex.writerFloorSkippedDexPaths.isEmpty())
        assertEquals(0, skipped.eligibleMethodCount)
        assertEquals(1.0, dex.eligibleMethodCoverage)
        assertEquals(1.0, dex.eligibleInstructionCoverage)
        assertTrue(plan.replacements.none { it.oldPath == "base/dex/classes2.dex" })

        val rewritten = repository.resolve("rewritten.aab")
        val rewrite = BundleZipRewriter().rewrite(
            ordinary,
            rewritten,
            plan.report.contentSaltSha256,
            plan.replacements,
        )
        val semanticResults = BundlePostRewriteSemanticVerifier().verify(
            ordinaryBundle = ordinary,
            rewrittenBundle = rewritten,
            manifest = rewrite.manifest,
            plan = plan.report,
            contentSalt = "content-salt".toByteArray(),
            dexScope = plan.dexVerificationScope,
        )
        BundleRewriteVerifier().verify(ordinary, rewritten, rewrite.manifest, semanticResults)

        val roundTripped = HardenedBundlePlanReportCodec.decode(HardenedBundlePlanReportCodec.encode(plan.report))
        assertEquals(dex.noEligibleMethodsSkippedDexPaths, roundTripped.dex.noEligibleMethodsSkippedDexPaths)
    }

    @Test
    fun `invalid no eligible dex is canonicalized without diluting coverage and report round trips`() {
        fixtureRepository()
        secondOwnedSource()
        val ordinary = repository.resolve("ordinary.aab")
        val transformableDex = dex(OWNED_DESCRIPTOR)
        val invalidNoEligibleDex = invalidClassInitializerDex(SECOND_OWNED_DESCRIPTOR)
        zip(
            ordinary,
            mapOf(
                "base/dex/classes.dex" to transformableDex,
                "base/dex/classes2.dex" to invalidNoEligibleDex,
                "base/resources.pb" to resourcesTable(),
                "base/res/layout/home.xml" to compiledXml(),
                "base/res/drawable/icon_notification.png" to byteArrayOf(2),
            ),
        )
        val seed = ByteArray(32) { 15 }

        val plan = HardenedBundlePlanner().plan(
            request(ordinary, seed, PseudowordRegistry(seed).snapshot(1)).copy(
                r8MappingText = twoClassMapping(),
                enforceMaximumDexGrowth = false,
                maximumDexGrowthRatio = 0.0,
            ),
        )

        val dex = plan.report.dex
        val canonicalized = dex.entries.single { it.path == "base/dex/classes2.dex" }
        val replacement = plan.replacements.single { it.oldPath == canonicalized.path }
        assertEquals(PlannedDexStatus.CANONICALIZED, canonicalized.status)
        assertEquals(listOf(canonicalized.path), dex.canonicalizedDexPaths)
        assertTrue(dex.noEligibleMethodsSkippedDexPaths.isEmpty())
        assertEquals(BundleSemanticVerifier.DEX_SEMANTICS, replacement.semanticVerifier)
        assertFalse(invalidNoEligibleDex.contentEquals(replacement.bytes))
        assertEquals(0, canonicalized.eligibleMethodCount)
        assertEquals(0, canonicalized.transformedMethodCount)
        assertEquals(1.0, dex.eligibleMethodCoverage)
        assertEquals(1.0, dex.eligibleInstructionCoverage)

        val rewritten = repository.resolve("rewritten.aab")
        val rewrite = BundleZipRewriter().rewrite(
            ordinary,
            rewritten,
            plan.report.contentSaltSha256,
            plan.replacements,
        )
        val semanticResults = BundlePostRewriteSemanticVerifier().verify(
            ordinary,
            rewritten,
            rewrite.manifest,
            plan.report,
            "content-salt".toByteArray(),
            plan.dexVerificationScope,
        )
        BundleRewriteVerifier().verify(ordinary, rewritten, rewrite.manifest, semanticResults)

        val encoded = HardenedBundlePlanReportCodec.encode(plan.report)
        val roundTripped = HardenedBundlePlanReportCodec.decode(encoded)
        assertEquals(dex.canonicalizedDexPaths, roundTripped.dex.canonicalizedDexPaths)
        assertTrue(encoded.contains("\"canonicalizedDexPaths\":[\"base/dex/classes2.dex\"]"))
    }

    @Test
    fun `writer floor skipped dex fails when aggregate code coverage is insufficient`() {
        fixtureRepository()
        secondOwnedSource()
        val ordinary = repository.resolve("ordinary.aab")
        zip(
            ordinary,
            mapOf(
                "base/dex/classes.dex" to dex(
                    OWNED_DESCRIPTOR,
                    sourceFile = "large-" + "x".repeat(10_000),
                ),
                "base/dex/classes2.dex" to dex(SECOND_OWNED_DESCRIPTOR),
                "base/resources.pb" to resourcesTable(),
                "base/res/layout/home.xml" to compiledXml(),
                "base/res/drawable/icon_notification.png" to byteArrayOf(2),
            ),
        )
        val seed = ByteArray(32) { 12 }

        val failure = assertFailsWith<IllegalArgumentException> {
            HardenedBundlePlanner().plan(
                request(ordinary, seed, PseudowordRegistry(seed).snapshot(1)).copy(
                    r8MappingText = twoClassMapping(),
                    minimumCodeCoverage = 0.75,
                    maximumDexGrowthRatio = 0.01,
                ),
            )
        }

        assertTrue(failure.message.orEmpty().contains("aggregate DEX coverage"))
    }

    @Test
    fun `dex summary derives aggregate coverage bytes and writer floor paths from entries`() {
        val transformed = plannedDexEntry("base/dex/classes.dex")
        val skipped = plannedDexEntry(
            path = "base/dex/classes2.dex",
            status = PlannedDexStatus.WRITER_FLOOR_SKIPPED,
        )

        val summary = PlannedDexSummary(
            discoveredOwnedDescriptorCount = 2,
            boundaryAcceptedDescriptorCount = 2,
            boundaryFilteredDescriptorCount = 0,
            minimumCodeCoverage = 0.50,
            maximumGrowthRatio = 0.0,
            enforceMaximumGrowth = false,
            entries = listOf(transformed, skipped),
        )

        assertEquals(0.5, summary.eligibleMethodCoverage)
        assertEquals(0.5, summary.eligibleInstructionCoverage)
        assertEquals(200L, summary.totalInputBytes)
        assertEquals(202L, summary.totalOutputBytes)
        assertEquals(1, summary.transformedDexCount)
        assertEquals(listOf("base/dex/classes2.dex"), summary.writerFloorSkippedDexPaths)
    }

    @Test
    fun `strict report codec rejects forged derived dex metrics`() {
        fixtureRepository()
        val ordinary = repository.resolve("ordinary.aab")
        zip(
            ordinary,
            mapOf(
                "base/dex/classes.dex" to dex(OWNED_DESCRIPTOR),
                "base/resources.pb" to resourcesTable(),
                "base/res/layout/home.xml" to compiledXml(),
                "base/res/drawable/icon_notification.png" to byteArrayOf(2),
            ),
        )
        val seed = ByteArray(32) { 13 }
        val report = HardenedBundlePlanner().plan(
            request(ordinary, seed, PseudowordRegistry(seed).snapshot(1)),
        ).report
        val encoded = HardenedBundlePlanReportCodec.encode(report)

        assertFailsWith<IllegalArgumentException> {
            HardenedBundlePlanReportCodec.decode(
                encoded.replaceFirst("\"eligibleMethodCoverage\":1.0", "\"eligibleMethodCoverage\":0.5"),
            )
        }
        assertFailsWith<IllegalArgumentException> {
            HardenedBundlePlanReportCodec.decode(
                encoded.replaceFirst(
                    "\"totalInputBytes\":${report.dex.totalInputBytes}",
                    "\"totalInputBytes\":${report.dex.totalInputBytes + 1}",
                ),
            )
        }
        val dexEntry = report.dex.entries.single()
        assertFailsWith<IllegalArgumentException> {
            HardenedBundlePlanReportCodec.decode(
                encoded.replaceFirst(
                    "\"byteGrowthRatio\":${dexEntry.byteGrowthRatio}",
                    "\"byteGrowthRatio\":${dexEntry.byteGrowthRatio + 0.01}",
                ),
            )
        }
        assertFailsWith<IllegalArgumentException> {
            HardenedBundlePlanReportCodec.decode(
                encoded.replaceFirst(
                    "\"writerFloorSkippedDexPaths\":[]",
                    "\"writerFloorSkippedDexPaths\":[\"base/dex/classes2.dex\"]",
                ),
            )
        }
    }

    @Test
    fun `reports mixed descriptors and rejects accepted descriptors absent from the AAB`() {
        fixtureRepository()
        secondOwnedSource()
        val ordinary = repository.resolve("ordinary.aab")
        zip(
            ordinary,
            mapOf(
                "base/dex/classes.dex" to dex(OWNED_DESCRIPTOR),
                "base/resources.pb" to resourcesTable(),
                "base/res/layout/home.xml" to compiledXml(),
                "base/res/drawable/icon_notification.png" to byteArrayOf(2),
            ),
        )
        val seed = ByteArray(32) { 14 }
        val mixedMapping =
            "com.example.demo.match.Calculator -> com.example.demo.match.Calculator:\n" +
                "com.example.demo.match.Second -> a.m:\n" +
                "third.party.Library -> a.m:\n"

        val mixedPlan = HardenedBundlePlanner().plan(
            request(ordinary, seed, PseudowordRegistry(seed).snapshot(1)).copy(r8MappingText = mixedMapping),
        )

        assertEquals(2, mixedPlan.report.dex.discoveredOwnedDescriptorCount)
        assertEquals(1, mixedPlan.report.dex.boundaryAcceptedDescriptorCount)
        assertEquals(1, mixedPlan.report.dex.boundaryFilteredDescriptorCount)

        val missing = assertFailsWith<IllegalArgumentException> {
            HardenedBundlePlanner().plan(
                request(ordinary, seed, PseudowordRegistry(seed).snapshot(1)).copy(
                    r8MappingText = twoClassMapping(),
                ),
            )
        }
        assertTrue(missing.message.orEmpty().contains("missing", ignoreCase = true))
    }

    @Test
    fun `rejects insufficient image byte coverage when image count coverage passes`() {
        val images = (0 until 10).map { index ->
            val transformed = index < 9
            PlannedImageEntry(
                oldPath = "base/res/drawable/image_$index.png",
                newPath = if (transformed) "base/res/drawable/renamed_$index.png" else null,
                status = if (transformed) ImageTransformStatus.TRANSFORMED else ImageTransformStatus.INELIGIBLE,
                reason = if (transformed) {
                    ImageIneligibilityReason.TRANSFORMED
                } else {
                    ImageIneligibilityReason.NO_SAFE_PERTURBATION
                },
                originalSha256 = "%064x".format(index + 1),
                transformedSha256 = if (transformed) "%064x".format(index + 101) else null,
                width = if (transformed) 10 else null,
                height = if (transformed) 10 else null,
                alphaPreserved = if (transformed) true else null,
                ssim = if (transformed) 0.999 else null,
                pHashDistance = if (transformed) 11 else null,
            )
        }

        val failure = assertFailsWith<IllegalArgumentException> {
            PlannedResourceSummary(
                inventoryVariantCount = 10,
                renamedResourceCount = 1,
                renamedFileCount = 1,
                resourcesPbInputSha256 = "a".repeat(64),
                resourcesPbOutputSha256 = "b".repeat(64),
                minimumImageCoverage = 0.90,
                minimumImageSsim = 0.995,
                minimumImagePHashDistance = 11,
                eligibleImageCount = 10,
                transformedImageCount = 9,
                imageCoverage = 0.90,
                eligibleImageBytes = 1_000,
                transformedImageBytes = 100,
                imageByteCoverage = 0.10,
                transformedPngCount = 9,
                transformedWebpCount = 0,
                diversifiedProtoXmlCount = 0,
                renames = listOf(
                    PlannedResourceRename(
                        resourceId = 0x7f010001,
                        type = ResourceType.DRAWABLE,
                        oldName = "image",
                        newName = "renamed_image",
                        renamedFileCount = 1,
                    ),
                ),
                images = images,
            )
        }

        assertTrue(failure.message.orEmpty().contains("image byte coverage"))
    }

    private fun request(
        ordinary: Path,
        seed: ByteArray,
        registry: com.holin.android.hardening.naming.RegistrySnapshot,
        ownership: HardeningOwnership = testHardeningOwnership(repository, OWNED_MODULES),
        fixedSeedHash: String? = null,
        minimumImageCoverage: Double = 0.90,
    ) =
        HardenedBundlePlanRequest(
            ordinary,
            repository,
            "" +
                "# stable-mapping-secret\ncom.example.demo.match.Calculator -> com.example.demo.match.Calculator:\n",
            "com.example.demo.match",
            "com.example.demo.app",
            seed,
            registry,
            1,
            "content-salt".toByteArray(),
            0.50,
            4,
            1.0,
            true,
            minimumImageCoverage,
            0.995,
            11,
            ":app",
            ownership,
            fixedSeedHash != null,
            fixedSeedHash,
        )

    private fun fixtureRepository() {
        check(ProcessBuilder("git", "init", "-q", repository.toString()).start().waitFor() == 0)
        repository.resolve("app/src/main/java/com/example/demo/match/Calculator.kt").also {
            it.parent.createDirectories()
            it.writeText("package com.example.demo.match\nclass Calculator")
        }
        repository.resolve("app/src/main/res/layout/home.xml").also {
            it.parent.createDirectories()
            it.writeText("<FrameLayout/>")
        }
        repository.resolve("app/src/main/res/drawable/icon_notification.png").also {
            it.parent.createDirectories()
            it.writeBytes(byteArrayOf(1, 2, 3))
        }
    }

    private fun notificationJpegOwnership(): HardeningOwnership {
        val app = repository.resolve("app")
        val sourceSet = HardeningOwnership.ResolvedSourceSetRoots(
            "main",
            setOf(app.resolve("src/main/java")),
            setOf(app.resolve("src/main/kotlin")),
            setOf(app.resolve("src/main/res")),
            setOf(app.resolve("src/main/AndroidManifest.xml")),
        )
        val roots = HardeningOwnership.ResolvedSourceRoots.fromSourceSets(listOf(sourceSet))
        val images = HardeningOwnership.ImageScope.resolve(
            setOf("src/main/res/drawable/icon_notification.jpg"),
            emptySet(),
            setOf(ImageFormat.JPEG),
        )
        return HardeningOwnership(
            listOf(
                HardeningOwnership.OwnedModule(
                    ":app",
                    app,
                    setOf("main"),
                    roots,
                    HardeningOwnership.WebpScope.none(),
                    images,
                ),
            ),
            setOf("com.example.junkcode"),
            emptySet(),
        )
    }

    private fun encodedImage(width: Int, height: Int, format: String): ByteArray =
        ByteArrayOutputStream().use { output ->
            check(ImageIO.write(BufferedImage(width, height, BufferedImage.TYPE_INT_RGB), format, output))
            output.toByteArray()
        }

    private fun secondOwnedSource() {
        repository.resolve("app/src/main/java/com/example/demo/match/Second.kt").also {
            it.parent.createDirectories()
            it.writeText("package com.example.demo.match\nclass Second")
        }
    }

    private fun twoClassMapping(): String =
        "com.example.demo.match.Calculator -> com.example.demo.match.Calculator:\n" +
            "com.example.demo.match.Second -> com.example.demo.match.Second:\n"

    private fun plannedDexEntry(
        path: String,
        status: PlannedDexStatus = PlannedDexStatus.TRANSFORMED,
    ) = PlannedDexEntry(
        path = path,
        status = status,
        inputSha256 = "a".repeat(64),
        outputSha256 = if (status == PlannedDexStatus.TRANSFORMED) "b".repeat(64) else "a".repeat(64),
        inputByteCount = 100,
        outputByteCount = if (status == PlannedDexStatus.TRANSFORMED) 102 else 100,
        ownedDescriptorCount = 1,
        ownedMethodCount = 1,
        eligibleMethodCount = 1,
        transformedMethodCount = if (status == PlannedDexStatus.TRANSFORMED) 1 else 0,
        ownedInstructionCount = 1,
        eligibleInstructionCount = 1,
        transformedInstructionCount = if (status == PlannedDexStatus.TRANSFORMED) 1 else 0,
        transformedMethods = if (status == PlannedDexStatus.TRANSFORMED) {
            listOf(PlannedDexMethod("Lfixture/Owner;->method()V", 1, 4))
        } else {
            emptyList()
        },
    )

    private fun resourcesTable(notificationExtension: String = "png"): ByteArray {
        fun file(path: String) = Resources.ConfigValue.newBuilder().setValue(
            Resources.Value.newBuilder().setItem(
                Resources.Item.newBuilder().setFile(Resources.FileReference.newBuilder().setPath(path)),
            ),
        )
        return Resources.ResourceTable.newBuilder().addPackage(
            Resources.Package.newBuilder()
                .setPackageId(Resources.PackageId.newBuilder().setId(0x7f))
                .addType(
                    Resources.Type.newBuilder()
                        .setTypeId(Resources.TypeId.newBuilder().setId(1))
                        .setName("layout")
                        .addEntry(
                            Resources.Entry.newBuilder()
                                .setEntryId(Resources.EntryId.newBuilder().setId(1))
                                .setName("home")
                                .addConfigValue(file("res/layout/home.xml")),
                        ),
                )
                .addType(
                    Resources.Type.newBuilder()
                        .setTypeId(Resources.TypeId.newBuilder().setId(2))
                        .setName("drawable")
                        .addEntry(
                            Resources.Entry.newBuilder()
                                .setEntryId(Resources.EntryId.newBuilder().setId(1))
                                .setName("icon_notification")
                                .addConfigValue(file("res/drawable/icon_notification.$notificationExtension")),
                        ),
                ),
        ).build().toByteArray()
    }

    private fun resourcesTableWithOtherLayout(): ByteArray {
        fun file(path: String) = Resources.ConfigValue.newBuilder().setValue(
            Resources.Value.newBuilder().setItem(
                Resources.Item.newBuilder().setFile(Resources.FileReference.newBuilder().setPath(path)),
            ),
        )
        return Resources.ResourceTable.parseFrom(resourcesTable()).toBuilder().apply {
            val resourcePackage = getPackage(0).toBuilder()
            val layouts = resourcePackage.getType(0).toBuilder().addEntry(
                Resources.Entry.newBuilder()
                    .setEntryId(Resources.EntryId.newBuilder().setId(2))
                    .setName("other")
                    .addConfigValue(file("res/layout/other.xml")),
            )
            resourcePackage.setType(0, layouts)
            setPackage(0, resourcePackage)
        }.build().toByteArray()
    }

    private fun resourcesTableWithFont(): ByteArray {
        fun file(path: String) = Resources.ConfigValue.newBuilder().setValue(
            Resources.Value.newBuilder().setItem(
                Resources.Item.newBuilder().setFile(Resources.FileReference.newBuilder().setPath(path)),
            ),
        )
        return Resources.ResourceTable.parseFrom(resourcesTable()).toBuilder().apply {
            val resourcePackage = getPackage(0).toBuilder().addType(
                Resources.Type.newBuilder()
                    .setTypeId(Resources.TypeId.newBuilder().setId(3))
                    .setName("font")
                    .addEntry(
                        Resources.Entry.newBuilder()
                            .setEntryId(Resources.EntryId.newBuilder().setId(1))
                            .setName("brand")
                            .addConfigValue(file("res/font/brand.ttf")),
                    ),
            ).build()
            setPackage(0, resourcePackage)
        }.build().toByteArray()
    }

    private fun sfntFont(): ByteArray {
        val bytes = ByteArray(40)
        val buffer = ByteBuffer.wrap(bytes).order(ByteOrder.BIG_ENDIAN)
        buffer.putInt(0, 0x00010000)
        buffer.putShort(4, 1.toShort())
        buffer.putShort(6, 16.toShort())
        buffer.putShort(8, 0.toShort())
        buffer.putShort(10, 0.toShort())
        buffer.putInt(12, 0x68656164)
        buffer.putInt(16, 0x00010000)
        buffer.putInt(20, 28)
        buffer.putInt(24, 12)
        buffer.putInt(28, 0x00010000)
        buffer.putInt(32, 0)
        buffer.putInt(36, 0)
        val adjustment = (0xb1b0afbaL - sfntChecksum(bytes)) and 0xffffffffL
        buffer.putInt(36, adjustment.toInt())
        return bytes
    }

    private fun sfntChecksum(bytes: ByteArray): Long {
        var checksum = 0L
        var offset = 0
        while (offset < bytes.size) {
            var word = 0L
            repeat(4) { index ->
                word = word shl 8
                if (offset + index < bytes.size) word = word or (bytes[offset + index].toLong() and 0xffL)
            }
            checksum = (checksum + word) and 0xffffffffL
            offset += 4
        }
        return checksum
    }

    private fun resourcesTableWithNotificationQualifiers(): ByteArray {
        fun file(path: String, landscape: Boolean = false) = Resources.ConfigValue.newBuilder()
            .apply {
                if (landscape) config = com.android.aapt.ConfigurationOuterClass.Configuration.newBuilder()
                    .setOrientationValue(2)
                    .build()
            }
            .setValue(
                Resources.Value.newBuilder().setItem(
                    Resources.Item.newBuilder().setFile(Resources.FileReference.newBuilder().setPath(path)),
                ),
            )
        return Resources.ResourceTable.newBuilder().addPackage(
            Resources.Package.newBuilder()
                .setPackageId(Resources.PackageId.newBuilder().setId(0x7f))
                .addType(
                    Resources.Type.newBuilder()
                        .setTypeId(Resources.TypeId.newBuilder().setId(1))
                        .setName("layout")
                        .addEntry(
                            Resources.Entry.newBuilder()
                                .setEntryId(Resources.EntryId.newBuilder().setId(1))
                                .setName("home")
                                .addConfigValue(file("res/layout/home.xml")),
                        ),
                )
                .addType(
                    Resources.Type.newBuilder()
                        .setTypeId(Resources.TypeId.newBuilder().setId(2))
                        .setName("drawable")
                        .addEntry(
                            Resources.Entry.newBuilder()
                                .setEntryId(Resources.EntryId.newBuilder().setId(1))
                                .setName("icon_notification")
                                .addConfigValue(file("res/drawable/icon_notification.png"))
                                .addConfigValue(file("res/drawable-land/icon_notification.png", landscape = true)),
                        ),
                ),
        ).build().toByteArray()
    }

    private fun compiledXml(): ByteArray = Resources.XmlNode.newBuilder()
        .setText("compiled-layout")
        .build()
        .toByteArray()

    private fun dex(descriptor: String, sourceFile: String? = null): ByteArray {
        val implementation = ImmutableMethodImplementation(
            0,
            listOf(ImmutableInstruction10x(Opcode.RETURN_VOID)),
            emptyList(),
            emptyList(),
        )
        val method = ImmutableMethod(
            descriptor,
            "calculate",
            emptyList(),
            "V",
            AccessFlags.PUBLIC.value or AccessFlags.STATIC.value,
            emptySet(),
            emptySet(),
            implementation,
        )
        val clazz = ImmutableClassDef(
            descriptor,
            AccessFlags.PUBLIC.value,
            "Ljava/lang/Object;",
            emptyList(),
            sourceFile,
            emptySet(),
            emptyList(),
            listOf(method),
        )
        val store = MemoryDataStore()
        DexPool.writeTo(store, ImmutableDexFile(Opcodes.getDefault(), listOf(clazz)))
        return store.data
    }

    private fun dexWithCrossPackageBridge(): ByteArray {
        val returnVoid = ImmutableMethodImplementation(
            0,
            listOf(ImmutableInstruction10x(Opcode.RETURN_VOID)),
            emptyList(),
            emptyList(),
        )
        val bridge = ImmutableMethod(
            OBFUSCATED_OWNED_DESCRIPTOR,
            "bridge",
            emptyList(),
            "V",
            AccessFlags.PUBLIC.value or AccessFlags.STATIC.value or AccessFlags.SYNTHETIC.value,
            emptySet(),
            emptySet(),
            returnVoid,
        )
        val calculate = ImmutableMethod(
            OBFUSCATED_OWNED_DESCRIPTOR,
            "calculate",
            emptyList(),
            "V",
            AccessFlags.PUBLIC.value or AccessFlags.STATIC.value,
            emptySet(),
            emptySet(),
            returnVoid,
        )
        val target = ImmutableClassDef(
            OBFUSCATED_OWNED_DESCRIPTOR,
            AccessFlags.FINAL.value,
            "Ljava/lang/Object;",
            emptyList(),
            null,
            emptySet(),
            emptyList(),
            listOf(bridge, calculate),
        )
        val callerDescriptor = "Lcom/example/demo/match/a;"
        val caller = ImmutableClassDef(
            callerDescriptor,
            AccessFlags.PUBLIC.value or AccessFlags.FINAL.value,
            "Ljava/lang/Object;",
            emptyList(),
            null,
            emptySet(),
            emptyList(),
            listOf(
                ImmutableMethod(
                    callerDescriptor,
                    "run",
                    emptyList(),
                    "V",
                    AccessFlags.PUBLIC.value or AccessFlags.STATIC.value,
                    emptySet(),
                    emptySet(),
                    ImmutableMethodImplementation(
                        0,
                        listOf(
                            ImmutableInstruction35c(
                                Opcode.INVOKE_STATIC,
                                0,
                                0,
                                0,
                                0,
                                0,
                                0,
                                ImmutableMethodReference(
                                    OBFUSCATED_OWNED_DESCRIPTOR,
                                    "bridge",
                                    emptyList<String>(),
                                    "V",
                                ),
                            ),
                            ImmutableInstruction10x(Opcode.RETURN_VOID),
                        ),
                        emptyList(),
                        emptyList(),
                    ),
                ),
            ),
        )
        val store = MemoryDataStore()
        DexPool.writeTo(store, ImmutableDexFile(Opcodes.getDefault(), listOf(caller, target)))
        return store.data
    }

    private fun classInitializerDex(descriptor: String): ByteArray {
        val implementation = ImmutableMethodImplementation(
            0,
            listOf(ImmutableInstruction10x(Opcode.RETURN_VOID)),
            emptyList(),
            emptyList(),
        )
        val method = ImmutableMethod(
            descriptor,
            "<clinit>",
            emptyList(),
            "V",
            AccessFlags.STATIC.value or AccessFlags.CONSTRUCTOR.value,
            emptySet(),
            emptySet(),
            implementation,
        )
        val clazz = ImmutableClassDef(
            descriptor,
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

    private fun invalidClassInitializerDex(descriptor: String): ByteArray {
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
                descriptor,
                AccessFlags.PUBLIC.value,
                "Ljava/lang/Object;",
                emptyList(),
                null,
                emptySet(),
                emptyList(),
                listOf(
                    method(
                        descriptor,
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
        require(methodIdsSize >= 2)
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

    private fun zip(path: Path, entries: Map<String, ByteArray>) {
        ZipOutputStream(Files.newOutputStream(path)).use { output ->
            entries.forEach { (name, bytes) ->
                output.putNextEntry(ZipEntry(name))
                output.write(bytes)
                output.closeEntry()
            }
        }
    }

    private companion object {
        val OWNED_MODULES = setOf(":app", ":core", ":compress", ":selector", ":ucrop")
        const val OWNED_DESCRIPTOR = "Lcom/example/demo/match/Calculator;"
        const val SECOND_OWNED_DESCRIPTOR = "Lcom/example/demo/match/Second;"
        const val OBFUSCATED_OWNED_DESCRIPTOR = "La/b;"
        const val METHOD_ID_ITEM_SIZE = 8
    }
}
