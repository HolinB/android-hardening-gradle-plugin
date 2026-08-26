package com.holin.android.hardening.similarity

import com.android.aapt.ConfigurationOuterClass.Configuration
import com.android.aapt.Resources
import java.nio.file.Path
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream
import kotlin.io.path.outputStream
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import org.junit.jupiter.api.io.TempDir

class BaselineOwnedResourceLocationResolverTest {
    @TempDir
    lateinit var temporary: Path

    @Test
    fun `resolves old ordinary and hardened physical paths independently from saved resource tables`() {
        val ordinary = aab(
            "ordinary.aab",
            table(fileValue("res/raw/old_ordinary.bin")),
            "base/res/raw/old_ordinary.bin",
        )
        val hardened = aab(
            "hardened.aab",
            table(fileValue("res/raw/old_hardened.bin")),
            "base/res/raw/old_hardened.bin",
        )
        val current = mapOf(
            KEY to OwnedResourceLocation(
                "new_name.bin", "base/res/raw/new_name.bin", "res/raw/new_name.bin", SEMANTIC_HASH,
            ),
        )
        val resolver = BaselineOwnedResourceLocationResolver()

        val resolvedOrdinary = resolver.resolve(ordinary, current)
        val resolvedHardened = resolver.resolve(hardened, current)

        assertEquals(
            OwnedResourceLocation(
                "old_ordinary.bin", "base/res/raw/old_ordinary.bin", "res/raw/old_ordinary.bin", SEMANTIC_HASH,
            ),
            resolvedOrdinary.getValue(KEY),
        )
        assertEquals(
            OwnedResourceLocation(
                "old_hardened.bin", "base/res/raw/old_hardened.bin", "res/raw/old_hardened.bin", SEMANTIC_HASH,
            ),
            resolvedHardened.getValue(KEY),
        )
    }

    @Test
    fun `rejects missing and ambiguous resource table mappings`() {
        val current = mapOf(KEY to currentLocation())
        val missing = aab(
            "missing.aab",
            table(fileValue("res/raw/other.bin"), entryId = 2),
            "base/res/raw/other.bin",
        )
        val ambiguous = aab(
            "ambiguous.aab",
            table(
                fileValue("res/raw/first.bin"),
                fileValue("res/raw/second.bin"),
            ),
            "base/res/raw/first.bin",
            "base/res/raw/second.bin",
        )

        val missingFailure = assertFailsWith<IllegalArgumentException> {
            BaselineOwnedResourceLocationResolver().resolve(missing, current)
        }
        val ambiguousFailure = assertFailsWith<IllegalArgumentException> {
            BaselineOwnedResourceLocationResolver().resolve(ambiguous, current)
        }

        assertTrue(missingFailure.message.orEmpty().contains("not found"))
        assertTrue(ambiguousFailure.message.orEmpty().contains("ambiguous"))
    }

    @Test
    fun `rejects malformed unsafe non-file and missing physical resource mappings`() {
        val current = mapOf(KEY to currentLocation())
        val malformed = aab("malformed.aab", byteArrayOf(0x7f), "base/res/raw/current.bin")
        val unsafe = aab(
            "unsafe.aab",
            table(fileValue("res/raw/../current.bin")),
            "base/res/raw/current.bin",
        )
        val nonFile = aab(
            "non-file.aab",
            table(nonFileValue()),
        )
        val missingPhysical = aab(
            "missing-physical.aab",
            table(fileValue("res/raw/current.bin")),
        )

        assertFailsWith<IllegalArgumentException> {
            BaselineOwnedResourceLocationResolver().resolve(malformed, current)
        }
        assertTrue(assertFailsWith<IllegalArgumentException> {
            BaselineOwnedResourceLocationResolver().resolve(unsafe, current)
        }.message.orEmpty().contains("unsafe"))
        assertTrue(assertFailsWith<IllegalArgumentException> {
            BaselineOwnedResourceLocationResolver().resolve(nonFile, current)
        }.message.orEmpty().contains("file resource"))
        assertTrue(assertFailsWith<IllegalArgumentException> {
            BaselineOwnedResourceLocationResolver().resolve(missingPhysical, current)
        }.message.orEmpty().contains("missing physical"))
    }

    private fun currentLocation() = OwnedResourceLocation(
        "current.bin", "base/res/raw/current.bin", "res/raw/current.bin", SEMANTIC_HASH,
    )

    private fun table(
        vararg values: Resources.ConfigValue,
        entryId: Int = 1,
    ): ByteArray = Resources.ResourceTable.newBuilder()
        .addPackage(
            Resources.Package.newBuilder()
                .setPackageId(Resources.PackageId.newBuilder().setId(0x7f))
                .setPackageName("com.example.demo")
                .addType(
                    Resources.Type.newBuilder()
                        .setTypeId(Resources.TypeId.newBuilder().setId(1))
                        .setName("raw")
                        .addEntry(
                            Resources.Entry.newBuilder()
                                .setEntryId(Resources.EntryId.newBuilder().setId(entryId))
                                .setName("current")
                                .addAllConfigValue(values.asList()),
                        ),
                ),
        )
        .build()
        .toByteArray()

    private fun fileValue(
        path: String,
        config: Configuration = Configuration.getDefaultInstance(),
    ): Resources.ConfigValue = Resources.ConfigValue.newBuilder()
        .setConfig(config)
        .setValue(
            Resources.Value.newBuilder().setItem(
                Resources.Item.newBuilder().setFile(Resources.FileReference.newBuilder().setPath(path)),
            ),
        )
        .build()

    private fun nonFileValue(): Resources.ConfigValue = Resources.ConfigValue.newBuilder()
        .setValue(
            Resources.Value.newBuilder().setItem(
                Resources.Item.newBuilder().setRawStr(Resources.RawString.newBuilder().setValue("inline")),
            ),
        )
        .build()

    private fun aab(name: String, resourcesPb: ByteArray, vararg resourcePaths: String): Path =
        temporary.resolve(name).also { path ->
            ZipOutputStream(path.outputStream()).use { output ->
                output.putNextEntry(ZipEntry("base/resources.pb"))
                output.write(resourcesPb)
                output.closeEntry()
                resourcePaths.forEach { resourcePath ->
                    output.putNextEntry(ZipEntry(resourcePath))
                    output.write(resourcePath.toByteArray())
                    output.closeEntry()
                }
            }
        }

    private companion object {
        val KEY = OwnedResourceKey(0x7f010001, "")
        const val SEMANTIC_HASH = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    }
}
