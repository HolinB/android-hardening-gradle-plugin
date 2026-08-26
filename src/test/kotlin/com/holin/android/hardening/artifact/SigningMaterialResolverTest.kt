package com.holin.android.hardening.artifact

import java.nio.file.Path
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import org.junit.jupiter.api.io.TempDir

class SigningMaterialResolverTest {
    @TempDir
    lateinit var temporary: Path

    @Test
    fun `build type wins then one distinct flavor then default`() {
        val release = material("release")
        val flavor = material("demo")
        val fallback = material("default")

        assertEquals(
            "release",
            SigningMaterialResolver.resolve(release, listOf(flavor), fallback).configName,
        )
        assertEquals(
            "demo",
            SigningMaterialResolver.resolve(null, listOf(flavor, flavor), fallback).configName,
        )
        assertEquals(
            "default",
            SigningMaterialResolver.resolve(null, emptyList(), fallback).configName,
        )
    }

    @Test
    fun `ambiguous flavor signing configs and missing material fail closed without exposing secrets`() {
        val failure = assertFailsWith<IllegalArgumentException> {
            SigningMaterialResolver.resolve(null, listOf(material("one"), material("two")), null)
        }
        assertEquals("selected hardening variant has ambiguous flavor signing configurations", failure.message)

        val missing = assertFailsWith<IllegalArgumentException> {
            SigningMaterial.create(
                configName = "demo",
                storeFile = null,
                storePassword = "do-not-print",
                keyAlias = "do-not-print",
                keyPassword = "do-not-print",
                storeType = "PKCS12",
            )
        }
        assertEquals("selected hardening signing configuration is incomplete", missing.message)
    }

    private fun material(name: String): SigningMaterial = SigningMaterial.create(
        configName = name,
        storeFile = temporary.resolve("$name.p12"),
        storePassword = "fixture-password",
        keyAlias = "fixture-alias",
        keyPassword = "fixture-password",
        storeType = "PKCS12",
    )
}
