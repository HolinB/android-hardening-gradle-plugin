package com.holin.android.hardening

import kotlin.test.Test
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class AgpPublicCapabilityProbeTest {
    @Test
    fun `accepts the complete public AGP capability set`() {
        assertTrue(
            EXPECTED_CAPABILITIES.size == EXPECTED_CAPABILITIES.toSet().size,
            "independent expected capability contract contains duplicates",
        )
        assertTrue(
            AgpPublicCapabilityProbe.requiredCapabilities.size ==
                AgpPublicCapabilityProbe.requiredCapabilities.toSet().size,
            "production capability probe contains duplicates",
        )
        assertTrue(
            AgpPublicCapabilityProbe.requiredCapabilities.toSet() == EXPECTED_CAPABILITIES.toSet(),
            "production capability probe must cover every AGP API consumed by the adapter",
        )
        AgpPublicCapabilityProbe.verify(
            "8.8.0",
            TestAgpPublicApi(EXPECTED_CAPABILITIES.toSet()),
        )
    }

    @Test
    fun `reports each missing public AGP capability precisely`() {
        EXPECTED_CAPABILITIES.forEach { missing ->
            val failure = assertFailsWith<IllegalArgumentException> {
                AgpPublicCapabilityProbe.verify(
                    "8.8.0",
                    TestAgpPublicApi(EXPECTED_CAPABILITIES.toSet() - missing),
                )
            }

            assertTrue(failure.message.orEmpty().contains("actual=8.8.0"), failure.message)
            assertTrue(failure.message.orEmpty().contains(missing.name), failure.message)
        }
    }

    private class TestAgpPublicApi(
        private val available: Set<AgpPublicCapability>,
    ) : AgpPublicApi {
        override fun isAvailable(capability: AgpPublicCapability): Boolean = capability in available
    }

    private companion object {
        val EXPECTED_CAPABILITIES = listOf(
            AgpPublicCapability("ApplicationAndroidComponentsExtension", "com.android.build.api.variant.ApplicationAndroidComponentsExtension"),
            AgpPublicCapability("ApplicationAndroidComponentsExtension.finalizeDsl", "com.android.build.api.variant.ApplicationAndroidComponentsExtension", "finalizeDsl"),
            AgpPublicCapability("ApplicationAndroidComponentsExtension.onVariants", "com.android.build.api.variant.ApplicationAndroidComponentsExtension", "onVariants"),
            AgpPublicCapability("ApplicationAndroidComponentsExtension.selector", "com.android.build.api.variant.ApplicationAndroidComponentsExtension", "selector"),
            AgpPublicCapability("ApplicationAndroidComponentsExtension.sdkComponents", "com.android.build.api.variant.ApplicationAndroidComponentsExtension", "sdkComponents"),
            AgpPublicCapability("VariantSelector", "com.android.build.api.variant.VariantSelector"),
            AgpPublicCapability("VariantSelector.all", "com.android.build.api.variant.VariantSelector", "all"),
            AgpPublicCapability("ApplicationVariant", "com.android.build.api.variant.ApplicationVariant"),
            AgpPublicCapability("ApplicationVariant.applicationId", "com.android.build.api.variant.ApplicationVariant", "applicationId"),
            AgpPublicCapability("ApplicationVariant.artifacts", "com.android.build.api.variant.ApplicationVariant", "artifacts"),
            AgpPublicCapability("ApplicationVariant.buildType", "com.android.build.api.variant.ApplicationVariant", "buildType"),
            AgpPublicCapability("ApplicationVariant.compileClasspath", "com.android.build.api.variant.ApplicationVariant", "compileClasspath"),
            AgpPublicCapability("ApplicationVariant.instrumentation", "com.android.build.api.variant.ApplicationVariant", "instrumentation"),
            AgpPublicCapability("ApplicationVariant.name", "com.android.build.api.variant.ApplicationVariant", "name"),
            AgpPublicCapability("ApplicationVariant.namespace", "com.android.build.api.variant.ApplicationVariant", "namespace"),
            AgpPublicCapability("ApplicationVariant.outputs", "com.android.build.api.variant.ApplicationVariant", "outputs"),
            AgpPublicCapability("ApplicationVariant.productFlavors", "com.android.build.api.variant.ApplicationVariant", "productFlavors"),
            AgpPublicCapability("ApplicationVariant.proguardFiles", "com.android.build.api.variant.ApplicationVariant", "proguardFiles"),
            AgpPublicCapability("ApplicationVariant.sources", "com.android.build.api.variant.ApplicationVariant", "sources"),
            AgpPublicCapability("ApplicationVariantOutputs.enabled", "com.android.build.api.variant.VariantOutput", "enabled"),
            AgpPublicCapability("ApplicationVariantOutputs.versionCode", "com.android.build.api.variant.VariantOutput", "versionCode"),
            AgpPublicCapability("ApplicationVariantOutputs.versionName", "com.android.build.api.variant.VariantOutput", "versionName"),
            AgpPublicCapability("ApplicationVariantSources.res", "com.android.build.api.variant.Sources", "res"),
            AgpPublicCapability("ApplicationVariantSources.res.static", "com.android.build.api.variant.SourceDirectories\$Layered", "static"),
            AgpPublicCapability("ApkSigningConfig", "com.android.build.api.dsl.ApkSigningConfig"),
            AgpPublicCapability("ApkSigningConfig.keyAlias", "com.android.build.api.dsl.ApkSigningConfig", "keyAlias"),
            AgpPublicCapability("ApkSigningConfig.keyPassword", "com.android.build.api.dsl.ApkSigningConfig", "keyPassword"),
            AgpPublicCapability("ApkSigningConfig.storeFile", "com.android.build.api.dsl.ApkSigningConfig", "storeFile"),
            AgpPublicCapability("ApkSigningConfig.storePassword", "com.android.build.api.dsl.ApkSigningConfig", "storePassword"),
            AgpPublicCapability("ApkSigningConfig.storeType", "com.android.build.api.dsl.ApkSigningConfig", "storeType"),
            AgpPublicCapability("ApplicationExtension.buildToolsVersion", "com.android.build.api.dsl.ApplicationExtension", "buildToolsVersion"),
            AgpPublicCapability("ApplicationExtension.defaultConfig", "com.android.build.api.dsl.ApplicationExtension", "defaultConfig"),
            AgpPublicCapability("ApplicationExtension.buildTypes", "com.android.build.api.dsl.ApplicationExtension", "buildTypes"),
            AgpPublicCapability("ApplicationExtension.productFlavors", "com.android.build.api.dsl.ApplicationExtension", "productFlavors"),
            AgpPublicCapability("ApplicationDefaultConfig.signingConfig", "com.android.build.api.dsl.ApplicationDefaultConfig", "signingConfig"),
            AgpPublicCapability("ApplicationBuildType.buildConfigField", "com.android.build.api.dsl.ApplicationBuildType", "buildConfigField"),
            AgpPublicCapability("ApplicationBuildType.isDebuggable", "com.android.build.api.dsl.ApplicationBuildType", "isDebuggable"),
            AgpPublicCapability("ApplicationBuildType.isMinifyEnabled", "com.android.build.api.dsl.ApplicationBuildType", "isMinifyEnabled"),
            AgpPublicCapability("ApplicationBuildType.name", "com.android.build.api.dsl.ApplicationBuildType", "name"),
            AgpPublicCapability("ApplicationBuildType.setDebuggable", "com.android.build.api.dsl.ApplicationBuildType", "setDebuggable"),
            AgpPublicCapability("ApplicationBuildType.setMinifyEnabled", "com.android.build.api.dsl.ApplicationBuildType", "setMinifyEnabled"),
            AgpPublicCapability("ApplicationBuildType.signingConfig", "com.android.build.api.dsl.ApplicationBuildType", "signingConfig"),
            AgpPublicCapability("ApplicationProductFlavor.name", "com.android.build.api.dsl.ApplicationProductFlavor", "name"),
            AgpPublicCapability("ApplicationProductFlavor.signingConfig", "com.android.build.api.dsl.ApplicationProductFlavor", "signingConfig"),
            AgpPublicCapability("Artifacts.get", "com.android.build.api.artifact.Artifacts", "get"),
            AgpPublicCapability("ScopedArtifacts", "com.android.build.api.variant.ScopedArtifacts"),
            AgpPublicCapability("ScopedArtifacts.Scope", "com.android.build.api.variant.ScopedArtifacts\$Scope"),
            AgpPublicCapability("ScopedArtifacts.Scope.PROJECT", "com.android.build.api.variant.ScopedArtifacts\$Scope", "PROJECT"),
            AgpPublicCapability("Artifacts.forScope", "com.android.build.api.artifact.Artifacts", "forScope"),
            AgpPublicCapability("ScopedArtifacts.use", "com.android.build.api.variant.ScopedArtifacts", "use"),
            AgpPublicCapability("ScopedArtifactsOperation.toGet", "com.android.build.api.variant.ScopedArtifactsOperation", "toGet"),
            AgpPublicCapability("ScopedArtifact.CLASSES", "com.android.build.api.artifact.ScopedArtifact\$CLASSES"),
            AgpPublicCapability("SdkComponents.bootClasspath", "com.android.build.api.dsl.SdkComponents", "bootClasspath"),
            AgpPublicCapability("SdkComponents.sdkDirectory", "com.android.build.api.dsl.SdkComponents", "sdkDirectory"),
            AgpPublicCapability("SingleArtifact.BUNDLE", "com.android.build.api.artifact.SingleArtifact\$BUNDLE"),
            AgpPublicCapability("SingleArtifact.MERGED_MANIFEST", "com.android.build.api.artifact.SingleArtifact\$MERGED_MANIFEST"),
            AgpPublicCapability("SingleArtifact.OBFUSCATION_MAPPING_FILE", "com.android.build.api.artifact.SingleArtifact\$OBFUSCATION_MAPPING_FILE"),
        )
    }
}
