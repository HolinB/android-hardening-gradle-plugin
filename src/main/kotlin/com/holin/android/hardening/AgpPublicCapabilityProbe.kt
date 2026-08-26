package com.holin.android.hardening

internal data class AgpPublicCapability(
    val name: String,
    val typeName: String,
    val memberName: String? = null,
)

internal fun interface AgpPublicApi {
    fun isAvailable(capability: AgpPublicCapability): Boolean
}

internal object AgpPublicCapabilityProbe {
    val requiredCapabilities = listOf(
        AgpPublicCapability(
            "ApplicationAndroidComponentsExtension",
            "com.android.build.api.variant.ApplicationAndroidComponentsExtension",
        ),
        AgpPublicCapability(
            "ApplicationAndroidComponentsExtension.finalizeDsl",
            "com.android.build.api.variant.ApplicationAndroidComponentsExtension",
            "finalizeDsl",
        ),
        AgpPublicCapability(
            "ApplicationAndroidComponentsExtension.onVariants",
            "com.android.build.api.variant.ApplicationAndroidComponentsExtension",
            "onVariants",
        ),
        AgpPublicCapability(
            "ApplicationAndroidComponentsExtension.selector",
            "com.android.build.api.variant.ApplicationAndroidComponentsExtension",
            "selector",
        ),
        AgpPublicCapability(
            "ApplicationAndroidComponentsExtension.sdkComponents",
            "com.android.build.api.variant.ApplicationAndroidComponentsExtension",
            "sdkComponents",
        ),
        AgpPublicCapability(
            "VariantSelector",
            "com.android.build.api.variant.VariantSelector",
        ),
        AgpPublicCapability(
            "VariantSelector.all",
            "com.android.build.api.variant.VariantSelector",
            "all",
        ),
        AgpPublicCapability(
            "ApplicationVariant",
            "com.android.build.api.variant.ApplicationVariant",
        ),
        AgpPublicCapability(
            "ApplicationVariant.artifacts",
            "com.android.build.api.variant.ApplicationVariant",
            "artifacts",
        ),
        AgpPublicCapability(
            "ApplicationVariant.instrumentation",
            "com.android.build.api.variant.ApplicationVariant",
            "instrumentation",
        ),
        AgpPublicCapability(
            "ApplicationVariant.applicationId",
            "com.android.build.api.variant.ApplicationVariant",
            "applicationId",
        ),
        AgpPublicCapability(
            "ApplicationVariant.buildType",
            "com.android.build.api.variant.ApplicationVariant",
            "buildType",
        ),
        AgpPublicCapability(
            "ApplicationVariant.compileClasspath",
            "com.android.build.api.variant.ApplicationVariant",
            "compileClasspath",
        ),
        AgpPublicCapability(
            "ApplicationVariant.name",
            "com.android.build.api.variant.ApplicationVariant",
            "name",
        ),
        AgpPublicCapability(
            "ApplicationVariant.namespace",
            "com.android.build.api.variant.ApplicationVariant",
            "namespace",
        ),
        AgpPublicCapability(
            "ApplicationVariant.outputs",
            "com.android.build.api.variant.ApplicationVariant",
            "outputs",
        ),
        AgpPublicCapability(
            "ApplicationVariant.productFlavors",
            "com.android.build.api.variant.ApplicationVariant",
            "productFlavors",
        ),
        AgpPublicCapability(
            "ApplicationVariant.proguardFiles",
            "com.android.build.api.variant.ApplicationVariant",
            "proguardFiles",
        ),
        AgpPublicCapability(
            "ApplicationVariant.sources",
            "com.android.build.api.variant.ApplicationVariant",
            "sources",
        ),
        AgpPublicCapability(
            "ApplicationVariantOutputs.enabled",
            "com.android.build.api.variant.VariantOutput",
            "enabled",
        ),
        AgpPublicCapability(
            "ApplicationVariantOutputs.versionCode",
            "com.android.build.api.variant.VariantOutput",
            "versionCode",
        ),
        AgpPublicCapability(
            "ApplicationVariantOutputs.versionName",
            "com.android.build.api.variant.VariantOutput",
            "versionName",
        ),
        AgpPublicCapability(
            "ApplicationVariantSources.res",
            "com.android.build.api.variant.Sources",
            "res",
        ),
        AgpPublicCapability(
            "ApplicationVariantSources.res.static",
            "com.android.build.api.variant.SourceDirectories\$Layered",
            "static",
        ),
        AgpPublicCapability(
            "SdkComponents.bootClasspath",
            "com.android.build.api.dsl.SdkComponents",
            "bootClasspath",
        ),
        AgpPublicCapability(
            "SdkComponents.sdkDirectory",
            "com.android.build.api.dsl.SdkComponents",
            "sdkDirectory",
        ),
        AgpPublicCapability(
            "ScopedArtifacts",
            "com.android.build.api.variant.ScopedArtifacts",
        ),
        AgpPublicCapability(
            "ScopedArtifacts.Scope",
            "com.android.build.api.variant.ScopedArtifacts\$Scope",
        ),
        AgpPublicCapability(
            "ScopedArtifacts.Scope.PROJECT",
            "com.android.build.api.variant.ScopedArtifacts\$Scope",
            "PROJECT",
        ),
        AgpPublicCapability(
            "Artifacts.forScope",
            "com.android.build.api.artifact.Artifacts",
            "forScope",
        ),
        AgpPublicCapability(
            "Artifacts.get",
            "com.android.build.api.artifact.Artifacts",
            "get",
        ),
        AgpPublicCapability(
            "ScopedArtifacts.use",
            "com.android.build.api.variant.ScopedArtifacts",
            "use",
        ),
        AgpPublicCapability(
            "ScopedArtifactsOperation.toGet",
            "com.android.build.api.variant.ScopedArtifactsOperation",
            "toGet",
        ),
        AgpPublicCapability(
            "ScopedArtifact.CLASSES",
            "com.android.build.api.artifact.ScopedArtifact\$CLASSES",
        ),
        AgpPublicCapability(
            "SingleArtifact.BUNDLE",
            "com.android.build.api.artifact.SingleArtifact\$BUNDLE",
        ),
        AgpPublicCapability(
            "SingleArtifact.MERGED_MANIFEST",
            "com.android.build.api.artifact.SingleArtifact\$MERGED_MANIFEST",
        ),
        AgpPublicCapability(
            "SingleArtifact.OBFUSCATION_MAPPING_FILE",
            "com.android.build.api.artifact.SingleArtifact\$OBFUSCATION_MAPPING_FILE",
        ),
        AgpPublicCapability(
            "ApplicationExtension.defaultConfig",
            "com.android.build.api.dsl.ApplicationExtension",
            "defaultConfig",
        ),
        AgpPublicCapability(
            "ApplicationExtension.buildToolsVersion",
            "com.android.build.api.dsl.ApplicationExtension",
            "buildToolsVersion",
        ),
        AgpPublicCapability(
            "ApplicationExtension.buildTypes",
            "com.android.build.api.dsl.ApplicationExtension",
            "buildTypes",
        ),
        AgpPublicCapability(
            "ApplicationExtension.productFlavors",
            "com.android.build.api.dsl.ApplicationExtension",
            "productFlavors",
        ),
        AgpPublicCapability(
            "ApplicationDefaultConfig.signingConfig",
            "com.android.build.api.dsl.ApplicationDefaultConfig",
            "signingConfig",
        ),
        AgpPublicCapability(
            "ApplicationBuildType.buildConfigField",
            "com.android.build.api.dsl.ApplicationBuildType",
            "buildConfigField",
        ),
        AgpPublicCapability(
            "ApplicationBuildType.isDebuggable",
            "com.android.build.api.dsl.ApplicationBuildType",
            "isDebuggable",
        ),
        AgpPublicCapability(
            "ApplicationBuildType.isMinifyEnabled",
            "com.android.build.api.dsl.ApplicationBuildType",
            "isMinifyEnabled",
        ),
        AgpPublicCapability(
            "ApplicationBuildType.name",
            "com.android.build.api.dsl.ApplicationBuildType",
            "name",
        ),
        AgpPublicCapability(
            "ApplicationBuildType.setDebuggable",
            "com.android.build.api.dsl.ApplicationBuildType",
            "setDebuggable",
        ),
        AgpPublicCapability(
            "ApplicationBuildType.setMinifyEnabled",
            "com.android.build.api.dsl.ApplicationBuildType",
            "setMinifyEnabled",
        ),
        AgpPublicCapability(
            "ApplicationBuildType.signingConfig",
            "com.android.build.api.dsl.ApplicationBuildType",
            "signingConfig",
        ),
        AgpPublicCapability(
            "ApplicationProductFlavor.name",
            "com.android.build.api.dsl.ApplicationProductFlavor",
            "name",
        ),
        AgpPublicCapability(
            "ApplicationProductFlavor.signingConfig",
            "com.android.build.api.dsl.ApplicationProductFlavor",
            "signingConfig",
        ),
        AgpPublicCapability(
            "ApkSigningConfig",
            "com.android.build.api.dsl.ApkSigningConfig",
        ),
        AgpPublicCapability("ApkSigningConfig.keyAlias", "com.android.build.api.dsl.ApkSigningConfig", "keyAlias"),
        AgpPublicCapability("ApkSigningConfig.keyPassword", "com.android.build.api.dsl.ApkSigningConfig", "keyPassword"),
        AgpPublicCapability("ApkSigningConfig.storeFile", "com.android.build.api.dsl.ApkSigningConfig", "storeFile"),
        AgpPublicCapability("ApkSigningConfig.storePassword", "com.android.build.api.dsl.ApkSigningConfig", "storePassword"),
        AgpPublicCapability("ApkSigningConfig.storeType", "com.android.build.api.dsl.ApkSigningConfig", "storeType"),
    )

    fun verify(actualAgpVersion: String, classLoader: ClassLoader) {
        verify(actualAgpVersion, ReflectiveAgpPublicApi(classLoader))
    }

    fun verify(actualAgpVersion: String, api: AgpPublicApi) {
        requiredCapabilities.firstOrNull { capability -> !api.isAvailable(capability) }?.let { missing ->
            throw IllegalArgumentException(
                "Android Gradle Plugin public capability is unavailable: " +
                    "actual=$actualAgpVersion, missing=${missing.name}",
            )
        }
    }

    private class ReflectiveAgpPublicApi(
        private val classLoader: ClassLoader,
    ) : AgpPublicApi {
        override fun isAvailable(capability: AgpPublicCapability): Boolean = runCatching {
            val type = Class.forName(capability.typeName, false, classLoader)
            capability.memberName == null || type.methods.any { method ->
                method.name == capability.memberName ||
                    method.name == "get${capability.memberName.replaceFirstChar(Char::uppercase)}"
            } || type.fields.any { field -> field.name == capability.memberName }
        }.getOrDefault(false)
    }
}
