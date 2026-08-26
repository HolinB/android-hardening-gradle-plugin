package com.holin.android.hardening

import org.gradle.api.file.Directory
import org.gradle.api.file.RegularFile
import org.gradle.api.provider.Provider

internal object Aapt2ExecutableResolver {
    fun resolve(
        sdkComponents: Any,
        sdkDirectory: Provider<Directory>,
        buildToolsVersion: Provider<String>,
        operatingSystemName: String = System.getProperty("os.name"),
    ): Provider<RegularFile> {
        val aapt2Getter = sdkComponents.javaClass.methods.firstOrNull { method ->
            method.name == "getAapt2" && method.parameterCount == 0
        }
        if (aapt2Getter != null) {
            @Suppress("UNCHECKED_CAST")
            val aapt2 = aapt2Getter.invoke(sdkComponents) as Provider<Any>
            return aapt2.flatMap { component ->
                val executableGetter = component.javaClass.methods.firstOrNull { method ->
                    method.name == "getExecutable" && method.parameterCount == 0
                } ?: throw IllegalArgumentException(
                    "Android Gradle Plugin Aapt2 public capability is unavailable: missing=Aapt2.executable",
                )
                @Suppress("UNCHECKED_CAST")
                executableGetter.invoke(component) as Provider<RegularFile>
            }
        }

        val executableName = if (operatingSystemName.contains("win", true)) "aapt2.exe" else "aapt2"
        return sdkDirectory.zip(buildToolsVersion) { sdk, version ->
            require(version.isNotBlank()) { "Android buildToolsVersion must be nonblank to resolve AAPT2" }
            sdk.file("build-tools/$version/$executableName")
        }
    }
}
