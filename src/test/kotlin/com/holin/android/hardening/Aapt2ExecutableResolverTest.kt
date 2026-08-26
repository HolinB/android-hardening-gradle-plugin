package com.holin.android.hardening

import java.nio.file.Path
import kotlin.test.Test
import kotlin.test.assertEquals
import org.gradle.api.file.Directory
import org.gradle.api.file.RegularFile
import org.gradle.api.provider.Provider
import org.gradle.testfixtures.ProjectBuilder
import org.junit.jupiter.api.io.TempDir

class Aapt2ExecutableResolverTest {
    @TempDir
    lateinit var projectDirectory: Path

    @Test
    fun `uses the public Aapt2 provider when AGP exposes it`() {
        val project = ProjectBuilder.builder().withProjectDir(projectDirectory.toFile()).build()
        val expected = project.layout.projectDirectory.file("modern/aapt2")
        val sdkComponents = TestModernSdkComponents(
            project.providers.provider {
                TestAapt2(project.providers.provider { expected })
            },
        )

        val actual = resolve(
            sdkComponents,
            project.providers.provider { project.layout.projectDirectory.dir("sdk") },
            project.providers.provider { "35.0.0" },
            "Mac OS X",
        ).get()

        assertEquals(expected.asFile, actual.asFile)
    }

    @Test
    fun `falls back to the selected build tools on AGP 8 8`() {
        val project = ProjectBuilder.builder().withProjectDir(projectDirectory.toFile()).build()

        val actual = resolve(
            TestLegacySdkComponents(),
            project.providers.provider { project.layout.projectDirectory.dir("sdk") },
            project.providers.provider { "35.0.0" },
            "Mac OS X",
        ).get()

        assertEquals(
            project.layout.projectDirectory.file("sdk/build-tools/35.0.0/aapt2").asFile,
            actual.asFile,
        )
    }

    @Test
    fun `uses the Windows Aapt2 executable name for the public fallback`() {
        val project = ProjectBuilder.builder().withProjectDir(projectDirectory.toFile()).build()

        val actual = resolve(
            TestLegacySdkComponents(),
            project.providers.provider { project.layout.projectDirectory.dir("sdk") },
            project.providers.provider { "35.0.0" },
            "Windows 11",
        ).get()

        assertEquals(
            project.layout.projectDirectory.file("sdk/build-tools/35.0.0/aapt2.exe").asFile,
            actual.asFile,
        )
    }

    @Suppress("UNCHECKED_CAST")
    private fun resolve(
        sdkComponents: Any,
        sdkDirectory: Provider<Directory>,
        buildToolsVersion: Provider<String>,
        operatingSystemName: String,
    ): Provider<RegularFile> {
        val type = Class.forName("com.holin.android.hardening.Aapt2ExecutableResolver")
        val instance = type.getField("INSTANCE").get(null)
        val method = type.getDeclaredMethod(
            "resolve",
            Any::class.java,
            Provider::class.java,
            Provider::class.java,
            String::class.java,
        ).apply { isAccessible = true }
        return method.invoke(
            instance,
            sdkComponents,
            sdkDirectory,
            buildToolsVersion,
            operatingSystemName,
        ) as Provider<RegularFile>
    }
}

class TestModernSdkComponents(
    val aapt2: Provider<TestAapt2>,
)

class TestAapt2(
    val executable: Provider<RegularFile>,
)

class TestLegacySdkComponents
