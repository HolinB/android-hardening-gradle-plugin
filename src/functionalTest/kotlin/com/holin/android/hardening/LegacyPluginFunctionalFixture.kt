package com.holin.android.hardening

import com.holin.android.hardening.state.Sha256
import java.nio.file.Path
import java.util.Base64
import kotlin.io.path.createDirectories
import kotlin.io.path.writeLines
import kotlin.io.path.writeText

internal fun installPinnedLegacyPluginFixture(projectDirectory: Path) {
    writeNeutralLegacyBaseline(projectDirectory)
    projectDirectory.resolve("fixture-legacy-plugin-observations.txt").writeLines(
        pinnedLegacyPluginObservationFields.map { fields ->
            fields.joinToString(".") { field ->
                Base64.getUrlEncoder().withoutPadding().encodeToString(field.toByteArray(Charsets.UTF_8))
            }
        },
    )
}

private fun writeNeutralLegacyBaseline(root: Path) {
    val appBuild = root.resolve("app/build.gradle.kts")
    val rootBuild = root.resolve("build.gradle.kts")
    val versionCatalog = root.resolve("gradle/libs.versions.toml")
    val baseline = root.resolve("app/hardening/legacy-plugins-baseline.json")
    appBuild.parent.createDirectories()
    versionCatalog.parent.createDirectories()
    baseline.parent.createDirectories()
    val applicationLines = listOf(
        "    id(\"io.github.qq549631030.android-junk-code\")\n",
        "    id(\"xml-class-guard\")\n",
        "    id(\"stringfog\")\n",
    )
    val junkDsl = "    androidJunkCode {\n        enabled.set(true)\n    }"
    val guardDsl = "    xmlClassGuard {\n        enabled.set(true)\n    }"
    val fogDsl = "configure<StringFogExtension> {\n    enabled.set(true)\n}"
    appBuild.writeText(
        "plugins {\n" + applicationLines.joinToString("") + "}\n\n" +
            "$junkDsl\n\n$guardDsl\n\n$fogDsl\n",
    )
    rootBuild.writeText(
        "id(\"io.github.qq549631030.android-junk-code\") version \"1.3.4\" apply false\n",
    )
    versionCatalog.writeText(
        "[versions]\nxmlClassGuard = \"1.2.6\"\nstringFogPlugin = \"5.2.0\"\nstringFogXor = \"5.0.0\"\n",
    )
    baseline.writeText(
        """
        {
          "schemaVersion": 3,
          "capture": {
            "hashAlgorithm": "SHA-256",
            "encoding": "UTF-8",
            "lineEndings": "raw",
            "regionBoundary": "start-inclusive-end-exclusive",
            "sourceProvenance": {
              "appBuild": {
                "path": "app/build.gradle.kts",
                "sourceRevision": "git-blob:fixture-app-build",
                "sha256": "${Sha256.file(appBuild)}"
              },
              "rootBuild": {
                "path": "build.gradle.kts",
                "sourceRevision": "git-blob:fixture-root-build",
                "sha256": "${Sha256.file(rootBuild)}"
              },
              "versionCatalog": {
                "path": "gradle/libs.versions.toml",
                "sourceRevision": "git-blob:fixture-version-catalog",
                "sha256": "${Sha256.file(versionCatalog)}"
              }
            },
            "regions": {
              "legacyPluginApplications": {
                "algorithm": "ordered-exact-lines",
                "file": "appBuild",
                "lines": [
                  "    id(\"io.github.qq549631030.android-junk-code\")${'\\'}n",
                  "    id(\"xml-class-guard\")${'\\'}n",
                  "    id(\"stringfog\")${'\\'}n"
                ]
              },
              "androidJunkCodeDsl": {
                "algorithm": "balanced-brace-block",
                "file": "appBuild",
                "startMarker": "    androidJunkCode {${'\\'}n"
              },
              "xmlClassGuardDsl": {
                "algorithm": "balanced-brace-block",
                "file": "appBuild",
                "startMarker": "    xmlClassGuard {${'\\'}n"
              },
              "stringFogDsl": {
                "algorithm": "balanced-brace-block",
                "file": "appBuild",
                "startMarker": "configure<StringFogExtension> {${'\\'}n"
              }
            }
          },
          "frozenRegions": {
            "legacyPluginApplications": {
              "file": "appBuild",
              "lineCount": 3,
              "sha256": "${Sha256.hex(applicationLines.joinToString("").toByteArray())}"
            },
            "androidJunkCodeDsl": {
              "file": "appBuild",
              "sha256": "${Sha256.hex(junkDsl.toByteArray())}"
            },
            "xmlClassGuardDsl": {
              "file": "appBuild",
              "sha256": "${Sha256.hex(guardDsl.toByteArray())}"
            },
            "stringFogDsl": {
              "file": "appBuild",
              "sha256": "${Sha256.hex(fogDsl.toByteArray())}"
            }
          },
          "versionSources": {
            "junkRuntime": {
              "path": "build.gradle.kts",
              "literal": "id(\"io.github.qq549631030.android-junk-code\") version \"1.3.4\" apply false"
            },
            "xmlGuardRuntime": {
              "path": "gradle/libs.versions.toml",
              "literal": "xmlClassGuard = \"1.2.6\""
            },
            "stringFogPlugin": {
              "path": "gradle/libs.versions.toml",
              "literal": "stringFogPlugin = \"5.2.0\""
            },
            "stringFogRuntime": {
              "path": "gradle/libs.versions.toml",
              "literal": "stringFogXor = \"5.0.0\""
            }
          },
          "plugins": [
            {
              "name": "androidJunkCode",
              "pluginId": "io.github.qq549631030.android-junk-code",
              "expectedVersion": "1.3.4",
              "implementationClass": "cn.hx.plugin.junkcode.plugin.AndroidJunkCodePlugin",
              "jarSha256": "6ca9ebff4a06767aa31bee36ec32ef7813894b2ee16a7f80f41a29ade2b49219",
              "extensionName": "androidJunkCode",
              "extensionClass": "cn.hx.plugin.junkcode.ext.AndroidJunkCodeExt_Decorated",
              "taskNames": ["generateDemoReleaseJunkCode"],
              "taskClasses": [
                "cn.hx.plugin.junkcode.task.GenerateJunkCodeTask",
                "cn.hx.plugin.junkcode.task.GenerateJunkCodeTask_Decorated",
                "java.lang.Object",
                "org.gradle.api.DefaultTask",
                "org.gradle.api.internal.AbstractTask"
              ],
              "configurationInputs": ["app/build.gradle.kts", "build.gradle.kts"],
              "mappingPaths": [],
              "frozenRegions": ["androidJunkCodeDsl", "legacyPluginApplications"],
              "versionSources": ["junkRuntime"]
            },
            {
              "name": "stringFog",
              "pluginId": "stringfog",
              "expectedVersion": "5.2.0",
              "implementationClass": "com.github.megatronking.stringfog.plugin.StringFogPlugin",
              "jarSha256": "2fa8c35ce2a5a2dfdcc225b8762cc1064f5946f2771ef92fcf22a241f9583756",
              "extensionName": "stringfog",
              "extensionClass": "com.github.megatronking.stringfog.plugin.StringFogExtension_Decorated",
              "taskNames": [
                "generateStringFogDemoDebug",
                "generateStringFogDemoRelease",
                "generateStringFogShowcaseDebug",
                "generateStringFogShowcaseRelease"
              ],
              "taskClasses": [
                "com.github.megatronking.stringfog.plugin.SourceGeneratingTask",
                "com.github.megatronking.stringfog.plugin.SourceGeneratingTask_Decorated",
                "java.lang.Object",
                "org.gradle.api.DefaultTask",
                "org.gradle.api.internal.AbstractTask"
              ],
              "configurationInputs": ["app/build.gradle.kts", "gradle/libs.versions.toml"],
              "mappingPaths": [],
              "frozenRegions": ["stringFogDsl"],
              "versionSources": ["stringFogPlugin", "stringFogRuntime"]
            },
            {
              "name": "xmlClassGuard",
              "pluginId": "xml-class-guard",
              "expectedVersion": "1.2.6",
              "implementationClass": "com.xml.guard.XmlClassGuardPlugin",
              "jarSha256": "fd0bff574e52a9ed6982da54724fd92a472dc9c2ad830af8e95b8c58ff63547a",
              "extensionName": "xmlClassGuard",
              "extensionClass": "com.xml.guard.entensions.GuardExtension_Decorated",
              "taskNames": [
                "xmlClassGuardDemoDebug",
                "xmlClassGuardDemoRelease",
                "xmlClassGuardShowcaseDebug",
                "xmlClassGuardShowcaseRelease"
              ],
              "taskClasses": [
                "com.xml.guard.tasks.XmlClassGuardTask",
                "com.xml.guard.tasks.XmlClassGuardTask_Decorated",
                "java.lang.Object",
                "org.gradle.api.DefaultTask",
                "org.gradle.api.internal.AbstractTask"
              ],
              "configurationInputs": ["app/build.gradle.kts", "gradle/libs.versions.toml"],
              "mappingPaths": ["app/xml-class-mapping.txt"],
              "frozenRegions": ["xmlClassGuardDsl"],
              "versionSources": ["xmlGuardRuntime"]
            }
          ]
        }
        """.trimIndent() + "\n",
    )
}

private val pinnedLegacyPluginObservationFields = listOf(
    listOf(
        "io.github.qq549631030.android-junk-code",
        "cn.hx.plugin.junkcode.plugin.AndroidJunkCodePlugin",
        "android-junk-code-1.3.4.jar",
        "6ca9ebff4a06767aa31bee36ec32ef7813894b2ee16a7f80f41a29ade2b49219",
        "androidJunkCode",
        "cn.hx.plugin.junkcode.ext.AndroidJunkCodeExt_Decorated",
        "generateDemoReleaseJunkCode",
        listOf(
            "cn.hx.plugin.junkcode.task.GenerateJunkCodeTask",
            "cn.hx.plugin.junkcode.task.GenerateJunkCodeTask_Decorated",
            "java.lang.Object",
            "org.gradle.api.DefaultTask",
            "org.gradle.api.internal.AbstractTask",
        ).joinToString("\u001f"),
    ),
    listOf(
        "xml-class-guard",
        "com.xml.guard.XmlClassGuardPlugin",
        "xml-class-guard-1.2.6.jar",
        "fd0bff574e52a9ed6982da54724fd92a472dc9c2ad830af8e95b8c58ff63547a",
        "xmlClassGuard",
        "com.xml.guard.entensions.GuardExtension_Decorated",
        listOf(
            "xmlClassGuardDemoDebug",
            "xmlClassGuardDemoRelease",
            "xmlClassGuardShowcaseDebug",
            "xmlClassGuardShowcaseRelease",
        ).joinToString("\u001f"),
        listOf(
            "com.xml.guard.tasks.XmlClassGuardTask",
            "com.xml.guard.tasks.XmlClassGuardTask_Decorated",
            "java.lang.Object",
            "org.gradle.api.DefaultTask",
            "org.gradle.api.internal.AbstractTask",
        ).joinToString("\u001f"),
    ),
    listOf(
        "stringfog",
        "com.github.megatronking.stringfog.plugin.StringFogPlugin",
        "stringfog-gradle-plugin-5.2.0.jar",
        "2fa8c35ce2a5a2dfdcc225b8762cc1064f5946f2771ef92fcf22a241f9583756",
        "stringfog",
        "com.github.megatronking.stringfog.plugin.StringFogExtension_Decorated",
        listOf(
            "generateStringFogDemoDebug",
            "generateStringFogDemoRelease",
            "generateStringFogShowcaseDebug",
            "generateStringFogShowcaseRelease",
        ).joinToString("\u001f"),
        listOf(
            "com.github.megatronking.stringfog.plugin.SourceGeneratingTask",
            "com.github.megatronking.stringfog.plugin.SourceGeneratingTask_Decorated",
            "java.lang.Object",
            "org.gradle.api.DefaultTask",
            "org.gradle.api.internal.AbstractTask",
        ).joinToString("\u001f"),
    ),
)
