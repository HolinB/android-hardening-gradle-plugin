# Android Hardening Gradle Plugin 1.2.0

[English](README.en.md)

`com.holin.android.hardening` 是一个面向 Android Application Variant 的本地二进制 Gradle 插件。它在显式授权的
Variant 和显式声明的代码/资源所有权范围内，复用 R8 映射、稳定化自有名称、审计外部契约、改写并重新签名 AAB，
生成通用 APK，并输出可审计的映射、语义、相似度和设备验收证据。默认 `enabled=false`，普通构建图不依赖任何
Hardening 任务。

## 安全边界

- 只把 `ownership` 中声明的 Android 模块和生产 source set 当作可改写输入；依赖、生成目录、测试目录和显式排除包不归插件所有。
- 无法解析的 App 反射、资源字符串查找、硬编码类/成员/资源/路由/URI/URL/文件名引用会失败关闭。插件不能安全地重命名未解析的外部、JNI、JavaScript、反射或序列化契约。
- 潜在 Bean 字段、没有显式 `@SerializedName` 的 Gson 模型字段、Java Serializable、ObjectBox Entity、JNI native 方法和 `@JavascriptInterface` 名称会被保留并报告；最终 DEX 还会复核潜在 Bean 字段名。
- 资源名称可以变化，但 v1 强制保持资源 ID；外部命名、通知图标、动画、NinePatch、依赖和生成资源有安全排除。
- 该插件不保证任意意义上的反逆向，也不保证绕过模糊检测器。相似度分数只描述插件定义的自有 AAB/APK 结构和内容，不等于安全等级、商店审核结果或第三方检测器结论。
- 插件不上传、发布或通知任何外部系统。`hardeningRun<Variant>` 是唯一授权设备执行入口，会安装并启动 APK；不要把 Hardening 任务与 `upload`、`publish`、`install` 或 `notify` 任务放在同一次调用中。

## 最低工具链和前置条件

- Gradle 8.10+
- AGP 8.8+
- JDK 17+
- Kotlin Android Plugin 2.3+
- Android SDK、Build Tools、Platform Tools，以及消费项目自己的 Gradle Wrapper

版本满足最低值仍不是充分条件。插件启动时会运行 AGP public API capability probe，检查当前 AGP 是否仍提供所需的
公开 Variant、Artifact、Signing、AAPT2 等能力；缺少能力会失败，而不会退回私有 API 或猜测兼容性。

发布包不携带 AGP 或 Kotlin 插件/runtime；消费项目按自己的版本解析它们。便携 ZIP 携带 Hardening 实现、插件 marker、
固定运行时依赖、`LICENSE`、`NOTICE`、`THIRD_PARTY_LICENSES.txt`、`verification-metadata.xml` 和 `SHA256SUMS`。

## 校验并准备 Release ZIP

先从同一 Release 获取 ZIP 和发布的 SHA-256，再进行解压。不要只相信文件名。

```shell
shasum -a 256 -c hardening-gradle-plugin-1.2.0-portable-maven.zip.sha256
mkdir -p .local/hardening-1.2.0
unzip -q hardening-gradle-plugin-1.2.0-portable-maven.zip -d .local/hardening-1.2.0
(cd .local/hardening-1.2.0 && shasum -a 256 -c SHA256SUMS)
```

Linux 可使用 `sha256sum -c hardening-gradle-plugin-1.2.0-portable-maven.zip.sha256` 校验外层 ZIP，并使用
`sha256sum -c SHA256SUMS` 校验解压内容。PowerShell 可用
`Get-FileHash .\hardening-gradle-plugin-1.2.0-portable-maven.zip -Algorithm SHA256` 对照 Release 值。
如启用 Gradle dependency verification，可审阅后把 ZIP 中的 `verification-metadata.xml` 放到消费项目的
`gradle/verification-metadata.xml`。

## CI 与 Release 边界

push/pull-request 工作流使用 JDK 17，校验 Wrapper 的两类 checksum，执行环境、单元测试、完整 functional TestKit 和
便携 ZIP 校验任务，并强制构建两次逐字节一致的便携 ZIP。现有二进制消费 fixture 从解压后的 Maven 发布物解析插件，
不使用 `includeBuild`。独立的手动/每周 Offline TestKit 工作流先联网准备 checksum 固定的
Gradle/AGP/Kotlin/AAPT2 矩阵，再在同一宿主上离线构建、校验两次并比较结果。

两个工作流都只具有仓库只读权限。ZIP 只在 runner 本地用于比较，job 结束即丢弃；CI 不上传 artifact、不发布插件或
Maven 仓库、不创建 Release/tag、不安装或运行 App，也不通知外部系统。完成本地审阅并获得明确授权后，Release 交付
仍由 Actions 之外的本地手动命令执行：

```shell
gh release upload v1.2.0 \
  build/distributions/hardening-gradle-plugin-1.2.0-portable-maven.zip \
  build/distributions/hardening-gradle-plugin-1.2.0-portable-maven.zip.sha256
```

## `hardeningw` 启动器

启动器要求 `--project-dir`、`--` 分隔符和至少一个转发给消费项目 Wrapper 的参数。它校验 JDK/Wrapper/SDK，下载并按固定
Release SHA-256 和内部 `SHA256SUMS` 验证 ZIP，原子写入版本缓存，再注入
`-PhardeningPluginRepo=<cache>/1.2.0/repository`。下载不可用时，在插件源码目录运行还可回退到本地
`packagePortableHardeningPlugin`。

POSIX:

```shell
./hardeningw --project-dir ./consumer -- \
  -PandroidHardening=true :mobile:hardeningBundleDemoQa
```

PowerShell:

```powershell
.\hardeningw.ps1 --project-dir .\consumer -- `
  -PandroidHardening=true :mobile:hardeningBundleDemoQa
```

Batch:

```bat
hardeningw.bat --project-dir .\consumer -- -PandroidHardening=true :mobile:hardeningBundleDemoQa
```

查询启动器版本：`./hardeningw --version`。自定义缓存只使用 `HARDENING_CACHE_HOME`；默认位于 Gradle 用户缓存下。

## 直接消费解压后的 Maven 仓库

完整的中性示例位于 [`examples/multi-module-consumer`](examples/multi-module-consumer)。Hardening 插件组只从本地解压仓库
解析；AGP/Kotlin 和应用依赖仍由消费项目的常规仓库解析。不要使用 `includeBuild`，也不要声明未发布的远程
Hardening 坐标。

```kotlin
// settings.gradle.kts
pluginManagement {
    val hardeningRepository = providers.gradleProperty("hardeningPluginRepo").orNull
        ?: error("Pass -PhardeningPluginRepo=<extracted>/repository")
    repositories {
        exclusiveContent {
            forRepository {
                maven {
                    name = "ExtractedHardeningPlugin"
                    url = uri(hardeningRepository)
                }
            }
            filter {
                includeGroup("com.holin.android.hardening")
            }
        }
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}
```

```kotlin
// 根 build.gradle.kts
plugins {
    id("com.android.application") version "8.13.2" apply false
    id("org.jetbrains.kotlin.android") version "2.3.0" apply false
    id("com.holin.android.hardening") version "1.2.0" apply false
}
```

```kotlin
// Application 模块 build.gradle.kts
plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("com.holin.android.hardening")
}
```

直接运行：

```shell
./gradlew -PhardeningPluginRepo=.local/hardening-1.2.0/repository \
  -PandroidHardening=true :mobile:hardeningBundleDemoQa
```

## 完整 `androidHardening` Kotlin DSL

下面展示 v1 的完整公开接口。路径、插件声明和迁移描述文件必须替换为消费项目真实且已审阅的输入。v1 强制
`legacyPlugins.verifyCompatibility=true`、真实 baseline 和至少一个已声明且实际应用的旧插件；没有绿色项目旁路。
自动状态迁移可以关闭；启用时必须先捕获真实 descriptor，不能复制占位内容。

```kotlin
androidHardening {
    enabled.set(providers.gradleProperty("androidHardening").map(String::toBoolean).orElse(false))
    projectKey.set("demo")

    variants {
        include("demoQa")
    }

    ownership {
        generatedPackagePrefixes.add("com.example.demo.generated")
        excludedPackagePrefixes.add("com.example.demo.external")

        module(":mobile") {
            sourceSets.addAll("main", "demo")
            manifestFiles.from(layout.projectDirectory.file("src/demo/AndroidManifest.xml"))
            webp {
                include("src/demoResources/res/drawable/**/*.webp")
                exclude("src/demoResources/res/drawable/no_rewrite/**/*.webp")
            }
        }
        module(":core") {
            sourceSets.add("main")
        }
        module(":media") {
            sourceSets.add("main")
        }

        hardcodedReferences {
            kinds.set(setOf(CLASS_NAME, MEMBER_NAME, RESOURCE_NAME, ROUTE, URI, URL, FILE_NAME))
            includeGlobs.set(listOf("src/**/*.kt", "src/**/*.java", "src/**/*.xml"))
            excludeGlobs.set(listOf("**/test/**", "**/androidTest/**"))
            failOnUnresolvedOwnedReference.set(true)
        }
    }

    rules {
        sourceFiles.from("proguard-rules.pro")
        preserveExactRules.from("hardening-preserve-exact.pro")
        additionalRules.from("hardening-additional.pro")
    }

    mapping {
        storeDirectory.set(rootProject.layout.projectDirectory.dir(".hardening/mappings"))
        reusePrevious.set(true)
        missingPolicy.set(RECREATE)
        keepHistory.set(true)
        quarantineInvalid.set(true)
        lockTimeoutSeconds.set(60)
    }

    reproducibility {
        fixedSeed.set(providers.gradleProperty("androidHardeningFixedSeed"))
    }

    naming {
        strategy.set(TYPED_PSEUDOWORDS)
        renamePackages.set(true)
        reuseAcrossBuilds.set(true)
    }

    code {
        engine.set(R8)
        preserveLineNumbers.set(true)
        sourceFileMode.set(PSEUDONYMIZE)
        stringFog.set(PRESERVE_CURRENT)
        diversification {
            mode.set(DEX)
            contentSalt.set(FRESH_PER_BUILD)
            minimumCoverage.set(0.50)
            minimumSimHashDistance.set(4)
            maximumGrowth.set(0.05)
            enforceMaximumGrowth.set(false)
        }
    }

    resources {
        mode.set(RENAME_AND_AUDIT)
        renameLayouts.set(true)
        renameDrawables.set(true)
        renameStyles.set(true)
        preserveResourceIds.set(true)
        reuseNamesAcrossBuilds.set(true)
        styleHashPolicy.set(RESOURCE_TABLE_ONLY)
        bitmapDiversification {
            safeOnly.set(true)
            minimumCoverage.set(0.90)
            minimumPHashDistance.set(11)
            minimumSsim.set(0.995)
        }
    }

    contracts {
        unresolvedAppReflection.set(FAIL_BUILD)
        unresolvedResourceLookup.set(FAIL_BUILD)
        externalNames.set(PRESERVE_AND_REPORT)
    }

    signing {
        reuseVariantSigningConfig.set(true)
    }

    benchmark {
        mode.set(REPORT_ONLY)
    }

    similarity {
        mode.set(OWNED_AAB_APK)
        baselineDirectory.set(rootProject.layout.projectDirectory.dir(".hardening/baselines"))
        minimumImprovementPoints.set(0.01)
        enforceRelativeImprovement.set(true)
        maximumOverallExclusive.set(75.0)
        enforceMaximumOverall.set(false)
        maximumAabGrowth.set(0.10)
        enforceMaximumAabGrowth.set(false)
    }

    deviceAcceptance {
        autoSelectSingleDevice.set(true)
        serial.set(providers.gradleProperty("androidHardeningDeviceSerial"))
        applicationId.set(providers.gradleProperty("androidHardeningApplicationId"))
        applicationIdFromVariant.set(true)
        launchActivity.set(providers.gradleProperty("androidHardeningLaunchActivity"))
        launchActivityFromManifest.set(true)
        stabilitySeconds.set(30)
    }

    legacyPlugins {
        mode.set(PRESERVE_UNMANAGED)
        verifyCompatibility.set(true)
        baselineFile.set(rootProject.layout.projectDirectory.file("legacy/legacy-plugin-baseline.json"))
        plugin("neutralLegacy") {
            pluginId.set("com.example.legacy")
            expectedVersion.set("1.0.0")
            configurationInputs.from(
                rootProject.layout.projectDirectory.file("gradle/libs.versions.toml"),
                layout.projectDirectory.file("build.gradle.kts"),
            )
            mappingPaths.from(layout.buildDirectory.file("outputs/mapping/demoQa/mapping.txt"))
        }
    }

    compatibility {
        autoMigrateLegacyState.set(true)
        migrationDescriptor.set(
            rootProject.layout.projectDirectory.file("hardening/portable-state-migration.json"),
        )
    }
}
```

不提供这三个可选 Gradle 属性时，设备、application ID 和启动 Activity 分别保持自动选择、从 Variant 解析和从 Manifest
解析的默认行为；提供属性时，显式值会覆盖对应的自动解析结果。

`ownership.module` 中的 source set 顺序也是优先级顺序，必须是已存在的 Android 生产 source set。自定义 `res.srcDir`
由 AGP public API 解析，但 WebP glob 是模块相对路径。显式 `hardcodedReferences.includeGlobs` 必须实际匹配至少一个可审计的
生产文件，否则失败，防止拼错范围后静默放行。

## WebP 和契约保护

WebP 改写默认关闭：只有某个所有权模块的 `webp.include(...)` 命中且未被 `exclude(...)` 命中的自有 drawable WebP 才会
启用。排除优先于包含。依赖/生成资源、外部命名资源、通知图标、动画 WebP、非 drawable、无法验证的 WebP 和找不到安全
扰动的图片不会改写。候选还必须保持尺寸和每个 alpha sample，达到 SSIM/pHash 阈值并满足字节增长限制。

R8 名称策略不会用“能编译”代替契约安全。审计会保留并报告 Gson/Bean/Serializable/ObjectBox/JNI/JavaScript 契约，
解析硬编码引用，并对未解析的自有反射或资源查找失败关闭。`preserveExactRules` 用于必须原样保留的已审阅规则；
`additionalRules` 是额外输入。不要通过宽泛 keep 规则隐藏未理解的外部契约。

## 任务表（示例 Variant `demoQa`）

每个 `variants.include("...")` 都按同一规则生成任务；`demoQa` 的 task suffix 是 `DemoQa`。

| 阶段 | 任务 | `androidHardening=false` | 作用/边界 |
|---|---|---|---|
| 准备 | `prepareHardeningDemoQa` | 直接调用失败并给出 opt-in | 锁定并准备映射、registry、seed 和配置身份 |
| 审计 | `auditHardeningDemoQa` | 直接调用失败 | 审计源码、运行时依赖、规则、外部契约和旧插件 |
| 验证 | `verifyHardeningDemoQa` | 直接调用失败 | 验证 AAB、R8 mapping continuity、Bean 字段与 Retrace |
| 归档 | `archiveHardeningDemoQa` | 直接调用失败 | 仅在验证通过后原子发布状态、AAB 和报告 |
| AAB 入口 | `hardeningBundleDemoQa` | 失败并打印同名 `-PandroidHardening=true` 命令 | 产出已签名、已验证 hardened AAB |
| APK 入口 | `hardeningAssembleDemoQa` | 失败并打印同名 opt-in 命令 | 产出并验证已签名 universal APK |
| Baseline | `captureHardeningBaselineDemoQa` | 直接调用失败 | 捕获不可变的普通/Hardening 自有 AAB/APK baseline；首次 compare 前显式运行一次 |
| 比较 | `compareHardeningDemoQa` | 直接调用失败 | 与 baseline 比较，强制相对改善 |
| 外部比较 | `compareExternalHardeningDemoQa` | 直接调用失败 | 使用 `-PandroidHardeningReferenceAab=reference/release.aab` 比较外部 AAB |
| Benchmark | `benchmarkHardeningDemoQa` | 直接调用失败 | `REPORT_ONLY` 生命周期标记；不会上传或执行设备操作 |
| Smoke | `smokeHardeningDemoQa` | 直接调用失败；即使启用也拒绝独立设备执行 | 只能由 `hardeningRunDemoQa` 授权 |
| Run | `hardeningRunDemoQa` | 失败并打印同名 opt-in 命令 | compare 通过后安装、启动、稳定 30 秒，再归档 |
| Hardened APK | `assembleHardeningDemoQaUniversalApk` | 内部任务不运行 | 从验证后的 AAB 生成、签名、zipalign 并验证 universal APK |
| Ordinary APK | `assembleOrdinaryDemoQaUniversalApk` | 内部任务不运行 | 仅供 baseline/similarity 的普通 universal APK |

普通 `assembleDemoQa`/`bundleDemoQa` 在关闭或开启属性但未请求 Hardening 入口时都不会获得 Hardening 任务依赖。不要把普通
APK/AAB 当作 Hardening 产物。插件也不会调用上传；上传必须在调用结束后，由消费方对已验证输出执行单独、明确授权的步骤。

## 产物、报告和状态

对 Variant 名 `demoQa`，小写 Variant 路径仍为 `demoQa`：

- `build/outputs/hardening/<variant>/<variant>-hardened.aab`
- `build/outputs/hardening/<variant>/<variant>-hardened-universal.apk`
- `build/outputs/hardening/<variant>/<variant>-ordinary-universal.apk`
- `build/reports/hardening/<variant>/audit.json`
- `build/reports/hardening/<variant>/bundle-verification.json`
- `build/reports/hardening/<variant>/mapping-verification.json`
- `build/reports/hardening/<variant>/universal-apk-verification.json`
- `build/reports/hardening/<variant>/similarity-report.json` 和 `.md`
- `build/reports/hardening/<variant>/external-aab-similarity-report.json` 和 `.md`
- `build/hardening/<variant>/prepared-<invocation-id>/` 和 `build/hardening/<variant>/invocations/<invocation-id>/`
- `.hardening/mappings/<projectKey>/<variant>/current/`、`history/`、`quarantine/`、`locks/`
- `.hardening/baselines/<projectKey>/<variant>/v1/`

第一次没有旧 mapping 时，`missingPolicy=RECREATE` 从 generation 0 建立新 lineage；没有历史 mapping 就没有连续性可继承，
不应把首次构建描述为“已证明跨版本稳定”。以后 `reusePrevious=true` 把 App 自有的旧映射作为 `-applymapping` 输入，验证任务
逐符号检查 mapping continuity，并使用当前 R8 官方 Retrace 恢复类、方法和行号。损坏或身份不匹配的 current state 在
`quarantineInvalid=true` 时按内容哈希隔离；已验证状态按 AAB 身份写入不可变 `history`。

首次相似度比较前，先在审阅过的输入上运行 `captureHardeningBaselineDemoQa`。Baseline 与所有权和完整配置身份绑定；配置漂移、
错误 Variant 或不同输入不能冒充同一 baseline。默认 v1 强制“相对 baseline 至少改善 `minimumImprovementPoints`”；
`maximumOverallExclusive` 和 `maximumAabGrowth` 会报告，但 v1 强制它们的 enforce 开关为 `false`。分数不能证明检测器规避。
分数范围是 0 到 100，越低表示插件所定义的自有结构越不相似；相对 gate 要求每个受测维度都降低足够点数，而不是只看平均值。

## 可复现性、签名和设备

默认使用安全随机调用 salt：稳定 mapping/registry 可以复用，但 AAB/APK 内容会轮换。传入
`-PandroidHardeningFixedSeed=<non-secret-lab-seed>` 会固定派生身份，并允许相同源码、工具链、依赖、签名材料、配置、路径语义和
状态在干净目录中产生确定性包。Fixed seed 不是密钥，也不能抵消环境或输入差异；不要把测试 seed 作为生产秘密或安全控制。

`signing.reuseVariantSigningConfig=true` 复用目标 Variant 的签名材料。插件验证 hardened AAB、universal APK 和普通比较 APK 的
证书/签名关系；仓库和示例不提供 keystore 或凭据。`hardeningRunDemoQa` 在未指定 `deviceAcceptance.serial` 时只会自动选择唯一
在线设备；零台或多台设备时失败。它从 Variant/合并 Manifest 解析 application ID 和 launcher activity，安装后观察 30 秒。

## 离线使用

先在联网、受控环境准备版本缓存和消费项目依赖，再断网运行：

```shell
./hardeningw --project-dir ./consumer -- \
  -PandroidHardening=true --offline :mobile:hardeningBundleDemoQa
```

便携 ZIP 不包含 AGP/Kotlin，所以“已经解压 ZIP”不等于消费构建已完全离线。需要完整、校验固定的离线矩阵时，使用发布的
offline TestKit ZIP；它携带支持矩阵、Gradle distributions、合并仓库、依赖校验元数据和逐文件 checksum。不要让离线构建
回退到未知宿主缓存或网络。

## 排障

- **提示 Hardening disabled**：确认使用精确的 `-PandroidHardening=true`，并调用 `hardeningBundle<Variant>`、`hardeningAssemble<Variant>` 或 `hardeningRun<Variant>`。
- **找不到插件**：确认 `hardeningPluginRepo` 指向解压目录内的 `repository`，且 settings 没有 `includeBuild` 或远程 Hardening 仓库替代。
- **工具链 capability 缺失**：升级到提供所需 public API 的 AGP；不要绕过 probe 或改用 AGP 私有类。
- **所有权或 WebP include 无匹配**：检查模块相对 glob、自定义 source set/res root 和生产文件是否真实存在；没有可处理 WebP 时移除 include，保持默认关闭。
- **未解析反射/Gson/JNI/JavaScript**：修复为可解析常量、添加精确外部契约规则，或把确实不归应用所有的包排除；不要把 fail-closed 改成猜测重命名。
- **mapping continuity/Retrace 失败**：保留失败报告和 `.hardening/mappings`，检查 R8 版本、旧 mapping、配置身份和隔离目录；不要手工覆盖 current/history。
- **baseline 缺失或身份不符**：在已审阅普通/Hardening 输入上重新明确捕获 baseline；不能复制别的项目/Variant baseline。
- **签名失败**：给目标 Variant 配置真实签名；不要把凭据或 keystore 提交到仓库。
- **设备选择失败**：只连接一台授权设备，或配置 `deviceAcceptance.serial`；设备操作只从 `hardeningRun<Variant>` 进入。
- **相似度未改善**：阅读 JSON/Markdown 的自有条目贡献和增长数据。不要把调阈值当作反逆向或检测器规避证明。
