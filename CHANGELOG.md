# Android Hardening Gradle Plugin 1.3.0

Release date: 2026-09-16

[中文](#中文) | [English](#english)

## 中文

### 更新内容

- 新增模块级 `ownership.module.images` DSL。可声明 `PNG`、`WEBP`、`JPEG` 格式以及模块相对的 include/exclude glob；旧 `webp` DSL 继续兼容。
- 扩大自有 PNG/WebP 的安全转换范围。转换必须保持宽高和逐采样 alpha，通过配置的 SSIM 与 pHash 门槛，并且不能与普通 AAB 图片语料中的任意图片形成过近的 pHash 匹配。
- 图片报告新增普通 AAB 图片语料数量、最近语料 pHash 距离、按格式的数量/字节覆盖率，以及明确的排除或失败关闭原因。
- 新增 `bundle.dependencyMetadata`，支持 `PRESERVE` 和 `OMIT`。`OMIT` 只删除精确路径 `BUNDLE-METADATA/com.android.tools.build.libraries/dependencies.pb`，不会修改 Gradle 依赖图、依赖坐标或版本。
- 新增 `bundle.structuralMetadataEntryCount`，允许 `0..64`。每个条目为 32 字节，确定性写入 `BUNDLE-METADATA/com.holin.android.hardening/structure/v1/`；插件验证这些 AAB 元数据不会进入 universal APK。
- Rewrite manifest 写出 Schema v2；Bundle plan 在启用新元数据设置或普通 AAB 含可解码图片语料时写出 v2，未触发新字段的默认路径仍可写出 v1。两者继续读取 Schema v1。新增图片范围与 Bundle 配置进入配置身份 hash，避免不同策略复用错误的 baseline 或状态。
- ZIP rewrite 清单新增受限的 `ADDED`/`REMOVED` 记录，继续拒绝重复条目、大小写冲突、路径穿越、签名路径、运行时模块路径和未声明改写。
- DEX 扰动在候选没有形成有效差异时使用确定性后备候选；所有候选均失败时保留原候选并失败关闭，不伪造覆盖率。

### 兼容性与默认行为

- 最低环境保持为 Gradle 8.10、AGP 8.8、JDK 17 和 Kotlin Android Plugin 2.3。
- `images` 默认没有格式和 include，`dependencyMetadata` 默认 `PRESERVE`，`structuralMetadataEntryCount` 默认 `0`。未启用新 DSL 的消费项目保持 1.2.0 的 AAB 元数据行为。
- `webp { ... }` 仍可使用，并会合并到新的图片范围；新项目建议使用 `images { formats(...) }`。
- `JPEG` 是有效的所有权格式。1.3.0 的最终 AAB 像素转换器覆盖 PNG/WebP；JPEG 在没有通过同等语义验证的安全转换路径时标记为不适用并参与覆盖率门槛，不会被强制改写。
- Schema v2 读取器兼容旧 Schema v1；只接受 v1 固定字段的外部消费者需要先升级，再读取 1.3.0 报告。
- 新选项不改变 Manifest 组件声明。`OMIT` 不改变运行时依赖，结构条目只属于 AAB 元数据。

### 从 1.2.0 升级

1. 从本 Release 下载 `hardening-gradle-plugin-1.3.0-portable-maven.zip` 和同名 `.sha256`，先校验外层 SHA-256，再校验 ZIP 内 `SHA256SUMS`。
2. 将根插件版本改为 `1.3.0`，继续把 `-PhardeningPluginRepo` 指向解压后的 `repository`；不要使用 `includeBuild` 替代正式二进制消费。
3. 保留现有 `webp` 配置，或逐模块迁移到显式 `images` 格式和 glob。先从小范围开始，检查未命中、排除原因以及数量/字节覆盖率。
4. 仅在确实不需要 AAB 依赖元数据时启用 `dependencyMetadata.set(OMIT)`；仅在需要 AAB 结构元数据时设置 `structuralMetadataEntryCount`。
5. 新配置会改变配置身份。审阅输入后重新运行 `captureHardeningBaseline<Variant>`，不要复制其他项目、Variant 或旧配置的 baseline。
6. 分别运行普通构建和 `hardeningBundle<Variant>`，检查 mapping continuity、Retrace、bundle verification、rewrite manifest、图片证据和 universal APK 隔离结果。设备运行兼容性仍需通过单独授权的 `hardeningRun<Variant>` 或消费项目自己的测试验证。

### 已知限制

- 插件只处理显式声明的自有模块、生产 source set 和图片范围；依赖、生成资源、外部命名资源、通知图标、动画和 NinePatch 继续失败关闭。
- 图片候选无法同时满足尺寸、alpha、SSIM、源图 pHash、普通 AAB 语料 pHash 和增长约束时，构建会报告原因并按覆盖率门槛决定是否失败，不会降低阈值或强制改图。
- `dependencies.pb` 和结构条目是 AAB 打包元数据，不会替换依赖治理、SBOM、运行时兼容测试或商店验证。
- 编译、TestKit、Bundletool、签名和 universal APK 验证不等同于真实设备运行验证。
- 相似度报告只描述插件定义的静态模型；本版本不承诺规避或通过任何未知第三方查重、风控、商店审核或安全检测系统。

### 发布验证范围

- Gradle Wrapper 完整性、环境检查、单元测试、functional TestKit、portable Maven ZIP 验证和 Offline TestKit 矩阵。
- portable ZIP 连续两次强制构建逐字节一致；外层 sidecar、内部 `SHA256SUMS`、ZIP 安全和敏感内容扫描通过。
- 使用最终 portable repository 完成 SingleLink Release AAB 生产构建检查；未安装应用、未运行设备测试、未上传应用。

本 Release 只提供以下两个资产，不发布 Offline TestKit，不发布到 Maven Central 或 Gradle Plugin Portal：

- `hardening-gradle-plugin-1.3.0-portable-maven.zip`
- `hardening-gradle-plugin-1.3.0-portable-maven.zip.sha256`

## English

### Changes

- Added the module-scoped `ownership.module.images` DSL. It accepts `PNG`, `WEBP`, and `JPEG` formats plus module-relative include/exclude globs; the legacy `webp` DSL remains compatible.
- Expanded safe transformation coverage for owned PNG/WebP images. A transformed candidate must preserve dimensions and every alpha sample, pass the configured SSIM and pHash thresholds, and remain outside the pHash threshold of every image in the ordinary AAB corpus.
- Image reports now include ordinary-corpus size, nearest-corpus pHash distance, count/byte coverage by format, and explicit exclusion or fail-closed reasons.
- Added `bundle.dependencyMetadata` with `PRESERVE` and `OMIT`. `OMIT` removes only `BUNDLE-METADATA/com.android.tools.build.libraries/dependencies.pb`; it does not alter the Gradle dependency graph, coordinates, or versions.
- Added `bundle.structuralMetadataEntryCount` with a `0..64` range. Each deterministic 32-byte entry is written below `BUNDLE-METADATA/com.holin.android.hardening/structure/v1/`; the plugin verifies that this AAB-only metadata is absent from the universal APK.
- Rewrite manifests write Schema v2. Bundle plans write v2 when new metadata settings are enabled or the ordinary AAB has a decodable image corpus; the default path without new fields may still write v1. Both retain Schema v1 readers. Image scope and Bundle settings participate in configuration identity so incompatible baselines or state cannot be reused silently.
- ZIP rewrite manifests now record tightly restricted `ADDED` and `REMOVED` actions while continuing to reject duplicates, case collisions, traversal, signature paths, runtime-module paths, and undeclared rewrites.
- DEX diversification tries deterministic fallback candidates when a candidate produces no effective difference. If all candidates fail, it retains the original candidate and fails closed instead of claiming false coverage.

### Compatibility and defaults

- Minimum versions remain Gradle 8.10, AGP 8.8, JDK 17, and Kotlin Android Plugin 2.3.
- `images` has no formats or includes by default, `dependencyMetadata` defaults to `PRESERVE`, and `structuralMetadataEntryCount` defaults to `0`. Consumers that do not enable the new DSL retain the 1.2.0 AAB metadata behavior.
- `webp { ... }` remains supported and is merged into the new image scope. New configurations should prefer `images { formats(...) }`.
- `JPEG` is a valid ownership format. The 1.3.0 final-AAB pixel transformers cover PNG/WebP; a JPEG without an equivalently verified safe transformation path is reported as ineligible and participates in the coverage gate rather than being rewritten forcibly.
- Schema v2 readers accept prior Schema v1 data. External consumers hard-coded to the v1 field set must be upgraded before consuming 1.3.0 reports.
- The new settings do not change Manifest component declarations. `OMIT` does not change runtime dependencies, and structural entries remain AAB-only metadata.

### Upgrade from 1.2.0

1. Download `hardening-gradle-plugin-1.3.0-portable-maven.zip` and its `.sha256` from this Release. Verify the outer SHA-256 and then the archive's internal `SHA256SUMS`.
2. Change the root plugin version to `1.3.0` and keep `-PhardeningPluginRepo` pointed at the extracted `repository`; do not substitute `includeBuild` for the released binary.
3. Keep the existing `webp` block or migrate module by module to explicit `images` formats and globs. Start narrowly and review unmatched paths, exclusion reasons, and both count and byte coverage.
4. Enable `dependencyMetadata.set(OMIT)` only when the AAB dependency metadata is intentionally unnecessary. Set `structuralMetadataEntryCount` only when AAB structural metadata is required.
5. New settings change configuration identity. After reviewing the inputs, rerun `captureHardeningBaseline<Variant>`; never copy a baseline from another project, variant, or configuration.
6. Run the ordinary build and `hardeningBundle<Variant>` separately. Review mapping continuity, Retrace, bundle verification, rewrite manifest, image evidence, and universal-APK isolation. Runtime compatibility still requires a separately authorized `hardeningRun<Variant>` or the consumer's own device tests.

### Known limitations

- Only explicitly owned modules, production source sets, and image scopes are handled. Dependencies, generated resources, externally named resources, notification icons, animations, and NinePatch remain fail closed.
- If an image cannot satisfy dimensions, alpha, SSIM, source-image pHash, ordinary-corpus pHash, and growth limits together, the report records the reason and the configured coverage gate decides the build. Thresholds are not weakened and the image is not forced through.
- `dependencies.pb` and structural entries are AAB packaging metadata. They do not replace dependency governance, SBOMs, runtime compatibility tests, or store validation.
- Compilation, TestKit, Bundletool, signing, and universal-APK checks are not device runtime validation.
- Similarity reports describe only the plugin's static model. This release makes no promise about bypassing or satisfying unknown third-party similarity, risk, store-review, or security systems.

### Release verification scope

- Gradle Wrapper integrity, environment checks, unit tests, functional TestKit, portable Maven ZIP verification, and the Offline TestKit matrix.
- Two forced portable ZIP builds were required to be byte-identical, with the outer sidecar, internal `SHA256SUMS`, ZIP safety checks, and sensitive-content scan all passing.
- A SingleLink Release AAB production build was checked against the final portable repository. No app was installed, no device test was run, and no app artifact was uploaded.

This Release contains only the following two assets. The Offline TestKit is not published, and nothing is published to Maven Central or the Gradle Plugin Portal:

- `hardening-gradle-plugin-1.3.0-portable-maven.zip`
- `hardening-gradle-plugin-1.3.0-portable-maven.zip.sha256`
