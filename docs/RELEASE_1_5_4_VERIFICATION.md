# 1.5.4 发布验证记录

日期：2026-11-02。本次提交包含完整插件实现：既有运行时分析优化、整数格式化保护和调用结束临时文件清理，以及默认启用的垃圾代码生成、真实启动调用和最终产物核验。

本记录核对 1.5.4 的发布元数据和真实二进制消费结果。此前生成器功能、AGP 矩阵和模拟器证据保留各自的实际候选版本，见 [生成验证](JUNK_CODE_VERIFICATION.md) 和 [调用验证](JUNK_CODE_CALLS_VERIFICATION.md)。

## 便携包身份

产物：`build/distributions/hardening-gradle-plugin-1.5.4-portable-maven.zip`

SHA-256：`d7865bebea80de9bb27dd683e6b25ff97c5d4ee9f34ac79fc15ac99c2bd2914f`

- 实现 JAR 的 `Implementation-Version`、实现 POM 和 Gradle 插件 marker 均为 `1.5.4`。
- 当前插件的便携仓库坐标仅包含 1.5.4；插件 ID 仍为 `com.holin.android.hardening`。
- 与前次已验证的本地 1.5.3 候选相比，1,790 个非 Manifest JAR 条目逐字节一致。1.5.4 更新版本元数据，生成器版本仍为 2。
- 中英文 README、CI 产物路径、现有发布契约和多模块消费示例同步到 1.5.4。
- 已发布的旧 launcher 仍使用其对应 1.4.2 下载地址和校验值；1.5.4 的接入方式是本次生成的便携 Maven 仓库，不将源码推送视为 Plugin Portal 发布。

身份核对结果保存在本地 `build/release-1.5.4-verification/version-proof.json`。

## 清理前验证

执行生产编译、JAR 打包、Gradle 插件校验、便携包校验及已有发布契约检查：

```sh
./gradlew --offline compileKotlin jar validatePlugins verifyPortableHardeningPlugin \
  test --tests '*PortablePublicationContractTest' \
       --tests '*RepositoryAutomationContractTest' \
       --tests '*DocumentationExampleContractTest' \
  compileFunctionalTestKotlin
```

构建成功，10 项已有测试通过：便携发布契约 3 项、仓库自动化契约 4 项、文档及消费示例契约 3 项。

另用一个临时测试复用既有二进制消费工程构造逻辑，解压正式便携包，通过 Maven marker 解析插件；未使用 `includeBuild` 或源码替换。环境为 AGP 8.13.2、Gradle 8.13、Kotlin 2.3.0、JDK 17，初始使用空的隔离 Gradle 缓存，离线构建，包含既有第三方 fixture 插件和多模块依赖。

执行 `:mobile:hardeningBundleDemoQa` 和 `:mobile:hardeningAssembleDemoQa`，137 个任务执行成功。临时测试 1 项通过，最终 AAB/APK 报告均为 `PASS`。

| 产物 | 字节数 | SHA-256 |
| --- | ---: | --- |
| AAB | 70,710 | `d766fe814378687b8162236edd9582753e93c5eb79868431fadb1864a1d88d4b` |
| 签名 APK | 84,410 | `c1247e6a0c233e53e9b9d62592d3d2202b62d4f16580c5cadacf013041f3cf67` |

最终产物包含默认的 100 个普通类、8 个禁用且不导出的 Activity、1,080 个计算方法、8 个 layout、40 个 drawable 和 40 个 string；另有 1 个运行入口类。两个产物报告的 `runtimeCalls.reachableGeneratedMethods` 均为 1,080。此消费工程未声明自定义 Application，因此由生成的 Application 子类提供启动入口。

Lint、R8 和最终核验均参与上述构建。实际裁剪和优化由 R8 执行；精确保留规则、真实调用以及最终 DEX 调用核验共同覆盖生成方法的保留要求。

原始记录位于本地 `build/release-1.5.4-verification/`：`build.log`、`release-contract-tests.json`、`consumer-functional.log`、`consumer-build.log`、`consumer-test-result.xml`、`consumer-result.json` 和 `junk-code-*.json`。这些构建输出不进入 Git 提交。

## 证据范围

生成器版本 2 此前已通过 52 项相关 JVM 检查、AGP 8.8.0/8.10.1/8.13.2 消费矩阵、固定种子跨目录复现、随机 salt 与稳定映射检查，以及 API 35 模拟器运行验证。它们对应原记录中的 1.5.3 候选与具体产物哈希。本次通过非 Manifest JAR 条目一致性核对，并单独运行 1.5.4 二进制消费验证；未将旧设备结果改写为新版本设备验收。

既有全量 JVM 套件此前在 30,000 填充单元压力项运行约 6 分钟后主动中止，未取得全量通过结果。部分已有便携功能测试仍包含对已由清理机制删除的临时文件的断言，本次没有为获得全量通过而改写这些断言。上述定向结果不代表全量测试通过。

本次没有新增生产应用业务验收或物理设备验收。构建通过、静态调用可达性、模拟器运行和生产业务验收分别记录。

## 临时内容清理和生产复核

清理结果及其后的生产检查记录于 `cleanup-record.json`、`post-source-cleanup-consumer.log` 和 `post-cleanup-production.log`。仅保留测试执行结果、日志、产物身份和正式插件分发包；本次新增测试源码、消费 fixture 和测试专用配置在验证后删除。既有测试只同步发布版本字面量，未增加永久测试逻辑或测试专用依赖。

删除临时测试源码后，使用同一个正式包再次 clean 构建消费工程，140 个任务成功（123 个执行、17 个保持最新）；AAB/APK 哈希与上表一致，两个产物仍有 1,080 个可达计算方法。随后删除整个临时消费工程，再执行生产编译、JAR 打包、插件校验、便携包校验和已有功能测试源码编译，均通过。

与本次版本调整前的基线比较，`src/test` 和 `src/functionalTest` 下原有的 128 个文件均保留；仅 5 个已有测试文件更新版本字面量，无新增测试文件、临时编译测试类或测试专用依赖残留。最终暂存发布文档后，另强制重跑上述 10 项发布契约检查，全部通过，记录为 `post-cleanup-contracts.log`。
