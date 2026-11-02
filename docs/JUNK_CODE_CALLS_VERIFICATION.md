# 垃圾代码实际调用验证记录

日期：2026-11-02。范围：1.5.3 本地工作区的生成器版本 2，承接版本 1 的垃圾代码生成实现。
原始证据保存在 `build/junk-code-calls-verification/`。这是插件机制、隔离消费工程和模拟器验证，不是生产应用完整业务验收。

## 实现

所有配置的 `(I)I` 计算方法通过生成的调用树实际执行，包括禁用 Activity 类的静态计算方法。
Application 构造方法正常返回前调用 `run()`，同步入口及执行标记保证每个应用类加载器只执行一轮，结果存入私有 volatile 字段。
默认生成 108 个业务隔离的类、1,080 个计算方法和 1 个运行入口类；较大配置使用最多 2,048 个直接目标的分组辅助类。
辅助类/方法另计，不进入业务 ownership 或命名 registry。生成的 Activity 不实例化、不启动，生命周期方法不作为计算入口。

自定义 Application 保留原类和原构造指令。注入后移除新增调用，比较归一化后的字节码，要求与原字节码完全一致。
系统默认 Application 使用生成子类。`AppComponentFactory` 的带参数构造同样受支持。
零计算方法时不生成运行入口。仅选定的加固构建注册 `injectHardening<Variant>JunkCalls`。

Lint 不负责裁剪产物；R8 负责裁剪和优化。实际调用与精确 keep 规则同时保留，最终 AAB/APK 核验还检查从 Application 构造方法到全部生成计算方法的 DEX 调用。
生成报告包含调用树，`junk-code-calls.json` 记录入口、插入调用数、原/新字节码哈希和逆向证明，最终报告的 `runtimeCalls.reachableGeneratedMethods` 记录可达方法数。
生成器版本进入既有完整配置指纹，保留已有 mapping、registry、baseline；旧相似度基线按现有规则处理。

## 清理前检查

- 52 项相关 JVM 检查通过：其中 9 项临时检查覆盖实际执行、并发一次性调用、5,000 方法分组、构造委托、零数量、Manifest 默认/自定义 Application、固定输入复现、非法调用树，以及真实 R8 DEX 缺失入口/分组调用时拒绝通过。其余 43 项是任务前已有的 wiring、AGP 能力、配置身份、DSL 和 ownership 检查。
- 默认 1,080 个不同计算方法均由 JVM 执行计数探针观测到；32 次并发调用只执行一轮，后续构造 Application 不再执行。另检查整数极值、负数和零输入无异常。
- 多模块源码消费示例同时启用资源压缩、字符串/资产运行时保护和私有组件重定位，构建通过；自定义 Application 的 1 处调用注入逆向证明为 PASS。
- 功能关闭时不注册生成/注入任务。普通 `demoDebug` APK 含 1,112 个类，其中生成垃圾类为 0；所有数量为零的加固构建通过，调用报告为 `SKIPPED_NO_METHODS`。
- 固定种子跨 clean，以及源码消费与另一目录中便携包消费，AAB、APK、完整 R8 mapping 和生成清单逐字节一致。
- 两次随机 salt 构建的内容盐及 class JAR 内容变化，生成类名、调用树和完整 mapping 保持一致。正式 registry 的 `seedSha256`、`assignments`、`tombstones` 一致，generation 正常递增，registry 不含生成类。

对应证据：`final-implementation-checks.log`、`results/`、`source-functional-4.log`、`ordinary-debug-result.json`、`zero-counts-*.json`、`cross-directory-identity.json`、`portable-fixed-clean-identity.json`、`random-continuity-result.json`、`random-registry-result.json`。

## AGP 与便携消费

使用正式便携 Maven ZIP、各版本 Gradle、隔离 Gradle 缓存、既有真实第三方 fixture 插件执行消费构建。各组最终 AAB/APK 均核验 1,080 个计算方法可从 Application 到达。

| AGP / Gradle | Application / 资源压缩 | APK SHA-256 |
| --- | --- | --- |
| 8.8.0 / 8.10.2 | 生成的默认 Application / 开启 | `707a005fe63c89223b6779bcceb59b470c3a8f86d9118498243fe5439f9b8d9c` |
| 8.10.1 / 8.11.1 | 依赖模块中的自定义 Application / 关闭 | `5a083240e5d4414d6b28d5fb25b9aba1869cfb472ac6bc6ae15bffa925a36cab` |
| 8.13.2 / 8.13 | 生成的默认 Application / 开启 | `400497c81e7a20b9b13ba052dfe67ceeefb5bf08ea3ecea47496ab949d737cd5` |

最终实现复核日志为 `final-portable-*.log`，`final-portable-*-plugin.json` 将实际便携 ZIP 身份与 APK 身份绑定。带参数 Application 构造的单独消费示例记录在 `factory-green.log` 和 `factory-*.json`。
该示例为自定义 Factory 配置了精确 keep 规则，避免既有业务命名分配与 Android 的 Factory 名称保留要求冲突；本次不改动既有业务映射策略。

最终便携包 `hardening-gradle-plugin-1.5.3-portable-maven.zip` 的 SHA-256 为
`2fc6007c6e49a23de595e5dfda3a9ef017fae3c7cb05952922884746c740ce89`。

## 模拟器与开销

使用只读 API 35 AVD 启动隔离的 `emulator-5588`。测试探针先读取执行标记，确认在探针调用运行入口之前，Application 构造已经完成计算。随后临时替换结果字段，再调用入口 10 次，结果字段保持探针设置的值，证明没有重复执行，最后恢复原结果。

- 自定义 Application APK：`5f0cf9d9e1b35cb4f10c667d783270ab371bcdf417380e2e9321854087c8884f`。
- 生成的默认 Application APK：`400497c81e7a20b9b13ba052dfe67ceeefb5bf08ea3ecea47496ab949d737cd5`。
- 两种入口的启动前执行标记和 10 次重复调用检查均为 PASS；证据为 `device-runtime-probe.txt`、`device-default-runtime-probe.txt` 和对应 `device-*-result.json`。
- 开关对照的首页解密文本、点击后重定位详情页均正常，生成 Activity 显式启动被系统拒绝，示例进程日志无 `FATAL EXCEPTION`。

同一业务代码、签名、运行时保护及组件配置的便携消费对照：

| 配置 | APK 字节数 | 预热后 clean 构建 | API 35 冷启动中位数（5 次） |
| --- | ---: | ---: | ---: |
| 关闭 | 34,402 | 10,350 ms | 204 ms |
| 默认开启 | 88,446 | 10,807 ms | 271 ms |
| 差值 | +54,044 | +457 ms | +67 ms |

构建耗时是单轮观察；模拟器冷启动样本受系统负载和调度影响，不据此推断生产设备性能或统计显著性。首次含预热的构建记录另存于 `control-measurements.json`，上表使用 `control-warm-clean-measurements.json`。冷启动原始 5 次记录与 APK 身份见 `device-control-measurements.json`。关闭 APK SHA-256 为 `7e62e95e311f555c608f5cdfbbe69160a3a57c6ed1f1cdfbac1be8e9d1d14d69`。

本次没有连接物理设备，没有操作生产应用。探针、两个示例应用、设备临时文件已移除，本任务启动的模拟器已停止，见 `device-cleanup.json`。

## 失败与限制

1. 临时红测复现原生成器没有运行入口；加入真实调用后通过。
2. 初始 DEX 核验错误地按大写名称识别 dexlib 指令，导致漏识别真实 `invoke-static`；改用指令枚举后通过，并添加真实 DEX 删除调用的拒绝检查。
3. 初始最终核验要求无参 Application 构造，真实 AppComponentFactory 示例因此失败；改为检查所有正常返回的构造方法。
4. 临时示例先后暴露配置问题：资产 reader 漏配、被资源压缩移除的既有布局未再引用、缺失 `.gitignore` 时直接追加、Groovy 直接访问与同名项目属性冲突。这些只修正测试 fixture，保留失败日志。
5. 更新最终便携矩阵 fixture 时，完整 ZIP 解压覆盖了矩阵原有 POM，校验按预期拒绝。恢复已固定的矩阵仓库文件，仅替换本次插件并更新其校验值后复核；没有放宽依赖校验。记录为 `final-matrix-fixture-metadata-failure.log`。
6. 一次全量旧 JVM 套件仍在既有 `SafeDexTransformerWeavingTest` 的 30,000 填充单元组合搜索压力项运行，约 6 分钟后主动中止，未宣称全量通过。线程记录为 `full-unit-interrupted-thread.txt`；随后 52 项相关回归通过。
7. 带参构造核验修正后，Factory 示例触发既有业务映射校验：命名分配期望改名 Factory，但 R8 的平台组件规则保留它。为临时示例添加精确 Factory keep 规则并重新建立该示例状态后验证；原失败报告保存在 `factory-existing-mapping-rule-failure.json`。

设备冒烟、静态调用核验、构建通过和完整业务验收分别记录。本次结果不替代生产消费应用的完整业务验收。

## 清理与生产复核

本次基线为 `baseline-sha256.json`、`baseline.diff` 和原始文件备份。任务前已有测试及用户改动按基线保留；清理和后续生产/消费复核记录在 `cleanup-record.json`、`post-cleanup-production.log` 和 `post-cleanup-consumer.log`。

已删除本次新增的 4 个临时测试源码文件、编译测试类、测试 fixture、Android 探针和测试专用配置。
任务前的 132 个测试文件逐一 SHA-256 比对一致，未新增测试专用依赖或修改生产构建配置以支持测试。
保留结果 XML、日志、截图、身份记录和验证报告。

清理后 `compileKotlin`、`jar`、`validatePlugins`、`verifyPortableHardeningPlugin`、既有测试源码编译和离线 TestKit 重新打包均通过。
随后在独立目录解压最终便携 ZIP，通过 Maven marker 消费插件，执行 `:app:hardeningAssembleDemoRelease`，145 个任务成功。
最终 AAB/APK 调用核验为 PASS，APK SHA-256 仍为
`5f0cf9d9e1b35cb4f10c667d783270ab371bcdf417380e2e9321854087c8884f`，与已验证的自定义 Application 模拟器候选逐字节一致。
该消费工程随后删除，再次执行生产编译、插件校验和便携包校验通过，见 `post-cleanup-production-final.log`。

`final-source-audit.json` 记录本次相对基线的改动，`production-source-sha256.json` 记录最终生产源码身份。使用说明见 [垃圾代码生成](junk-code-generation.md)。
