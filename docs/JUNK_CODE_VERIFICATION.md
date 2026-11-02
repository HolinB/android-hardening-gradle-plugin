# 垃圾代码生成验证记录

日期：2026-11-02。范围：当前 1.5.3 本地插件工作区，不代表发布版本或消费应用的完整业务验收。

本页保留生成器版本 1 的历史证据。新增 Application 实际调用、生成器版本 2 的验证见
[垃圾代码实际调用验证记录](JUNK_CODE_CALLS_VERIFICATION.md)，不使用本页旧设备结果替代新调用链验证。

## 实现范围

参考 AndroidJunkCode 的普通类、Activity、layout、drawable、string 及保留机制，使用插件已有 ASM 生成 class JAR，使用 AGP 公共 API 追加 classes、资源和 Manifest。没有引入 JavaPoet、500 档字典或 `.junk-code` 状态。

生成器版本为 1。默认开启仅适用于已选定的加固构建；默认生成 100 个普通类、8 个禁用且不导出的 Activity、1,080 个生成方法、8 个 layout、40 个 drawable、40 个 string。构造方法和生命周期方法另计。原有业务入口、权限与源码不被生成器修改。

类名、方法名、资源名前缀使用 lineage seed；方法常量、drawable 颜色和 string 内容使用 invocation salt。生成内容没有业务源码所有权，不进入业务命名分配、registry、保护覆盖率分母或 owned similarity 评分。生成策略进入完整配置身份；关闭时不追加此功能的身份字段。已有 mapping、registry 和 baseline 使用原有保护与兼容规则。

## 清理前验证

本地原始证据位于 `build/junk-code-verification/`，不加入版本控制。目录内保留日志、结果 XML、JSON 报告和设备观察证据；本任务编写的测试源码及 fixture 在验证后删除。

| 检查 | 结果与范围 |
| --- | --- |
| 完整 JVM 回归 | 873 项：872 通过、1 项按既有条件跳过；零失败。记录于 `regression-fixed.log` 和 `evidence/unit-suite.json` |
| 最终生成器机制检查 | 13/13 通过，覆盖默认 DSL、跨目录确定性、salt 变化、字节码加载和边界整数执行、零数量、非法/溢出配置、精确保留、Manifest 保留与重复/XXE 拒绝、清单篡改、重新生成及缩减数量、AGP 实际输出位置、缺失 DEX 拒绝、依赖 AAR 资源冲突 |
| 普通与关闭功能构建 | 普通 `assembleDemoDebug`、关闭功能的加固构建均未执行垃圾代码任务；开启构建最终核验通过 |
| 组合构建 | 运行时必需字符串保护、私有 Activity 重定位、垃圾代码同时开启；字符串实际转换 1/1、组件转换 1/1，业务命名分配中生成类数量为 0 |
| 资源压缩 | `shrinkResources=true` 和 `false` 均通过最终 AAB/APK 的 DEX、资源表和 Manifest 核验 |
| 多变体 | `demoRelease`、`demoDebug`、`secondRelease` 已构建；两个 flavor 的生成类名及资源名交集均为 0 |
| 第三方插件并存 | 便携测试使用任务前已有的中立第三方插件 fixture，保留其原有兼容审计和 bundletool classloader 检查；这不是对任意第三方插件的兼容承诺 |

完整 JVM 回归先于最终的旧版 AGP 资源目录修复；该修复随后经过 13 项定向机制检查及下表的实际矩阵构建。没有将较早的整套回归冒充为修改后的再次全量运行。

## 便携插件与兼容矩阵

每个消费工程都使用解压后的便携 Maven 插件及对应离线依赖仓库，在空 Gradle 用户缓存下构建，不使用插件源码替换。三组均验证了最终 108 个类、1,080 个生成方法、88 个目标资源及 8 个禁用且不导出的 Activity。

| AGP | Gradle | AAB / APK | APK SHA-256 |
| --- | --- | --- | --- |
| 8.8.0 | 8.10.2 | PASS / PASS | `fbd82e3ff64571105e827e0b02f0f8f04c35f2ec094b13422aee7b5cb484955a` |
| 8.10.1 | 8.11.1 | PASS / PASS | `de9320140e692bf47750d2ffda984e036f3815d8d720f298398cb7f1ac93ef5a` |
| 8.13.2 | 8.13 | PASS / PASS | `2e27fc5686a4449cb406a178698f244c49d7bcb24e301865d36bdd8f73ca1ff5` |

对应证据：`portable-matrix-fixed.log`、`evidence/portable-matrix-results.xml` 和 `evidence/portable-agp-*-{aab,apk,identity}.json`。

固定 seed 的两个全新工程目录产生完全相同的 AAB、APK、R8 mapping、生成清单及 registry 内容。APK SHA-256 为 `d471fa1b81f0fffd94b6c7cb01e9961eb0d13a7f72ff2b122280d73900f75e52`。另一次相同工程的跨 clean 重建也保持 APK 字节一致。

随机 salt 的连续构建中，生成类/方法名称与完整 R8 mapping 保持一致，AAB、APK 和生成内容哈希变化。正式 registry 的核验读取 `current/active.json` 指向的快照，比较 seed、assignments、tombstones；generation 按既有机制递增。详见 `active-registry.log` 及 `evidence/portable-random-*-identity.json`。

## 对照开销和设备冒烟

同一多模块 `demoRelease` 示例、相同签名和业务代码，同时启用运行时字符串保护及私有组件重定位，垃圾代码使用默认数量：

| 配置 | APK 大小 | 预热后 clean 构建耗时 | Samsung 冷启动观测 |
| --- | ---: | ---: | ---: |
| 关闭垃圾代码 | 34,279 字节 | 9,411 ms | 305 ms |
| 默认开启 | 88,325 字节 | 10,564 ms | 313 ms |
| 差值 | +54,046 字节 | +1,153 ms | +8 ms |

耗时是单轮本机样例观测，不能用于推断生产应用性能或统计显著性。首次关闭构建包含缓存预热，未用于耗时差值。大小及耗时原始记录为 `evidence/coexistence-measurements.json`。

在 Samsung SM-A155F上分别安装以下隔离示例产物，验证启动、解密按钮文本、点击后进入重定位页面、页面文本和进程日志无 `FATAL EXCEPTION`。生成 Activity 的显式启动被系统拒绝，最终 Manifest 核验同时证明它实际存在且保持禁用、不导出。

- 开启 APK：`ecab1327fe5b67ee7fd37b1f7c7cd6f71291ba1a9e068f8bf5f9845bbb994c5f`
- 关闭 APK：`76b392a839badf746d555a17ce4ab705866b6bc6308cf5bee24d68367e7fc997`
- 证据：`evidence/device-candidate/smoke-result.json`、`*-launch.txt`、UI XML、截图和限定示例进程的日志。

设备样例在旧版 AGP 输出路径兼容修复前、AGP 8.13.2 上生成；记录严格绑定上述 APK，不将它当作三个 AGP 版本逐一上机的结果。示例应用及本任务写入设备的临时文件已清理。本次没有操作生产应用数据，也没有进行生产消费应用的完整业务验收。

## 发现的问题与处理

1. 新能力最初进入全局 AGP 能力探测，导致两个既有单测失败；改为仅在垃圾代码功能接入时探测，全量 JVM 回归通过。
2. AGP 的 `toAppend` 会指定 JAR 输出位置；只写预设目录会导致最终 DEX 缺失生成类。任务现向实际 AGP 属性发布 JAR，最终产物核验通过。
3. AGP 8.8/8.10 同样会重设资源目录；旧矩阵的最终校验因此拒绝缺失 layout 的产物。任务现向实际资源目录发布并清理旧内容，三组矩阵均通过。
4. 第三方 AAR 名称冲突检查最初无差别解析项目依赖，触发 AGP 本地模块多产物选择歧义；现从 app/owned source roots 检查本地资源，从非项目依赖 AAR 检查外部资源。
5. 项目专用 Gradle 缓存缺少矩阵分发包及依赖；使用已有且经 `prepareOfflineTestKitEnvironment` 验证完整的用户级缓存完成离线打包和消费构建。
6. 原有 `PortableBinaryConsumerFunctionalTest` 初跑 9 项中 6 项失败：2 项发现并促成上述资源路径修复；另外 4 项要求已被工作区原有清理服务删除的临时 `applymapping.pro` / `registry.json` 继续存在。保留这些既有测试及用户改动，没有改写其断言。独立临时验证改为核对正式 state、最终 mapping 和最终 AAB/APK。原始失败结果保存于 `matrix-fixed.log` 及 `evidence/matrix-original-TEST-*.xml`，不能将原套便携功能测试宣称为全部通过。
7. 临时示例重建期间换签导致一次覆盖安装被 Android 拒绝；卸载仅由本任务安装的示例后，使用固定 APK/报告快照重新完成开关对照，正式记录采用后一次快照。
8. 收尾消费检查将源码替换接入改为解压 ZIP 接入时，临时 Groovy settings 首次缺少仓库声明之间的换行；修正该临时配置后真实消费构建通过。首次诊断保存在 `post-cleanup-consumer-setup-failure.log`。

## 清理及交付后检查

任务前已有测试和未提交改动以 `baseline-sha256.json`、`baseline.diff` 和原始文件副本为基线保存。最终删除本任务新增的测试源码、fixture、探针、临时 APK 与编译测试类；保留验证结果，不交付测试专用依赖或配置。

删除新增测试源码后，生产 `compileKotlin`、`jar`、`validatePlugins`、`verifyPortableHardeningPlugin` 通过，同时重编译原有测试集以清除旧测试 class。记录于 `post-cleanup-production.log`。

随后解压正式便携 ZIP，在独立多模块消费目录中移除 `includeBuild`，通过版本 `1.5.3` 的 Maven marker 加载插件，重新执行 `:app:hardeningAssembleDemoRelease`。140 个任务执行成功，AAB/APK 内容核验均为 PASS，APK SHA-256 为 `999f84f140cf6ae0582c2514cb08c554832755a12b9a577f3fc68b4bc7773cb9`。日志为 `post-cleanup-consumer.log`，报告副本为 `evidence/post-cleanup-*.json`。该消费检查目录在结果归档后删除，再次执行生产编译、插件和便携包校验，记录于 `post-cleanup-production-final.log`。

`cleanup-record.json` 记录实际清理项。任务前的测试文件与基线逐一 SHA-256 对照，没有被本任务修改；本任务新增测试源码和编译类均不再存在。`production-source-sha256.json` 记录最终生产源码身份。

使用方法、关闭开关、数量配置及正式报告路径见 [垃圾代码生成说明](junk-code-generation.md)。本地包未提交、推送或发布。
