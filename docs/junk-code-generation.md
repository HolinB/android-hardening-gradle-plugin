# Generated junk code / 垃圾代码生成

Selected hardening builds generate an isolated class JAR, disabled Activities, layouts,
drawables and strings by default. Ordinary Android builds and runtime-string preflight
do not register this payload. No additional plugin or Java source compiler is required.

选定的加固构建默认生成隔离的 class JAR、禁用的 Activity、布局、drawable 和 string。
普通 Android 构建及独立字符串预检不接入这些产物。生成器复用插件已有 ASM，
无需 AndroidJunkCode、JavaPoet、额外 Java 源码编译或 JSON profile 状态。

```kotlin
androidHardening {
    junkCode {
        enabled.set(true)
        packageCount.set(4)
        classCount.set(100)
        activityCount.set(8)
        methodCountPerClass.set(10)
        drawableCount.set(40)
        stringCount.set(40)
    }
}
```

`classCount` counts ordinary classes; `activityCount` is additional. Counts are totals
per variant, not per package. Each Activity adds one layout. Each class, including an
Activity, gets `methodCountPerClass` generated methods in addition to its constructor
and applicable lifecycle method. The defaults therefore add 108 classes, 1,080
generated methods, eight layouts, 40 drawables and 40 strings. One runtime dispatcher
class is added at the default counts; larger configurations use bounded helper groups.
Infrastructure classes/methods and resource keep metadata are counted separately.

`classCount` 是普通类总数，Activity 另计；数量按变体计算，不是每个包的数量。
每个 Activity 对应一个布局；每类生成的方法数不包含构造和生命周期方法。
默认共 108 个类、1,080 个生成方法、8 个布局及各 40 个 drawable/string。
默认另有 1 个运行入口类；较大配置使用分组辅助类。入口和辅助类/方法、资源保留声明另计。
数量可以为零；生成类时 `packageCount` 必须大于零。
负数、计数溢出以及超过 JVM 单类方法或 Android 单类型资源数量限制的配置会直接失败。
插件不会自动调整消费项目的 multidex 配置。

To disable generation for hardening builds:

关闭加固构建中的垃圾代码生成：

```kotlin
androidHardening {
    junkCode { enabled.set(false) }
}
```

## Isolation and reproducibility / 隔离与复现

- Names derive from the existing lineage seed and variant identity. Method bodies,
  drawable colors and string values derive from invocation salt. The existing
  `-PandroidHardeningFixedSeed=...` option also controls this feature. No raw seed is
  written to these reports. JAR entry order and timestamps are deterministic.
- Class names are in a dedicated generated package. Resource names have a dedicated
  generated prefix. Exact keep rules retain only these classes and resources.
  Generated content is excluded from source-proven business ownership, naming registry,
  protection coverage and the existing owned-code similarity score.
- All configured computation methods are called through a generated dispatcher when
  the Application constructor finishes. A synchronized guard executes one round per
  application classloader (normally once per app process), and a private volatile field
  retains the result. No I/O, logging, thread creation, business callbacks or intentional
  exceptions are generated. There are no static initializer side effects.
- A custom Application keeps its existing class and constructor behavior; the plugin
  adds a stack-neutral call before successful constructor returns and verifies that
  removing these calls exactly restores the normalized original bytecode. With the
  framework default Application, the manifest selects a generated Application subclass.
  No bootstrap is added when there are no configured computation methods.
- Calls execute on the startup thread and their cost grows with the configured counts.
  Lint reports issues; R8 performs shrinking. Exact keep rules remain necessary alongside
  actual calls to preserve the methods and prevent optimization of pure computations.
- Activities are system `android.app.Activity` subclasses, with `enabled=false` and
  `exported=false`, no intent filters and no new permissions. They are never launched
  automatically. Layouts use system widgets only.
- Generation configuration is included in the complete configuration fingerprint.
  Enabling the feature or changing its counts can require a new similarity baseline.
  Existing mapping, registry and baseline state is never automatically overwritten.
  Disabling the feature omits its fields from configuration identity.

名称由现有 lineage seed 和变体身份派生；方法内容、颜色和字符串值随调用 salt 变化。
固定种子沿用现有参数。生成内容独立于业务源码 ownership、命名 registry、覆盖率和
既有业务相似度评分；保留规则只匹配生成的内容。方法不执行 I/O、日志或线程操作，
没有主动抛异常或静态初始化副作用。生成器版本 2 在 Application 构造完成时，
通过生成入口调用全部配置的计算方法，同步开关保证每个应用类加载器只执行一轮
（通常对应每个应用进程），计算结果写入私有 volatile 字段。

自定义 Application 保留原类及构造逻辑，只在构造正常返回前插入调用，并进行逆向字节码
校验；使用系统默认 Application 时，Manifest 改为生成的 Application 子类。
没有计算方法时不添加运行入口。调用在启动线程执行，数量增大会增加启动开销。
Lint 负责检查，R8 负责裁剪；实际调用与精确 keep 规则同时生效，防止纯计算被内联或删除。
仅执行 Activity 类中的静态计算方法，不实例化 Activity 或调用其生命周期。

生成的 Activity 使用系统基类，显式禁用且不导出，不包含 intent-filter 或新增权限，
不会自动启动。新增配置纳入完整配置指纹，配置变化后按已有机制重建相似度基线，
不会自动覆盖旧 mapping、registry 或 baseline。

## Outputs and verification / 产物和核验

Stable task outputs are under `build/intermediates/hardening/<variant>/junk-code/`.
They include `classes.jar`, `res/`, `AndroidManifest.xml`, `keep.pro` and `inventory.json`.
They are replaced on regeneration, excluded from ordinary builds even if files remain,
and removed by Gradle clean. Temporary staging uses the existing invocation scratch area.
AGP may assign its own JAR and resource output locations; the task publishes the same
payload to those public-API locations, including on AGP 8.8 and 8.10.

The following reports are under `build/reports/hardening/<variant>/`:

| Report | Meaning / 含义 |
| --- | --- |
| `junk-code-generation.json` | Policy, generator version, expected identities, generated-file hashes and byte count / 配置、版本、预期身份、文件哈希与生成字节数 |
| `junk-code-calls.json` | Application entry, injected call count, bytecode hashes and inverse proof / Application 入口、插入调用数、字节码哈希及逆向校验 |
| `junk-code-aab-verification.json` | Actual class, method, resource and component checks before AAB archival / AAB 归档前的实际内容核验 |
| `junk-code-apk-verification.json` | Actual payload checks on the signed APK candidate before publication / 签名 APK 发布前的实际内容核验 |

Verification reports identify the exact artifact hash and invocation salt hash. A report
from another build is not evidence for the current artifact. APK verification converts
a temporary copy to protobuf resources with the consumer's AAPT2 and deletes that copy;
the delivered signed APK is not changed by verification. The final DEX check also follows
the Application constructor, dispatcher and helper call groups to every configured
computation method. `runtimeCalls.reachableGeneratedMethods` records the verified count.

生成报告中的 `generatedBytes` 是生成器输出文件的总大小，不是最终 APK 的净增量。
最终报告绑定实际 AAB/APK 哈希；旧报告不能用于认定新产物通过。APK 校验使用消费方
AAPT2 转换临时副本并在校验后删除，不修改交付的签名 APK。
最终 DEX 核验同时检查 Application 构造方法 → 运行入口 → 分组调用 → 全部计算方法，
缺失调用会阻止产物通过；`runtimeCalls.reachableGeneratedMethods` 记录已核验的可达方法数。
入口接入任务为 `injectHardening<Variant>JunkCalls`，位于已有运行时保护和组件处理之前。

Package size, installation work and build time increase with the configured counts.
Measure those costs against the same consumer configuration with generation disabled.
Artifact checks and device smoke tests do not replace acceptance of the consumer's
business workflows.

配置数量会影响包体、安装工作量和构建时间，应与同一消费配置关闭本功能时进行对照。
产物校验及设备冒烟不能替代消费项目的完整业务验收。
