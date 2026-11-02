# Android Hardening Gradle Plugin 1.5.4 升级说明

1.5.4 在既有运行时分析、整数格式化保护及调用结束自动清理能力上，加入默认启用的垃圾代码生成和真实启动调用。仅选定的加固构建生效，普通构建和独立字符串预检不接入这些产物。

## 接入 1.5.4

在插件源码目录执行：

```sh
./gradlew --offline compileKotlin validatePlugins verifyPortableHardeningPlugin
```

生成并校验：

```text
build/distributions/hardening-gradle-plugin-1.5.4-portable-maven.zip
build/distributions/hardening-gradle-plugin-1.5.4-portable-maven.zip.sha256
```

核对外层 SHA-256，解压并校验内部 `SHA256SUMS`，将消费项目的 `hardeningPluginRepo` 指向解压后的 `repository`。根插件声明使用：

```kotlin
plugins {
    id("com.holin.android.hardening") version "1.5.4" apply false
}
```

继续使用消费项目自己的 Gradle Wrapper：

```sh
./gradlew -PhardeningPluginRepo=.local/hardening-1.5.4/repository bundleDemoReleaseHardening
```

最低版本保持 AGP 8.8.0、Gradle 8.10、JDK 17、Kotlin Android 插件 2.3.0。基础 DSL 见 [完整接入说明](PLUGIN_GUIDE_1_5_2_ZH.md)，当前版本和包路径以上文为准。源码提交不等同于 Gradle Plugin Portal 发布；便携 Maven 包使用本地仓库接入。

## 垃圾代码配置与运行行为

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

普通类数量与 Activity 数量分开计算；默认 108 个生成类、1,080 个计算方法，另有 1 个运行入口类、8 个布局和各 40 个 drawable/string。较大配置使用有界辅助调用组。

Application 构造正常返回前调用生成的计算方法。同步开关保证每个应用类加载器只执行一轮，通常对应每个进程一次。自定义 Application 保留原类及构造逻辑；默认 Application 使用生成子类。生成的 Activity 只参与静态计算，保持禁用、不导出，不被自动启动。

R8 保留规则和实际调用同时生效；最终 AAB/APK 核验类、方法、资源、禁用组件和从 Application 到全部生成方法的调用链。方法仅进行有界计算，数量会增加包体、构建及启动开销。关闭方式：

```kotlin
androidHardening {
    junkCode { enabled.set(false) }
}
```

命名来自 lineage seed，方法与资源内容来自本次调用 salt。固定种子使用既有配置；生成策略和生成器版本进入完整配置身份。升级或改变数量后，如旧相似度基线身份不匹配，按既有流程重建基线；已有 mapping、registry 和历史证据不会被自动覆盖。

报告位于模块的 `build/reports/hardening/<variant>/`：

- `junk-code-generation.json`：策略、版本、数量、名称、调用树及生成内容哈希。
- `junk-code-calls.json`：Application 注入位置数量、字节码哈希和逆向证明。
- `junk-code-aab-verification.json`、`junk-code-apk-verification.json`：与最终产物哈希绑定的内容及调用链检查。
- `cleanup-report.json`：调用结束后的临时文件清理记录。

详细生成规则见 [垃圾代码使用说明](junk-code-generation.md)。运行时分析和资源保护边界见 [运行时保护说明](runtime-content-protection.md)。

## 验证记录

生成器版本 2 的功能、AGP 矩阵、复现、模拟器运行和开销证据见 [调用验证记录](JUNK_CODE_CALLS_VERIFICATION.md)。其中原始候选使用本地 1.5.3 包，报告保留其实际版本和产物哈希。

1.5.4 的版本元数据、打包、发布契约和二进制消费验证单独记录于 [1.5.4 验证记录](RELEASE_1_5_4_VERIFICATION.md)。构建、模拟器冒烟和生产应用完整业务验收属于不同证据范围。
