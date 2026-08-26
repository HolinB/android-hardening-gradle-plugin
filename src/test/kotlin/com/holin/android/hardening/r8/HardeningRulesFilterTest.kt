package com.holin.android.hardening.r8

import kotlin.test.Test
import kotlin.test.assertContains
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class HardeningRulesFilterTest {
    @Test
    fun `protects SuspendLambda state machines from cross-package bridge optimization`() {
        val result = HardeningRulesFilter.filter("")

        assertContains(result.effectiveRules, SUSPEND_LAMBDA_SAFETY_RULE)
        assertFalse(
            result.effectiveRules.contains(
                "-keep,allowobfuscation,allowshrinking,allowoptimization class * extends " +
                    "kotlin.coroutines.jvm.internal.SuspendLambda",
            ),
        )
    }

    @Test
    fun `uses declared preserved and additional rules without built in project rules`() {
        val preserved = "-keep class com.example.generated.** { *; }\n"
        val additional = "-keep,allowobfuscation class com.example.core.ReflectionBase\n"

        val result = HardeningRulesFilter.filter(
            "-keep class androidx.** { *; }\n$preserved",
            setOf("com.example"),
            preserved,
            additional,
        )

        assertFalse(result.effectiveRules.contains("androidx.**"))
        assertEquals(1, preserved.toRegex(RegexOption.LITERAL).findAll(result.effectiveRules).count())
        assertContains(result.effectiveRules, additional.trim())
        assertFalse(result.effectiveRules.contains("com.example.demo"))
        assertTrue(
            result.manifest.decisions.any {
                it.directive == preserved.trim() &&
                    it.reason == RuleDecisionReason.PRESERVED_EXACT_RULE &&
                    it.action == RuleDecisionAction.PRESERVE
            },
        )
    }
    @Test
    fun `removes broad keep rules scoped to an owned package root`() {
        val rule = "-keep class com.example.portable.** { *; }"

        val result = HardeningRulesFilter.filter(
            "$rule\n",
            setOf("com.example.portable"),
        )

        assertFalse(result.effectiveRules.contains(rule))
        assertEquals(
            RuleDecisionReason.BROAD_OWNED_PACKAGE,
            result.manifest.decisions.single { it.directive == rule }.reason,
        )
    }

    @Test
    fun `removes exact broad Parcelable class-name rules in inline and multiline formats`() {
        val broadRules = listOf(
            "-keep class * implements android.os.Parcelable { public static final android.os.Parcelable${'$'}Creator *; }",
            """
                -keep${'\t'}class * implements android.os.Parcelable
                {
                    public static final android.os.Parcelable${'$'}Creator *;
                }
            """.trimIndent(),
        )

        val result = HardeningRulesFilter.filter(broadRules.joinToString(separator = "\n", postfix = "\n"))

        assertEquals(
            2,
            result.manifest.decisions.count {
                it.action == RuleDecisionAction.REMOVE &&
                    it.reason.name == "BROAD_PARCELABLE_CLASS_NAMES"
            },
        )
        assertEquals(2, result.manifest.decisions.count { it.action == RuleDecisionAction.REMOVE })
    }

    @Test
    fun `preserves nonexact Parcelable class-name rules`() {
        val creator = "android.os.Parcelable${'$'}Creator"
        val preservedRules = listOf(
            "-keep,allowobfuscation class * implements android.os.Parcelable { public static final $creator *; }",
            "-keep public class * implements android.os.Parcelable { public static final $creator *; }",
            "-keep class com.example.LocalMedia implements android.os.Parcelable { public static final $creator *; }",
            "-keep class com.example.** implements android.os.Parcelable { public static final $creator *; }",
            "-keepclassmembers class * implements android.os.Parcelable { public static final ** CREATOR; }",
            "-keep class * implements android.os.Parcelable { <init>(); }",
            "-keep class * implements android.os.Parcelable { public static final $creator *; <init>(); }",
            "-keep class * implements android.os.Parcelable",
            """
                -keep class * implements android.os.Parcelable {
                    public static final $creator *;
                    # Reflective parcel reconstruction.
                }
            """.trimIndent(),
            "-keep class * implements com.example.Parcelable { public static final $creator *; }",
            "-keep class * implements android.os.Parcelable { public static final com.example.Creator *; }",
        )

        val result = HardeningRulesFilter.filter(preservedRules.joinToString(separator = "\n", postfix = "\n"))

        preservedRules.forEach { rule -> assertContains(result.effectiveRules, rule) }
        assertEquals(
            0,
            result.manifest.decisions.count {
                it.reason.name == "BROAD_PARCELABLE_CLASS_NAMES"
            },
        )
    }

    @Test
    fun `removes only the five broad Gson implementation class name rules`() {
        val broadRules = listOf(
            "-keep class * extends com.google.gson.reflect.TypeToken",
            "-keep class * extends com.google.gson.TypeAdapter",
            "-keep class * implements com.google.gson.TypeAdapterFactory",
            "-keep class * implements com.google.gson.JsonSerializer",
            "-keep class * implements com.google.gson.JsonDeserializer",
        )
        val preservedRules = listOf(
            "-keep class com.google.gson.reflect.TypeToken { *; }",
            "-keep,allowobfuscation,allowshrinking class * extends com.google.gson.reflect.TypeToken",
            "-keepclassmembers class * extends com.google.gson.TypeAdapter { <init>(); }",
            "-keepclassmembers class * implements com.google.gson.TypeAdapterFactory { <init>(); }",
            "-keepclassmembers class * implements com.google.gson.JsonSerializer { <init>(); }",
            "-keepclassmembers class * implements com.google.gson.JsonDeserializer { <init>(); }",
            "-keep,allowoptimization class * extends com.google.gson.TypeAdapter",
            "-keep class * extends com.google.gson.TypeAdapter { <init>(); }",
            "-keep class com.example.demo.match.GsonAdapter extends com.google.gson.TypeAdapter",
            "-keep class * extends com.google.gson.TypeAdapterFactory",
            "-keep class * implements com.google.gson.jsonserializer",
        )
        val source = (broadRules + preservedRules).joinToString(separator = "\n", postfix = "\n")

        val result = HardeningRulesFilter.filter(source)

        broadRules.forEach { rule ->
            assertFalse(result.effectiveRules.lineSequence().any { it == rule })
        }
        preservedRules.forEach { rule -> assertContains(result.effectiveRules, rule) }
        assertEquals(
            5,
            result.manifest.decisions.count {
                it.action == RuleDecisionAction.REMOVE &&
                    it.reason.name == "BROAD_GSON_IMPLEMENTATION_CLASS_NAMES"
            },
        )
        assertEquals(
            5,
            result.manifest.decisions.count { it.action == RuleDecisionAction.REMOVE },
        )
    }

    @Test
    fun `preserves a broad Gson directive when its member body opens on the next line`() {
        val rule = """
            -keep class * extends com.google.gson.TypeAdapter
            {
                <init>();
            }
        """.trimIndent()

        val result = HardeningRulesFilter.filter("$rule\n")

        assertContains(result.effectiveRules, rule)
        assertEquals(
            0,
            result.manifest.decisions.count {
                it.reason.name == "BROAD_GSON_IMPLEMENTATION_CLASS_NAMES"
            },
        )
    }

    @Test
    fun `preserves a broad Gson directive when blank and comment lines precede its member body`() {
        val rule = """
            -keep class * extends com.google.gson.TypeAdapter

              # Adapter construction is reflective.
            {
                <init>();
            }
        """.trimIndent()

        val result = HardeningRulesFilter.filter("$rule\n")

        assertContains(result.effectiveRules, rule)
        assertEquals(
            0,
            result.manifest.decisions.count {
                it.reason.name == "BROAD_GSON_IMPLEMENTATION_CLASS_NAMES"
            },
        )
    }

    @Test
    fun `removes an exact wildcard subclass blanket in one line and structured multiline sources`() {
        val sources = listOf(
            "-keep public class * extends com.example.adapter.*\n",
            """
                # Consumer adapters

                -keep   public${'\t'}class * extends   com.example.adapter.*
                # Preserve the following contract.
            """.trimIndent() + "\n",
        )

        sources.forEach { source ->
            val result = HardeningRulesFilter.filter(source, setOf("com.example.adapter"))

            assertFalse(result.effectiveRules.contains("extends com.example.adapter.*"))
            assertEquals(
                1,
                result.manifest.decisions.count {
                    it.action == RuleDecisionAction.REMOVE &&
                        it.reason == RuleDecisionReason.BROAD_WILDCARD_SUBCLASS
                },
            )
        }
    }

    @Test
    fun `preserves wildcard subclass blankets when ownership is unavailable`() {
        val rule = "-keep public class * extends com.example.adapter.*"

        val result = HardeningRulesFilter.filter("$rule\n", emptySet())

        assertContains(result.effectiveRules, rule)
        assertEquals(
            RuleDecisionReason.UNKNOWN_RULE,
            result.manifest.decisions.single { it.directive == rule }.reason,
        )
    }

    @Test
    fun `preserves external wildcard subclass blankets in owned builds`() {
        val rule = "-keep public class * extends com.thirdparty.adapter.*"

        val result = HardeningRulesFilter.filter(
            "$rule\n",
            setOf("com.example.feature"),
        )

        assertContains(result.effectiveRules, rule)
        assertFalse(result.effectiveRules.contains("-keep,allowobfuscation public class * extends com.thirdparty.adapter.*"))
        assertEquals(
            RuleDecisionReason.UNKNOWN_RULE,
            result.manifest.decisions.single { it.directive == rule }.reason,
        )
    }

    @Test
    fun `does not duplicate an existing allow obfuscation subclass rule`() {
        val blockingRule = "-keep public class * extends com.thirdparty.adapter.*"
        val safeRule = "-keep,allowobfuscation public class * extends com.thirdparty.adapter.*"

        val result = HardeningRulesFilter.filter(
            "$blockingRule\n$safeRule\n",
            setOf("com.example.feature"),
        )

        assertEquals(
            1,
            result.effectiveRules.lineSequence().count { line -> line == safeRule },
        )
    }

    @Test
    fun `preserves neighboring and explicitly preserved wildcard subclass rules`() {
        val source = """
            -keep class com.example.adapter.** { *; }
            -keep public class * extends com.example.BaseViewHolder
            -keepclassmembers class **${'$'}** extends com.example.adapter.viewholder.QuickViewHolder {
                <init>(...);
            }
            -keepclassmembers class **${'$'}** extends com.example.adapter.viewholder.DataBindingHolder {
                <init>(...);
            }
            -keep,allowobfuscation public class * extends com.example.adapter.*
            -keep public class * extends com.example.adapter.viewholder.QuickViewHolder
            -keep public class * extends com.example.adapter.**
            -keep class * extends com.example.adapter.*
            -keep public class * extends com.example.adapter.* { <init>(); }
            -keep public class * extends com.example.preserved.*
        """.trimIndent() + "\n"
        val explicitlyPreserved = "-keep public class * extends com.example.preserved.*\n"

        val result = HardeningRulesFilter.filter(source, emptySet(), explicitlyPreserved)

        listOf(
            "-keep class com.example.adapter.** { *; }",
            "-keep public class * extends com.example.BaseViewHolder",
            "extends com.example.adapter.viewholder.QuickViewHolder",
            "extends com.example.adapter.viewholder.DataBindingHolder",
            "-keep,allowobfuscation public class * extends com.example.adapter.*",
            "-keep public class * extends com.example.adapter.**",
            "-keep class * extends com.example.adapter.*",
            "-keep public class * extends com.example.adapter.* { <init>(); }",
            explicitlyPreserved.trim(),
        ).forEach { rule -> assertContains(result.effectiveRules, rule) }
        assertEquals(
            0,
            result.manifest.decisions.count { it.reason == RuleDecisionReason.BROAD_WILDCARD_SUBCLASS },
        )
    }

    @Test
    fun `removes an exact subclass blanket when its base belongs to owned packages`() {
        val rule = "-keep public class * extends com.example.core.BaseViewHolder"

        val result = HardeningRulesFilter.filter(
            "$rule\n",
            setOf("com.example"),
        )

        assertFalse(result.effectiveRules.contains(rule))
        assertEquals(
            RuleDecisionReason.BROAD_WILDCARD_SUBCLASS,
            result.manifest.decisions.single { it.directive == rule }.reason,
        )
    }

    @Test
    fun `removes broad Serializable class names while retaining serialization hooks`() {
        val source = """
            -keepnames   class *${'\t'}implements java.io.Serializable
            -keepclassmembers class * implements java.io.Serializable {
                private static final java.io.ObjectStreamField[] serialPersistentFields;
                private void writeObject(java.io.ObjectOutputStream);
                private void readObject(java.io.ObjectInputStream);
                private java.lang.Object writeReplace();
                private java.lang.Object readResolve();
                private static final long serialVersionUID;
            }
        """.trimIndent() + "\n"

        val result = HardeningRulesFilter.filter(source)

        assertFalse(
            result.effectiveRules.lineSequence().any { line ->
                line.trimStart().startsWith("-keepnames") && line.contains("implements java.io.Serializable")
            },
        )
        assertContains(result.effectiveRules, "serialPersistentFields;")
        assertContains(result.effectiveRules, "writeObject(java.io.ObjectOutputStream);")
        assertContains(result.effectiveRules, "readObject(java.io.ObjectInputStream);")
        assertContains(result.effectiveRules, "writeReplace();")
        assertContains(result.effectiveRules, "readResolve();")
        assertContains(result.effectiveRules, "serialVersionUID;")
        assertTrue(
            result.manifest.decisions.any { decision ->
                decision.action == RuleDecisionAction.REMOVE && decision.reason.name == "BROAD_SERIALIZABLE_CLASS_NAMES"
            },
        )
    }

    @Test
    fun `keeps generic reflection endpoints without freezing subclass names or methods`() {
        val result = HardeningRulesFilter.filter(
            "",
            emptySet(),
            "",
            DEMO_ADDITIONAL_RULES,
        )

        assertContains(
            result.effectiveRules,
            "-keep,allowobfuscation class * implements androidx.viewbinding.ViewBinding",
        )
        assertContains(
            result.effectiveRules,
            "-keepclassmembers class * implements androidx.viewbinding.ViewBinding {",
        )
        assertFalse(
            result.effectiveRules.contains(
                "-keepclassmembers,allowoptimization,allowshrinking class * implements androidx.viewbinding.ViewBinding",
            ),
        )
        listOf(
            "com.example.core.common.BaseActivity",
            "com.example.core.common.BaseFragment",
            "com.example.core.common.BaseDialogFragment",
            "com.example.core.common.BaseBottomSheetDialogFragment",
        ).forEach { baseClass ->
            assertContains(
                result.effectiveRules,
                "-keep,allowobfuscation,allowshrinking,allowoptimization class $baseClass",
            )
            assertContains(
                result.effectiveRules,
                "-keep,allowobfuscation,allowshrinking,allowoptimization class * extends $baseClass",
            )
        }
        assertFalse(result.effectiveRules.contains("class com.example.core.**"))
        assertFalse(result.effectiveRules.contains("extends com.example.core.common.BaseActivity {"))
    }

    @Test
    fun `removes only known broad blockers while preserving exact junk external and unknown rules`() {
        val source = """
            # broad AndroidX blocker
            -keep class androidx.** {*;}
            # broad Google blocker
            -keep class com.google.** { *; }
            # exact external contract
            -keep class com.google.firebase.crashlytics.** { *; }
            # frozen Junk Code rule
            -keep class com.example.demo.match.junkcode.** {*;}
            # unknown rule must not be guessed away
            -adaptresourcefilenames okhttp3/internal/publicsuffix/PublicSuffixDatabase.gz
        """.trimIndent() + "\n"

        val result = HardeningRulesFilter.filter(
            source,
            emptySet(),
            "-keep class com.example.demo.match.junkcode.** {*;}\n",
            DEMO_ADDITIONAL_RULES,
        )

        assertFalse(result.effectiveRules.contains("-keep class androidx.** {*;}"))
        assertFalse(result.effectiveRules.contains("-keep class com.google.** { *; }"))
        assertContains(result.effectiveRules, "-keep class com.google.firebase.crashlytics.** { *; }")
        assertContains(result.effectiveRules, "-keep class com.example.demo.match.junkcode.** {*;}")
        assertContains(result.effectiveRules, "-adaptresourcefilenames okhttp3/internal/publicsuffix/PublicSuffixDatabase.gz")
        assertContains(
            result.effectiveRules,
            "class * implements androidx.viewbinding.ViewBinding",
        )
        assertContains(result.effectiveRules, "public static *** inflate(...);")
        assertEquals(
            listOf(RuleDecisionReason.BROAD_ANDROIDX, RuleDecisionReason.BROAD_GOOGLE),
            result.manifest.decisions.filter { it.action == RuleDecisionAction.REMOVE }.map { it.reason },
        )
        assertTrue(result.manifest.decisions.any { it.reason == RuleDecisionReason.PRESERVED_EXACT_RULE && it.action == RuleDecisionAction.PRESERVE })
    }

    @Test
    fun `removes owned library blanket keeps while preserving warnings and narrow contracts`() {
        val source = """
            -keep class com.luck.picture.lib.** { *; }
            -keep class com.luck.lib.camerax.** { *; }
            -keep class com.yalantis.ucrop** { *; }
            -keep interface com.yalantis.ucrop** { *; }
            -dontwarn com.luck.picture.lib.**
            -dontnote com.luck.lib.camerax.**
            -dontwarn com.yalantis.ucrop**
            -keep class com.luck.picture.lib.entity.LocalMedia { <fields>; }
            -keep class com.luck.lib.camerax.preview.** { <methods>; }
            -keepclassmembers class com.yalantis.ucrop.model.CropParameters {
                @com.yalantis.ucrop.annotation.Required <fields>;
            }
        """.trimIndent() + "\n"

        val result = HardeningRulesFilter.filter(
            source,
            setOf(
                "com.luck.picture.lib.entity",
                "com.luck.lib.camerax.preview",
                "com.yalantis.ucrop.model",
            ),
        )

        assertFalse(result.effectiveRules.contains("-keep class com.luck.picture.lib.** { *; }"))
        assertFalse(result.effectiveRules.contains("-keep class com.luck.lib.camerax.** { *; }"))
        assertFalse(result.effectiveRules.contains("-keep class com.yalantis.ucrop** { *; }"))
        assertFalse(result.effectiveRules.contains("-keep interface com.yalantis.ucrop** { *; }"))
        assertContains(result.effectiveRules, "-dontwarn com.luck.picture.lib.**")
        assertContains(result.effectiveRules, "-dontnote com.luck.lib.camerax.**")
        assertContains(result.effectiveRules, "-dontwarn com.yalantis.ucrop**")
        assertContains(result.effectiveRules, "-keep class com.luck.picture.lib.entity.LocalMedia { <fields>; }")
        assertContains(result.effectiveRules, "-keep class com.luck.lib.camerax.preview.** { <methods>; }")
        assertContains(result.effectiveRules, "@com.yalantis.ucrop.annotation.Required <fields>;")
        assertEquals(
            List(4) { "BROAD_OWNED_PACKAGE" },
            result.manifest.decisions.filter { it.action == RuleDecisionAction.REMOVE }.map { it.reason.name },
        )
    }

    @Test
    fun `removes multiline global fields views components R binding and first party package blockers`() {
        val source = """
            # global field blocker
            -keepclassmembers class * {
                !transient <fields>;
            }
            # global XML constructor blocker
            -keepclasseswithmembers class * {
                public <init>(android.content.Context, android.util.AttributeSet);
            }
            -keep public class * extends android.app.Activity
            -keep class **.R$* {*;}
            -keep class **.*Binding {*;}
            -keep @kotlin.Metadata class com.example.demo.match.**
            # narrow Gson contract remains
            -keepclassmembers,allowobfuscation class * {
                @com.google.gson.annotations.SerializedName <fields>;
            }
            # narrow Serializable protocol remains
            -keepclassmembers class * implements java.io.Serializable {
                private void writeObject(java.io.ObjectOutputStream);
            }
        """.trimIndent() + "\n"

        val result = HardeningRulesFilter.filter(source, setOf("com.example.demo.match"))

        assertFalse(result.effectiveRules.contains("!transient <fields>;"))
        assertFalse(result.effectiveRules.contains("android.util.AttributeSet"))
        assertFalse(result.effectiveRules.contains("extends android.app.Activity"))
        assertFalse(result.effectiveRules.contains("**.R$*"))
        assertFalse(result.effectiveRules.contains("**.*Binding"))
        assertContains(result.effectiveRules, "@com.google.gson.annotations.SerializedName <fields>;")
        assertContains(result.effectiveRules, "private void writeObject(java.io.ObjectOutputStream);")
        assertEquals(
            setOf(
                RuleDecisionReason.GLOBAL_FIELDS,
                RuleDecisionReason.GLOBAL_VIEW_OR_COMPONENT,
                RuleDecisionReason.BROAD_R_OR_BINDING,
                RuleDecisionReason.BROAD_OWNED_PACKAGE,
            ),
            result.manifest.decisions.filter { it.action == RuleDecisionAction.REMOVE }.map { it.reason }.toSet(),
        )
    }

    @Test
    fun `preserves exact runtime contracts and warnings while removing only first party Kotlin blankets`() {
        val source = """
            -dontwarn androidx.**
            -dontwarn com.google.**
            -keep class io.objectbox.** { *; }
            -keepclassmembers class * implements java.io.Serializable {
                private void writeObject(java.io.ObjectOutputStream);
            }
            -keepclasseswithmembernames class * {
                native <methods>;
            }
            -keepclassmembers class * {
                @android.webkit.JavascriptInterface <methods>;
            }
            -keepclassmembers class * {
                @com.wyjson.router.annotation.Param <fields>;
            }
            -keepclassmembers,allowobfuscation class * {
                @com.google.gson.annotations.SerializedName <fields>;
            }
            -keep @kotlin.Metadata class com.example.demo.match.**
            -keepclasseswithmembers @kotlin.Metadata class com.example.core.** { *; }
        """.trimIndent() + "\n"

        val result = HardeningRulesFilter.filter(
            source,
            setOf("com.example.demo.match", "com.example.core"),
        )

        assertContains(result.effectiveRules, "-dontwarn androidx.**")
        assertContains(result.effectiveRules, "-dontwarn com.google.**")
        assertContains(result.effectiveRules, "-keep class io.objectbox.** { *; }")
        assertContains(result.effectiveRules, "private void writeObject(java.io.ObjectOutputStream);")
        assertContains(result.effectiveRules, "native <methods>;")
        assertContains(result.effectiveRules, "@android.webkit.JavascriptInterface <methods>;")
        assertContains(result.effectiveRules, "@com.wyjson.router.annotation.Param <fields>;")
        assertContains(result.effectiveRules, "@com.google.gson.annotations.SerializedName <fields>;")
        assertFalse(result.effectiveRules.contains("@kotlin.Metadata class com.example.demo.match.**"))
        assertFalse(result.effectiveRules.contains("@kotlin.Metadata class com.example.core.**"))
        assertEquals(
            2,
            result.manifest.decisions.count {
                it.action == RuleDecisionAction.REMOVE && it.reason == RuleDecisionReason.BROAD_OWNED_PACKAGE
            },
        )
    }

    @Test
    fun `removes only owned first party package blankets while preserving narrow contracts`() {
        val source = """
            -keep class com.example.core.enum.** {*;}
            -keep class com.example.demo.match.common.bean.** {*;}
            -keep class com.example.demo.match.common.enums.** {*;}
            -keep class com.example.demo.match.common.event.** {*;}
            -keep class com.example.demo.match.common.netease.model.** {*;}
            -keepclassmembers,allowobfuscation class * {
                @com.google.gson.annotations.SerializedName <fields>;
            }
            -keepclassmembers class * {
                @org.greenrobot.eventbus.Subscribe <methods>;
            }
            -keepclassmembers class * implements java.io.Serializable {
                private void writeObject(java.io.ObjectOutputStream);
            }
            -keep class com.example.demo.match.common.bean.UserProfile { <fields>; }
            -keep class com.example.demo.match.common.bean.** { <methods>; }
            -keep class com.example.demo.match.common.other.** { *; }
        """.trimIndent() + "\n"

        val result = HardeningRulesFilter.filter(
            source,
            setOf(
                "com.example.core.enum",
                "com.example.demo.match.common.bean",
                "com.example.demo.match.common.enums",
                "com.example.demo.match.common.event",
                "com.example.demo.match.common.netease.model",
            ),
        )

        listOf(
            "-keep class com.example.core.enum.** {*;}",
            "-keep class com.example.demo.match.common.bean.** {*;}",
            "-keep class com.example.demo.match.common.enums.** {*;}",
            "-keep class com.example.demo.match.common.event.** {*;}",
            "-keep class com.example.demo.match.common.netease.model.** {*;}",
        ).forEach { blanketRule ->
            assertFalse(result.effectiveRules.contains(blanketRule))
        }
        assertContains(result.effectiveRules, "@com.google.gson.annotations.SerializedName <fields>;")
        assertContains(result.effectiveRules, "@org.greenrobot.eventbus.Subscribe <methods>;")
        assertContains(result.effectiveRules, "private void writeObject(java.io.ObjectOutputStream);")
        assertContains(result.effectiveRules, "-keep class com.example.demo.match.common.bean.UserProfile { <fields>; }")
        assertContains(result.effectiveRules, "-keep class com.example.demo.match.common.bean.** { <methods>; }")
        assertContains(result.effectiveRules, "-keep class com.example.demo.match.common.other.** { *; }")
        assertEquals(
            5,
            result.manifest.decisions.count {
                it.action == RuleDecisionAction.REMOVE && it.reason == RuleDecisionReason.BROAD_OWNED_PACKAGE
            },
        )
    }

    @Test
    fun `normalizes line endings and trailing whitespace for deterministic manifest hashes`() {
        val unix = "-keep class androidx.** {*;}\n-keep class okio.**{*;}\n"
        val windows = "-keep class androidx.** {*;}  \r\n-keep class okio.**{*;}\r\n"

        val first = HardeningRulesFilter.filter(unix)
        val second = HardeningRulesFilter.filter(windows)

        assertEquals(first.effectiveRules, second.effectiveRules)
        assertEquals(first.manifest.normalizedSourceSha256, second.manifest.normalizedSourceSha256)
        assertEquals(first.manifest.normalizedOutputSha256, second.manifest.normalizedOutputSha256)
        assertTrue(first.manifest.sourceSha256 != second.manifest.sourceSha256)
        assertEquals(64, first.manifest.outputSha256.length)
    }

    @Test
    fun `rejects an unterminated multiline rule instead of filtering partial input`() {
        val source = "-keepclassmembers class * {\n  <fields>;\n"

        assertFailsWith<IllegalArgumentException> {
            HardeningRulesFilter.filter(source)
        }
    }

    private companion object {
        val SUSPEND_LAMBDA_SAFETY_RULE = """
            -keep,allowobfuscation,allowshrinking class * extends kotlin.coroutines.jvm.internal.SuspendLambda {
                *;
            }
        """.trimIndent()

        val DEMO_ADDITIONAL_RULES = """
            -keep,allowobfuscation class * implements androidx.viewbinding.ViewBinding
            -keepclassmembers class * implements androidx.viewbinding.ViewBinding {
                public static *** inflate(...);
            }

            -keep,allowobfuscation,allowshrinking,allowoptimization class com.example.core.common.BaseActivity
            -keep,allowobfuscation,allowshrinking,allowoptimization class * extends com.example.core.common.BaseActivity
            -keep,allowobfuscation,allowshrinking,allowoptimization class com.example.core.common.BaseFragment
            -keep,allowobfuscation,allowshrinking,allowoptimization class * extends com.example.core.common.BaseFragment
            -keep,allowobfuscation,allowshrinking,allowoptimization class com.example.core.common.BaseDialogFragment
            -keep,allowobfuscation,allowshrinking,allowoptimization class * extends com.example.core.common.BaseDialogFragment
            -keep,allowobfuscation,allowshrinking,allowoptimization class com.example.core.common.BaseBottomSheetDialogFragment
            -keep,allowobfuscation,allowshrinking,allowoptimization class * extends com.example.core.common.BaseBottomSheetDialogFragment
        """.trimIndent() + "\n"
    }
}
