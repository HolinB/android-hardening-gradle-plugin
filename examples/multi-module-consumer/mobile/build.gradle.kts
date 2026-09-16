plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("com.holin.android.hardening")
}

val signingStoreFile = providers.environmentVariable("DEMO_SIGNING_STORE_FILE")
val signingStorePassword = providers.environmentVariable("DEMO_SIGNING_STORE_PASSWORD")
val signingKeyAlias = providers.environmentVariable("DEMO_SIGNING_KEY_ALIAS")
val signingKeyPassword = providers.environmentVariable("DEMO_SIGNING_KEY_PASSWORD")
val signingIsComplete = listOf(
    signingStoreFile,
    signingStorePassword,
    signingKeyAlias,
    signingKeyPassword,
).all { value -> value.isPresent }

android {
    namespace = "com.example.demo"
    compileSdk = 35

    defaultConfig {
        applicationId = "com.example.demo"
        minSdk = 26
        targetSdk = 35
        versionCode = 1
        versionName = "1.0"
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    flavorDimensions += "distribution"
    productFlavors {
        create("demo") {
            dimension = "distribution"
        }
    }

    val localSigning = if (signingIsComplete) {
        signingConfigs.create("localHardening") {
            storeFile = file(signingStoreFile.get())
            storePassword = signingStorePassword.get()
            keyAlias = signingKeyAlias.get()
            keyPassword = signingKeyPassword.get()
        }
    } else {
        null
    }

    buildTypes {
        create("qa") {
            isMinifyEnabled = true
            signingConfig = localSigning
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro",
            )
        }
    }

    sourceSets {
        getByName("demo") {
            res.srcDir("src/demoResources/res")
        }
    }
}

dependencies {
    implementation(project(":core"))
    implementation(project(":media"))
}

androidHardening {
    enabled.set(providers.gradleProperty("androidHardening").map(String::toBoolean).orElse(false))
    projectKey.set("demo")

    variants.include("demoQa")

    ownership {
        module(":mobile") {
            sourceSets.addAll("main", "demo")
            images {
                formats(PNG, WEBP)
                include("src/main/res/drawable/**/*.png")
                exclude("src/main/res/drawable/**/*.9.png")
            }
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
    }

    rules {
        sourceFiles.from("proguard-rules.pro")
        preserveExactRules.from("hardening-preserve-exact.pro")
        additionalRules.from("hardening-additional.pro")
    }

    mapping {
        storeDirectory.set(rootProject.layout.projectDirectory.dir(".hardening/mappings"))
    }

    reproducibility {
        fixedSeed.set(providers.gradleProperty("androidHardeningFixedSeed"))
    }

    bundle {
        dependencyMetadata.set(OMIT)
        structuralMetadataEntryCount.set(16)
    }

    signing {
        reuseVariantSigningConfig.set(true)
    }

    legacyPlugins {
        mode.set(PRESERVE_UNMANAGED)
        verifyCompatibility.set(true)
        baselineFile.set(rootProject.layout.projectDirectory.file("legacy/legacy-plugin-baseline.json"))
        plugin("neutralLegacy") {
            pluginId.set("com.example.legacy")
            expectedVersion.set("1.0.0")
            configurationInputs.from(
                rootProject.layout.projectDirectory.file("build.gradle.kts"),
                layout.projectDirectory.file("build.gradle.kts"),
            )
            mappingPaths.from(layout.buildDirectory.file("outputs/mapping/demoQa/mapping.txt"))
        }
    }

    compatibility {
        autoMigrateLegacyState.set(false)
    }
}
