pluginManagement {
    val localHardeningRepository = providers.gradleProperty("hardeningPluginRepo").orNull
        ?: error("Pass -PhardeningPluginRepo=<extracted-portable-zip>/repository")
    repositories {
        exclusiveContent {
            forRepository {
                maven {
                    name = "ExtractedHardeningPlugin"
                    url = uri(localHardeningRepository)
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

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
    }
}

rootProject.name = "hardening-multi-module-consumer"
include(":mobile", ":core", ":media")
