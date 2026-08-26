package com.holin.android.hardening

import org.gradle.api.Plugin
import org.gradle.api.Project

class AndroidHardeningPlugin : Plugin<Project> {
    override fun apply(project: Project) {
        val registration = HardeningPluginRegistration()
        registration.configure(project)
        project.pluginManager.withPlugin("com.android.application") {
            val toolchain = ProjectToolchainInspector.inspect(project)
            PortableToolchainCompatibility.verify(toolchain)
            val androidPlugin = requireNotNull(project.plugins.findPlugin("com.android.application"))
            AgpPublicCapabilityProbe.verify(toolchain.androidGradlePlugin, androidPlugin.javaClass.classLoader)
            AgpHardeningAdapter().configure(project, registration)
        }
    }
}
