package com.holin.android.hardening.state

import java.nio.file.Path
import org.gradle.api.file.DirectoryProperty
import org.gradle.api.logging.Logging
import org.gradle.api.provider.Property
import org.gradle.api.services.BuildService
import org.gradle.api.services.BuildServiceParameters

/** Kept alive by every task that may still consume this invocation's intermediate files. */
abstract class HardeningCleanupService : BuildService<HardeningCleanupService.Parameters>, AutoCloseable {
    interface Parameters : BuildServiceParameters {
        val buildDirectory: DirectoryProperty
        val repositoryRoot: DirectoryProperty
        val module: Property<String>
        val variant: Property<String>
        val invocationId: Property<String>
    }

    private val logger = Logging.getLogger(HardeningCleanupService::class.java)
    private var attempted = false
    private var session: HardeningScratchSession? = null

    @Synchronized
    fun begin() {
        if (attempted) return
        attempted = true
        try {
            val created = HardeningScratchSession(parameters.buildDirectory.get().asFile.toPath(),
                parameters.repositoryRoot.get().asFile.toPath(), parameters.module.get(),
                parameters.variant.get(), parameters.invocationId.get())
            session = created
            created.start()
        } catch (failure: Exception) {
            logger.warn("Hardening scratch ownership could not be established; files will be retained ({})", failure.javaClass.simpleName)
        }
    }

    @Synchronized
    fun retainExplicitOutputs(outputs: Collection<Path>) {
        begin()
        try {
            session?.retain(outputs)
        } catch (failure: Exception) {
            logger.warn("Hardening explicit output retention could not be recorded ({})", failure.javaClass.simpleName)
        }
    }

    @Synchronized
    override fun close() {
        try {
            session?.close()
            if ((session?.failureCount ?: 0) > 0) {
                logger.warn("Hardening scratch cleanup retained {} unsafe or inaccessible entries; see cleanup-report.json", session?.failureCount)
            }
        } catch (failure: Exception) {
            logger.warn("Hardening scratch cleanup was incomplete; retained ownership records will be retried ({})", failure.javaClass.simpleName)
        }
    }
}
