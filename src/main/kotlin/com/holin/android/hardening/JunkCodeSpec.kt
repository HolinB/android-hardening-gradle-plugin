package com.holin.android.hardening

import com.holin.android.hardening.junk.JunkCodePolicy
import javax.inject.Inject
import org.gradle.api.model.ObjectFactory
import org.gradle.api.provider.Property

open class JunkCodeSpec @Inject constructor(objects: ObjectFactory) {
    val enabled: Property<Boolean> = objects.property(Boolean::class.java).convention(true)
    val packageCount: Property<Int> = objects.property(Int::class.java).convention(4)
    val classCount: Property<Int> = objects.property(Int::class.java).convention(100)
    val activityCount: Property<Int> = objects.property(Int::class.java).convention(8)
    val methodCountPerClass: Property<Int> = objects.property(Int::class.java).convention(10)
    val drawableCount: Property<Int> = objects.property(Int::class.java).convention(40)
    val stringCount: Property<Int> = objects.property(Int::class.java).convention(40)

    fun policy(): JunkCodePolicy = JunkCodePolicy(
        enabled.get(), packageCount.get(), classCount.get(), activityCount.get(),
        methodCountPerClass.get(), drawableCount.get(), stringCount.get(),
    )
}
