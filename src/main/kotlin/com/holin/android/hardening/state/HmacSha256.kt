package com.holin.android.hardening.state

import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

object HmacSha256 {
    fun bytes(key: ByteArray, message: ByteArray): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(key, "HmacSHA256"))
        return mac.doFinal(message)
    }

    fun hex(key: ByteArray, message: ByteArray): String = bytes(key, message).joinToString("") { "%02x".format(it) }
}
