package com.holin.android.hardening.code

import com.google.gson.ExclusionStrategy
import com.google.gson.FieldAttributes
import com.google.gson.Gson
import com.google.gson.GsonBuilder
import com.google.gson.JsonParser
import com.google.gson.annotations.Expose
import com.google.gson.annotations.SerializedName
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse

class PotentialBeanGsonCompatibilityTest {
    @Test
    fun `class renaming preserves default and annotated JSON keys`() {
        val gson = projectGson()
        val ordinary = OrdinaryProfile().apply {
            inherited = "parent"
            id = 7
            name = "Ada"
            address = OrdinaryAddress().apply {
                id = 11
                city = "Shenzhen"
            }
            aliases = mutableListOf(
                OrdinaryAlias().apply {
                    id = 21
                    value = "alpha"
                },
                OrdinaryAlias().apply {
                    id = 22
                    value = "beta"
                },
            )
            displayName = "Ada Lovelace"
            serverOnly = "private"
            baseObjId = 99
        }
        val hardened = CinderProfile().apply {
            inherited = "parent"
            id = 7
            name = "Ada"
            address = EmberAddress().apply {
                id = 11
                city = "Shenzhen"
            }
            aliases = mutableListOf(
                EmberAlias().apply {
                    id = 21
                    value = "alpha"
                },
                EmberAlias().apply {
                    id = 22
                    value = "beta"
                },
            )
            displayName = "Ada Lovelace"
            serverOnly = "private"
            baseObjId = 99
        }

        val ordinaryJson = JsonParser.parseString(gson.toJson(ordinary)).asJsonObject
        val hardenedJson = JsonParser.parseString(gson.toJson(hardened)).asJsonObject

        assertEquals(ordinaryJson, hardenedJson)
        assertEquals("Ada Lovelace", hardenedJson.get("display_name").asString)
        assertFalse(hardenedJson.has("displayName"))
        assertFalse(hardenedJson.has("serverOnly"))
        assertFalse(hardenedJson.has("baseObjId"))
    }

    @Test
    fun `historical alternate keys deserialize into a class-renamed fixture`() {
        val historical =
            """{"id":7,"name":"Ada","displayName":"Historical Ada","inherited":"parent","address":{"id":11,"city":"Shenzhen"},"aliases":[{"id":21,"value":"alpha"}]}"""

        val decoded = projectGson().fromJson(historical, CinderProfile::class.java)

        assertEquals(7, decoded.id)
        assertEquals("Ada", decoded.name)
        assertEquals("Historical Ada", decoded.displayName)
        assertEquals("parent", decoded.inherited)
        assertEquals(11, decoded.address.id)
        assertEquals("Shenzhen", decoded.address.city)
        assertEquals(listOf(21), decoded.aliases.map(EmberAlias::id))
    }

    private fun projectGson(): Gson = GsonBuilder()
        .addSerializationExclusionStrategy(object : ExclusionStrategy {
            override fun shouldSkipField(field: FieldAttributes): Boolean {
                val expose = field.getAnnotation(Expose::class.java)
                return expose?.deserialize == false || field.name == "baseObjId"
            }

            override fun shouldSkipClass(clazz: Class<*>): Boolean = false
        })
        .create()

    private open class OrdinaryParent {
        var inherited: String = ""
    }

    private class OrdinaryProfile : OrdinaryParent() {
        var id: Int = 0
        var name: String = ""
        var address: OrdinaryAddress = OrdinaryAddress()
        var aliases: MutableList<OrdinaryAlias> = mutableListOf()

        @SerializedName(value = "display_name", alternate = ["displayName"])
        var displayName: String = ""

        @Expose(deserialize = false)
        var serverOnly: String = ""

        var baseObjId: Long = 0
    }

    private class OrdinaryAddress {
        var id: Int = 0
        var city: String = ""
    }

    private class OrdinaryAlias {
        var id: Int = 0
        var value: String = ""
    }

    private open class CinderParent {
        var inherited: String = ""
    }

    private class CinderProfile : CinderParent() {
        var id: Int = 0
        var name: String = ""
        var address: EmberAddress = EmberAddress()
        var aliases: MutableList<EmberAlias> = mutableListOf()

        @SerializedName(value = "display_name", alternate = ["displayName"])
        var displayName: String = ""

        @Expose(deserialize = false)
        var serverOnly: String = ""

        var baseObjId: Long = 0
    }

    private class EmberAddress {
        var id: Int = 0
        var city: String = ""
    }

    private class EmberAlias {
        var id: Int = 0
        var value: String = ""
    }
}
