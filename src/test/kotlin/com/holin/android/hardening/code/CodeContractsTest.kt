package com.holin.android.hardening.code

import com.holin.android.hardening.audit.ExternalNameCandidate
import com.holin.android.hardening.audit.ExternalNameContractKind
import com.holin.android.hardening.audit.HardeningSourceAudit
import com.holin.android.hardening.audit.HardcodedReferenceFinding
import com.holin.android.hardening.HardcodedReferenceKind
import com.holin.android.hardening.audit.ResolvedContract
import com.holin.android.hardening.audit.ResolvedContractKind
import com.holin.android.hardening.audit.UnresolvedContract
import com.holin.android.hardening.audit.UnresolvedContractKind
import com.holin.android.hardening.naming.PseudowordRegistry
import java.nio.file.Path
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import org.objectweb.asm.Opcodes

class CodeContractsTest {
    @Test
    fun `exact hardcoded member evidence excludes only the unique owned bytecode symbols`() {
        val model = type(
            "com/example/Model",
            "Profile.kt",
            true,
            "java/lang/Object",
            emptyList(),
            listOf(
                exactField("com/example/Model", "token", "Ljava/lang/String;"),
                exactField("com/example/Model", "ordinary", "Ljava/lang/String;"),
            ),
            listOf(
                method("com/example/Model", "render", "(Ljava/lang/String;)Ljava/lang/String;"),
                method("com/example/Model", "render", "(I)Ljava/lang/String;"),
                method("com/example/Model", "ordinary", "(Ljava/lang/String;)Ljava/lang/String;"),
            ),
            Opcodes.ACC_PUBLIC,
        )
        val unrelated = type(
            "com/example/Unrelated",
            "Profile.kt",
            true,
            "java/lang/Object",
            emptyList(),
            listOf(exactField("com/example/Unrelated", "token", "Ljava/lang/String;")),
            listOf(method("com/example/Unrelated", "render", "(Ljava/lang/String;)Ljava/lang/String;")),
            Opcodes.ACC_PUBLIC,
        )
        val findings = listOf(
            HardcodedReferenceFinding(
                HardcodedReferenceKind.MEMBER_NAME,
                "app/src/main/java/com/example/Contract.kt",
                4,
                "render(java.lang.String)",
                "com/example/Model",
                "(Ljava/lang/String;)",
            ),
            HardcodedReferenceFinding(
                HardcodedReferenceKind.MEMBER_NAME,
                "app/src/main/java/com/example/Contract.kt",
                5,
                "token",
                "com/example/Model",
                null,
            ),
        )

        val result = classifier().classify(
            inventory(listOf(model, unrelated), listOf(objectType())),
            audit(emptyList(), emptyList(), emptyList(), findings),
            emptyList(),
        )

        assertEquals(
            setOf(
                fieldKey(model.fields.single { it.name == "token" }),
                methodKey(model.methods.single {
                    it.name == "render" && it.descriptor.startsWith("(Ljava/lang/String;)")
                }),
            ),
            result.exclusions
                .filter { it.reason == CodeExclusionReason.HARDCODED_MEMBER_NAME }
                .map(CodeExclusion::key)
                .toSet(),
        )
        assertTrue(result.eligible.any { it.key == fieldKey(unrelated.fields.single()) })
        assertTrue(result.eligible.any { it.key == methodKey(unrelated.methods.single()) })
        assertTrue(result.eligible.any { it.key == fieldKey(model.fields.single { it.name == "ordinary" }) })
        assertTrue(result.eligible.any { it.key == methodKey(model.methods.single { it.name == "ordinary" }) })
    }

    @Test
    fun `ambiguous exact hardcoded field evidence fails closed`() {
        val model = type(
            "com/example/Model",
            "Profile.kt",
            true,
            "java/lang/Object",
            emptyList(),
            listOf(
                exactField("com/example/Model", "token", "Ljava/lang/String;"),
                exactField("com/example/Model", "token", "I"),
            ),
            emptyList(),
            Opcodes.ACC_PUBLIC,
        )
        val finding = HardcodedReferenceFinding(
            HardcodedReferenceKind.MEMBER_NAME,
            "app/src/main/java/com/example/Contract.kt",
            5,
            "token",
            "com/example/Model",
            null,
        )

        val failure = assertFailsWith<IllegalArgumentException> {
            classifier().classify(
                inventory(listOf(model), listOf(objectType())),
                audit(emptyList(), emptyList(), emptyList(), listOf(finding)),
                emptyList(),
            )
        }

        assertTrue(failure.message.orEmpty().contains("multiple owned symbols"))
    }

    @Test
    fun `custom Gson field naming strategy fails stable naming classification`() {
        val failure = assertFailsWith<IllegalArgumentException> {
            classifier().classify(
                inventory(listOf(type("com/example/Profile")), listOf(objectType())),
                audit(
                    unresolved = listOf(
                        UnresolvedContract(
                            UnresolvedContractKind.GSON_FIELD_NAMING_STRATEGY,
                            "app/src/main/java/com/example/GsonFactory.kt",
                            12,
                            "GsonBuilder().setFieldNamingStrategy(ServerNamingStrategy())",
                            "custom Gson FieldNamingStrategy can derive JSON keys from renamed metadata",
                        ),
                    ),
                ),
            )
        }

        assertTrue(failure.message.orEmpty().contains("GsonFactory.kt:12"))
    }

    @Test
    fun `potential Bean instance field exclusion leaves class and ordinary method eligible`() {
        val owner = "com/example/Profile"
        val field = field(owner, "id")
        val ordinaryMethod = method(owner, "refresh", "()V")
        val constructor = method(owner, "<init>", "()V")

        val result = classifier().classify(
            inventory(
                listOf(type(owner, fields = listOf(field), methods = listOf(ordinaryMethod, constructor))),
                listOf(objectType()),
            ),
            audit(),
        )

        assertEquals(
            listOf(CodeExclusionReason.POTENTIAL_BEAN_INSTANCE_FIELD),
            result.exclusions.filter { it.key == fieldKey(field) }.map(CodeExclusion::reason),
        )
        assertTrue(result.eligible.any { it.key == classKey(type(owner)) })
        assertTrue(result.eligible.any { it.key == methodKey(ordinaryMethod) })
        assertEquals(
            listOf(CodeExclusionReason.CONSTRUCTOR),
            result.exclusions.filter { it.key == methodKey(constructor) }.map(CodeExclusion::reason),
        )
    }

    @Test
    fun `public Activity View callback keep rule excludes an arbitrary public static method through external ancestors`() {
        val owner = "com/example/SignInActivity"
        val callback = method(owner, "returnToWelcome", "(Landroid/view/View;)V", Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC)
        val appCompatActivity = type(
            "androidx/appcompat/app/AppCompatActivity",
            owned = false,
            superName = "androidx/fragment/app/FragmentActivity",
        )
        val fragmentActivity = type(
            "androidx/fragment/app/FragmentActivity",
            owned = false,
            superName = "android/app/Activity",
        )
        val activity = type("android/app/Activity", owned = false)

        val result = classifier().classify(
            inventory(
                listOf(type(owner, superName = appCompatActivity.internalName, methods = listOf(callback))),
                listOf(appCompatActivity, fragmentActivity, activity, objectType()),
            ),
            audit(),
        )

        val activityCallbackExclusions = result.exclusions.filter { it.reason.name == "ACTIVITY_VIEW_CALLBACK_KEEP_RULE" }

        assertEquals(listOf(methodKey(callback)), activityCallbackExclusions.map(CodeExclusion::key))
        assertEquals(
            listOf(
                "public Activity View callback keep-rule contract public void *(android.view.View): returnToWelcome(Landroid/view/View;)V",
            ),
            activityCallbackExclusions.map(CodeExclusion::evidence),
        )
        assertFalse(result.eligible.any { it.key == methodKey(callback) })
    }

    @Test
    fun `Activity View callback keep rule rejects near matches and never excludes non-method owned or external symbols`() {
        val owner = "com/example/ProfileActivity"
        val callbackDescriptor = "(Landroid/view/View;)V"
        val privateCallback = method(owner, "privateTap", callbackDescriptor, Opcodes.ACC_PRIVATE)
        val nonVoid = method(owner, "returnsValue", "(Landroid/view/View;)Ljava/lang/Object;")
        val noArguments = method(owner, "noArguments", "()V")
        val multipleArguments = method(owner, "multipleArguments", "(Landroid/view/View;I)V")
        val viewSubclassParameter = method(owner, "viewSubclass", "(Landroid/widget/TextView;)V")
        val objectParameter = method(owner, "objectParameter", "(Ljava/lang/Object;)V")
        val constructor = method(owner, "<init>", callbackDescriptor)
        val classInitializer = method(owner, "<clinit>", "()V", Opcodes.ACC_STATIC)
        val ownedField = field(owner, "callback")
        val nonActivityOwner = "com/example/CallbackHost"
        val nonActivityMethod = method(nonActivityOwner, "exactShape", callbackDescriptor)
        val incompleteOwner = "com/example/IncompleteActivity"
        val incompleteMethod = method(incompleteOwner, "exactShape", callbackDescriptor)
        val externalOwner = "external/ExternalActivity"
        val externalMethod = method(externalOwner, "exactShape", callbackDescriptor)
        val activity = type("android/app/Activity", owned = false)
        val nearMatches = listOf(
            privateCallback,
            nonVoid,
            noArguments,
            multipleArguments,
            viewSubclassParameter,
            objectParameter,
        )
        val profileActivity = type(
            owner,
            fields = listOf(ownedField),
            methods = nearMatches + constructor + classInitializer,
            superName = activity.internalName,
        )
        val callbackHost = type(nonActivityOwner, methods = listOf(nonActivityMethod))
        val incompleteActivity = type(
            incompleteOwner,
            methods = listOf(incompleteMethod),
            superName = "external/MissingActivityBase",
        )
        val externalActivity = type(
            externalOwner,
            owned = false,
            methods = listOf(externalMethod),
            superName = activity.internalName,
        )

        val result = classifier().classify(
            inventory(
                listOf(profileActivity, callbackHost, incompleteActivity),
                listOf(externalActivity, activity, objectType()),
            ),
            audit(),
        )

        assertTrue(result.exclusions.none { it.reason.name == "ACTIVITY_VIEW_CALLBACK_KEEP_RULE" })
        assertTrue(
            result.eligible.map(EligibleCodeSymbol::key).containsAll(
                listOf(classKey(profileActivity)) + nearMatches.map(::methodKey) +
                    listOf(methodKey(nonActivityMethod), methodKey(incompleteMethod)),
            ),
        )
        assertTrue(result.exclusions.any {
            it.key == fieldKey(ownedField) && it.reason == CodeExclusionReason.POTENTIAL_BEAN_INSTANCE_FIELD
        })
        assertTrue(result.eligible.none { it.key == methodKey(externalMethod) })
        assertEquals(
            setOf(methodKey(constructor), methodKey(classInitializer)),
            result.exclusions.filter { it.reason == CodeExclusionReason.CONSTRUCTOR }.map(CodeExclusion::key).toSet(),
        )
    }

    @Test
    fun `callback parameter keep rules exclude exact void single object callbacks regardless of method name or access`() {
        val owner = "com/example/CallbackBridge"
        val eventParameter = "Lcom/example/events/OnPaymentEvent;"
        val nestedListenerParameter = "Lcom/example/listeners/Host${'$'}OnStateListener;"
        val eventCallback = method(owner, "dispatch", "($eventParameter)V", Opcodes.ACC_PRIVATE or Opcodes.ACC_STATIC)
        val listenerCallback = method(owner, "relayToUi", "($nestedListenerParameter)V", 0)
        val result = classifier().classify(
            inventory(listOf(type(owner, methods = listOf(eventCallback, listenerCallback))), listOf(objectType())),
            audit(),
        )

        val callbackExclusions = result.exclusions.filter { it.reason.name == "CALLBACK_PARAMETER_KEEP_RULE" }

        assertEquals(
            listOf(methodKey(eventCallback), methodKey(listenerCallback)),
            callbackExclusions.map(CodeExclusion::key),
        )
        assertEquals(
            listOf(
                "callback parameter keep-rule contract **On*Event: com.example.events.OnPaymentEvent ($eventParameter)",
                "callback parameter keep-rule contract **On*Listener: com.example.listeners.Host${'$'}OnStateListener ($nestedListenerParameter)",
            ),
            callbackExclusions.map(CodeExclusion::evidence),
        )
        assertTrue(result.eligible.none { it.key in setOf(methodKey(eventCallback), methodKey(listenerCallback)) })
    }

    @Test
    fun `callback parameter keep rules reject near matches and never exclude owners fields or external methods`() {
        val owner = "com/example/CallbackBridge"
        val eventParameter = "Lcom/example/events/OnPaymentEvent;"
        val listenerParameter = "Lcom/example/listeners/OnStateListener;"
        val listenerGetter = method(owner, "getListener", "()$listenerParameter")
        val multipleArguments = method(owner, "join", "($eventParameter$listenerParameter)V")
        val nonVoid = method(owner, "make", "($eventParameter)Ljava/lang/Object;")
        val primitiveArgument = method(owner, "acceptInt", "(I)V")
        val arrayArgument = method(owner, "acceptArray", "([$eventParameter)V")
        val wrongSuffix = method(owner, "payload", "(Lcom/example/events/OnPaymentEventPayload;)V")
        val wrongCase = method(owner, "caseSensitive", "(Lcom/example/events/onPaymentEvent;)V")
        val constructor = method(owner, "<init>", "($eventParameter)V")
        val classInitializer = method(owner, "<clinit>", "()V", Opcodes.ACC_STATIC)
        val ownedField = field(owner, "callback")
        val externalOwner = "external/CallbackBridge"
        val externalMethod = method(externalOwner, "dispatch", "($eventParameter)V")
        val nearMatches = listOf(
            listenerGetter,
            multipleArguments,
            nonVoid,
            primitiveArgument,
            arrayArgument,
            wrongSuffix,
            wrongCase,
        )
        val result = classifier().classify(
            inventory(
                listOf(type(owner, fields = listOf(ownedField), methods = nearMatches + constructor + classInitializer)),
                listOf(type(externalOwner, owned = false, methods = listOf(externalMethod)), objectType()),
            ),
            audit(),
        )

        assertTrue(result.exclusions.none { it.reason.name == "CALLBACK_PARAMETER_KEEP_RULE" })
        assertTrue(result.eligible.map(EligibleCodeSymbol::key).containsAll(
            listOf(classKey(type(owner))) + nearMatches.map(::methodKey),
        ))
        assertTrue(result.exclusions.any {
            it.key == fieldKey(ownedField) && it.reason == CodeExclusionReason.POTENTIAL_BEAN_INSTANCE_FIELD
        })
        assertTrue(result.eligible.none { it.key == methodKey(externalMethod) })
        assertTrue(result.exclusions.any { it.key == methodKey(constructor) && it.reason == CodeExclusionReason.CONSTRUCTOR })
        assertTrue(result.exclusions.any { it.key == methodKey(classInitializer) && it.reason == CodeExclusionReason.CONSTRUCTOR })
    }

    @Test
    fun `generated enum API excludes only exact owned values and valueOf methods`() {
        val enumOwner = "com/example/Status"
        val values = method(enumOwner, "values", "()[L$enumOwner;", Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC)
        val valueOf = method(
            enumOwner,
            "valueOf",
            "(Ljava/lang/String;)L$enumOwner;",
            Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC,
        )
        val wrongDescriptor = method(enumOwner, "values", "()[Ljava/lang/Object;", Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC)
        val otherEnumMethod = method(enumOwner, "label", "()Ljava/lang/String;", Opcodes.ACC_PUBLIC)
        val enumField = field(enumOwner, "ACTIVE")
        val enumClass = type(
            enumOwner,
            fields = listOf(enumField),
            methods = listOf(values, valueOf, wrongDescriptor, otherEnumMethod),
            access = Opcodes.ACC_PUBLIC or Opcodes.ACC_ENUM,
        )
        val missingPublicOwner = "com/example/MissingPublicStatus"
        val missingPublic = method(missingPublicOwner, "values", "()[L$missingPublicOwner;", Opcodes.ACC_STATIC)
        val missingPublicEnum = type(
            missingPublicOwner,
            methods = listOf(missingPublic),
            access = Opcodes.ACC_PUBLIC or Opcodes.ACC_ENUM,
        )
        val missingStaticOwner = "com/example/MissingStaticStatus"
        val missingStatic = method(missingStaticOwner, "valueOf", "(Ljava/lang/String;)L$missingStaticOwner;", Opcodes.ACC_PUBLIC)
        val missingStaticEnum = type(
            missingStaticOwner,
            methods = listOf(missingStatic),
            access = Opcodes.ACC_PUBLIC or Opcodes.ACC_ENUM,
        )
        val nonEnumOwner = "com/example/StatusLike"
        val nonEnumValues = method(nonEnumOwner, "values", "()[L$nonEnumOwner;", Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC)
        val nonEnumClass = type(nonEnumOwner, methods = listOf(nonEnumValues))
        val externalOwner = "external/Status"
        val externalValues = method(externalOwner, "values", "()[L$externalOwner;", Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC)
        val externalEnum = type(
            externalOwner,
            owned = false,
            methods = listOf(externalValues),
            access = Opcodes.ACC_PUBLIC or Opcodes.ACC_ENUM,
        )

        val result = classify(
            listOf(enumClass, missingPublicEnum, missingStaticEnum, nonEnumClass),
            listOf(externalEnum, objectType()),
        )
        val enumApiExclusions = result.exclusions.filter { it.reason.name == "GENERATED_ENUM_API" }

        assertEquals(
            setOf(methodKey(values), methodKey(valueOf)),
            enumApiExclusions.map(CodeExclusion::key).toSet(),
        )
        assertEquals(
            setOf(
                "generated enum API contract: values()[Lcom/example/Status;",
                "generated enum API contract: valueOf(Ljava/lang/String;)Lcom/example/Status;",
            ),
            enumApiExclusions.map(CodeExclusion::evidence).toSet(),
        )
        assertFalse(result.eligible.any { it.key == methodKey(values) || it.key == methodKey(valueOf) })
        assertTrue(
            result.eligible.map(EligibleCodeSymbol::key).containsAll(
                listOf(
                    classKey(enumClass),
                    methodKey(wrongDescriptor),
                    methodKey(missingPublic),
                    methodKey(missingStatic),
                    methodKey(otherEnumMethod),
                    classKey(nonEnumClass),
                    methodKey(nonEnumValues),
                ),
            ),
        )
        assertTrue(result.exclusions.any {
            it.key == fieldKey(enumField) && it.reason == CodeExclusionReason.POTENTIAL_BEAN_INSTANCE_FIELD
        })
        assertTrue(result.exclusions.none { it.reason.name == "GENERATED_ENUM_API" && it.key == methodKey(externalValues) })
    }

    @Test
    fun `EventBus Subscribe annotation preserves only exact owned subscriber methods`() {
        val eventBusSubscribe = "Lorg/greenrobot/eventbus/Subscribe;"
        val subscriber = BytecodeMethod(
            "com/example/EventListener",
            "receivedPayResultEvent",
            "(Ljava/lang/Object;)V",
            Opcodes.ACC_PUBLIC,
            setOf(eventBusSubscribe),
        )
        val unannotated = method("com/example/EventListener", "handleLocally", "()V")
        val annotatedConstructor = BytecodeMethod(
            "com/example/EventListener",
            "<init>",
            "()V",
            Opcodes.ACC_PUBLIC,
            setOf(eventBusSubscribe),
        )
        val annotatedClassInitializer = BytecodeMethod(
            "com/example/EventListener",
            "<clinit>",
            "()V",
            Opcodes.ACC_STATIC,
            setOf(eventBusSubscribe),
        )
        val wrongPackage = BytecodeMethod(
            "com/example/EventListener",
            "receivedWrongPackageEvent",
            "()V",
            Opcodes.ACC_PUBLIC,
            setOf("Lcom/example/Subscribe;"),
        )
        val annotatedField = BytecodeField(
            "com/example/EventListener",
            "subscriberState",
            "Ljava/lang/Object;",
            Opcodes.ACC_PRIVATE,
            setOf(eventBusSubscribe),
        )
        val owner = BytecodeClass(
            "com/example/EventListener",
            ":app",
            "EventListener.kt",
            Path.of("/repo/app/src/main/java/com/example/EventListener.kt"),
            Opcodes.ACC_PUBLIC,
            "java/lang/Object",
            emptyList(),
            setOf(eventBusSubscribe),
            listOf(annotatedField),
            listOf(subscriber, unannotated, annotatedConstructor, annotatedClassInitializer, wrongPackage),
        )
        val externalSubscriber = BytecodeMethod(
            "external/EventListener",
            "receivedExternalEvent",
            "()V",
            Opcodes.ACC_PUBLIC,
            setOf(eventBusSubscribe),
        )
        val externalOwner = type(
            "external/EventListener",
            owned = false,
            methods = listOf(externalSubscriber),
        )

        val result = classify(listOf(owner), listOf(externalOwner, objectType()))

        assertTrue(result.exclusions.any {
            it.key == methodKey(subscriber) &&
                it.reason == CodeExclusionReason.EVENTBUS_SUBSCRIBER &&
                it.evidence == "EventBus @Subscribe method-name contract (Lorg/greenrobot/eventbus/Subscribe;)"
        })
        assertFalse(result.eligible.any { it.key == methodKey(subscriber) })
        assertTrue(result.eligible.any { it.key == classKey(owner) })
        assertTrue(result.exclusions.any {
            it.key == fieldKey(annotatedField) && it.reason == CodeExclusionReason.POTENTIAL_BEAN_INSTANCE_FIELD
        })
        assertTrue(result.eligible.any { it.key == methodKey(unannotated) })
        assertTrue(result.eligible.any { it.key == methodKey(wrongPackage) })
        assertTrue(result.exclusions.none {
            it.reason == CodeExclusionReason.EVENTBUS_SUBSCRIBER &&
                (it.key == methodKey(annotatedConstructor) ||
                    it.key == methodKey(annotatedClassInitializer) ||
                    it.key.owner == externalOwner.internalName)
        })
        assertEquals(
            setOf(methodKey(annotatedConstructor), methodKey(annotatedClassInitializer)),
            result.exclusions.filter { it.reason == CodeExclusionReason.CONSTRUCTOR }.map(CodeExclusion::key).toSet(),
        )
    }

    @Test
    fun `implementation fields are protected while external contracts are reported`() {
        val runnable = type(
            "java/lang/Runnable",
            owned = false,
            methods = listOf(method("java/lang/Runnable", "run", "()V", Opcodes.ACC_PUBLIC or Opcodes.ACC_ABSTRACT)),
        )
        val owner = type(
            "com/example/Profile",
            interfaces = listOf(runnable.internalName),
            fields = listOf(field("com/example/Profile", "binding"), field("com/example/Profile", "value${'$'}delegate")),
            methods = listOf(method("com/example/Profile", "run", "()V"), method("com/example/Profile", "send", "()V")),
        )
        val result = classify(
            owned = listOf(owner),
            external = listOf(runnable, objectType()),
            candidates = listOf(candidate(ExternalNameContractKind.JAVASCRIPT_INTERFACE, "Profile.kt", "send")),
        )

        assertEquals(
            setOf("binding", "value${'$'}delegate"),
            result.exclusions.filter { it.reason == CodeExclusionReason.POTENTIAL_BEAN_INSTANCE_FIELD }
                .mapTo(linkedSetOf()) { it.key.name },
        )
        assertEquals(
            setOf(
                CodeExclusionReason.EXTERNAL_OVERRIDE,
                CodeExclusionReason.JAVASCRIPT_INTERFACE,
                CodeExclusionReason.POTENTIAL_BEAN_INSTANCE_FIELD,
            ),
            result.exclusions.mapTo(sortedSetOf()) { it.reason },
        )
    }

    @Test
    fun `constructors and class initializers are excluded but implementation methods are eligible`() {
        val owner = type(
            "com/example/Owner",
            methods = listOf(
                method("com/example/Owner", "<init>", "()V"),
                method("com/example/Owner", "<clinit>", "()V", Opcodes.ACC_STATIC),
                method("com/example/Owner", "calculate", "()V"),
            ),
        )

        val result = classify(listOf(owner), listOf(objectType()))

        assertEquals(setOf("<init>", "<clinit>"), result.exclusions.filter { it.reason == CodeExclusionReason.CONSTRUCTOR }.mapTo(sortedSetOf()) { it.key.name })
        assertTrue(result.eligible.any { it.key.name == "calculate" })
    }

    @Test
    fun `public direct View subclasses exclude exact getter and setter property methods`() {
        val view = type("android/view/View", owned = false, superName = "java/lang/Object")
        val owner = type(
            "com/example/DirectView",
            superName = view.internalName,
            methods = listOf(
                method("com/example/DirectView", "setCount", "(I)V"),
                method("com/example/DirectView", "setTarget", "(Ljava/lang/Object;)V"),
                method("com/example/DirectView", "setNames", "([Ljava/lang/String;)V"),
                method("com/example/DirectView", "getCount", "()I"),
            ),
        )

        val result = classify(listOf(owner), listOf(view, objectType()))

        assertEquals(
            setOf("setCount", "setTarget", "setNames", "getCount"),
            viewPropertyExclusions(result).mapTo(sortedSetOf()) { it.key.name },
        )
        assertTrue(viewPropertyExclusions(result).all {
            it.evidence == "public View subclass property-name contract"
        })
    }

    @Test
    fun `public View subclasses resolve property contracts through owned and external ancestors`() {
        val view = type("android/view/View", owned = false, superName = "java/lang/Object")
        val externalParent = type("external/WidgetBase", owned = false, superName = view.internalName)
        val ownedParent = type("com/example/OwnedWidgetBase", superName = externalParent.internalName)
        val owner = type(
            "com/example/TransitiveView",
            superName = ownedParent.internalName,
            methods = listOf(method("com/example/TransitiveView", "getTitle", "()Ljava/lang/String;")),
        )

        val result = classify(listOf(ownedParent, owner), listOf(externalParent, view, objectType()))

        assertEquals(
            listOf(methodKey(owner.methods.single())),
            viewPropertyExclusions(result).map(CodeExclusion::key),
        )
    }

    @Test
    fun `View property contracts retain fluent setters`() {
        val view = type("android/view/View", owned = false, superName = "java/lang/Object")
        val setter = method(
            "com/example/FluentView",
            "setTitle",
            "(Ljava/lang/String;)Lcom/example/FluentView;",
        )
        val owner = type(
            "com/example/FluentView",
            superName = view.internalName,
            methods = listOf(setter),
        )

        val result = classify(listOf(owner), listOf(view, objectType()))

        assertTrue(viewPropertyExclusions(result).isEmpty())
        assertTrue(result.eligible.any { it.key == methodKey(setter) })
    }

    @Test
    fun `View property contract excludes no classes fields or boundary methods`() {
        val view = type("android/view/View", owned = false, superName = "java/lang/Object")
        val publicView = type(
            "com/example/PublicView",
            superName = view.internalName,
            fields = listOf(field("com/example/PublicView", "state")),
            methods = listOf(
                method("com/example/PublicView", "<init>", "()V"),
                method("com/example/PublicView", "calculate", "()V"),
                method("com/example/PublicView", "isVisible", "()Z"),
                method("com/example/PublicView", "setZero", "()V"),
                method("com/example/PublicView", "setPair", "(II)V"),
                method("com/example/PublicView", "getAt", "(I)Ljava/lang/Object;"),
            ),
        )
        val nonPublicView = type(
            "com/example/HiddenView",
            superName = view.internalName,
            methods = listOf(
                method("com/example/HiddenView", "setValue", "(I)V"),
                method("com/example/HiddenView", "getValue", "()I"),
            ),
            access = Opcodes.ACC_FINAL,
        )
        val nonView = type(
            "com/example/PlainOwner",
            methods = listOf(
                method("com/example/PlainOwner", "setValue", "(I)V"),
                method("com/example/PlainOwner", "getValue", "()I"),
            ),
        )

        val result = classify(listOf(publicView, nonPublicView, nonView), listOf(view, objectType()))

        assertTrue(viewPropertyExclusions(result).isEmpty())
        assertTrue(
            result.eligible.map { it.key }.containsAll(
                listOf(
                    classKey(publicView),
                ) + publicView.methods.filter { it.name != "<init>" }.map(::methodKey) +
                    nonPublicView.methods.map(::methodKey) + nonView.methods.map(::methodKey),
            ),
        )
        assertTrue(result.exclusions.any {
            it.key == fieldKey(publicView.fields.single()) &&
                it.reason == CodeExclusionReason.POTENTIAL_BEAN_INSTANCE_FIELD
        })
    }

    @Test
    fun `Gson JavaScript JNI and exported contracts resolve to exact owned symbols`() {
        val profile = type(
            "com/example/Profile",
            fields = listOf(field("com/example/Profile", "displayName"), field("com/example/Profile", "internalState")),
            methods = listOf(method("com/example/Profile", "send", "()V"), method("com/example/Profile", "nativeToken", "()Ljava/lang/String;", Opcodes.ACC_PUBLIC or Opcodes.ACC_NATIVE)),
        )
        val activity = type("com/example/PublicActivity", source = "PublicActivity.kt")
        val result = classify(
            listOf(profile, activity),
            listOf(objectType()),
            listOf(
                candidate(ExternalNameContractKind.GSON_UNEXPLICIT_FIELD, "Profile.kt", "displayName"),
                candidate(ExternalNameContractKind.JAVASCRIPT_INTERFACE, "Profile.kt", "send"),
                candidate(ExternalNameContractKind.JNI_NATIVE, "Profile.kt", "nativeToken"),
                candidate(ExternalNameContractKind.EXPORTED_COMPONENT, "AndroidManifest.xml", "com.example.PublicActivity"),
            ),
        )

        assertEquals(
            setOf(
                CodeExclusionReason.GSON_UNEXPLICIT_FIELD,
                CodeExclusionReason.JAVASCRIPT_INTERFACE,
                CodeExclusionReason.JNI_NATIVE,
                CodeExclusionReason.EXPORTED_COMPONENT,
                CodeExclusionReason.POTENTIAL_BEAN_INSTANCE_FIELD,
            ),
            result.exclusions.mapTo(sortedSetOf()) { it.reason },
        )
        assertTrue(result.exclusions.any { it.key.name == "Profile" && it.reason == CodeExclusionReason.JNI_NATIVE })
        assertTrue(result.exclusions.any {
            it.key.name == "internalState" && it.reason == CodeExclusionReason.POTENTIAL_BEAN_INSTANCE_FIELD
        })
    }

    @Test
    fun `external manifest component remains report-only without an app registry exclusion`() {
        val appActivity = type("com/example/AppActivity")
        val customTabActivity = type("com/facebook/CustomTabActivity", owned = false)
        val manifestComponent = ExternalNameCandidate(
            ExternalNameContractKind.EXPORTED_COMPONENT,
            "app/src/main/AndroidManifest.xml",
            1,
            "com.facebook.CustomTabActivity",
        )
        val sourceAudit = audit(candidates = listOf(manifestComponent))

        val result = classifier().classify(
            inventory(listOf(appActivity), listOf(customTabActivity, objectType())),
            sourceAudit,
        )

        assertEquals(listOf(manifestComponent), sourceAudit.externalNameCandidates)
        assertTrue(result.exclusions.none { it.reason == CodeExclusionReason.EXPORTED_COMPONENT })
        assertTrue(result.eligible.any { it.key.owner == appActivity.internalName })
    }

    @Test
    fun `owned manifest and layout classes exclude only their exact class keys while external candidates report only`() {
        val manifestOwner = type(
            "com/example/App",
            fields = listOf(field("com/example/App", "state")),
            methods = listOf(method("com/example/App", "start", "()V")),
        )
        val viewOwner = type(
            "com/example/CustomView",
            fields = listOf(field("com/example/CustomView", "color")),
            methods = listOf(method("com/example/CustomView", "render", "()V")),
        )
        val external = type("com/vendor/ExternalView", owned = false)
        val manifest = ExternalNameCandidate(
            ExternalNameContractKind.MANIFEST_DECLARED_CLASS,
            "app/src/main/AndroidManifest.xml",
            2,
            "com.example.App",
        )
        val repeatedManifest = ExternalNameCandidate(
            ExternalNameContractKind.MANIFEST_DECLARED_CLASS,
            "core/src/main/AndroidManifest.xml",
            8,
            "com.example.App",
        )
        val view = ExternalNameCandidate(
            ExternalNameContractKind.LAYOUT_CUSTOM_VIEW,
            "app/src/main/res/layout/main.xml",
            3,
            "com.example.CustomView",
        )
        val repeatedView = ExternalNameCandidate(
            ExternalNameContractKind.LAYOUT_CUSTOM_VIEW,
            "app/src/main/res/layout-land/main.xml",
            7,
            "com.example.CustomView",
        )
        val externalView = ExternalNameCandidate(
            ExternalNameContractKind.LAYOUT_CUSTOM_VIEW,
            "app/src/main/res/layout/main.xml",
            4,
            "com.vendor.ExternalView",
        )

        val bytecode = inventory(listOf(manifestOwner, viewOwner), listOf(external, objectType()))
        val candidates = listOf(repeatedManifest, manifest, repeatedView, view, externalView)
        val result = classifier().classify(bytecode, audit(candidates = candidates))
        val reordered = classifier().classify(bytecode, audit(candidates = candidates.reversed()))

        assertEquals(
            setOf(
                CodeExclusionReason.MANIFEST_DECLARED_CLASS to manifestOwner.internalName,
                CodeExclusionReason.POTENTIAL_BEAN_INSTANCE_FIELD to manifestOwner.internalName,
                CodeExclusionReason.LAYOUT_CUSTOM_VIEW to viewOwner.internalName,
                CodeExclusionReason.POTENTIAL_BEAN_INSTANCE_FIELD to viewOwner.internalName,
            ),
            result.exclusions.map { it.reason to it.key.owner }.toSet(),
        )
        assertEquals(4, result.exclusions.size)
        assertEquals(result, reordered)
        assertEquals(
            "MANIFEST_DECLARED_CLASS at app/src/main/AndroidManifest.xml:2: com.example.App",
            result.exclusions.single { it.reason == CodeExclusionReason.MANIFEST_DECLARED_CLASS }.evidence,
        )
        assertEquals(
            "LAYOUT_CUSTOM_VIEW at app/src/main/res/layout-land/main.xml:7: com.example.CustomView",
            result.exclusions.single { it.reason == CodeExclusionReason.LAYOUT_CUSTOM_VIEW }.evidence,
        )
        assertTrue(result.exclusions.any {
            it.key == fieldKey(manifestOwner.fields.single()) &&
                it.reason == CodeExclusionReason.POTENTIAL_BEAN_INSTANCE_FIELD
        })
        assertTrue(result.eligible.any { it.key == methodKey(manifestOwner.methods.single()) })
        assertTrue(result.exclusions.any {
            it.key == fieldKey(viewOwner.fields.single()) &&
                it.reason == CodeExclusionReason.POTENTIAL_BEAN_INSTANCE_FIELD
        })
        assertTrue(result.eligible.any { it.key == methodKey(viewOwner.methods.single()) })
    }

    @Test
    fun `Serializable and ObjectBox preserve schema classes and fields`() {
        val serial = type(
            "com/example/Session",
            fields = listOf(field("com/example/Session", "token")),
            methods = listOf(method("com/example/Session", "writeObject", "(Ljava/io/ObjectOutputStream;)V")),
        )
        val entity = type(
            "com/example/Gift",
            source = "Gift.kt",
            fields = listOf(field("com/example/Gift", "id"), field("com/example/Gift", "name")),
        )

        val result = classify(
            listOf(serial, entity),
            listOf(objectType()),
            listOf(
                candidate(ExternalNameContractKind.SERIALIZABLE, "Profile.kt", "Session"),
                candidate(ExternalNameContractKind.OBJECTBOX_ENTITY, "Gift.kt", "Gift"),
            ),
        )

        assertTrue(result.exclusions.filter { it.reason == CodeExclusionReason.SERIALIZABLE }.map { it.key.name }.containsAll(listOf("Session", "token", "writeObject")))
        assertTrue(result.exclusions.filter { it.reason == CodeExclusionReason.OBJECTBOX_ENTITY }.map { it.key.name }.containsAll(listOf("Gift", "id", "name")))
    }

    @Test
    fun `external synthetic bridge is distinguished from its implementation target`() {
        val factory = type(
            "third/Factory",
            owned = false,
            methods = listOf(method("third/Factory", "create", "()Ljava/lang/Object;", Opcodes.ACC_PUBLIC or Opcodes.ACC_ABSTRACT)),
        )
        val value = type("com/example/Value")
        val implementation = type(
            "com/example/FactoryImpl",
            source = "FactoryImpl.kt",
            interfaces = listOf(factory.internalName),
            methods = listOf(
                method("com/example/FactoryImpl", "create", "()Lcom/example/Value;"),
                method("com/example/FactoryImpl", "create", "()Ljava/lang/Object;", Opcodes.ACC_PUBLIC or Opcodes.ACC_BRIDGE or Opcodes.ACC_SYNTHETIC),
            ),
        )

        val result = classify(listOf(value, implementation), listOf(factory, objectType()))

        assertTrue(result.exclusions.any { it.key.descriptor == "()Ljava/lang/Object;" && it.reason == CodeExclusionReason.SYNTHETIC_BRIDGE_EXTERNAL })
        assertTrue(result.exclusions.any { it.key.descriptor == "()Lcom/example/Value;" && it.reason == CodeExclusionReason.EXTERNAL_OVERRIDE })
        assertFalse(result.eligible.any { it.key.name == "create" })
    }

    @Test
    fun `inherited implementation is excluded when a child introduces an external interface`() {
        val runnable = type(
            "third/Runnable",
            owned = false,
            methods = listOf(method("third/Runnable", "run", "()V", Opcodes.ACC_PUBLIC or Opcodes.ACC_ABSTRACT)),
        )
        val base = type("com/example/Base", source = "Base.kt", methods = listOf(method("com/example/Base", "run", "()V")))
        val child = type("com/example/Child", source = "Child.kt", superName = base.internalName, interfaces = listOf(runnable.internalName))

        val result = classify(listOf(base, child), listOf(runnable, objectType()))

        assertTrue(result.exclusions.any {
            it.key.owner == base.internalName && it.key.name == "run" && it.reason == CodeExclusionReason.EXTERNAL_OVERRIDE
        })
        assertFalse(result.eligible.any { it.key.owner == base.internalName && it.key.name == "run" })
    }

    @Test
    fun `overlapping exclusions retain every reason in stable precedence order`() {
        val runnable = type(
            "third/Runnable",
            owned = false,
            methods = listOf(method("third/Runnable", "run", "()V", Opcodes.ACC_PUBLIC or Opcodes.ACC_ABSTRACT)),
        )
        val owner = type(
            "com/example/Profile",
            interfaces = listOf(runnable.internalName),
            methods = listOf(method("com/example/Profile", "run", "()V")),
        )

        val result = classify(
            listOf(owner),
            listOf(runnable, objectType()),
            listOf(candidate(ExternalNameContractKind.JAVASCRIPT_INTERFACE, "Profile.kt", "run")),
        )

        assertEquals(
            listOf(CodeExclusionReason.EXTERNAL_OVERRIDE, CodeExclusionReason.JAVASCRIPT_INTERFACE),
            result.exclusions.filter { it.key.name == "run" }.map(CodeExclusion::reason),
        )
    }

    @Test
    fun `naming inventory collections are immutable value state`() {
        val key = CodeSymbolKey(CodeSymbolKind.FIELD, "com/example/Profile", "name", "Ljava/lang/String;")
        val eligibleValues = mutableListOf(EligibleCodeSymbol(key, null))
        val exclusionValues = mutableListOf(CodeExclusion(key, CodeExclusionReason.GSON_UNEXPLICIT_FIELD, "source"))
        val first = CodeNamingInventory(eligibleValues, exclusionValues)
        val equal = CodeNamingInventory(first.eligible, first.exclusions)
        eligibleValues.clear()
        exclusionValues.clear()

        assertEquals(1, first.eligible.size)
        assertEquals(1, first.exclusions.size)
        assertEquals(equal, first)
        assertEquals(equal.hashCode(), first.hashCode())
        assertFailsWith<UnsupportedOperationException> { (first.eligible as MutableList).clear() }
        assertFailsWith<UnsupportedOperationException> { (first.exclusions as MutableList).clear() }
    }

    @Test
    fun `classification is deterministic for bytecode and audit input permutations`() {
        val firstOwner = type(
            "com/example/First",
            source = "First.kt",
            fields = listOf(field("com/example/First", "wire"), field("com/example/First", "implementation")),
        )
        val secondOwner = type(
            "com/example/Second",
            source = "Second.kt",
            methods = listOf(method("com/example/Second", "send", "()V"), method("com/example/Second", "work", "()V")),
        )
        val objectType = objectType()
        val firstCandidates = listOf(
            candidate(ExternalNameContractKind.GSON_UNEXPLICIT_FIELD, "First.kt", "wire"),
            candidate(ExternalNameContractKind.JAVASCRIPT_INTERFACE, "Second.kt", "send"),
        )
        val firstOwnerPermuted = type(
            "com/example/First",
            source = "First.kt",
            fields = firstOwner.fields.reversed(),
        )
        val secondOwnerPermuted = type(
            "com/example/Second",
            source = "Second.kt",
            methods = secondOwner.methods.reversed(),
        )
        val firstBytecode = BytecodeInventory(
            linkedMapOf(firstOwner.internalName to firstOwner, secondOwner.internalName to secondOwner),
            linkedMapOf(firstOwner.internalName to firstOwner, secondOwner.internalName to secondOwner, objectType.internalName to objectType),
        )
        val secondBytecode = BytecodeInventory(
            linkedMapOf(
                secondOwnerPermuted.internalName to secondOwnerPermuted,
                firstOwnerPermuted.internalName to firstOwnerPermuted,
            ),
            linkedMapOf(
                objectType.internalName to objectType,
                secondOwnerPermuted.internalName to secondOwnerPermuted,
                firstOwnerPermuted.internalName to firstOwnerPermuted,
            ),
        )

        val first = classifier().classify(firstBytecode, audit(candidates = firstCandidates))
        val second = classifier().classify(secondBytecode, audit(candidates = firstCandidates.reversed()))

        assertEquals(first, second)
        assertEquals(first.hashCode(), second.hashCode())
    }

    @Test
    fun `resolved app reflection field remains protected by the Bean policy`() {
        val owner = type("com/example/Profile", fields = listOf(field("com/example/Profile", "displayName")))
        val audit = audit(
            resolved = listOf(ResolvedContract(ResolvedContractKind.FIELD, "app/src/main/java/com/example/Profile.kt", 3, "displayName", "Profile::class.java.getDeclaredField(\"displayName\")")),
        )

        val result = classifier().classify(inventory(listOf(owner), listOf(objectType())), audit)

        assertTrue(result.exclusions.any {
            it.key.name == "displayName" && it.reason == CodeExclusionReason.POTENTIAL_BEAN_INSTANCE_FIELD
        })
    }

    @Test
    fun `unresolved app reflection fails closed while resource lookup does not masquerade as reflection`() {
        val owner = type("com/example/Profile")
        val appFailure = assertFailsWith<IllegalArgumentException> {
            classifier().classify(
                inventory(listOf(owner), listOf(objectType())),
                audit(unresolved = listOf(UnresolvedContract(UnresolvedContractKind.APP_REFLECTION, "Profile.kt", 7, "getMethod(name)", "dynamic name"))),
            )
        }
        assertTrue(appFailure.message.orEmpty().contains("Profile.kt"))

        val result = classifier().classify(
            inventory(listOf(owner), listOf(objectType())),
            audit(unresolved = listOf(UnresolvedContract(UnresolvedContractKind.RESOURCE_LOOKUP, "Profile.kt", 8, "getIdentifier(name)", "dynamic resource"))),
        )
        assertTrue(result.eligible.any { it.key.name == "Profile" })
    }

    @Test
    fun `unique Gson field with exact owned source proof is preserved`() {
        val owner = type("com/example/Profile", fields = listOf(field("com/example/Profile", "value")))

        val result = classifier().classify(
            inventory(listOf(owner), listOf(objectType())),
            audit(candidates = listOf(candidate(ExternalNameContractKind.GSON_UNEXPLICIT_FIELD, "Profile.kt", "value"))),
        )

        assertEquals(
            listOf("value"),
            result.exclusions.filter { it.reason == CodeExclusionReason.GSON_UNEXPLICIT_FIELD }.map { it.key.name },
        )
    }

    @Test
    fun `Gson candidate without a physical field remains report only with exact owned source proof`() {
        val owner = type("com/example/MyJsBridge", source = "MyJsBridge.kt")
        val sourceCandidate = candidate(ExternalNameContractKind.GSON_UNEXPLICIT_FIELD, "MyJsBridge.kt", "commonJsBridgeBean")
        val sourceAudit = audit(candidates = listOf(sourceCandidate))

        val result = classifier().classify(inventory(listOf(owner), listOf(objectType())), sourceAudit)

        assertEquals(listOf(sourceCandidate), sourceAudit.externalNameCandidates)
        assertTrue(result.exclusions.none { it.reason == CodeExclusionReason.GSON_UNEXPLICIT_FIELD })
    }

    @Test
    fun `Gson candidate without exact owned source proof fails closed`() {
        val owner = type("com/example/Profile", source = "Profile.kt")

        val failure = assertFailsWith<IllegalArgumentException> {
            classifier().classify(
                inventory(listOf(owner), listOf(objectType())),
                audit(candidates = listOf(candidate(ExternalNameContractKind.GSON_UNEXPLICIT_FIELD, "Missing.kt", "value"))),
            )
        }

        assertTrue(failure.message.orEmpty().contains("source proof"))
    }

    @Test
    fun `Gson candidate matching an unproven owned module hierarchy field fails closed`() {
        val proven = type("com/example/MyJsBridge", source = "MyJsBridge.kt")
        val unproven = unprovenType(
            "com/example/MyJsBridge${'$'}Injected",
            source = "MyJsBridge.kt",
            fields = listOf(field("com/example/MyJsBridge${'$'}Injected", "commonJsBridgeBean")),
        )

        val failure = assertFailsWith<IllegalArgumentException> {
            classifier().classify(
                inventory(listOf(proven), listOf(unproven, objectType())),
                audit(candidates = listOf(candidate(ExternalNameContractKind.GSON_UNEXPLICIT_FIELD, "MyJsBridge.kt", "commonJsBridgeBean"))),
            )
        }

        assertTrue(failure.message.orEmpty().contains("unproven owned-module bytecode"))
    }

    @Test
    fun `unproven hierarchy without a correlated same name field does not contaminate Gson source proof`() {
        val proven = type("com/example/MyJsBridge", source = "MyJsBridge.kt")
        val otherField = unprovenType(
            "com/example/MyJsBridge${'$'}Synthetic",
            source = "MyJsBridge.kt",
            fields = listOf(field("com/example/MyJsBridge${'$'}Synthetic", "syntheticState")),
        )
        val otherModule = unprovenType(
            "com/example/BaseBridge",
            modulePath = ":core",
            source = "MyJsBridge.kt",
            fields = listOf(field("com/example/BaseBridge", "commonJsBridgeBean")),
        )
        val otherSource = unprovenType(
            "com/example/OtherBridge",
            source = "OtherBridge.kt",
            fields = listOf(field("com/example/OtherBridge", "commonJsBridgeBean")),
        )

        val result = classifier().classify(
            inventory(listOf(proven), listOf(otherField, otherModule, otherSource, objectType())),
            audit(candidates = listOf(candidate(ExternalNameContractKind.GSON_UNEXPLICIT_FIELD, "MyJsBridge.kt", "commonJsBridgeBean"))),
        )

        assertTrue(result.exclusions.none { it.reason == CodeExclusionReason.GSON_UNEXPLICIT_FIELD })
    }

    @Test
    fun `unproven hierarchy class reports only its class while remaining hierarchy-only`() {
        val proven = type(
            "com/example/Proven",
            source = "Shared.kt",
            fields = listOf(field("com/example/Proven", "ownedValue")),
            methods = listOf(method("com/example/Proven", "ownedCall", "()V")),
        )
        val unproven = unprovenType(
            "com/example/Unproven",
            source = "Shared.kt",
            fields = listOf(
                field("com/example/Unproven", "jsonValue"),
                field("com/example/Unproven", "otherValue"),
            ),
            methods = listOf(
                method("com/example/Unproven", "firstCall", "()V"),
                method("com/example/Unproven", "secondCall", "(I)V"),
            ),
        )
        val bytecode = inventory(listOf(proven), listOf(unproven, objectType()))

        val classified = classifier().classify(bytecode, audit())

        assertEquals(
            listOf(classKey(unproven)),
            classified.exclusions.filter { it.reason == CodeExclusionReason.UNPROVEN_SOURCE }.map(CodeExclusion::key),
        )
        assertTrue(classified.eligible.none { it.key.owner == unproven.internalName })
        assertEquals(unproven.fields, bytecode.hierarchyClasses.getValue(unproven.internalName).fields)
        assertEquals(unproven.methods, bytecode.hierarchyClasses.getValue(unproven.internalName).methods)
        assertTrue(classified.eligible.map(EligibleCodeSymbol::key).containsAll(listOf(
            classKey(proven),
            methodKey(proven.methods.single()),
        )))
        assertTrue(classified.exclusions.any {
            it.key == fieldKey(proven.fields.single()) &&
                it.reason == CodeExclusionReason.POTENTIAL_BEAN_INSTANCE_FIELD
        })

        val gsonFailure = assertFailsWith<IllegalArgumentException> {
            classifier().classify(
                bytecode,
                audit(candidates = listOf(candidate(ExternalNameContractKind.GSON_UNEXPLICIT_FIELD, "Shared.kt", "jsonValue"))),
            )
        }
        assertTrue(gsonFailure.message.orEmpty().contains("unproven owned-module bytecode"))

        val plan = CodeNameAllocator(PseudowordRegistry(ByteArray(32))).allocate(classified, bytecode, generation = 1)
        assertTrue(plan.assignments.none { it.key.owner == unproven.internalName })
        assertTrue(plan.registry.assignments.none { unproven.internalName in it.key.originalIdentity })
        val manifest = CodeNamingManifest(
            schemaVersion = 1,
            variant = "demoDebug",
            generation = 1,
            ownedModules = setOf(":app", ":core", ":compress", ":selector", ":ucrop"),
            mappingSha256 = "a".repeat(64),
            registrySha256 = "b".repeat(64),
            expectedSymbols = plan.assignments,
            exclusions = plan.exclusions,
        )
        val decoded = CodeNamingManifestCodec().decode(CodeNamingManifestCodec().encode(manifest))

        assertEquals(listOf(classKey(unproven)), decoded.exclusions.filter { it.reason == CodeExclusionReason.UNPROVEN_SOURCE }.map(CodeExclusion::key))
        assertTrue(decoded.expectedSymbols.none { it.key.owner == unproven.internalName })
    }

    @Test
    fun `every exact owned Gson field from one proven source is preserved`() {
        val first = type(
            "com/example/Gift",
            source = "Gift.kt",
            fields = listOf(field("com/example/Gift", "app_gift_uuid")),
        )
        val second = type(
            "com/example/SendGiftResultData",
            source = "Gift.kt",
            fields = listOf(field("com/example/SendGiftResultData", "app_gift_uuid")),
        )
        val bytecode = inventory(listOf(first, second), listOf(objectType()))

        val result = classifier().classify(
            bytecode,
            audit(candidates = listOf(candidate(ExternalNameContractKind.GSON_UNEXPLICIT_FIELD, "Gift.kt", "app_gift_uuid"))),
        )

        assertEquals(
            listOf(
                CodeSymbolKey(CodeSymbolKind.FIELD, "com/example/Gift", "app_gift_uuid", "Ljava/lang/Object;"),
                CodeSymbolKey(CodeSymbolKind.FIELD, "com/example/SendGiftResultData", "app_gift_uuid", "Ljava/lang/Object;"),
            ),
            result.exclusions.filter { it.reason == CodeExclusionReason.GSON_UNEXPLICIT_FIELD }.map(CodeExclusion::key),
        )
    }

    @Test
    fun `non Gson candidate resolving to multiple owned symbols fails closed`() {
        val first = type("com/example/First", methods = listOf(method("com/example/First", "send", "()V")))
        val second = type("com/example/Second", methods = listOf(method("com/example/Second", "send", "()V")))

        val failure = assertFailsWith<IllegalArgumentException> {
            classifier().classify(
                inventory(listOf(first, second), listOf(objectType())),
                audit(candidates = listOf(candidate(ExternalNameContractKind.JAVASCRIPT_INTERFACE, "Profile.kt", "send"))),
            )
        }

        assertTrue(failure.message.orEmpty().contains("multiple owned symbols"))
    }

    @Test
    fun `platform and generated reflection evidence does not rename its owned caller`() {
        val owner = type("com/example/ReflectionHelper", source = "ReflectionHelper.kt", methods = listOf(method("com/example/ReflectionHelper", "inspect", "()V")))

        val result = classify(
            listOf(owner),
            listOf(objectType()),
            listOf(
                candidate(ExternalNameContractKind.PLATFORM_REFLECTION, "ReflectionHelper.kt", "Class.forName(\"android.app.Activity\")"),
                candidate(ExternalNameContractKind.GENERATED_VIEW_BINDING_REFLECTION, "ReflectionHelper.kt", "binding.getDeclaredMethod(\"inflate\")"),
                candidate(ExternalNameContractKind.PLATFORM_RESOURCE_LOOKUP, "ReflectionHelper.kt", "android:dimen/status_bar_height"),
            ),
        )

        assertTrue(result.eligible.any { it.key.name == "inspect" })
        assertTrue(result.exclusions.none { it.reason == CodeExclusionReason.PLATFORM_REFLECTION || it.reason == CodeExclusionReason.GENERATED_VIEW_BINDING_REFLECTION })
    }

    @Test
    fun `exact external keep contracts preserve only their proven owned symbols`() {
        val layoutManager = type("androidx/recyclerview/widget/RecyclerView\$LayoutManager", owned = false)
        val layoutManagerIntermediate = type(
            "external/IntermediateLayoutManager",
            owned = false,
            superName = layoutManager.internalName,
        )
        val nearLayoutManager = type("androidx/recyclerview/widget/RecyclerView\$LayoutManagers", owned = false)
        val layoutOwners = listOf(
            type(
                "com/example/NamedLayoutManager",
                superName = layoutManager.internalName,
                fields = listOf(field("com/example/NamedLayoutManager", "state")),
                methods = listOf(method("com/example/NamedLayoutManager", "arrange", "()V")),
            ),
            type("com/example/OtherLayoutManager", superName = layoutManager.internalName),
            type("com/example/TransitiveLayoutManager", superName = layoutManagerIntermediate.internalName),
            type("com/example/Screen\$layoutManager\$1", superName = layoutManager.internalName),
            type("com/example/Screen\$layoutManager\$2", superName = layoutManagerIntermediate.internalName),
            type("com/example/Screen\$layoutManager\$3", superName = layoutManager.internalName),
            type("com/example/Screen\$layoutManager\$4", superName = layoutManagerIntermediate.internalName),
        )
        val nonPublicLayoutManager = type(
            "com/example/InternalLayoutManager",
            superName = layoutManager.internalName,
            access = Opcodes.ACC_PRIVATE,
        )
        val missingLayoutManager = type("com/example/MissingLayoutManager", superName = "external/MissingLayoutManager")
        val nearLayoutManagerOwner = type("com/example/NearLayoutManager", superName = nearLayoutManager.internalName)

        val interceptor = type(
            "com/wyjson/router/interfaces/IInterceptor",
            owned = false,
            interfaces = emptyList(),
            methods = listOf(method("com/wyjson/router/interfaces/IInterceptor", "intercept", "()V", Opcodes.ACC_PUBLIC or Opcodes.ACC_ABSTRACT)),
        )
        val interceptorChild = type(
            "external/CustomInterceptor",
            owned = false,
            interfaces = listOf(interceptor.internalName),
        )
        val service = type("com/wyjson/router/interfaces/IService", owned = false)
        val serviceChild = type("external/CustomService", owned = false, interfaces = listOf(service.internalName))
        val nearRouterInterface = type("com/wyjson/router/interfaces/IInterceptors", owned = false)
        val directInterceptor = type(
            "com/example/DirectInterceptor",
            interfaces = listOf(interceptor.internalName),
            fields = listOf(field("com/example/DirectInterceptor", "state")),
            methods = listOf(
                method("com/example/DirectInterceptor", "intercept", "()V"),
                method("com/example/DirectInterceptor", "ordinary", "()V"),
            ),
        )
        val transitiveInterceptor = type("com/example/TransitiveInterceptor", interfaces = listOf(interceptorChild.internalName))
        val directService = type("com/example/DirectService", interfaces = listOf(service.internalName))
        val transitiveService = type("com/example/TransitiveService", interfaces = listOf(serviceChild.internalName))
        val nearRouterOwner = type("com/example/NearRouter", interfaces = listOf(nearRouterInterface.internalName))

        val paramOwner = type(
            "com/example/RouteArguments",
            fields = listOf(
                field("com/example/RouteArguments", "route", setOf("Lcom/wyjson/router/annotation/Param;")),
                field("com/example/RouteArguments", "near", setOf("Lcom/wyjson/router/annotation/Params;")),
                field("com/example/RouteArguments", "plain"),
            ),
        )

        val androidStartup = type("com/rousetime/android_startup/AndroidStartup", owned = false)
        val startupIntermediate = type(
            "external/IntermediateStartup",
            owned = false,
            superName = androidStartup.internalName,
        )
        val providerConfig = type("com/rousetime/android_startup/provider/StartupProviderConfig", owned = false)
        val providerConfigChild = type(
            "external/CustomStartupProviderConfig",
            owned = false,
            interfaces = listOf(providerConfig.internalName),
        )
        val nearAndroidStartup = type("com/rousetime/android_startup/AndroidStartups", owned = false)
        val directStartup = type(
            "com/example/DirectStartup",
            superName = androidStartup.internalName,
            fields = listOf(field("com/example/DirectStartup", "state")),
            methods = listOf(
                method("com/example/DirectStartup", "<init>", "()V"),
                method("com/example/DirectStartup", "create", "()V"),
            ),
        )
        val transitiveStartup = type(
            "com/example/TransitiveStartup",
            superName = startupIntermediate.internalName,
            fields = listOf(field("com/example/TransitiveStartup", "state")),
            methods = listOf(method("com/example/TransitiveStartup", "create", "()V")),
        )
        val directProvider = type(
            "com/example/DirectStartupProvider",
            interfaces = listOf(providerConfig.internalName),
            fields = listOf(field("com/example/DirectStartupProvider", "state")),
            methods = listOf(method("com/example/DirectStartupProvider", "create", "()V")),
        )
        val transitiveProvider = type(
            "com/example/TransitiveStartupProvider",
            interfaces = listOf(providerConfigChild.internalName),
            fields = listOf(field("com/example/TransitiveStartupProvider", "state")),
            methods = listOf(method("com/example/TransitiveStartupProvider", "create", "()V")),
        )
        val nonPublicStartup = type(
            "com/example/InternalStartup",
            superName = androidStartup.internalName,
            access = Opcodes.ACC_PRIVATE,
        )
        val missingStartup = type("com/example/MissingStartup", superName = "external/MissingStartup")
        val nearStartup = type("com/example/NearStartup", superName = nearAndroidStartup.internalName)

        val result = classifier().classify(
            inventory(
                layoutOwners + listOf(
                    nonPublicLayoutManager,
                    missingLayoutManager,
                    nearLayoutManagerOwner,
                    directInterceptor,
                    transitiveInterceptor,
                    directService,
                    transitiveService,
                    nearRouterOwner,
                    paramOwner,
                    directStartup,
                    transitiveStartup,
                    directProvider,
                    transitiveProvider,
                    nonPublicStartup,
                    missingStartup,
                    nearStartup,
                ),
                listOf(
                    layoutManager,
                    layoutManagerIntermediate,
                    nearLayoutManager,
                    interceptor,
                    interceptorChild,
                    service,
                    serviceChild,
                    nearRouterInterface,
                    androidStartup,
                    startupIntermediate,
                    providerConfig,
                    providerConfigChild,
                    nearAndroidStartup,
                    objectType(),
                ),
            ),
            audit(),
        )

        val layoutKeys = layoutOwners.map(::classKey).toSet()
        assertEquals(layoutKeys, result.exclusions.filter { it.reason.name == "RECYCLERVIEW_LAYOUT_MANAGER_KEEP_RULE" }.map(CodeExclusion::key).toSet())
        assertTrue(result.eligible.none { it.key in layoutKeys })
        assertTrue(result.exclusions.any {
            it.key == fieldKey(layoutOwners.first().fields.single()) &&
                it.reason == CodeExclusionReason.POTENTIAL_BEAN_INSTANCE_FIELD
        })
        assertTrue(result.eligible.any { it.key == methodKey(layoutOwners.first().methods.single()) })
        assertTrue(
            listOf(nonPublicLayoutManager, missingLayoutManager, nearLayoutManagerOwner)
                .all { owner -> result.eligible.any { it.key == classKey(owner) } },
        )

        val routerKeys = setOf(classKey(directInterceptor), classKey(transitiveInterceptor), classKey(directService), classKey(transitiveService))
        assertEquals(routerKeys, result.exclusions.filter { it.reason.name == "GOROUTER_COMPONENT_KEEP_RULE" }.map(CodeExclusion::key).toSet())
        assertTrue(result.eligible.none { it.key in routerKeys })
        assertTrue(result.exclusions.any {
            it.key == fieldKey(directInterceptor.fields.single()) &&
                it.reason == CodeExclusionReason.POTENTIAL_BEAN_INSTANCE_FIELD
        })
        assertTrue(result.eligible.any { it.key == methodKey(directInterceptor.methods.single { it.name == "ordinary" }) })
        assertTrue(result.eligible.any { it.key == classKey(nearRouterOwner) })
        assertTrue(result.exclusions.any { it.key == methodKey(directInterceptor.methods.first()) && it.reason == CodeExclusionReason.EXTERNAL_OVERRIDE })

        assertEquals(
            setOf(fieldKey(paramOwner.fields.first())),
            result.exclusions.filter { it.reason.name == "GOROUTER_PARAM_FIELD_KEEP_RULE" }.map(CodeExclusion::key).toSet(),
        )
        assertTrue(paramOwner.fields.drop(1).all { field ->
            result.exclusions.any {
                it.key == fieldKey(field) && it.reason == CodeExclusionReason.POTENTIAL_BEAN_INSTANCE_FIELD
            }
        })

        val startupOwners = setOf(directStartup, transitiveStartup, directProvider, transitiveProvider)
        val startupKeys = startupOwners.flatMap(::symbolsForTest).toSet()
        assertEquals(startupKeys, result.exclusions.filter { it.reason.name == "ANDROID_STARTUP_KEEP_RULE" }.map(CodeExclusion::key).toSet())
        assertTrue(result.eligible.none { it.key in startupKeys })
        assertTrue(
            listOf(nonPublicStartup, missingStartup, nearStartup)
                .all { owner -> result.eligible.any { it.key == classKey(owner) } },
        )
        assertTrue(result.exclusions.any { it.key == methodKey(directStartup.methods.first()) && it.reason == CodeExclusionReason.CONSTRUCTOR })
        assertEquals(result.exclusions.distinct().size, result.exclusions.size)
    }

    @Test
    fun `external keep hierarchy traversal fails closed for missing nodes and cycles`() {
        val cyclicSuperclassFirst = type(
            "external/CyclicSuperclassFirst",
            owned = false,
            superName = "external/CyclicSuperclassSecond",
        )
        val cyclicSuperclassSecond = type(
            "external/CyclicSuperclassSecond",
            owned = false,
            superName = cyclicSuperclassFirst.internalName,
        )
        val cyclicInterfaceFirst = type(
            "external/CyclicInterfaceFirst",
            owned = false,
            interfaces = listOf("external/CyclicInterfaceSecond"),
        )
        val cyclicInterfaceSecond = type(
            "external/CyclicInterfaceSecond",
            owned = false,
            interfaces = listOf(cyclicInterfaceFirst.internalName),
        )
        val missingRouterIntermediate = type(
            "external/MissingRouterIntermediate",
            owned = false,
            interfaces = listOf("com/wyjson/router/interfaces/IService"),
        )
        val missingStartupIntermediate = type(
            "external/MissingStartupIntermediate",
            owned = false,
            interfaces = listOf("com/rousetime/android_startup/provider/StartupProviderConfig"),
        )
        val cyclicSuperclassOwner = type("com/example/CyclicSuperclassOwner", superName = cyclicSuperclassFirst.internalName)
        val cyclicInterfaceOwner = type("com/example/CyclicInterfaceOwner", interfaces = listOf(cyclicInterfaceFirst.internalName))
        val missingDirectRouter = type("com/example/MissingDirectRouter", interfaces = listOf("com/wyjson/router/interfaces/IInterceptor"))
        val missingTransitiveRouter = type("com/example/MissingTransitiveRouter", interfaces = listOf(missingRouterIntermediate.internalName))
        val missingDirectStartupProvider = type(
            "com/example/MissingDirectStartupProvider",
            interfaces = listOf("com/rousetime/android_startup/provider/StartupProviderConfig"),
        )
        val missingTransitiveStartupProvider = type(
            "com/example/MissingTransitiveStartupProvider",
            interfaces = listOf(missingStartupIntermediate.internalName),
        )
        val owners = listOf(
            cyclicSuperclassOwner,
            cyclicInterfaceOwner,
            missingDirectRouter,
            missingTransitiveRouter,
            missingDirectStartupProvider,
            missingTransitiveStartupProvider,
        )

        val result = classifier().classify(
            inventory(
                owners,
                listOf(
                    cyclicSuperclassFirst,
                    cyclicSuperclassSecond,
                    cyclicInterfaceFirst,
                    cyclicInterfaceSecond,
                    missingRouterIntermediate,
                    missingStartupIntermediate,
                    objectType(),
                ),
            ),
            audit(),
        )

        val externalKeepReasons = setOf(
            "GOROUTER_COMPONENT_KEEP_RULE",
            "RECYCLERVIEW_LAYOUT_MANAGER_KEEP_RULE",
            "COORDINATOR_LAYOUT_BEHAVIOR_KEEP_RULE",
            "ANDROID_STARTUP_KEEP_RULE",
        )
        val ownerKeys = owners.map(::classKey).toSet()
        assertTrue(ownerKeys.all { key -> result.eligible.any { it.key == key } })
        assertTrue(result.exclusions.none { it.key in ownerKeys && it.reason.name in externalKeepReasons })
    }

    @Test
    fun `coordinator behavior consumer rule preserves public owned class names transitively`() {
        val coordinatorBehavior = type(
            "androidx/coordinatorlayout/widget/CoordinatorLayout\$Behavior",
            "Profile.kt",
            false,
        )
        val appBarBehavior = type(
            "com/google/android/material/appbar/AppBarLayout\$Behavior",
            "Profile.kt",
            false,
            coordinatorBehavior.internalName,
        )
        val direct = type(
            "com/example/DirectBehavior",
            "DirectBehavior.kt",
            true,
            coordinatorBehavior.internalName,
        )
        val transitive = type(
            "com/example/TransitiveBehavior",
            "TransitiveBehavior.kt",
            true,
            appBarBehavior.internalName,
        )

        val result = classifier().classify(
            inventory(
                listOf(direct, transitive),
                listOf(coordinatorBehavior, appBarBehavior, objectType()),
            ),
            audit(),
        )

        val expected = setOf(classKey(direct), classKey(transitive))
        assertEquals(
            expected,
            result.exclusions
                .filter { it.reason.name == "COORDINATOR_LAYOUT_BEHAVIOR_KEEP_RULE" }
                .map(CodeExclusion::key)
                .toSet(),
        )
        assertTrue(result.eligible.none { it.key in expected })
    }

    private fun classify(
        owned: List<BytecodeClass>,
        external: List<BytecodeClass>,
        candidates: List<ExternalNameCandidate> = emptyList(),
    ) = classifier().classify(inventory(owned, external), audit(candidates = candidates))

    private fun classifier() = OwnedCodeContractClassifier()

    private fun viewPropertyExclusions(result: CodeNamingInventory) =
        result.exclusions.filter { it.reason.name == "ANDROID_VIEW_PROPERTY" }

    private fun inventory(owned: List<BytecodeClass>, external: List<BytecodeClass>): BytecodeInventory {
        val all = (owned + external).associateBy(BytecodeClass::internalName)
        return BytecodeInventory(owned.associateBy(BytecodeClass::internalName), all)
    }

    private fun audit(
        resolved: List<ResolvedContract> = emptyList(),
        unresolved: List<UnresolvedContract> = emptyList(),
        candidates: List<ExternalNameCandidate> = emptyList(),
        findings: List<HardcodedReferenceFinding> = emptyList(),
    ) = HardeningSourceAudit(
        emptyList(),
        resolved,
        unresolved,
        candidates,
        emptyList(),
        emptyList(),
        findings,
        emptyList(),
    )

    private fun candidate(kind: ExternalNameContractKind, source: String, symbol: String) =
        ExternalNameCandidate(kind, "app/src/main/java/com/example/$source", 1, symbol)

    private fun type(
        name: String,
        source: String = "Profile.kt",
        owned: Boolean = true,
        superName: String? = "java/lang/Object",
        interfaces: List<String> = emptyList(),
        fields: List<BytecodeField> = emptyList(),
        methods: List<BytecodeMethod> = emptyList(),
        access: Int = Opcodes.ACC_PUBLIC,
    ) = BytecodeClass(
        name,
        if (owned) ":app" else null,
        source,
        if (owned) Path.of("/repo/app/src/main/java/com/example/$source") else null,
        access,
        superName,
        interfaces,
        emptySet(),
        fields,
        methods,
    )

    private fun objectType() = type("java/lang/Object", owned = false, superName = null)
    private fun unprovenType(
        name: String,
        modulePath: String = ":app",
        source: String,
        fields: List<BytecodeField>,
        methods: List<BytecodeMethod> = emptyList(),
    ) = BytecodeClass(
        name,
        modulePath,
        source,
        Path.of("/repo/app/build/intermediates/javac/debug/classes/$name.class"),
        Opcodes.ACC_PUBLIC,
        "java/lang/Object",
        emptyList(),
        emptySet(),
        fields,
        methods,
    )
    private fun symbolsForTest(owner: BytecodeClass) =
        listOf(classKey(owner)) + owner.fields.map(::fieldKey) + owner.methods.map(::methodKey)

    private fun field(owner: String, name: String, annotations: Set<String> = emptySet()) =
        BytecodeField(owner, name, "Ljava/lang/Object;", Opcodes.ACC_PRIVATE, annotations)
    private fun exactField(owner: String, name: String, descriptor: String) =
        BytecodeField(owner, name, descriptor, Opcodes.ACC_PRIVATE, emptySet())
    private fun method(owner: String, name: String, descriptor: String, access: Int = Opcodes.ACC_PUBLIC) =
        BytecodeMethod(owner, name, descriptor, access, emptySet())
}
