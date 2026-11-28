plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.compose")
}

android {
    namespace = "network.budlum.validator"
    compileSdk = 36

    // Pin NDK version for deterministic cargo-ndk builds of budlum-mobile-core.
    ndkVersion = "27.2.12479018"

    defaultConfig {
        applicationId = "network.budlum.validator"
        minSdk = 29
        targetSdk = 36
        // Goes up with every build the owner is given, so Android can
        // tell a newer one from an older one. The name is what the
        // release is called on GitHub.
        versionCode = 17
        versionName = "0.17"
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"

        ndk {
            abiFilters += listOf("arm64-v8a", "x86_64")
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            isCrunchPngs = false
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
    }

    buildFeatures {
        compose = true
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = "17"
    }

    packaging {
        jniLibs {
            useLegacyPackaging = false
        }
        resources {
            excludes += "/META-INF/{AL2.0,LGPL2.1}"
        }
    }

    // The pure Kotlin field-log formatter is a host-JVM test fixture, not an
    // Android runtime class. Make it available to both JUnit and the local
    // command-line safety specification without copying it into the APK.
    sourceSets.getByName("test").java.srcDir("../devicetests")

    // F-Droid reproducible builds require omitting Play's encrypted dependency blob.
    dependenciesInfo {
        includeInApk = false
        includeInBundle = false
    }
}

// The debug UI may submit a bounded faucet request and read untrusted RPC
// responses, but cannot sign, stake or start validator duties. A distributable
// validator release must not omit its owner-proof API or native libraries.
// This gate currently refuses release: the wallet signer, registration proof,
// and live duty transport have not been integrated into Android yet.
val checkNativeValidatorRelease by tasks.registering {
    group = "verification"
    doLast {
        val required = listOf(
            "src/main/java/network/budlum/validator/core/budlum_mobile_ffi.kt",
            "src/main/java/network/budlum/validator/core/NativeValidatorGateway.kt",
            "src/main/jniLibs/arm64-v8a/libbudlum_mobile_ffi.so",
            "src/main/jniLibs/x86_64/libbudlum_mobile_ffi.so",
        )
        val missing = required.filterNot { file(it).isFile }
        if (missing.isNotEmpty()) {
            throw org.gradle.api.GradleException(
                "Refusing validator release without generated UniFFI bindings, a production gateway, " +
                    "and native libraries: ${missing.joinToString()}"
            )
        }
        // The gate was the literal `= false` and this looked for that
        // spelling. It is now computed from a list of what is still
        // missing, so what is looked for is a list with nothing left on
        // it - the condition, not the characters.
        val gate = file("src/main/java/network/budlum/validator/core/MobileCoreBridge.kt").readText()
        // Spelled once, here, and escaped into the pattern. Written twice
        // it drifts: the safety specification looks for this exact name in
        // this file to prove the release check still consults the gate, and
        // a pattern that spelled the name with escapes did not contain the
        // name it was matching.
        val gateFunction = "missingPieces()"
        val stillMissing = Regex("fun " + Regex.escape(gateFunction) + """: List<String> = listOf\(([^)]*)\)""")
            .find(gate)
            ?.groupValues
            ?.get(1)
            ?.trim()
            ?.trimEnd(',')
            ?: throw org.gradle.api.GradleException(
                "Cannot find the onboarding gate's list of what is missing"
            )
        if (stillMissing.isNotEmpty()) {
            throw org.gradle.api.GradleException(
                "Refusing validator release while these are unconnected: $stillMissing"
            )
        }
    }
}

tasks.matching { it.name == "preReleaseBuild" }.configureEach {
    dependsOn(checkNativeValidatorRelease)
}

tasks.withType<org.gradle.api.tasks.bundling.AbstractArchiveTask>().configureEach {
    isPreserveFileTimestamps = false
    isReproducibleFileOrder = true
}

// The safety specification checks repository source and F-Droid metadata.
// Gradle otherwise runs JUnit from mobile/android/app, where those paths do
// not resolve. This is a test-only working directory, never an APK input.
tasks.withType<org.gradle.api.tasks.testing.Test>().configureEach {
    workingDir = rootProject.projectDir.parentFile.parentFile
    // A failing safety check says which check failed in its message. The
    // default console shows only the exception class, which told a reader
    // that something in a seventeen-part specification broke and nothing
    // more. Print the message and whatever the test wrote on its way there.
    testLogging {
        events("failed")
        exceptionFormat = org.gradle.api.tasks.testing.logging.TestExceptionFormat.FULL
        showStandardStreams = true
    }
}

// Zero third-party analytics, tracking, or remote crash SDKs (Section 7.9 /).
dependencies {
    val composeBom = platform("androidx.compose:compose-bom:2024.10.01")
    implementation(composeBom)
    implementation("androidx.core:core-ktx:1.15.0")
    implementation("androidx.activity:activity-compose:1.9.3")
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.8.7")
    implementation("androidx.work:work-runtime-ktx:2.10.0")
    implementation("androidx.biometric:biometric:1.1.0")
    implementation("net.java.dev.jna:jna:5.15.0@aar")
    // Section 2.5 draws a QR and section 2.6 reads one. zxing core is the
    // encoder and decoder only: no activity, no camera code of its own.
    implementation("com.google.zxing:core:3.5.3")
    implementation("androidx.camera:camera-camera2:1.4.0")
    implementation("androidx.camera:camera-lifecycle:1.4.0")
    implementation("androidx.camera:camera-view:1.4.0")

    testImplementation("junit:junit:4.13.2")
    // Android's org.json API is stubbed in local JVM unit tests.
    testImplementation("org.json:json:20240303")
    // Measured on run 44982930517: the emulator booted, then
    // connectedDebugAndroidTest reported "Starting 0 tests" and crashed with
    // "ClassNotFoundException: Didn't find class
    // androidx.test.runner.AndroidJUnitRunner". The instrumentation runner
    // named in defaultConfig lives in androidx.test:runner, and the POM of
    // androidx.test.ext:junit:1.2.1 lists annotation, storage, core, monitor,
    // junit and kotlin-stdlib but not runner, so the test APK shipped without
    // the class the manifest asked it to load.
    androidTestImplementation("androidx.test:runner:1.6.2")
    androidTestImplementation("androidx.test.ext:junit:1.2.1")
    androidTestImplementation("androidx.work:work-testing:2.10.0")
}
