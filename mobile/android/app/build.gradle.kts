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
        versionCode = 1
        versionName = "0.1.0-testnet"
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
        val gate = file("src/main/java/network/budlum/validator/core/MobileCoreBridge.kt").readText()
        if ("readyForDuties(): Boolean = false" in gate) {
            throw org.gradle.api.GradleException(
                "Refusing validator release while owner registration and duty transport are unconnected"
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

    testImplementation("junit:junit:4.13.2")
    // Android's org.json API is stubbed in local JVM unit tests.
    testImplementation("org.json:json:20240303")
    androidTestImplementation("androidx.test.ext:junit:1.2.1")
    androidTestImplementation("androidx.work:work-testing:2.10.0")
}
