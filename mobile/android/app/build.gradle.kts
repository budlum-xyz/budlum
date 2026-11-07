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

    // F-Droid reproducible builds require omitting Play's encrypted dependency blob (WP-58).
    dependenciesInfo {
        includeInApk = false
        includeInBundle = false
    }
}

tasks.withType<org.gradle.api.tasks.bundling.AbstractArchiveTask>().configureEach {
    isPreserveFileTimestamps = false
    isReproducibleFileOrder = true
}

// Zero third-party analytics, tracking, or remote crash SDKs (Section 7.9 / WP-36).
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
    androidTestImplementation("androidx.test.ext:junit:1.2.1")
    androidTestImplementation("androidx.work:work-testing:2.10.0")
}
