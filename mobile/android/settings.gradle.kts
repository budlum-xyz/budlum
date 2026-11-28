pluginManagement {
    repositories {
        google()
        mavenCentral()
        // Maven Central rate-limits shared CI egress (HTTP 429), which turns a
        // healthy build red. The Google-hosted read-only mirror of Maven Central
        // serves byte-identical artifacts and is consulted only after the
        // canonical repositories, so normal resolution is unchanged.
        maven("https://maven-central.storage-download.googleapis.com/maven2")
        gradlePluginPortal()
    }
}

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
        // Maven Central rate-limits shared CI egress (HTTP 429), which turns a
        // healthy build red. The Google-hosted read-only mirror of Maven Central
        // serves byte-identical artifacts and is consulted only after the
        // canonical repositories, so normal resolution is unchanged.
        maven("https://maven-central.storage-download.googleapis.com/maven2")
    }
}

rootProject.name = "BudlumMobileValidator"
include(":app")
