//! Static gate: Android Mobile validator (), F-Droid reproducible APK
//! recipe (), and iOS `MobileOpportunistic` validator ().

use std::path::Path;

fn read_rel(root: &Path, rel: &str) -> Result<String, String> {
    let p = root.join(rel);
    std::fs::read_to_string(&p).map_err(|e| format!("cannot read `{rel}`: {e}"))
}

fn strip_cfg_test(src: &str) -> &str {
    match src.find("#[cfg(test)]") {
        Some(idx) => src.get(..idx).unwrap_or(src),
        None => src,
    }
}

fn check(root: &Path) -> Result<String, String> {
    let manifest = read_rel(root, "mobile/android/app/src/main/AndroidManifest.xml")?;
    if manifest.contains("REQUEST_IGNORE_BATTERY_OPTIMIZATIONS") {
        return Err(String::from(
            "`AndroidManifest.xml` must never declare `REQUEST_IGNORE_BATTERY_OPTIMIZATIONS` (Section 7.9.11)",
        ));
    }
    for required in [
        "FOREGROUND_SERVICE_SPECIAL_USE",
        "android:foregroundServiceType=\"specialUse\"",
        "android.app.PROPERTY_SPECIAL_USE_FGS_SUBTYPE",
        "android:allowBackup=\"false\"",
    ] {
        if !manifest.contains(required) {
            return Err(format!(
                "`AndroidManifest.xml` missing required declaration `{required}`"
            ));
        }
    }

    let gradle = read_rel(root, "mobile/android/app/build.gradle.kts")?;
    for required in [
        "minSdk = 29",
        "targetSdk = 36",
        "ndkVersion = \"27.2.12479018\"",
        "includeInApk = false",
    ] {
        if !gradle.contains(required) {
            return Err(format!(
                "`mobile/android/app/build.gradle.kts` missing `{required}`"
            ));
        }
    }
    for banned in ["firebase", "play-services-ads", "crashlytics", "sentry"] {
        if gradle.to_ascii_lowercase().contains(banned) {
            return Err(format!(
                "`mobile/android/app/build.gradle.kts` links banned third-party SDK `{banned}`"
            ));
        }
    }

    let fdroid = read_rel(root, "mobile/android/fdroid/network.budlum.validator.yml")?;
    if !fdroid.contains("ndk: 27.2.12479018") {
        return Err(String::from(
            "`mobile/android/fdroid/network.budlum.validator.yml` must pin `ndk: 27.2.12479018`",
        ));
    }

    let plist = read_rel(root, "mobile/ios/Info.plist")?;
    for required in [
        "BGTaskSchedulerPermittedIdentifiers",
        "xyz.budlum.validator.audit",
        "<string>16.0</string>",
    ] {
        if !plist.contains(required) {
            return Err(format!("`mobile/ios/Info.plist` missing `{required}`"));
        }
    }

    let ios_engine = read_rel(
        root,
        "mobile/ios/Sources/BudlumValidator/OpportunisticValidatorEngine.swift",
    )?;
    for required in [
        "MobileOpportunistic",
        "maxQuotaBytes: UInt64 = 8 * gib",
        "requiresExternalPower: Bool = true",
        "isExcludedFromBackup = true",
    ] {
        if !ios_engine.contains(required) {
            return Err(format!(
                "`OpportunisticValidatorEngine.swift` missing `{required}`"
            ));
        }
    }

    let runtime_prod =
        strip_cfg_test(&read_rel(root, "src/registry/mobile_runtime.rs")?).to_string();
    for needle in [
        "MobileValidatorController",
        "run_ios_bg_processing_task",
        "verify_reproducible_apk_builds",
    ] {
        if !runtime_prod.contains(needle) {
            return Err(format!(
                "`src/registry/mobile_runtime.rs` missing `{needle}`"
            ));
        }
    }

    for doc in [
        "mobile/android/PLAY_DECLARATION.md",
        "mobile/ios/APP_STORE_REVIEW_NOTES.md",
    ] {
        if read_rel(root, doc)?.trim().is_empty() {
            return Err(format!("`{doc}` is empty"));
        }
    }

    Ok(String::from(
        "mobile-validator-apps OK: Android targetSdk 36 specialUse FGS, F-Droid NDK recipe, iOS MobileOpportunistic 8 GiB cap, and mobile runtime verified.",
    ))
}

/// Run the gate against `root`.
///
/// # Errors
///
/// Returns an error string when any Android, F-Droid, or iOS invariant fails.
pub fn run(root: &Path) -> Result<String, String> {
    check(root)
}

/// Run positive and negative synthetic canary checks.
///
/// # Errors
///
/// Returns an error string if the positive fixture fails or any negative fixture passes.
pub fn self_test() -> Result<String, String> {
    let dir = crate::gates::rust_literals::exclusive_scratch_dir("budlum-gates-mobile-apps")?;
    let res = (|| -> Result<String, String> {
        let put = |rel: &str, body: &str| -> Result<(), String> {
            let p = dir.join(rel);
            if let Some(parent) = p.parent() {
                std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
            }
            std::fs::write(&p, body).map_err(|e| e.to_string())
        };

        let clean_manifest = "<manifest><uses-permission android:name=\"android.permission.FOREGROUND_SERVICE_SPECIAL_USE\"/><application android:allowBackup=\"false\"><service android:foregroundServiceType=\"specialUse\"><property android:name=\"android.app.PROPERTY_SPECIAL_USE_FGS_SUBTYPE\"/></service></application></manifest>";
        let clean_gradle = "minSdk = 29\ntargetSdk = 36\nndkVersion = \"27.2.12479018\"\nincludeInApk = false\n";
        let clean_fdroid = "ndk: 27.2.12479018\n";
        let clean_plist = "<plist><key>BGTaskSchedulerPermittedIdentifiers</key><string>xyz.budlum.validator.audit</string><string>16.0</string></plist>";
        let clean_ios = "case mobileOpportunistic = \"MobileOpportunistic\"\npublic static let maxQuotaBytes: UInt64 = 8 * gib\nrequiresExternalPower: Bool = true\nisExcludedFromBackup = true\n";
        let clean_rt = "pub struct MobileValidatorController;\npub fn run_ios_bg_processing_task() {}\npub fn verify_reproducible_apk_builds() {}\n";

        put("mobile/android/app/src/main/AndroidManifest.xml", clean_manifest)?;
        put("mobile/android/app/build.gradle.kts", clean_gradle)?;
        put("mobile/android/fdroid/network.budlum.validator.yml", clean_fdroid)?;
        put("mobile/ios/Info.plist", clean_plist)?;
        put(
            "mobile/ios/Sources/BudlumValidator/OpportunisticValidatorEngine.swift",
            clean_ios,
        )?;
        put("src/registry/mobile_runtime.rs", clean_rt)?;
        put("mobile/android/PLAY_DECLARATION.md", "# Declaration\n")?;
        put("mobile/ios/APP_STORE_REVIEW_NOTES.md", "# Review Notes\n")?;

        check(&dir).map_err(|e| format!("clean canary failed: {e}"))?;

        // Negative canary 1: REQUEST_IGNORE_BATTERY_OPTIMIZATIONS must be rejected.
        put(
            "mobile/android/app/src/main/AndroidManifest.xml",
            &format!("{clean_manifest}\nREQUEST_IGNORE_BATTERY_OPTIMIZATIONS"),
        )?;
        if check(&dir).is_ok() {
            return Err(String::from(
                "negative canary 1 passed despite REQUEST_IGNORE_BATTERY_OPTIMIZATIONS",
            ));
        }
        put("mobile/android/app/src/main/AndroidManifest.xml", clean_manifest)?;

        // Negative canary 2: banned Firebase SDK in Gradle file must be rejected.
        put(
            "mobile/android/app/build.gradle.kts",
            &format!("{clean_gradle}\nimplementation(\"com.google.firebase:firebase-analytics\")"),
        )?;
        if check(&dir).is_ok() {
            return Err(String::from(
                "negative canary 2 passed despite banned Firebase SDK",
            ));
        }

        Ok(String::from(
            "mobile-validator-apps canary OK: positive tree passed; 2 negative fixtures rejected.",
        ))
    })();
    let _ = std::fs::remove_dir_all(&dir);
    res
}
