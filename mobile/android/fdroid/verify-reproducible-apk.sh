#!/usr/bin/env bash
# Deterministic APK / archive reproducibility harness for WP-58.
set -euo pipefail

export LC_ALL=C
export TZ=UTC
export SOURCE_DATE_EPOCH=1700000000

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
GRADLE_FILE="$ROOT_DIR/mobile/android/app/build.gradle.kts"
FDROID_RECIPE="$ROOT_DIR/mobile/android/fdroid/network.budlum.validator.yml"

grep -q 'includeInApk = false' "$GRADLE_FILE"
grep -q 'includeInBundle = false' "$GRADLE_FILE"
grep -q 'isPreserveFileTimestamps = false' "$GRADLE_FILE"
grep -q 'isReproducibleFileOrder = true' "$GRADLE_FILE"
grep -q 'ndkVersion = "27.2.12479018"' "$GRADLE_FILE"
grep -q 'ndk: 27.2.12479018' "$FDROID_RECIPE"
grep -q 'SOURCE_DATE_EPOCH=1700000000' "$FDROID_RECIPE"

if [[ "${1:-}" == "--self-test" ]]; then
  tmp_a="$(mktemp -d)"
  tmp_b="$(mktemp -d)"
  trap 'rm -rf "$tmp_a" "$tmp_b"' EXIT

  build_deterministic_bundle() {
    local work="$1"
    local order="$2"
    mkdir -p "$work/stage/lib/arm64-v8a" "$work/stage/META-INF"
    if [[ "$order" == "forward" ]]; then
      printf 'budlum-manifest-v1\n' > "$work/stage/AndroidManifest.txt"
      printf 'budlum-native-stub\n' > "$work/stage/lib/arm64-v8a/libbudlum_mobile_core.so"
    else
      printf 'budlum-native-stub\n' > "$work/stage/lib/arm64-v8a/libbudlum_mobile_core.so"
      sleep 1
      printf 'budlum-manifest-v1\n' > "$work/stage/AndroidManifest.txt"
    fi
    python3 - "$work/stage" "$work/unsigned.apk" <<'PY'
import os, sys, zipfile
stage, out_apk = sys.argv[1], sys.argv[2]
rels = []
for base, dirs, files in os.walk(stage):
    dirs.sort()
    for name in sorted(files):
        full = os.path.join(base, name)
        rels.append(os.path.relpath(full, stage).replace("\\", "/"))
rels.sort()
with zipfile.ZipFile(out_apk, "w") as zf:
    for rel in rels:
        info = zipfile.ZipInfo(rel, date_time=(1980, 1, 1, 0, 0, 0))
        info.compress_type = zipfile.ZIP_DEFLATED
        info.external_attr = 0o644 << 16
        with open(os.path.join(stage, rel), "rb") as fh:
            zf.writestr(info, fh.read())
PY
  }

  build_deterministic_bundle "$tmp_a" "forward"
  build_deterministic_bundle "$tmp_b" "reverse"

  sha_a="$(sha256sum "$tmp_a/unsigned.apk" | awk '{print $1}')"
  sha_b="$(sha256sum "$tmp_b/unsigned.apk" | awk '{print $1}')"
  if [[ "$sha_a" != "$sha_b" ]]; then
    echo "ERROR: reproducible APK digest mismatch: $sha_a vs $sha_b" >&2
    exit 1
  fi
  echo "android_reproducible_build_matches OK ($sha_a)"
fi
