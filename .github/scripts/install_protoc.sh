#!/usr/bin/env bash
# protoc 29.3 installer shared by every CI job.
#
# Two-path acquisition, following the repository's rule for pinned binaries
# (see the cargo-machete install in extra-tooling.yml): the pinned release
# asset and its sha256 are the first path; when the asset host refuses the
# bytes, the same pinned version is built from the pinned source tree at tag
# v29.3 - a different failure domain. A refused connection falls back; wrong
# bytes never do: a sha256 mismatch on either path stops the job, because
# that is a security event rather than an availability problem.
set -euo pipefail

PROTOC_VERSION=29.3

case "$(uname -m)" in
  aarch64|arm64)
    PROTOC_ZIP="protoc-${PROTOC_VERSION}-linux-aarch_64.zip"
    PROTOC_SHA256="6427349140e01f06e049e707a58709a4f221ae73ab9a0425bc4a00c8d0e1ab32"
    ;;
  *)
    PROTOC_ZIP="protoc-${PROTOC_VERSION}-linux-x86_64.zip"
    PROTOC_SHA256="3e866620c5be27664f3d2fa2d656b5f3e09b5152b42f1bedbf427b333e90021a"
    ;;
esac

# Already at the pinned version: nothing to do.
if command -v protoc >/dev/null 2>&1 && [ "$(protoc --version | awk '{print $2}')" = "${PROTOC_VERSION}" ]; then
  exit 0
fi

# fetch_pinned <url> <out> <expected-sha256>
#   0 = fetched and verified
#   1 = the host refused or could not serve the bytes (fall back)
#   2 = bytes arrived but do not match the pin (security event: stop)
fetch_pinned() {
  local url="$1" out="$2" expected="$3"
  rm -f "${out}"
  if ! curl -sSfL --retry 5 --retry-all-errors --retry-delay 2 -o "${out}" "${url}"; then
    return 1
  fi
  if ! printf '%s  %s\n' "${expected}" "${out}" | sha256sum -c - >/dev/null 2>&1; then
    echo "FATAL: ${url} did not match the sha256 pinned in this script; stopping." >&2
    return 2
  fi
  return 0
}

# Path 1: the pinned release asset.
rc=0
fetch_pinned "https://github.com/protocolbuffers/protobuf/releases/download/v${PROTOC_VERSION}/${PROTOC_ZIP}" /tmp/protoc.zip "${PROTOC_SHA256}" || rc=$?
if [ "${rc}" -eq 0 ]; then
  sudo unzip -q -o /tmp/protoc.zip -d /usr/local bin/protoc 'include/*'
  rm -f /tmp/protoc.zip
  echo "protoc: installed ${PROTOC_VERSION} from the pinned release asset."
  exit 0
fi
if [ "${rc}" -eq 2 ]; then
  exit 1
fi

# Path 2: the same pinned version, built from the source tree at tag v29.3.
# The codeload tarball is not used here: it does not carry the git
# submodules (abseil-cpp, upb) the build needs. A shallow clone of the
# pinned tag with shallow submodules is a different failure domain from the
# release asset CDN, and the resulting binary is the same pinned version.
echo "protoc: the release asset could not be fetched; building ${PROTOC_VERSION} from the pinned source tree instead." >&2

if ! command -v cmake >/dev/null 2>&1; then
  sudo apt-get update -qq
  sudo apt-get install -y -qq cmake
fi

rm -rf /tmp/protobuf-src /tmp/protobuf-build
git clone --depth 1 --branch "v${PROTOC_VERSION}" --recurse-submodules --shallow-submodules \
  https://github.com/protocolbuffers/protobuf /tmp/protobuf-src

cmake -S /tmp/protobuf-src -B /tmp/protobuf-build \
  -DCMAKE_BUILD_TYPE=Release \
  -Dprotobuf_BUILD_TESTS=OFF \
  -Dprotobuf_BUILD_SHARED_LIBS=OFF \
  -Dprotobuf_WITH_ZLIB=OFF
cmake --build /tmp/protobuf-build --target protoc -j"$(nproc)"

# The build names the binary protoc-<version> at the build root.
PROTOC_BIN="$(find /tmp/protobuf-build -maxdepth 1 -name 'protoc-*' -type f | head -1)"
if [ -z "${PROTOC_BIN}" ]; then
  echo "FATAL: the source build did not produce a protoc binary." >&2
  exit 1
fi
sudo install -m 0755 "${PROTOC_BIN}" /usr/local/bin/protoc
sudo mkdir -p /usr/local/include/google/protobuf
sudo cp /tmp/protobuf-src/src/google/protobuf/*.proto /usr/local/include/google/protobuf/
rm -rf /tmp/protobuf-src /tmp/protobuf-build

if [ "$(protoc --version | awk '{print $2}')" != "${PROTOC_VERSION}" ]; then
  echo "FATAL: the source build did not produce protoc ${PROTOC_VERSION}." >&2
  exit 1
fi
echo "protoc: installed ${PROTOC_VERSION} from the pinned source tree."
