#!/usr/bin/env bash
# ============================================================================
# check-content-encryption-is-declared-and-bound.sh
#
# A manifest must say whether its bytes are ciphertext, and the saying must be
# part of what the id commits to.
#
# Why this gate exists.
#
# `src/storage/` held no encryption of any kind and no statement about it
# either. Every manifest was silent, so every reader resolved the silence for
# itself: an operator could not tell whether the shard it served was readable
# content, and a client whose decrypt failed could not tell a wrong key from a
# corrupt shard.
#
# The chain cannot encrypt anything. It holds no bytes. What it can do is
# carry the uploader's statement and make it immutable, and the only way to
# make it immutable is to put it inside `manifest_id`. Left outside, the claim
# is rewritable under a stable id: register as `ClientSide`, serve a manifest
# reading `Plaintext` at the same id, and every later reader concludes the
# bytes were never protected. That is the whole reason the binding, and not
# just the field, is what this gate watches.
#
# The measured shapes this refuses:
#
#   1. The field exists but `manifest_id_from_parts` never reads it. The
#      declaration is then decorative: two manifests share an id and disagree
#      about whether the content is private, and first-writer-wins picks one.
#   2. The commitment tag is derived from the enum's declaration order rather
#      than written out, so reordering variants silently changes every
#      manifest id ever computed.
#   3. `Plaintext` stops being the default, so every manifest written before
#      the field deserializes into a privacy claim nobody made.
#   4. A key, key id, wrapped key or nonce is added to the declaration, which
#      publishes key material on a public chain.
#
# What this gate does not check: that anything was actually encrypted. Nothing
# on chain can check that, and a gate claiming to would be reporting a
# guarantee the system does not have. The declaration is a published statement
# by the uploader, verifiable only in the one arithmetic sense the size floor
# covers.
#
# Usage:
#   bash scripts/check-content-encryption-is-declared-and-bound.sh
#   bash scripts/check-content-encryption-is-declared-and-bound.sh --self-test
# ============================================================================
set -euo pipefail

ROOT="${BUDLUM_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"

scan() {
  python3 - "$1" <<'PY'
import os
import re
import sys

root = sys.argv[1]
manifest = os.path.join(root, "src", "storage", "manifest.rs")
locks = os.path.join(root, "src", "tests", "manifest_commitment_locks.rs")

for path in (manifest, locks):
    if not os.path.isfile(path):
        print(f"FAIL: expected source file missing: {path}", file=sys.stderr)
        sys.exit(2)


def strip_comments(src):
    return re.sub(r"//[^\n]*", "", src)


def body_of(src, header):
    """Text of the item whose signature matches `header`, brace-matched.

    Cutting at the first `#[cfg(test)]` would drop the production half of a
    file that puts tests at the bottom, and cutting at the next `}` would stop
    at the first nested block. Matching braces is the only reading that
    survives both.
    """
    m = re.search(header, src)
    if not m:
        return None
    i = src.index("{", m.end() - 1) if "{" not in m.group(0) else m.end() - 1
    depth, j = 0, i
    while j < len(src):
        if src[j] == "{":
            depth += 1
        elif src[j] == "}":
            depth -= 1
            if depth == 0:
                return src[i : j + 1]
        j += 1
    return None


manifest_src = open(manifest, encoding="utf-8").read()
manifest_code = strip_comments(manifest_src)
locks_src = open(locks, encoding="utf-8").read()

problems = []
checked = 0

# 1. The declaration type must exist and must offer both states. A type with
#    only one state says nothing.
checked += 1
enum_body = body_of(manifest_code, r"pub enum ContentEncryption\s*\{")
if enum_body is None:
    problems.append(
        "`ContentEncryption` is gone. A manifest with no declaration leaves "
        "every reader to resolve the silence for itself: an operator cannot "
        "tell whether it is serving readable content, and a failed decrypt "
        "cannot be distinguished from a corrupt shard."
    )
else:
    checked += 1
    for state in ("Plaintext", "ClientSide"):
        if state not in enum_body:
            problems.append(
                f"`ContentEncryption::{state}` is gone; the type no longer "
                "distinguishes protected content from readable content."
            )

# 2. `Plaintext` must be the default. Manifests written before this field
#    deserialize through it, and they were written by a tree with no
#    encryption in it at all.
checked += 1
m = re.search(
    r"pub enum ContentEncryption\s*\{(.*?)\n\}", manifest_code, re.S
)
if m:
    variants = m.group(1)
    default_at = variants.find("#[default]")
    plaintext_at = variants.find("Plaintext")
    clientside_at = variants.find("ClientSide")
    if default_at == -1:
        problems.append(
            "`ContentEncryption` has no `#[default]`. Manifests written "
            "before this field deserialize through the default, and without "
            "one the type will not derive `Default` at all."
        )
    elif not (plaintext_at != -1 and default_at < plaintext_at
              and (clientside_at == -1 or default_at < clientside_at)):
        problems.append(
            "`#[default]` is not on `Plaintext`. Every manifest written "
            "before this field would deserialize into a privacy claim nobody "
            "made, which is worse than no claim: a reader would trust it."
        )

# 3. The field must exist on the manifest and carry `#[serde(default)]`, or
#    older snapshots fail to load rather than reading as plaintext.
checked += 1
struct_body = body_of(manifest_code, r"pub struct ContentManifest\s*\{")
if struct_body is None:
    problems.append("cannot find `ContentManifest` to check its fields.")
else:
    checked += 1
    if not re.search(r"pub encryption:\s*ContentEncryption", struct_body):
        problems.append(
            "`ContentManifest` has no `encryption` field, so nothing records "
            "whether the shards are ciphertext."
        )
    field_at = struct_body.find("pub encryption:")
    if field_at != -1:
        preceding = struct_body[max(0, field_at - 200) : field_at]
        if "#[serde(default)]" not in preceding:
            problems.append(
                "`encryption` is not `#[serde(default)]`, so every snapshot "
                "written before this field fails to deserialize."
            )

# 4. The binding. This is the check the gate exists for: a field the
#    commitment never reads is decorative, and the claim stays rewritable
#    under a stable id.
checked += 1
commit = body_of(manifest_code, r"pub fn manifest_id_from_parts\s*\(")
sig = re.search(
    r"pub fn manifest_id_from_parts\s*\((.*?)\)\s*->", manifest_code, re.S
)
if commit is None or sig is None:
    problems.append(
        "`manifest_id_from_parts` is gone; nothing binds the manifest's "
        "fields to its id."
    )
else:
    checked += 1
    if "ContentEncryption" not in sig.group(1):
        problems.append(
            "`manifest_id_from_parts` does not take the encryption "
            "declaration. Outside the commitment the claim is rewritable "
            "under a stable id: register `ClientSide`, then serve a manifest "
            "reading `Plaintext` at the same id."
        )
    checked += 1
    if "commitment_tag" not in commit:
        problems.append(
            "`manifest_id_from_parts` never reads the declaration's "
            "commitment tag, so the argument is accepted and ignored. That "
            "is the same as not binding it, with the appearance of binding."
        )
    checked += 1
    if "BDLM_MANIFEST_V3" not in commit:
        problems.append(
            "the commitment is not domain-separated as V3. Adding a field "
            "without changing the domain tag lets a V2 id and a V3 id collide "
            "across different meanings."
        )

# 5. Every production caller must pass the manifest's own declaration, not a
#    literal. A call site hardcoding `Plaintext` binds the wrong claim while
#    satisfying every check above.
checked += 1
for call in re.finditer(
    r"manifest_id_from_parts\(\s*&self\.shards[^)]*\)", manifest_code
):
    if "self.encryption" not in call.group(0):
        problems.append(
            "a `manifest_id_from_parts` call inside `ContentManifest` does "
            f"not pass `self.encryption`: {call.group(0).strip()}. The id "
            "would then commit to a declaration the manifest does not carry."
        )

# 6. The tag must be written out per variant, not derived from ordering.
#    `as u8` over the enum would make variant order part of consensus.
checked += 1
tagfn = body_of(manifest_code, r"pub fn commitment_tag\s*\(&self\)\s*->\s*u8")
if tagfn is None:
    problems.append("`commitment_tag` is gone; the commitment has no stable byte.")
else:
    checked += 1
    if re.search(r"\bas u8\b", tagfn) and "match" not in tagfn:
        problems.append(
            "`commitment_tag` casts the enum rather than matching it. "
            "Reordering the variants would then silently change every "
            "manifest id ever computed."
        )

# 7. No key material in the declaration.
checked += 1
if enum_body is not None:
    banned = re.findall(
        r"\b(key|nonce|secret|iv|wrapped)\w*\s*:", enum_body, re.I
    )
    if banned:
        problems.append(
            f"`ContentEncryption` carries what looks like key material "
            f"({', '.join(sorted(set(banned)))}). A key in a public "
            "commitment is a key published on a public chain."
        )

# 8. The regressions must exist as real tests.
checked += 1
for test in (
    "declaring_client_side_encryption_changes_the_manifest_id",
    "rewriting_the_declaration_breaks_the_id",
    "a_manifest_written_before_this_field_reads_as_plaintext",
    "an_object_too_small_to_hold_an_auth_tag_cannot_claim_encryption",
    "an_object_at_the_tag_length_is_accepted",
    "the_declaration_carries_no_key_material",
):
    if not re.search(
        r"#\[test\]\s*(?:#\[[^\]]*\]\s*)*fn\s+" + test + r"\s*\(", locks_src
    ):
        problems.append(
            f"required regression test `{test}` is missing or is not a `#[test]`."
        )

if not checked:
    print("FAIL: gate checked nothing", file=sys.stderr)
    sys.exit(2)

if problems:
    for problem in problems:
        print(f"FAIL: {problem}", file=sys.stderr)
    sys.exit(1)

print(
    f"content encryption declaration gate OK: {checked} checks, the claim is "
    "declared, defaulted honestly and bound to the id"
)
PY
}

self_test() {
  local tmp
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' RETURN

  expect_finding() {
    local dir="$1" what="$2" rc=0
    ( scan "$dir" ) >/dev/null 2>&1 || rc=$?
    if [ "$rc" -eq 0 ]; then
      echo "GATE IS VACUOUS: $what passed!" >&2
      return 1
    fi
    if [ "$rc" -ne 1 ]; then
      echo "GATE IS BROKEN: $what exited $rc, which is not a finding." >&2
      return 1
    fi
  }

  # Fixtures are written by python: bodies contain `#[test]` and `#[default]`,
  # and bash treats `[` as a glob inside `${var//pattern/...}`, so a
  # substitution would silently do nothing and leave the canary asserting
  # against an unmodified tree.
  build() {
    python3 - "$@" <<'PYB'
import os
import sys

root = sys.argv[1]
enum_mode = sys.argv[2]
field_mode = sys.argv[3]
commit_mode = sys.argv[4]
tag_mode = sys.argv[5]
tests_mode = sys.argv[6]

for sub in ("src/storage", "src/tests"):
    os.makedirs(os.path.join(root, sub), exist_ok=True)

if enum_mode == "gone":
    enum = ""
elif enum_mode == "wrongdefault":
    enum = """pub enum ContentEncryption {
    ClientSide(ContentCipher),
    #[default]
    Plaintext,
}
"""
elif enum_mode == "nodefault":
    enum = """pub enum ContentEncryption {
    Plaintext,
    ClientSide(ContentCipher),
}
"""
elif enum_mode == "haskey":
    enum = """pub enum ContentEncryption {
    #[default]
    Plaintext,
    ClientSide { cipher: ContentCipher, wrapped_key: Vec<u8> },
}
"""
else:
    enum = """pub enum ContentEncryption {
    #[default]
    Plaintext,
    ClientSide(ContentCipher),
}
"""

if tag_mode == "cast":
    tagfn = """    pub fn commitment_tag(&self) -> u8 {
        *self as u8
    }
"""
elif tag_mode == "gone":
    tagfn = ""
else:
    tagfn = """    pub fn commitment_tag(&self) -> u8 {
        match self {
            ContentEncryption::Plaintext => 0,
            ContentEncryption::ClientSide(c) => c.commitment_tag(),
        }
    }
"""

if field_mode == "gone":
    field = ""
elif field_mode == "noserde":
    field = "    pub encryption: ContentEncryption,\n"
else:
    field = "    #[serde(default)]\n    pub encryption: ContentEncryption,\n"

struct = """pub struct ContentManifest {
    pub manifest_id: ContentId,
    pub total_size: u64,
    pub shard_count: u32,
    pub shards: Vec<ShardRef>,
%s}
""" % field

if commit_mode == "bound":
    commit = """pub fn manifest_id_from_parts(
    shards: &[ShardRef],
    erasure: &ErasureScheme,
    encryption: &ContentEncryption,
) -> ContentId {
    let mut buf = Vec::new();
    buf.extend_from_slice(b"BDLM_MANIFEST_V3");
    buf.extend_from_slice(&erasure.k.to_le_bytes());
    buf.push(encryption.commitment_tag());
    ContentId(hash_fields_bytes(&[b"BDLM_MANIFEST_V3", &buf]))
}
"""
    site = "        self.manifest_id = manifest_id_from_parts(&self.shards, &self.erasure, &self.encryption);\n"
elif commit_mode == "ignored":
    # Takes the argument and never reads it. Every signature check passes.
    commit = """pub fn manifest_id_from_parts(
    shards: &[ShardRef],
    erasure: &ErasureScheme,
    encryption: &ContentEncryption,
) -> ContentId {
    let mut buf = Vec::new();
    buf.extend_from_slice(b"BDLM_MANIFEST_V3");
    buf.extend_from_slice(&erasure.k.to_le_bytes());
    ContentId(hash_fields_bytes(&[b"BDLM_MANIFEST_V3", &buf]))
}
"""
    site = "        self.manifest_id = manifest_id_from_parts(&self.shards, &self.erasure, &self.encryption);\n"
elif commit_mode == "unbound":
    commit = """pub fn manifest_id_from_parts(
    shards: &[ShardRef],
    erasure: &ErasureScheme,
) -> ContentId {
    let mut buf = Vec::new();
    buf.extend_from_slice(b"BDLM_MANIFEST_V3");
    buf.extend_from_slice(&erasure.k.to_le_bytes());
    ContentId(hash_fields_bytes(&[b"BDLM_MANIFEST_V3", &buf]))
}
"""
    site = "        self.manifest_id = manifest_id_from_parts(&self.shards, &self.erasure);\n"
elif commit_mode == "v2tag":
    commit = """pub fn manifest_id_from_parts(
    shards: &[ShardRef],
    erasure: &ErasureScheme,
    encryption: &ContentEncryption,
) -> ContentId {
    let mut buf = Vec::new();
    buf.extend_from_slice(b"BDLM_MANIFEST_V2");
    buf.push(encryption.commitment_tag());
    ContentId(hash_fields_bytes(&[b"BDLM_MANIFEST_V2", &buf]))
}
"""
    site = "        self.manifest_id = manifest_id_from_parts(&self.shards, &self.erasure, &self.encryption);\n"
else:  # literal: binds a hardcoded claim instead of the manifest's own
    commit = """pub fn manifest_id_from_parts(
    shards: &[ShardRef],
    erasure: &ErasureScheme,
    encryption: &ContentEncryption,
) -> ContentId {
    let mut buf = Vec::new();
    buf.extend_from_slice(b"BDLM_MANIFEST_V3");
    buf.push(encryption.commitment_tag());
    ContentId(hash_fields_bytes(&[b"BDLM_MANIFEST_V3", &buf]))
}
"""
    site = "        self.manifest_id = manifest_id_from_parts(&self.shards, &self.erasure, &ContentEncryption::Plaintext);\n"

impl = """impl ContentEncryption {
%s    pub fn is_encrypted(&self) -> bool {
        matches!(self, ContentEncryption::ClientSide(_))
    }
}
""" % tagfn

recompute = """impl ContentManifest {
    pub fn with_encryption(mut self, encryption: ContentEncryption) -> Self {
        self.encryption = encryption;
%s        self
    }
}
""" % site

open(os.path.join(root, "src/storage/manifest.rs"), "w").write(
    "\n".join([enum, impl, struct, recompute, commit])
)

names = [
    "declaring_client_side_encryption_changes_the_manifest_id",
    "rewriting_the_declaration_breaks_the_id",
    "a_manifest_written_before_this_field_reads_as_plaintext",
    "an_object_too_small_to_hold_an_auth_tag_cannot_claim_encryption",
    "an_object_at_the_tag_length_is_accepted",
    "the_declaration_carries_no_key_material",
]
if tests_mode == "absent":
    names = names[:-1]
body = "".join("#[test]\nfn %s() {}\n" % n for n in names)
open(os.path.join(root, "src/tests/manifest_commitment_locks.rs"), "w").write(body)
PYB
  }

  # 1. The corrected shape must pass, or every canary below proves nothing.
  build "$tmp/good" ok serde bound match present
  if ! ( scan "$tmp/good" ) >/dev/null 2>&1; then
    echo "GATE IS WRONG: the corrected tree was rejected!" >&2
    ( scan "$tmp/good" ) >&2 || true
    return 1
  fi

  # 2. The original state: no declaration at all.
  build "$tmp/noenum" gone serde bound match present
  expect_finding "$tmp/noenum" "a tree with no encryption declaration" || return 1

  # 3. The field exists but the commitment never takes it.
  build "$tmp/unbound" ok serde unbound match present
  expect_finding "$tmp/unbound" "a declaration outside the commitment" || return 1

  # 4. The subtle one: the commitment takes the argument and ignores it.
  #    Every signature-based check passes and nothing is bound.
  build "$tmp/ignored" ok serde ignored match present
  expect_finding "$tmp/ignored" "a commitment that accepts and ignores the claim" || return 1

  # 5. A call site binds a hardcoded `Plaintext` rather than the manifest's
  #    own declaration, so an encrypted manifest commits to the wrong claim.
  build "$tmp/literal" ok serde literal match present
  expect_finding "$tmp/literal" "a call site binding a literal claim" || return 1

  # 6. The domain tag was not advanced, so V2 and V3 ids can collide.
  build "$tmp/v2" ok serde v2tag match present
  expect_finding "$tmp/v2" "a V3 field under the V2 domain tag" || return 1

  # 7. `#[default]` moved off `Plaintext`, so old manifests read as private.
  build "$tmp/wrongdefault" wrongdefault serde bound match present
  expect_finding "$tmp/wrongdefault" "a default that invents a privacy claim" || return 1

  # 8. No default at all.
  build "$tmp/nodefault" nodefault serde bound match present
  expect_finding "$tmp/nodefault" "an enum with no default" || return 1

  # 9. The field is not `#[serde(default)]`, so older snapshots fail to load.
  build "$tmp/noserde" ok noserde bound match present
  expect_finding "$tmp/noserde" "a field older snapshots cannot deserialize" || return 1

  # 10. The field disappears from the struct.
  build "$tmp/nofield" ok gone bound match present
  expect_finding "$tmp/nofield" "a manifest with no encryption field" || return 1

  # 11. The tag is cast from variant order, making ordering consensus.
  build "$tmp/cast" ok serde bound cast present
  expect_finding "$tmp/cast" "a commitment tag derived from variant order" || return 1

  # 12. The tag function disappears.
  build "$tmp/notag" ok serde bound gone present
  expect_finding "$tmp/notag" "a missing commitment tag" || return 1

  # 13. Key material lands in the declaration.
  build "$tmp/haskey" haskey serde bound match present
  expect_finding "$tmp/haskey" "key material inside a public commitment" || return 1

  # 14. A regression test is dropped.
  build "$tmp/notest" ok serde bound match absent
  expect_finding "$tmp/notest" "a missing regression test" || return 1

  echo "content encryption declaration gate self-test OK: 14 canaries"
}

if [[ "${1:-}" == "--self-test" ]]; then
  self_test
else
  scan "$ROOT"
fi
