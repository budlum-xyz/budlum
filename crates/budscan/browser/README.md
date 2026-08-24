# The Budscan patch layer

This directory is the Gecko side of Budscan. The engine source is **not** here
and never will be: at build time the Mozilla source is downloaded, the patches
in this directory are applied, and the result is compiled.

## Why no engine is written

A browser engine is three things: an HTML/CSS layout engine, a JavaScript
engine and a sandbox. Each is decades of work and each is the whole attack
surface. A web3 browser that writes its own engine adds a browser security
problem on top of the problem it set out to solve.

Budscan patches Gecko and asks the `budscan` crate for every decision.

## Why the tooling layer is not shell

In the Firefox derivatives studied as references, the patch tooling is shell
throughout. The concrete measured problem is `check-patchfail.sh` in those
repositories:

```sh
for j in $(grep -n rej$ ../patch.tmp | awk '{ print $(NF); }'); do
    s="$s $j"
    ...
done
if [ ! -z "$s" ]; then failed_patches="$failed_patches [$curpatch]"; fi
```

If `grep` finds nothing the loop runs empty, `s` stays empty, and the script
prints **"success: All patches where applied successfully."** and returns 0. So
if the format of the `patch` output changes, the check inspects nothing and
says OK even when a patch failed completely. A check that silently inspects
nothing is worse than no check at all: nobody mistakes a missing check for a
written one.

Budscan's patch tooling lives in `budscan::patchset`, in Rust. There, "I could
inspect nothing" is a distinct outcome (`Verdict::Vacuous`) and `is_ok()`
returns false.

The checks:

```
cargo run -p budscan --bin budscan -- patch-list budscan/browser/patches.txt
cargo run --manifest-path xtask/gates/Cargo.toml -- budscan-patchset
```

## Directory layout

| path | what |
|---|---|
| `patches.txt` | the ordered list of patches to apply; a `!` prefix disables one |
| `patches/` | unified diff files |
| `settings/budscan.cfg` | locked preferences (`lockPref`) |
| `settings/policies.json` | the distribution policy |
| `l10n/tr-TR/`, `l10n/en-US/` | the address-bar badge strings |
| `mozconfig` | the build configuration |

## Branding

No other browser's brand name appears in this tree. The patch arrangement was
taken as an idea, not as a name; the `budscan::patchset::FORBIDDEN_BRAND_TOKENS`
list turns that into a rule and the `budscan-patchset` gate measures it in CI.

## What the patches do

**`bud-protocol-handler.patch`**: registers the `bud://` scheme. The scheme is
not `URI_DANGEROUS_TO_LOAD` and not `URI_IS_LOCAL_RESOURCE` either: it is an
ordinary loadable scheme carrying its own origin (`bud://<name>`). Content is
written to the channel **after** the `budscan` core has verified it; unverified
bytes never enter the channel at all.

**`address-bar-verification-badge.patch`**: writes the verification strength
into the address bar. There are four values (`verified`, `transport only`,
`claim only`, `refused`) and the badge shows **the weakest link**. Even when a
page's bytes are verified, the badge says `claim only` if the name resolution
carries no proof.

**`name-bar-punycode.patch`**: a name that does not pass the name rule is
displayed as punycode in the address bar. What is displayed being the same as
what is resolved is this browser's rule; the gap between the two is exactly
where the homograph attack lives.
