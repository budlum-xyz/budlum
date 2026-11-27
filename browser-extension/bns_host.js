// Copyright budlum-xyz (https://github.com/budlum-xyz)
// Licensed under PolyForm Shield License 1.0.0.
//
// Deterministic BNS host parser mirroring `src/web_gateway/host.rs` and
// `src/registry/params.rs::RESERVED_LABELS`.

export const DEFAULT_GATEWAY_SUFFIX = "budlum.xyz";

export const RESERVED_LABELS = Object.freeze([
  "bud",
  "www",
  "app",
  "api",
  "rpc",
  "docs",
  "mail",
  "explorer",
  "faucet",
  "status",
  "testnet",
  "mainnet",
  "devnet",
  "seed",
  "seed-1",
  "root",
  "admin",
  "bns",
  "budlum",
  "validator",
  "node",
  "gateway",
]);

const RESERVED_SET = new Set(RESERVED_LABELS);

/**
 * Validate a single DNS-safe BNS label matching `src/bns/registry.rs`:
 * lowercase ASCII letters, digits, or internal hyphens; no leading or
 * trailing hyphen; no RFC 5891 R-LDH / Punycode `--` tag at indices 2..4;
 * length within [minLen, 32].
 */
export function isValidLabel(label, minLen = 3) {
  if (typeof label !== "string") {
    return false;
  }
  if (label.length < minLen || label.length > 32) {
    return false;
  }
  if (label.startsWith("-") || label.endsWith("-")) {
    return false;
  }
  if (label.length >= 4 && label.charCodeAt(2) === 45 && label.charCodeAt(3) === 45) {
    return false;
  }
  for (let i = 0; i < label.length; i += 1) {
    const c = label.charCodeAt(i);
    const isDigit = c >= 48 && c <= 57;
    const isLower = c >= 97 && c <= 122;
    const isDash = c === 45;
    if (!isDigit && !isLower && !isDash) {
      return false;
    }
  }
  return true;
}

/**
 * Parse a browser hostname into a canonical `.bud` name.
 *
 * Accepts:
 * - `name.bud` and `sub.name.bud`
 * - `name.<suffix>` and `sub.name.<suffix>` (default suffix: `budlum.xyz`)
 *
 * Rejects reserved apex labels, punycode/non-ASCII labels, deeper label
 * hierarchies (3+ labels before suffix), and malformed labels.
 */
export function parseBnsHost(rawHost, suffix = DEFAULT_GATEWAY_SUFFIX) {
  if (typeof rawHost !== "string" || rawHost.length === 0) {
    return { ok: false, reason: "empty host" };
  }

  let host = rawHost.trim().toLowerCase();
  const colonIdx = host.indexOf(":");
  if (colonIdx !== -1) {
    host = host.slice(0, colonIdx);
  }
  if (host.endsWith(".")) {
    host = host.slice(0, -1);
  }

  const normalizedSuffix = suffix.trim().toLowerCase().replace(/^\.+|\.+$/g, "");
  let prefix = null;

  if (host.endsWith(".bud")) {
    prefix = host.slice(0, -".bud".length);
  } else if (host.endsWith("." + normalizedSuffix)) {
    prefix = host.slice(0, -(normalizedSuffix.length + 1));
  } else {
    return { ok: false, reason: "host is neither .bud nor ." + normalizedSuffix };
  }

  if (!prefix) {
    return { ok: false, reason: "missing BNS label" };
  }

  const parts = prefix.split(".");
  if (parts.length === 1) {
    const apex = parts[0];
    if (RESERVED_SET.has(apex)) {
      return { ok: false, reason: "reserved label: " + apex };
    }
    if (!isValidLabel(apex, 3)) {
      return { ok: false, reason: "invalid apex label: " + apex };
    }
    return { ok: true, name: apex + ".bud", apex, subdomain: null };
  }

  if (parts.length === 2) {
    const [sub, apex] = parts;
    if (RESERVED_SET.has(apex)) {
      return { ok: false, reason: "reserved apex label: " + apex };
    }
    if (!isValidLabel(sub, 1) || !isValidLabel(apex, 3)) {
      return { ok: false, reason: "invalid subdomain or apex label" };
    }
    return { ok: true, name: sub + "." + apex + ".bud", apex, subdomain: sub };
  }

  return { ok: false, reason: "nested subdomains deeper than one level are not allowed" };
}

/**
 * Fold a lowercase ASCII `.bud` label into its visual lookalike skeleton,
 * mirroring `crates/wallet-core/src/bns.rs::bns_visual_skeleton`.
 */
export function bnsVisualSkeleton(label) {
  let out = "";
  let i = 0;
  while (i < label.length) {
    if (i + 1 < label.length) {
      const pair = label.slice(i, i + 2);
      if (pair === "rn") {
        out += "m";
        i += 2;
        continue;
      }
      if (pair === "vv") {
        out += "w";
        i += 2;
        continue;
      }
      if (pair === "cl") {
        out += "d";
        i += 2;
        continue;
      }
    }
    const ch = label[i];
    if (ch === "-") {
      // Drop hyphens so pay-pal.bud collides with paypal.bud.
    } else if (ch === "0") {
      out += "o";
    } else if (ch === "1" || ch === "i") {
      out += "l";
    } else if (ch === "3") {
      out += "e";
    } else if (ch === "5") {
      out += "s";
    } else if (ch === "8") {
      out += "b";
    } else {
      out += ch;
    }
    i += 1;
  }
  return out;
}

function editDistanceIsOne(a, b) {
  if (Math.abs(a.length - b.length) > 1) {
    return false;
  }
  if (a.length === b.length) {
    let diffs = 0;
    for (let i = 0; i < a.length; i += 1) {
      if (a[i] !== b[i]) {
        diffs += 1;
        if (diffs > 1) {
          return false;
        }
      }
    }
    return diffs === 1;
  }
  const [shortStr, longStr] = a.length < b.length ? [a, b] : [b, a];
  let si = 0;
  let li = 0;
  let skipped = false;
  while (si < shortStr.length && li < longStr.length) {
    if (shortStr[si] === longStr[li]) {
      si += 1;
      li += 1;
    } else if (!skipped) {
      skipped = true;
      li += 1;
    } else {
      return false;
    }
  }
  return true;
}

function isSyntacticallyValidBudName(name) {
  if (typeof name !== "string" || !name.endsWith(".bud")) {
    return false;
  }
  const stem = name.slice(0, -".bud".length);
  const parts = stem.split(".");
  if (parts.length === 1) {
    return isValidLabel(parts[0], 3);
  }
  if (parts.length === 2) {
    return isValidLabel(parts[0], 1) && isValidLabel(parts[1], 3);
  }
  return false;
}

/**
 * Inspect `candidate` against `knownNames` and return a warning object if
 * `candidate` is a distinct valid `.bud` name that visually mimics one of
 * `knownNames` (including reserved protocol names such as `budlum.bud` or
 * `faucet.bud`). Returns `null` for exact matches or invalid names.
 */
export function detectConfusableBudName(candidate, knownNames) {
  if (typeof candidate !== "string" || !Array.isArray(knownNames)) {
    return null;
  }
  if (!isSyntacticallyValidBudName(candidate)) {
    return null;
  }
  for (const known of knownNames) {
    if (known === candidate) {
      return null;
    }
  }
  const candStem = candidate.slice(0, -".bud".length);
  const candSkel = bnsVisualSkeleton(candStem);

  for (const known of knownNames) {
    if (!isSyntacticallyValidBudName(known)) {
      continue;
    }
    const knownStem = known.slice(0, -".bud".length);
    if (candSkel === bnsVisualSkeleton(knownStem)) {
      return {
        candidate,
        similarTo: known,
        reason: "visual_skeleton_match",
      };
    }
  }

  if (candStem.length >= 4) {
    for (const known of knownNames) {
      if (!isSyntacticallyValidBudName(known)) {
        continue;
      }
      const knownStem = known.slice(0, -".bud".length);
      if (knownStem.length >= 4 && editDistanceIsOne(candStem, knownStem)) {
        return {
          candidate,
          similarTo: known,
          reason: "near_edit_distance",
        };
      }
    }
  }

  return null;
}
