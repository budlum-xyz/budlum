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
 * trailing hyphen; length within [minLen, 32].
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
