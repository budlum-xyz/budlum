// Copyright budlum-xyz (https://github.com/budlum-xyz)
// Licensed under PolyForm Shield License 1.0.0.
//
// Canonical `budlum:pay/v1?...` payment request URI codec and prompt formatter
// mirroring `src/unification/payment_router.rs::UniversalPaymentRequestUri`
// and `crates/wallet-core/src/payment.rs::PaymentRequestUri`.

export const MAX_PAYMENT_URI_BYTES = 512;
const U64_MAX = (1n << 64n) - 1n;
const U128_MAX = (1n << 128n) - 1n;
const ZERO_HEX_64 = "0".repeat(64);
const LOWER_HEX_64 = /^[0-9a-f]{64}$/;
const DECIMAL_UINT = /^(0|[1-9][0-9]*)$/;
const ALLOWED_KEYS = new Set([
  "amount",
  "asset",
  "callback",
  "deadline",
  "domain",
  "invoice",
  "recipient",
]);

function isAscii(raw) {
  for (let i = 0; i < raw.length; i += 1) {
    if (raw.charCodeAt(i) > 0x7f) {
      return false;
    }
  }
  return true;
}

function validateSafeLabel(field, value, maxLen) {
  if (typeof value !== "string" || value.length === 0 || value.length > maxLen) {
    return { ok: false, reason: `${field} length must be within 1..=${maxLen}` };
  }
  if (value.includes("..") || value.includes("\\")) {
    return { ok: false, reason: `${field} contains forbidden path characters` };
  }
  for (let i = 0; i < value.length; i += 1) {
    const code = value.charCodeAt(i);
    if (code === 0 || code < 0x20 || code === 0x7f) {
      return { ok: false, reason: `${field} contains forbidden control characters` };
    }
  }
  return { ok: true };
}

/**
 * Encode a payment request object into canonical `budlum:pay/v1?...` bytes.
 */
export function encodePaymentRequestUri(req) {
  if (!req || typeof req !== "object") {
    return { ok: false, reason: "payment request must be an object" };
  }
  if (req.version !== 1) {
    return { ok: false, reason: `unsupported payment request URI version ${req.version}` };
  }
  if (typeof req.targetDomain !== "bigint" || req.targetDomain <= 0n || req.targetDomain > U64_MAX) {
    return { ok: false, reason: "targetDomain must be a non-zero u64 BigInt" };
  }
  if (typeof req.targetAmount !== "bigint" || req.targetAmount <= 0n || req.targetAmount > U128_MAX) {
    return { ok: false, reason: "targetAmount must be a non-zero u128 BigInt" };
  }
  if (
    typeof req.deadlineUnixSecs !== "bigint" ||
    req.deadlineUnixSecs < 0n ||
    req.deadlineUnixSecs > U64_MAX
  ) {
    return { ok: false, reason: "deadlineUnixSecs must be a u64 BigInt" };
  }
  for (const [field, val, requireNonZero] of [
    ["recipient", req.recipient, true],
    ["targetAssetId", req.targetAssetId, true],
    ["invoiceDigest", req.invoiceDigest, false],
  ]) {
    if (typeof val !== "string" || !LOWER_HEX_64.test(val)) {
      return { ok: false, reason: `${field} must be 64 lowercase hex characters` };
    }
    if (requireNonZero && val === ZERO_HEX_64) {
      return { ok: false, reason: `${field} must be non-zero` };
    }
  }

  let out =
    `budlum:pay/v1?amount=${req.targetAmount.toString()}` +
    `&asset=${req.targetAssetId}` +
    `&deadline=${req.deadlineUnixSecs.toString()}` +
    `&domain=${req.targetDomain.toString()}` +
    `&invoice=${req.invoiceDigest}` +
    `&recipient=${req.recipient}`;

  if (req.callbackRef !== null && req.callbackRef !== undefined) {
    const check = validateSafeLabel("callbackRef", req.callbackRef, 64);
    if (!check.ok) {
      return check;
    }
    out += `&callback=${req.callbackRef}`;
  }

  if (out.length > MAX_PAYMENT_URI_BYTES || !isAscii(out)) {
    return { ok: false, reason: "payment request URI exceeds 512 ASCII bytes" };
  }
  return { ok: true, uri: out };
}

/**
 * Decode a canonical `budlum:pay/v1?...` URI fail-closed.
 */
export function parsePaymentRequestUri(raw) {
  if (typeof raw !== "string") {
    return { ok: false, reason: "payment request URI must be a string" };
  }
  if (!raw.startsWith("budlum:pay/v1?")) {
    return { ok: false, reason: "payment request URI must start with budlum:pay/v1?" };
  }
  if (raw.length > MAX_PAYMENT_URI_BYTES || !isAscii(raw)) {
    return { ok: false, reason: "payment request URI exceeds 512 ASCII bytes" };
  }

  const query = raw.slice("budlum:pay/v1?".length);
  const kv = new Map();
  for (const pair of query.split("&")) {
    const eq = pair.indexOf("=");
    if (eq === -1) {
      return { ok: false, reason: "malformed query parameter in payment request URI" };
    }
    const k = pair.slice(0, eq);
    const v = pair.slice(eq + 1);
    if (!ALLOWED_KEYS.has(k)) {
      return { ok: false, reason: `unknown parameter ${k} in payment request URI` };
    }
    if (kv.has(k)) {
      return { ok: false, reason: `duplicate parameter ${k} in payment request URI` };
    }
    kv.set(k, v);
  }

  for (const required of ["amount", "asset", "deadline", "domain", "invoice", "recipient"]) {
    if (!kv.has(required)) {
      return { ok: false, reason: `missing ${required} in payment request URI` };
    }
  }

  const amountRaw = kv.get("amount");
  const domainRaw = kv.get("domain");
  const deadlineRaw = kv.get("deadline");
  if (!DECIMAL_UINT.test(amountRaw) || !DECIMAL_UINT.test(domainRaw) || !DECIMAL_UINT.test(deadlineRaw)) {
    return { ok: false, reason: "numeric URI fields must be canonical unsigned base-10 integers" };
  }

  const value = {
    version: 1,
    recipient: kv.get("recipient"),
    targetDomain: BigInt(domainRaw),
    targetAssetId: kv.get("asset"),
    targetAmount: BigInt(amountRaw),
    invoiceDigest: kv.get("invoice"),
    deadlineUnixSecs: BigInt(deadlineRaw),
    callbackRef: kv.has("callback") ? kv.get("callback") : null,
  };

  const reencoded = encodePaymentRequestUri(value);
  if (!reencoded.ok) {
    return reencoded;
  }
  if (reencoded.uri !== raw) {
    return { ok: false, reason: "payment request URI is not in canonical byte order" };
  }
  return { ok: true, value };
}

/**
 * Format a decoded payment request for the browser wallet confirmation screen.
 * Keeps raw chain/domain IDs hidden inside `advancedDetails` by default.
 */
export function formatPaymentPrompt(parsed, assetDisplaySymbol = "BUD") {
  const symCheck = validateSafeLabel("assetDisplaySymbol", assetDisplaySymbol, 16);
  if (!symCheck.ok) {
    return symCheck;
  }
  return {
    ok: true,
    headline: `${parsed.targetAmount.toString()} ${assetDisplaySymbol}`,
    recipientShort: `${parsed.recipient.slice(0, 10)}...${parsed.recipient.slice(-8)}`,
    deadlineUnixSecs: parsed.deadlineUnixSecs.toString(),
    advancedDetails: {
      targetDomain: parsed.targetDomain.toString(),
      targetAssetId: parsed.targetAssetId,
      invoiceDigest: parsed.invoiceDigest,
      callbackRef: parsed.callbackRef,
    },
  };
}
