// Copyright budlum-xyz (https://github.com/budlum-xyz)
// Licensed under PolyForm Shield License 1.0.0.

import test from "node:test";
import assert from "node:assert/strict";
import {
  isValidLabel,
  parseBnsHost,
  detectConfusableBudName,
} from "./bns_host.js";
import {
  parsePaymentRequestUri,
  encodePaymentRequestUri,
  formatPaymentPrompt,
} from "./payment_uri.js";

test("rejects punycode and RFC 5891 R-LDH homograph labels", () => {
  assert.equal(isValidLabel("xn--pypal-4ve", 3), false);
  assert.equal(isValidLabel("ab--cd", 3), false);
  assert.equal(parseBnsHost("xn--pypal-4ve.bud").ok, false);
  assert.equal(parseBnsHost("xn--pypal-4ve.budlum.xyz").ok, false);
  assert.equal(parseBnsHost("pay.xn--pypal-4ve.bud").ok, false);

  // Legitimate single internal hyphen remains valid.
  assert.equal(isValidLabel("my-shop", 3), true);
  assert.equal(parseBnsHost("my-shop.bud").ok, true);
  assert.equal(parseBnsHost("pay.my-shop.bud").ok, true);
  // Reserved labels remain rejected.
  assert.equal(parseBnsHost("api.budlum.xyz").ok, false);
});

test("detects confusable ASCII .bud lookalikes and allows exact matches", () => {
  const known = ["paypal.bud", "google.bud", "market.bud", "budlum.bud", "wall.bud", "dao.bud"];
  assert.equal(detectConfusableBudName("paypal.bud", known), null);
  assert.equal(detectConfusableBudName("coffee.bud", known), null);

  const w1 = detectConfusableBudName("paypa1.bud", known);
  assert.equal(w1?.similarTo, "paypal.bud");
  assert.equal(w1?.reason, "visual_skeleton_match");

  const w2 = detectConfusableBudName("g00gle.bud", known);
  assert.equal(w2?.similarTo, "google.bud");

  const w3 = detectConfusableBudName("rnarket.bud", known);
  assert.equal(w3?.similarTo, "market.bud");

  const w4 = detectConfusableBudName("vvall.bud", known);
  assert.equal(w4?.similarTo, "wall.bud");

  const w5 = detectConfusableBudName("clao.bud", known);
  assert.equal(w5?.similarTo, "dao.bud");

  const w6 = detectConfusableBudName("pay-pal.bud", known);
  assert.equal(w6?.similarTo, "paypal.bud");

  const w7 = detectConfusableBudName("budlun.bud", known);
  assert.equal(w7?.similarTo, "budlum.bud");
  assert.equal(w7?.reason, "near_edit_distance");

  // Spoofing reserved protocol names (e.g. faucet.bud -> fauc3t.bud) must also warn.
  const w8 = detectConfusableBudName("fauc3t.bud", ["faucet.bud"]);
  assert.equal(w8?.similarTo, "faucet.bud");
  assert.equal(w8?.reason, "visual_skeleton_match");
});

test("canonical budlum:pay/v1 URI roundtrip and fail-closed rejections", () => {
  const asset = "22".repeat(32);
  const invoice = "33".repeat(32);
  const recipient = "11".repeat(32);
  const req = {
    version: 1,
    recipient,
    targetDomain: 2n,
    targetAssetId: asset,
    targetAmount: 100000000n,
    invoiceDigest: invoice,
    deadlineUnixSecs: 1800000000n,
    callbackRef: "pos-term-7",
  };
  const encoded = encodePaymentRequestUri(req);
  assert.ok(encoded.ok, encoded.reason);
  assert.ok(encoded.uri.startsWith("budlum:pay/v1?amount=100000000&"));

  const decoded = parsePaymentRequestUri(encoded.uri);
  assert.ok(decoded.ok, decoded.reason);
  assert.deepEqual(decoded.value, req);

  // Non-canonical key order must fail closed.
  const reordered = `budlum:pay/v1?domain=2&amount=100000000&asset=${asset}&deadline=1800000000&invoice=${invoice}&recipient=${recipient}`;
  assert.equal(parsePaymentRequestUri(reordered).ok, false);

  // Duplicate key, unknown key, zero recipient, zero domain, u128 overflow, traversal callback all fail closed.
  assert.equal(parsePaymentRequestUri(`${encoded.uri}&domain=2`).ok, false);
  assert.equal(parsePaymentRequestUri(`${encoded.uri}&evil=1`).ok, false);
  assert.equal(encodePaymentRequestUri({ ...req, recipient: "00".repeat(32) }).ok, false);
  assert.equal(encodePaymentRequestUri({ ...req, targetDomain: 0n }).ok, false);
  assert.equal(encodePaymentRequestUri({ ...req, targetAmount: 0n }).ok, false);
  assert.equal(encodePaymentRequestUri({ ...req, targetAmount: 1n << 128n }).ok, false);
  assert.equal(encodePaymentRequestUri({ ...req, callbackRef: "../escape" }).ok, false);
  assert.equal(parsePaymentRequestUri("javascript:alert(1)").ok, false);

  // User-facing payment prompt hides raw network/domain names in primary headline.
  const prompt = formatPaymentPrompt(decoded.value, "USDC");
  assert.equal(prompt.ok, true);
  assert.equal(prompt.headline, "100000000 USDC");
  assert.equal(prompt.headline.includes("domain"), false);
  assert.equal(prompt.advancedDetails.targetDomain, "2");
});
