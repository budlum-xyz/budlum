// Copyright budlum-xyz (https://github.com/budlum-xyz)
// Licensed under PolyForm Shield License 1.0.0.
//
// Gateway-free BNS cryptographic resolver for Manifest V3.
// Fetches `bud_bnsGetProof` from configured RPC endpoints and verifies the
// Merkle inclusion or absence proof locally using `budlum-wallet-core` WASM
// (`BrowserHeaderBook`, `resolve_bns`, `verify_bns_proof`).
//
// Security invariant: unverified RPC responses are NEVER rendered, and
// decryption keys for Sealed B.U.D. 3.0 objects NEVER leave the browser.

import { parseBnsHost } from "./bns_host.js";

const statusEl = document.getElementById("status");
const detailEl = document.getElementById("detail");
const summaryEl = document.getElementById("proof-summary");

function showError(headline, detail) {
  statusEl.textContent = headline;
  statusEl.className = "status err";
  detailEl.textContent = detail;
}

function showVerified(name, record) {
  statusEl.textContent = "Cryptographically verified: " + name;
  statusEl.className = "status ok";
  detailEl.textContent = record.held
    ? "Inclusion proof verified locally against trusted header root."
    : "Absence proof verified locally: name is not registered at this height.";
  summaryEl.hidden = false;
  summaryEl.textContent = JSON.stringify(record, null, 2);
}

async function fetchBnsProof(endpoint, name) {
  const response = await fetch(endpoint, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      jsonrpc: "2.0",
      id: 1,
      method: "bud_bnsGetProof",
      params: [name]
    })
  });
  if (!response.ok) {
    throw new Error("RPC HTTP " + response.status + " from " + endpoint);
  }
  const body = await response.json();
  if (body.error) {
    throw new Error("RPC error from " + endpoint + ": " + (body.error.message || "unknown"));
  }
  if (!body.result) {
    throw new Error("RPC returned empty proof result from " + endpoint);
  }
  return JSON.stringify(body.result);
}

async function loadWalletCoreWasm() {
  const mod = await import("./wasm/budlum_wallet_core.js");
  if (typeof mod.default === "function") {
    await mod.default();
  }
  if (typeof mod.BrowserHeaderBook !== "function" || typeof mod.resolve_bns !== "function") {
    throw new Error("budlum_wallet_core WASM bundle is missing BrowserHeaderBook or resolve_bns");
  }
  return mod;
}

async function run() {
  const params = new URLSearchParams(window.location.search);
  const rawTarget = params.get("target") || "";
  if (!rawTarget) {
    showError("Missing target URL", "Open a .bud or *.budlum.xyz address to resolve it locally.");
    return;
  }

  let parsedUrl;
  try {
    parsedUrl = new URL(rawTarget);
  } catch {
    showError("Invalid target URL", "Could not parse URL: " + rawTarget);
    return;
  }

  const hostResult = parseBnsHost(parsedUrl.host);
  if (!hostResult.ok) {
    showError("Refused host", hostResult.reason);
    return;
  }

  const { rpcEndpoints = [], trustedHeaders = [] } = await chrome.storage.local.get([
    "rpcEndpoints",
    "trustedHeaders"
  ]);

  if (!Array.isArray(rpcEndpoints) || rpcEndpoints.length === 0) {
    showError("No RPC endpoints configured", "Configure at least one Budlum RPC endpoint in the extension popup.");
    return;
  }

  if (!Array.isArray(trustedHeaders) || trustedHeaders.length === 0) {
    showError(
      "Fail-closed: no trusted header roots",
      "No light-client header roots are pinned in extension storage. Add at least one trusted (height, bns_root, epoch) checkpoint in the popup before resolving " + hostResult.name + "."
    );
    return;
  }

  let wasm;
  try {
    wasm = await loadWalletCoreWasm();
  } catch (err) {
    showError(
      "Fail-closed: wallet-core WASM bundle not installed",
      "Build crates/wallet-core with wasm-pack into browser-extension/wasm/ (see browser-extension/README.md). Detail: " + err.message
    );
    return;
  }

  const book = new wasm.BrowserHeaderBook();
  for (const h of trustedHeaders) {
    book.trust(BigInt(h.height), String(h.bns_root), BigInt(h.epoch));
  }

  const settled = await Promise.allSettled(
    rpcEndpoints.map((ep) => fetchBnsProof(ep, hostResult.name))
  );
  const answers = settled
    .filter((r) => r.status === "fulfilled")
    .map((r) => r.value);

  if (answers.length === 0) {
    showError("All RPC endpoints failed", "Could not fetch bud_bnsGetProof for " + hostResult.name + ".");
    return;
  }

  try {
    const verifiedJson = wasm.resolve_bns(hostResult.name, answers, book);
    const verified = JSON.parse(verifiedJson);
    showVerified(hostResult.name, verified);
  } catch (err) {
    showError(
      "Fail-closed: BNS proof verification rejected",
      "None of the RPC proofs verified against your trusted header roots: " + err.message
    );
  }
}

run();
