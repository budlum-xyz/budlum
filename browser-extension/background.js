// Copyright budlum-xyz (https://github.com/budlum-xyz)
// Licensed under PolyForm Shield License 1.0.0.
//
// Service worker for Budlum BNS Resolver (Manifest V3).
// Maintains user-configured RPC endpoints and trusted header roots in
// extension storage. Never sends decryption keys to any remote endpoint.

const DEFAULT_SETTINGS = Object.freeze({
  rpcEndpoints: [
    "http://127.0.0.1:8545"
  ],
  trustedHeaders: []
});

chrome.runtime.onInstalled.addListener(async () => {
  const current = await chrome.storage.local.get(["rpcEndpoints", "trustedHeaders"]);
  if (!Array.isArray(current.rpcEndpoints) || current.rpcEndpoints.length === 0) {
    await chrome.storage.local.set({ rpcEndpoints: DEFAULT_SETTINGS.rpcEndpoints });
  }
  if (!Array.isArray(current.trustedHeaders)) {
    await chrome.storage.local.set({ trustedHeaders: DEFAULT_SETTINGS.trustedHeaders });
  }
});
