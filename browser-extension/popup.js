// Copyright budlum-xyz (https://github.com/budlum-xyz)
// Licensed under PolyForm Shield License 1.0.0.

const rpcsEl = document.getElementById("rpcs");
const headersEl = document.getElementById("headers");
const saveBtn = document.getElementById("save");
const savedEl = document.getElementById("saved");

async function load() {
  const data = await chrome.storage.local.get(["rpcEndpoints", "trustedHeaders"]);
  rpcsEl.value = (data.rpcEndpoints || []).join("\n");
  headersEl.value = JSON.stringify(data.trustedHeaders || [], null, 2);
}

saveBtn.addEventListener("click", async () => {
  const rpcEndpoints = rpcsEl.value
    .split(/\r?\n/)
    .map((s) => s.trim())
    .filter(Boolean);

  let trustedHeaders;
  try {
    trustedHeaders = JSON.parse(headersEl.value || "[]");
    if (!Array.isArray(trustedHeaders)) {
      throw new Error("trustedHeaders must be a JSON array");
    }
  } catch (err) {
    savedEl.textContent = "Invalid JSON: " + err.message;
    return;
  }

  await chrome.storage.local.set({ rpcEndpoints, trustedHeaders });
  savedEl.textContent = "Saved";
});

load();
