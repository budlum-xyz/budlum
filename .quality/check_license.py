#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""License consistency gate: PolyForm Shield 1.0.0.

Why this file exists: when the license changes, changing a single LICENSE file
IS NOT ENOUGH. In this repository the license was declared in FIVE separate places:
  LICENSE.md, budzero/LICENSE, 6 x Cargo.toml, the README badge, NOTICE
and BEFORE the change they CONTRADICTED each other: budzero/LICENSE said "MIT
License" while budzero/Cargo.toml said "Apache-2.0". Nobody had noticed
because there was no program checking it.

Also: third party attributions (Plonky3 MIT OR Apache-2.0, the deny.toml
dependency allow list) MUST NOT BE CHANGED. This gate protects those too.
"""
import glob
import hashlib
import io
import re
import sys

SPDX = "LicenseRef-PolyForm-Shield-1.0.0"
CANONICAL_LENGTH = 5747
CANONICAL_SHA256 = "80ee7a573d585da44a6b993274071240470d2645922fff9f37910418b34fb836"

OK = F = 0

def k(name, condition, extra=""):
    global OK, F
    if condition: OK += 1
    else: F += 1; print(f"  FAILED: {name} {extra}")

lic_bytes = io.open("LICENSE.md", "rb").read()
lic = lic_bytes.decode("utf-8")

# A network independent digest of the canonical Shield text in PolyForm's 1.0.0 repository.
# The local LICENSE.md then carries the project specific mandatory notices.
canonical_digest = hashlib.sha256(lic_bytes[:CANONICAL_LENGTH]).hexdigest()
k(
    "LICENSE.md starts with the canonical PolyForm text",
    len(lic_bytes) >= CANONICAL_LENGTH and canonical_digest == CANONICAL_SHA256,
)

BOLUMLER = ["Acceptance", "Copyright License", "Distribution License", "Notices",
            "Changes and New Works License", "Patent License", "Noncompete",
            "Competition", "New Products", "Discontinued Products",
            "Sales of Business", "Fair Use", "No Other Rights", "Patent Defense",
            "Violations", "No Liability", "Definitions"]

for p in ("LICENSE.md", "budzero/LICENSE"):
    s = io.open(p, encoding="utf-8").read()
    k(f"{p}: Shield basligi", "PolyForm Shield License 1.0.0" in s)
    for b in BOLUMLER:
        k(f"{p}: '{b}' bolumu", f"## {b}" in s)
    k(f"{p}: Required Notice", "Required Notice:" in s)
    k(f"{p}: Licensor Line of Business", "Licensor Line of Business:" in s)
    # Eski lisanslarin GERI GELMEDIGI
    k(f"{p}: Apache metni yok", "Apache License" not in s)
    k(f"{p}: no MIT text", "MIT License" not in s)

# Every Cargo.toml must declare the same SPDX
for c in sorted(glob.glob("**/Cargo.toml", recursive=True)):
    s = io.open(c, encoding="utf-8").read()
    m = re.search(r'^license\s*=\s*"(.+?)"', s, re.M)
    if m:
        k(f"{c}: SPDX = {SPDX}", m.group(1) == SPDX, m.group(1))
k("SPDX LicenseRef syntax",
  re.fullmatch(r"LicenseRef-[A-Za-z0-9.\-]+", SPDX) is not None)

r = io.open("README.md", encoding="utf-8").read()
k("the README badge is Shield", "PolyForm%20Shield" in r)
k("the README has NO old Apache badge", "license-Apache" not in r)

n = io.open("docs/NOTICE", encoding="utf-8").read()
k("NOTICE declares Shield", "PolyForm Shield License 1.0.0" in n)
# --- THIRD PARTY ATTRIBUTIONS MUST BE PRESERVED ---
k("the NOTICE Plonky3 attribution is preserved", "Plonky3" in n)
k("the NOTICE Plonky3 license is preserved", "MIT OR Apache-2.0" in n)
d = io.open("budzero/deny.toml", encoding="utf-8").read()
k("the deny.toml dependency allow list is preserved",
  '"Apache-2.0"' in d and '"MIT"' in d)

print(f"\nRESULT: {OK} PASSED, {F} FAILED")
sys.exit(1 if F else 0)
