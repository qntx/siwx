#!/usr/bin/env bash
# Regenerate vectors/evm/e2e/contracts.json from the Solidity fixtures.
# Reproducible: solc and evm_version are pinned and metadata/trailer output
# is disabled, so the emitted bytecode is byte-identical across machines.
set -euo pipefail
cd "$(dirname "$0")/../.."
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
mkdir -p "$TMP/src"
cp vectors/evm/e2e/*.sol "$TMP/src/"
printf '[profile.default]\nsolc_version = "0.8.36"\nevm_version = "paris"\noptimizer = true\noptimizer_runs = 200\nbytecode_hash = "none"\ncbor_metadata = false\n' > "$TMP/foundry.toml"
forge build --root "$TMP" --out "$TMP/out" --quiet
python3 - "$TMP" <<'PY'
import json, sys, subprocess
tmp = sys.argv[1]
out = {}
ver = subprocess.run(
    ["forge", "fmt", "--version"], capture_output=True, text=True
).stdout.strip()
solc = subprocess.run(
    ["forge", "--root", tmp, "inspect", "Owner1271", "metadata"],
    capture_output=True, text=True,
).stdout
import re
m = re.search(r'"compiler":\s*{\s*"version":\s*"([0-9.]+)"', solc)
for name in ("Owner1271", "Factory"):
    art = json.load(open(f"{tmp}/out/{name}.sol/{name}.json"))
    out[name] = {
        "creationBytecode": art["bytecode"]["object"],
        "deployedBytecode": art["deployedBytecode"]["object"],
    }
doc = {
    "solc": m.group(1) if m else "unknown",
    "optimizer": {"enabled": True, "runs": 200},
    "evm_version": "paris",
    "contracts": out,
}
with open("vectors/evm/e2e/contracts.json", "w") as f:
    f.write(json.dumps(doc, indent=2) + "\n")
print("wrote vectors/evm/e2e/contracts.json")
PY
