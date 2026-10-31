#!/usr/bin/env bash
# Regenerate vectors/evm/e2e/contracts.json from the Solidity fixtures.
set -euo pipefail
cd "$(dirname "$0")/../.."
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
mkdir -p "$TMP/src"
cp vectors/evm/e2e/*.sol "$TMP/src/"
printf '[profile.default]\noptimizer = true\noptimizer_runs = 200\n' > "$TMP/foundry.toml"
forge build --root "$TMP" --out "$TMP/out" --quiet
python3 - "$TMP" <<'PY'
import json, sys, re, subprocess
tmp = sys.argv[1]
out = {}
ver = subprocess.run(["forge", "--version"], capture_output=True, text=True).stdout.strip()
m = re.search(r"([0-9]+\.[0-9]+\.[0-9]+)", ver)
for name in ("Owner1271", "Factory"):
    art = json.load(open(f"{tmp}/out/{name}.sol/{name}.json"))
    out[name] = {
        "creationBytecode": art["bytecode"]["object"],
        "deployedBytecode": art["deployedBytecode"]["object"],
    }
doc = {
    "solc": m.group(1) if m else "unknown",
    "optimizer": {"enabled": True, "runs": 200},
    "contracts": out,
}
json.dump(doc, open("vectors/evm/e2e/contracts.json", "w"), indent=2)
print("wrote vectors/evm/e2e/contracts.json")
PY
