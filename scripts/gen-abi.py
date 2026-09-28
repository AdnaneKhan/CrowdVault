#!/usr/bin/env python3
"""Regenerate web/src/abi.ts from the Foundry build output.

Run `forge build` in contracts/ first. CI regenerates the file and fails if it
differs from the committed one, so the web app can't drift from the contracts.
"""
import json
import pathlib

ROOT = pathlib.Path(__file__).resolve().parent.parent
OUT = ROOT / "contracts" / "out"


def abi(contract: str) -> list:
    return json.loads((OUT / f"{contract}.sol" / f"{contract}.json").read_text())["abi"]


exports = [
    f"export const {name} = {json.dumps(abi(contract), indent=2)} as const;"
    for name, contract in [("crowdVaultAbi", "CrowdVault"), ("factoryAbi", "CrowdVaultFactory")]
]
text = "// Generated from contracts/out (forge build).\n" + "\n\n".join(exports) + "\n"
(ROOT / "web" / "src" / "abi.ts").write_text(text)
