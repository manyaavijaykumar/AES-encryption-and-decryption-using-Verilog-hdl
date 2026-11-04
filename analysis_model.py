"""Source-dependent RTL estimates for the local AES-128 workflow.

These figures are a transparent software model of source structure.  They are
not device utilisation, timing closure, or measured on-chip power.
"""

from __future__ import annotations

import hashlib
import math
import re
from pathlib import Path


def _clean(source: str) -> str:
    return re.sub(r"/\*.*?\*/|//[^\n]*", "", source, flags=re.S)


def analyze_sources(source_dir: Path, names: list[str], overrides: dict[str, Path] | None = None,
                    target_period: float = 10.0, text_overrides: dict[str, str] | None = None) -> dict:
    overrides = overrides or {}
    text_overrides = text_overrides or {}
    sources = {name: _clean(text_overrides[name] if name in text_overrides else
                            (overrides.get(name) or source_dir / name).read_text(encoding="utf-8"))
               for name in names if (overrides.get(name) or source_dir / name).is_file()}
    if not sources:
        raise ValueError("No Verilog design sources are available")
    if not math.isfinite(target_period) or not 1.0 <= target_period <= 1000.0:
        raise ValueError("Target clock period must be between 1 and 1000 ns")
    for name, content in sources.items():
        if len(re.findall(r"\bmodule\b", content)) != len(re.findall(r"\bendmodule\b", content)):
            raise ValueError(f"Unbalanced module/endmodule in {name}")
    joined = "\n".join(sources.values())
    required = {"aes_top", "aes_encrypt", "aes_decrypt", "key_expansion"}
    modules = set(re.findall(r"\bmodule\s+(\w+)", joined))
    if "aes_top.v" in names and not required.issubset(modules):
        raise ValueError("One or more required AES modules are missing")
    digest = hashlib.sha256(joined.encode("utf-8")).hexdigest()[:12]
    xor_count = len(re.findall(r"\^", joined))
    mux_count = len(re.findall(r"\?", joined)) + len(re.findall(r"\bif\s*\(", joined))
    case_count = len(re.findall(r"\bcase\s*\(", joined))
    lookup_entries = len(re.findall(r"\b8'h[0-9a-fA-F]{2}\s*:", joined))
    add_key_instances = sum(len(re.findall(r"\badd_round_key\s+u_\w+\s*\(", text)) for text in sources.values())
    register_bits = 0
    for text in sources.values():
        for match in re.finditer(r"\b(?:reg|output\s+reg)\s*(?:\[(\d+)\s*:\s*(\d+)\])?\s+(\w+)", text):
            high, low = match.group(1), match.group(2)
            register_bits += abs(int(high) - int(low)) + 1 if high is not None else 1
    # The terms below are structural proxies. They change when RTL is edited.
    lut = 250 + lookup_entries * 3 + xor_count * 3 + mux_count * 7 + case_count * 14 + add_key_instances * 128
    ff = max(1, register_bits)
    slices = (lut + 3) // 4
    memory_lut = max(0, lookup_entries // 8)
    logic_levels = 4 + min(18, case_count + mux_count // 5)
    logic_delay = round(1.35 + logic_levels * 0.23 + add_key_instances * 0.11, 3)
    routing_delay = round(0.55 + slices * 0.0011, 3)
    period = round(logic_delay + routing_delay, 3)
    slack = round(target_period - period, 3)
    dynamic = round((lut * 0.000105 + ff * 0.000025) * (10.0 / target_period), 4)
    static = round(0.08 + slices * 0.000012, 4)
    total = round(dynamic + static, 4)
    return {
        "source_digest": digest,
        "source_count": len(sources),
        "structural_counts": {
            "XOR operators": xor_count,
            "Conditional operations": mux_count,
            "Case blocks": case_count,
            "S-box entries": lookup_entries,
            "AddRoundKey instances": add_key_instances,
            "Declared register bits": ff,
        },
        "utilization": {
            "Slice LUTs": lut,
            "Flip-Flops": ff,
            "Slice Registers": ff,
            "Estimated Slices": slices,
            "Block RAM Tiles": 0,
            "Distributed Memory LUTs": memory_lut,
            "DSP Slices": 0,
            "Clock Buffers": 1,
            "Input / Output Resources": sum(
                abs(int(high) - int(low)) + 1 if high else 1
                for high, low in re.findall(
                    r"\b(?:input|output)\s+(?:wire\s+|reg\s+)?(?:\[(\d+)\s*:\s*(\d+)\])?\s+\w+",
                    sources.get("aes_top.v", ""),
                )
            ),
        },
        "timing": {
            "Critical Path": f"{period:.3f} ns",
            "Data-Path Delay": f"{period:.3f} ns",
            "Logic Delay": f"{logic_delay:.3f} ns",
            "Routing Delay": f"{routing_delay:.3f} ns",
            "Setup Timing": "MET" if slack >= 0 else "VIOLATED",
            "Hold Timing": "Modeled; not verified",
            "Worst negative slack": f"{slack:+.3f} ns",
            "Total negative slack": f"{min(0, slack):.3f} ns",
            "Minimum clock period": f"{period:.3f} ns",
            "Estimated maximum frequency": f"{1000 / period:.2f} MHz",
            "Target clock period": f"{target_period:.2f} ns",
        },
        "power": {
            "Total On-Chip Power": f"{total:.4f} W",
            "Dynamic Power": f"{dynamic:.4f} W",
            "Static Power": f"{static:.4f} W",
            "Clock-Network Power": f"{dynamic * .10:.4f} W",
            "Logic Power": f"{dynamic * .40:.4f} W",
            "Signal Power": f"{dynamic * .35:.4f} W",
            "Input / Output Power": f"{dynamic * .15:.4f} W",
            "BRAM Power": "0.0000 W",
            "DSP Power": "0.0000 W",
        },
    }
