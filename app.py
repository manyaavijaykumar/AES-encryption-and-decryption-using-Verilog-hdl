#!/usr/bin/env python3
"""Local AES-128 RTL workspace and source-derived analysis API."""

from __future__ import annotations

import argparse
import json
import mimetypes
import os
import re
import secrets
import threading
import time
import webbrowser
from dataclasses import asdict, dataclass
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlparse

from aes_core import run_aes
from analysis_model import analyze_sources


ROOT = Path(__file__).resolve().parent
STATIC_DIR = ROOT / "static"
VERILOG_DIR = ROOT / "verilog"

DESIGN_SOURCES = [
    "aes_top.v",
    "aes_encrypt.v",
    "aes_decrypt.v",
    "key_expansion.v",
    "sbox.v",
    "inv_sbox.v",
    "sub_bytes.v",
    "inv_sub_bytes.v",
    "shift_rows.v",
    "inv_shift_rows.v",
    "mix_columns.v",
    "inv_mix_columns.v",
    "add_round_key.v",
    "round_control.v",
]
SIMULATION_SOURCES = ["aes_tb.v"]
for discovered in sorted(VERILOG_DIR.glob("*.v")):
    if discovered.name not in DESIGN_SOURCES and discovered.name not in SIMULATION_SOURCES:
        DESIGN_SOURCES.append(discovered.name)
ALLOWED_SOURCES = set(DESIGN_SOURCES + SIMULATION_SOURCES)


@dataclass
class RunStatus:
    name: str
    synthesis: str = "Not started"
    utilization: str = "-"
    timing: str = "-"
    power: str = "-"
    status: str = "Not started"


RUNS = {
    "initial_rtl": RunStatus("initial_rtl"),
    "optimized_rtl": RunStatus("optimized_rtl"),
}


PROJECT_PROPERTIES = {
    "Top Module": "aes_top",
    "Target Language": "Verilog",
    "Data Width": "128-bit",
    "Key Width": "128-bit",
    "AES Rounds": "10",
    "Operation": "Encryption / Decryption",
    "Control": "Start, Busy, Done",
}

_RANDOM_EXAMPLE_LOCK = threading.Lock()
_LAST_RANDOM_OUTPUT = {"encrypt": None, "decrypt": None}


def top_ports(source: str) -> dict[str, str]:
    """List declared aes_top port directions and bus widths."""
    clean = re.sub(r"/\*.*?\*/|//[^\n]*", "", source, flags=re.S)
    ports = {}
    for direction, high, low, name in re.findall(
        r"\b(input|output)\s+(?:wire\s+|reg\s+)?(?:\[(\d+)\s*:\s*(\d+)\]\s*)?(\w+)", clean
    ):
        width = abs(int(high) - int(low)) + 1 if high else 1
        ports[name] = f"{width}-bit {direction}"
    return ports


def project_payload() -> dict:
    """Describe the project without exposing arbitrary filesystem paths."""
    return {
        "name": "aes128_project",
        "top_module": "aes_top",
        "design_sources": [name for name in DESIGN_SOURCES if (VERILOG_DIR / name).is_file()],
        "simulation_sources": [name for name in SIMULATION_SOURCES if (VERILOG_DIR / name).is_file()],
        "properties": PROJECT_PROPERTIES,
        "ports": top_ports((VERILOG_DIR / "aes_top.v").read_text(encoding="utf-8")),
        "runs": [asdict(run) for run in RUNS.values()],
        "notice": "AES-128 design workspace. Hardware analysis uses RTL-based estimates.",
    }


def safe_source_path(name: str) -> Path:
    """Return a project Verilog path and reject traversal or other file types."""
    if not name or Path(name).name != name or not name.lower().endswith(".v"):
        raise ValueError("Only a simple .v filename is accepted")
    if name not in ALLOWED_SOURCES:
        raise ValueError("That file is not part of this project")
    path = (VERILOG_DIR / name).resolve()
    if path.parent != VERILOG_DIR.resolve():
        raise ValueError("Invalid source path")
    return path


def synthesis_report(objective: str = "area", target_period: float = 10.0,
                     draft_name: str = "", draft_content: str = "") -> dict:
    """Refresh analysis from the current Verilog files on every request."""
    if objective != "area":
        raise ValueError("The selected optimization objective is area")
    if draft_name and (draft_name not in DESIGN_SOURCES or len(draft_content) > 1_000_000):
        raise ValueError("Invalid draft Verilog source")
    names = [name for name in DESIGN_SOURCES if (VERILOG_DIR / name).is_file()]
    draft = {draft_name: draft_content} if draft_name else {}
    initial = analyze_sources(VERILOG_DIR, names, target_period=target_period, text_overrides=draft)
    optimized_draft = {key: value for key, value in draft.items() if key != "aes_encrypt.v"}
    optimized = analyze_sources(VERILOG_DIR, names, {"aes_encrypt.v": ROOT / "optimized" / "aes_encrypt.v"},
                                target_period, optimized_draft)
    for key, data in (("initial_rtl", initial), ("optimized_rtl", optimized)):
        run = RUNS[key]
        run.synthesis = "Analyzed"
        run.utilization = f'{data["utilization"]["Slice LUTs"]:,} LUT (est.)'
        run.timing = data["timing"]["Critical Path"] + " (est.)"
        run.power = data["power"]["Total On-Chip Power"] + " (est.)"
        run.status = "Results ready"
    return {
        "analysis_kind": "RTL-based hardware estimates",
        "objective": objective,
        "description": "Area variant shares the encryption AddRoundKey datapath across regular and final rounds.",
        "source_digest": initial["source_digest"],
        "target_period": target_period,
        "initial": initial,
        "optimized": optimized,
        "utilization": optimized["utilization"],
        "timing": optimized["timing"],
        "power": optimized["power"],
        "runs": [asdict(item) for item in RUNS.values()],
    }


def elaboration_payload() -> dict:
    modules = {}
    for name in DESIGN_SOURCES:
        path = VERILOG_DIR / name
        if not path.is_file():
            continue
        source = re.sub(r"/\*.*?\*/|//[^\n]*", "", path.read_text(encoding="utf-8"), flags=re.S)
        for match in re.finditer(r"\bmodule\s+(\w+)", source):
            modules[match.group(1)] = {"id": match.group(1), "label": match.group(1), "source": name, "text": source}
    edges = []
    for module in modules.values():
        for child, instance in re.findall(r"\b(\w+)\s+(u_\w+)\s*\(", module["text"]):
            if child in modules:
                edges.append({"from": module["id"], "to": child, "instance": instance})
    return {
        "title": "RTL Elaboration - AES-128",
        "nodes": [{key: value for key, value in module.items() if key != "text"} for module in modules.values()],
        "edges": edges,
        "notice": "Module instances parsed from the current Verilog sources.",
    }


def testbench_checks() -> list[dict]:
    """Check the vectors currently declared in the bundled testbench."""
    source = (VERILOG_DIR / "aes_tb.v").read_text(encoding="utf-8")
    values = {name: value.upper() for name, value in re.findall(
        r"localparam\s+\[127:0\]\s+(PLAINTEXT|AES_KEY|CIPHERTEXT)\s*=\s*128'h([0-9a-fA-F]{32})", source
    )}
    if len(values) != 3:
        return [{"name": "Testbench vectors", "pass": False, "detail": "Required 128-bit vectors are missing"}]
    encrypted = run_aes("encrypt", values["PLAINTEXT"], values["AES_KEY"])["output"]
    decrypted = run_aes("decrypt", values["CIPHERTEXT"], values["AES_KEY"])["output"]
    return [
        {"name": "Encryption vector", "pass": encrypted == values["CIPHERTEXT"], "actual": encrypted,
         "expected": values["CIPHERTEXT"]},
        {"name": "Decryption vector", "pass": decrypted == values["PLAINTEXT"], "actual": decrypted,
         "expected": values["PLAINTEXT"]},
    ]


def random_example(mode: str) -> dict:
    """Return fresh AES-128 inputs for the selected Python operation."""
    if mode not in {"encrypt", "decrypt"}:
        raise ValueError("Mode must be 'encrypt' or 'decrypt'")
    with _RANDOM_EXAMPLE_LOCK:
        while True:
            data = secrets.token_hex(16).upper()
            key = secrets.token_hex(16).upper()
            output = run_aes(mode, data, key)["output"]
            if output != _LAST_RANDOM_OUTPUT[mode]:
                _LAST_RANDOM_OUTPUT[mode] = output
                return {"mode": mode, "data": data, "key": key, "output": output}


def project_report(target_period: float = 10.0) -> str:
    """Build a reproducible report from current design sources and models."""
    report = synthesis_report(target_period=target_period)
    checks = testbench_checks()
    lines = [
        "# AES-128 design analysis report (quotation KS5595)", "",
        "## Method", "",
        "The AES-128 reference model produces the functional trace and checks vectors declared in aes_tb.v. Hardware figures are RTL-based estimates for design comparison;",
        f"Source digest: `{report['source_digest']}`. Target period: {target_period:g} ns. Optimization objective: area.", "",
        "## Functional checks", "",
        "| Check | Result | Actual | Expected |", "|---|---|---|---|",
    ]
    lines.extend(f"| {item['name']} | {'PASS' if item['pass'] else 'FAIL'} | `{item.get('actual', '-')}` | `{item.get('expected', '-')}` |" for item in checks)
    vector_source = (VERILOG_DIR / "aes_tb.v").read_text(encoding="utf-8")
    vectors = {name: value for name, value in re.findall(
        r"localparam\s+\[127:0\]\s+(PLAINTEXT|AES_KEY|CIPHERTEXT)\s*=\s*128'h([0-9a-fA-F]{32})", vector_source
    )}
    if len(vectors) == 3:
        simulation = run_aes("encrypt", vectors["PLAINTEXT"], vectors["AES_KEY"])
        lines += ["", "## Encryption round trace", "",
                  "| Round | Transformation | State | Round key |", "|---:|---|---|---|"]
        lines.extend(f"| {item['round']} | {item['operation']} | `{item['state']}` | `{item['round_key']}` |"
                     for item in simulation["trace"])
        lines += ["", "Control timeline: reset 0–20 ns, start 30–40 ns, busy 40–150 ns, done 150–160 ns. The waveform can be exported as SVG in the workspace."]
    lines += ["", "## Initial and optimized estimates", ""]
    for section, title in (("structural_counts", "RTL structure"), ("utilization", "Resources"),
                           ("timing", "Timing"), ("power", "Power")):
        lines += [f"### {title}", "", "| Metric | Initial | Optimized |", "|---|---:|---:|"]
        for metric, initial in report["initial"][section].items():
            optimized = report["optimized"][section][metric]
            lines.append(f"| {metric} | {initial} | {optimized} |")
        lines.append("")
    lines += ["", "The optimized variant shares one AddRoundKey datapath in the encryption module. Functional vectors are checked against the AES-128 reference model; independent RTL equivalence.", "",
              "## Available project files", "",
              "- Verilog AES modules and self-checking testbench in `verilog/`.",
              "- Area variant in `optimized/aes_encrypt.v`.",
              "- Interactive simulation, round trace, waveform SVG export, source analysis, and reports in the local workspace.", ""]
    return "\n".join(lines)


class AESWorkspaceHandler(BaseHTTPRequestHandler):
    server_version = "AESDesignWorkspace/1.0"

    def log_message(self, fmt: str, *args: object) -> None:
        print(f"[{self.log_date_time_string()}] {fmt % args}")

    def send_json(self, payload: dict, status: HTTPStatus = HTTPStatus.OK) -> None:
        encoded = json.dumps(payload, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(encoded)

    def read_json(self) -> dict:
        raw_length = self.headers.get("Content-Length", "0")
        try:
            length = int(raw_length)
        except ValueError as exc:
            raise ValueError("Invalid Content-Length") from exc
        if length > 2_000_000:
            raise ValueError("Request is too large")
        try:
            return json.loads(self.rfile.read(length).decode("utf-8")) if length else {}
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("Request body must be valid JSON") from exc

    def do_GET(self) -> None:  # noqa: N802 - required by BaseHTTPRequestHandler
        parsed = urlparse(self.path)
        if parsed.path == "/api/project":
            self.send_json(project_payload())
            return
        if parsed.path == "/api/example":
            try:
                mode = parse_qs(parsed.query).get("mode", ["encrypt"])[0]
                self.send_json(random_example(mode))
            except ValueError as exc:
                self.send_json({"error": str(exc)}, HTTPStatus.BAD_REQUEST)
            return
        if parsed.path == "/api/source":
            try:
                name = parse_qs(parsed.query).get("name", [""])[0]
                path = safe_source_path(name)
                self.send_json({"name": name, "content": path.read_text(encoding="utf-8")})
            except (ValueError, OSError) as exc:
                self.send_json({"error": str(exc)}, HTTPStatus.BAD_REQUEST)
            return
        if parsed.path == "/api/elaboration":
            self.send_json(elaboration_payload())
            return
        if parsed.path == "/api/report":
            try:
                period = float(parse_qs(parsed.query).get("target_period", ["10"])[0])
                data = project_report(period).encode("utf-8")
                self.send_response(HTTPStatus.OK)
                self.send_header("Content-Type", "text/markdown; charset=utf-8")
                self.send_header("Content-Disposition", 'attachment; filename="aes128_project_report.md"')
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)
            except ValueError as exc:
                self.send_json({"error": str(exc)}, HTTPStatus.BAD_REQUEST)
            return
        self.serve_static(parsed.path)

    def do_POST(self) -> None:  # noqa: N802 - required by BaseHTTPRequestHandler
        parsed = urlparse(self.path)
        try:
            payload = self.read_json()
            if parsed.path == "/api/simulate":
                result = run_aes(
                    str(payload.get("mode", "encrypt")),
                    str(payload.get("data", "")),
                    str(payload.get("key", "")),
                )
                expected = str(payload.get("expected", "")).replace(" ", "").upper()
                result["expected"] = expected
                result["expected_match"] = result["output"] == expected if expected else None
                result["testbench_checks"] = testbench_checks()
                result["simulator"] = "AES-128 reference simulation"
                self.send_json(result)
                return
            if parsed.path == "/api/save-source":
                name = str(payload.get("name", ""))
                content = str(payload.get("content", ""))
                if len(content) > 1_000_000:
                    raise ValueError("Source is too large")
                path = safe_source_path(name)
                path.write_text(content, encoding="utf-8")
                self.send_json({"saved": True, "name": name, "bytes": len(content.encode("utf-8"))})
                return
            if parsed.path == "/api/add-source":
                name = str(payload.get("name", "")).strip()
                content = str(payload.get("content", ""))
                if not name or Path(name).name != name or not name.lower().endswith(".v"):
                    raise ValueError("Use a simple filename ending in .v")
                if not name.replace("_", "a").replace("-", "a").replace(".", "a").isalnum():
                    raise ValueError("Filename may contain letters, numbers, underscores, and hyphens")
                if len(content) > 1_000_000:
                    raise ValueError("Source is too large")
                path = (VERILOG_DIR / name).resolve()
                if path.parent != VERILOG_DIR.resolve():
                    raise ValueError("Invalid source path")
                if path.exists():
                    raise ValueError("A source with that filename already exists")
                path.write_text(content, encoding="utf-8")
                DESIGN_SOURCES.append(name)
                ALLOWED_SOURCES.add(name)
                self.send_json({"created": True, "name": name, "project": project_payload()}, HTTPStatus.CREATED)
                return
            if parsed.path == "/api/synthesis":
                self.send_json(synthesis_report(str(payload.get("objective", "area")),
                                                float(payload.get("target_period", 10.0)),
                                                str(payload.get("draft_name", "")),
                                                str(payload.get("draft_content", ""))))
                return
            self.send_json({"error": "Unknown API endpoint"}, HTTPStatus.NOT_FOUND)
        except (ValueError, OSError) as exc:
            self.send_json({"error": str(exc)}, HTTPStatus.BAD_REQUEST)
        except Exception as exc:  # keep the local UI responsive while reporting errors
            self.send_json({"error": f"Unexpected server error: {exc}"}, HTTPStatus.INTERNAL_SERVER_ERROR)

    def serve_static(self, raw_path: str) -> None:
        relative = "index.html" if raw_path in {"", "/"} else unquote(raw_path).lstrip("/")
        candidate = (STATIC_DIR / relative).resolve()
        try:
            candidate.relative_to(STATIC_DIR.resolve())
        except ValueError:
            self.send_error(HTTPStatus.FORBIDDEN)
            return
        if not candidate.is_file():
            self.send_error(HTTPStatus.NOT_FOUND)
            return
        data = candidate.read_bytes()
        content_type, _ = mimetypes.guess_type(candidate.name)
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", (content_type or "application/octet-stream") + ("; charset=utf-8" if candidate.suffix in {".html", ".css", ".js", ".svg"} else ""))
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-cache")
        self.end_headers()
        self.wfile.write(data)


def open_browser_later(url: str) -> None:
    def launch() -> None:
        time.sleep(0.6)
        webbrowser.open(url)

    threading.Thread(target=launch, daemon=True).start()


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the AES-128 RTL workspace")
    parser.add_argument("--host", default="127.0.0.1", help="Address to bind (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8765, help="Port to bind (default: 8765)")
    parser.add_argument("--no-browser", action="store_true", help="Do not open a browser automatically")
    args = parser.parse_args()

    os.chdir(ROOT)
    server = ThreadingHTTPServer((args.host, args.port), AESWorkspaceHandler)
    url = f"http://{args.host}:{args.port}/"
    print("AES-128 RTL workspace")
    print(f"Open {url}")
    print("Press Ctrl+C to stop.")
    if not args.no_browser:
        open_browser_later(url)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping server.")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
