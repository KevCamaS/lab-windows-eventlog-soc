#!/usr/bin/env python3
# Qué revisé al analizar estos eventos (Kevin)
# - RDP Type 10 desde IP pública a las 03:14 = prioridad alta
# - 4625 seguidos de 4624: no asumir falso positivo sin mirar horario/host
# - Contar fallos por (src_ip, user) >= 3 como sospecha T1110
"""SOC T1: parsea Event ID 4624/4625, extrae IoCs y mapea MITRE."""

from __future__ import annotations

import csv
import json
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CSV_PATH = ROOT / "datos" / "eventos_windows.csv"
OUT = ROOT / "resultados" / "triage_windows.json"

LOGON_TYPE = {"2": "Interactive", "3": "Network", "10": "RemoteInteractive (RDP)"}


def mitre_for(event_id: str) -> str:
    return "T1110" if event_id == "4625" else "T1078"


def main() -> None:
    rows = list(csv.DictReader(CSV_PATH.open(encoding="utf-8")))
    fails: dict[tuple[str, str], int] = defaultdict(int)
    findings = []

    for r in rows:
        key = (r["src_ip"], r["target_user"])
        if r["event_id"] == "4625":
            fails[key] += 1
        findings.append(
            {
                "timestamp": r["timestamp"],
                "event_id": r["event_id"],
                "logon_type": LOGON_TYPE.get(r["logon_type"], r["logon_type"]),
                "user": r["target_user"],
                "src_ip": r["src_ip"],
                "workstation": r["workstation"],
                "iocs": [r["src_ip"], r["target_user"], r["workstation"]],
                "mitre": mitre_for(r["event_id"]),
            }
        )

    spray = [
        {"src_ip": ip, "user": user, "failed_attempts": n, "mitre": "T1110", "severity": "alta"}
        for (ip, user), n in fails.items()
        if n >= 3
    ]

    OUT.parent.mkdir(parents=True, exist_ok=True)
    report = {
        "eventos": len(findings),
        "brute_force_sospechoso": spray,
        "detalle": findings,
        "nota_t1": "Tras varios 4625, buscar 4624 posterior (compromiso). RDP Type 10 desde Internet = priorizar.",
    }
    OUT.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"Eventos: {len(findings)} | posibles brute force: {len(spray)}")
    print(f"Reporte: {OUT}")


if __name__ == "__main__":
    main()
