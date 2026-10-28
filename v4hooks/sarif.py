"""SARIF 2.1.0 output, so findings show up in GitHub Code Scanning and other viewers.

File paths in a scan are relative to the Foundry project root. When that root isn't the
repository root (e.g. a project under ``contracts/``), pass ``uri_prefix`` so annotations
land on the right file.
"""

from __future__ import annotations

from typing import Any

from .detectors import ALL_DETECTORS
from .scanner import ScanResult

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
LEVELS = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}
# GitHub sorts and filters Code Scanning alerts by this 0-10 score.
SECURITY_SEVERITY = {"critical": "9.5", "high": "8.0", "medium": "5.5", "low": "3.0", "info": "1.0"}
RULE_SEVERITY = {"V4H-01": "8.0", "V4H-02": "5.5", "V4H-03": "8.0"}
HELP_URI = "https://github.com/0xlordgrace/v4hooks/blob/main/README.md"


def to_sarif(result: ScanResult, uri_prefix: str = "", tool_version: str = "") -> dict[str, Any]:
    prefix = uri_prefix.strip("/")
    prefix = f"{prefix}/" if prefix else ""
    rules = [
        {
            "id": d.id,
            "name": d.id.replace("-", ""),
            "shortDescription": {"text": d.title},
            "fullDescription": {"text": (d.__doc__ or d.title).strip().splitlines()[0]},
            "helpUri": HELP_URI,
            # GitHub reads security-severity from the rule, not the result.
            "properties": {"tags": ["security", "uniswap-v4", "hooks"],
                           "security-severity": RULE_SEVERITY.get(d.id, "5.0")},
        }
        for d in ALL_DETECTORS
    ]
    results = []
    for f in result.findings:
        results.append(
            {
                "ruleId": f.detector,
                "level": LEVELS.get(f.severity, "warning"),
                "message": {"text": f.message},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": prefix + f.file},
                            "region": {"startLine": max(f.line_start, 1), "endLine": max(f.line_end, f.line_start, 1)},
                        },
                        "logicalLocations": [{"fullyQualifiedName": f"{f.contract}.{f.function}", "kind": "function"}],
                    }
                ],
                "partialFingerprints": {"v4hooks/v1": f.fingerprint},
                "properties": {
                    "severity": f.severity,
                    "confidence": f.confidence,
                    "security-severity": SECURITY_SEVERITY.get(f.severity, "5.0"),
                },
            }
        )
    driver: dict[str, Any] = {"name": "v4hooks", "informationUri": HELP_URI, "rules": rules}
    if tool_version:
        driver["version"] = tool_version
    return {"$schema": SARIF_SCHEMA, "version": "2.1.0", "runs": [{"tool": {"driver": driver}, "results": results}]}
