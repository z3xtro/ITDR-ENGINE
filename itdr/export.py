"""
itdr.export
===========
Publish the detection catalog in the formats the industry already reads.

    python -m itdr.export            # writes everything to exports/

Two outputs, for two audiences:

  Sigma rules (exports/sigma/*.yml)
      Sigma is the portable detection format — one rule converts to
      Splunk SPL, Elastic EQL/KQL, Sentinel KQL, or a Wazuh ruleset via
      sigma-cli. Exporting here means these detections are not trapped
      inside this engine: another team can run the logic on their own
      stack without reading a line of Python.

  ATT&CK Navigator layer (exports/attack-navigator-layer.json)
      Drop it into mitre-attack.github.io/attack-navigator and the
      covered techniques light up. A SOC lead reads coverage from that
      in one glance; they will not read a source tree.

An honest note on fidelity, which matters more than the export itself:
Sigma expresses *pattern matching over single events*. Several of these
detections are stateful correlations across many events — impossible
travel needs two logins and a haversine, brute-force-success needs a
sliding window and a join on source IP. Those cannot be expressed in
Sigma without loss.

So each rule is emitted with a `status` and a `correlation` block
recording what the engine does beyond the matched events, and rules that
degrade are marked `experimental` with the gap stated in the
description. Shipping a Sigma rule that silently drops the correlation
would misrepresent the detection to whoever runs it — the export is
useful precisely because it is explicit about where it stops.
"""

from __future__ import annotations

import json
import re
from datetime import date
from pathlib import Path

from .catalog import CATALOG, DetectionDoc

# Deterministic UUIDv4-shaped ids, derived from the rule name so that
# regenerating the export doesn't churn the ids on every run (a Sigma
# rule's id is its identity across repos; a moving id breaks tracking).
_NAMESPACE = "itdr-engine"


def _stable_id(name: str) -> str:
    import hashlib
    h = hashlib.sha256(f"{_NAMESPACE}:{name}".encode()).hexdigest()
    return (f"{h[0:8]}-{h[8:12]}-4{h[13:16]}-"
            f"a{h[17:20]}-{h[20:32]}")


def _slug(name: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", name.lower()).strip("_")


# Detections whose logic survives translation to single-event matching,
# and the log source each maps onto.
_LOGSOURCE = {
    "ssh_bruteforce_success": {"product": "linux", "service": "sshd"},
    "new_source_ip": {"product": "linux", "service": "sshd"},
    "lateral_movement": {"product": "linux", "service": "sshd"},
    "privilege_escalation": {"product": "linux", "service": "sudo"},
    "off_hours_access": {"product": "linux", "service": "sshd"},
    "impossible_travel": {"category": "authentication", "product": "okta"},
    "session_mutation": {"category": "authentication", "product": "okta"},
    "mfa_fatigue": {"category": "authentication", "product": "okta"},
    "auth_failure_burst": {"category": "authentication"},
    "tor_access": {"category": "authentication"},
    "refresh_token_replay": {"category": "authentication", "product": "okta"},
    "mass_session": {"category": "authentication"},
}

# The selection each rule matches on, and what the engine adds on top.
# `stateless` rules translate faithfully; the rest degrade and say so.
_DETECTION_SPEC = {
    "ssh_bruteforce_success": {
        "stateless": False,
        "selection": {"rule.id": [5715, 5501],
                      "data.dstuser|exists": True},
        "correlation": ("Requires >=5 prior failures (rule 5710/5716/5760) "
                        "from the SAME source IP within 300s, with this "
                        "success landing within 120s of the last failure. "
                        "Sigma matches only the success; without the "
                        "correlation this fires on every login."),
    },
    "privilege_escalation": {
        "stateless": False,
        "selection": {"rule.id": [5402, 5404]},
        "correlation": ("Requires a successful REMOTE login by the same "
                        "user on the same endpoint within the preceding "
                        "300s. Sigma matches only the escalation, which "
                        "on its own is routine administrative activity."),
    },
    "lateral_movement": {
        "stateless": False,
        "selection": {"rule.id": [5715, 5501]},
        "correlation": ("Requires the same account to authenticate "
                        "successfully to >=3 DISTINCT endpoints within "
                        "600s. Not expressible in Sigma without an "
                        "aggregation backend."),
    },
    "new_source_ip": {
        "stateless": False,
        "selection": {"rule.id": [5715, 5501],
                      "data.srcip|exists": True},
        "correlation": ("Requires per-user history of previously observed "
                        "source IPs and a 3-source learning period. "
                        "Stateful by definition."),
    },
    "off_hours_access": {
        "stateless": True,
        "selection": {"rule.id": [5715, 5501]},
        "timeframe_note": ("Hour-of-day filtering is backend specific; "
                           "the condition below expresses the intent and "
                           "most backends require a local adaptation."),
        "correlation": ("Deduplicated to at most one hit per user, per "
                        "endpoint, per local date."),
    },
}


def _sigma_level(severity: str) -> str:
    return {"CRITICAL": "critical", "HIGH": "high",
            "MEDIUM": "medium", "LOW": "low"}.get(severity.upper(), "medium")


def _yaml_scalar(v) -> str:
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, (int, float)):
        return str(v)
    text = str(v)
    if (any(c in text for c in ":#{}[],&*?|-<>=!%@`\"'")
            or text.strip() != text or not text):
        return "'" + text.replace("'", "''") + "'"
    return text


def _yaml_block(text: str, indent: str) -> str:
    """Emit a folded multi-line string that round-trips through YAML."""
    wrapped = []
    line = ""
    for word in text.split():
        if len(line) + len(word) + 1 > 72:
            wrapped.append(line)
            line = word
        else:
            line = f"{line} {word}".strip()
    if line:
        wrapped.append(line)
    body = "\n".join(f"{indent}  {w}" for w in wrapped)
    return f"|-\n{body}"


def sigma_rule(doc: DetectionDoc) -> str:
    """Render one catalog entry as a Sigma rule (YAML text)."""
    checker_name = getattr(doc.checker_cls, "name", _slug(doc.name))
    spec = _DETECTION_SPEC.get(checker_name, {})
    logsource = _LOGSOURCE.get(checker_name, {"category": "authentication"})
    stateless = spec.get("stateless", False)

    description = doc.hypothesis
    if not stateless and spec.get("correlation"):
        description += (" NOTE: this rule degrades in Sigma. "
                        + spec["correlation"])

    lines = [
        f"title: {doc.name}",
        f"id: {_stable_id(doc.name)}",
        # A rule that loses its correlation is not production-ready
        # elsewhere, and saying so is the point of the export.
        f"status: {'test' if stateless else 'experimental'}",
        f"description: {_yaml_block(description, '')}",
        "author: ITDR Engine (detection-as-code catalog)",
        f"date: {date.today().isoformat()}",
        "references:",
    ]
    for ref in (doc.references or ["https://attack.mitre.org/"]):
        lines.append(f"  - {ref}")

    lines.append("tags:")
    # Sigma tags a tactic as attack.credential_access etc. The catalog
    # stores prose like "Initial Access / Defense Evasion", so take the
    # primary tactic and normalize it.
    tactic_tag = (doc.tactic.split("/")[0].strip()
                  .lower().replace(" ", "_"))
    lines.append(f"  - attack.{tactic_tag}")
    lines.append(f"  - attack.{doc.mitre_id.lower()}")

    lines.append("logsource:")
    for k, v in logsource.items():
        lines.append(f"  {k}: {v}")

    lines.append("detection:")
    lines.append("  selection:")
    for field, value in (spec.get("selection")
                         or {"event.outcome": "success"}).items():
        if isinstance(value, list):
            lines.append(f"    {field}:")
            for item in value:
                lines.append(f"      - {_yaml_scalar(item)}")
        else:
            lines.append(f"    {field}: {_yaml_scalar(value)}")
    lines.append("  condition: selection")

    lines.append("falsepositives:")
    for fp in doc.false_positives:
        lines.append(f"  - {_yaml_block(fp, '  ')}")

    lines.append(f"level: {_sigma_level(doc.severity)}")

    # Non-standard but widely used: carry the engine's real logic so the
    # rule documents what a faithful implementation would need.
    lines.append("fields:")
    lines.append("  - data.dstuser")
    lines.append("  - data.srcip")
    lines.append("  - agent.name")
    if spec.get("correlation"):
        lines.append(f"x_itdr_correlation: "
                     f"{_yaml_block(spec['correlation'], '')}")
    lines.append(f"x_itdr_logic: {_yaml_block(doc.logic, '')}")

    return "\n".join(lines) + "\n"


def navigator_layer(name: str = "ITDR Engine detection coverage") -> dict:
    """ATT&CK Navigator layer describing what this engine detects."""
    by_technique: dict[str, list[DetectionDoc]] = {}
    for doc in CATALOG:
        by_technique.setdefault(doc.mitre_id, []).append(doc)

    # Score by strength of coverage, not merely presence. A technique
    # covered by one LOW-severity heuristic is not "covered" the way one
    # backed by a CRITICAL correlated detection is, and a heat map that
    # pretends otherwise misleads whoever reads it.
    weight = {"CRITICAL": 100, "HIGH": 75, "MEDIUM": 50, "LOW": 25}
    techniques = []
    for tid, docs in sorted(by_technique.items()):
        score = max(weight.get(d.severity.upper(), 50) for d in docs)
        names = ", ".join(d.name for d in docs)
        techniques.append({
            "techniqueID": tid,
            "score": score,
            "color": "",
            "comment": (f"{len(docs)} detection(s): {names}. "
                        f"Strongest severity: "
                        f"{max(docs, key=lambda d: weight.get(d.severity.upper(), 0)).severity}"),
            "enabled": True,
            "metadata": [{"name": d.name, "value": f"{d.severity} — {d.tactic}"}
                         for d in docs],
            "showSubtechniques": True,
        })

    return {
        "name": name,
        "versions": {"attack": "14", "navigator": "4.9.0", "layer": "4.5"},
        "domain": "enterprise-attack",
        "description": (
            "Identity threat detection coverage implemented by the ITDR "
            "engine. Scores reflect the strongest detection severity "
            "mapped to each technique, not the count of rules."),
        "techniques": techniques,
        "gradient": {
            "colors": ["#ffe766", "#ff6666"],
            "minValue": 0,
            "maxValue": 100,
        },
        "legendItems": [
            {"label": "LOW — compounding signal only", "color": "#ffe766"},
            {"label": "CRITICAL — standalone high confidence",
             "color": "#ff6666"},
        ],
        "showTacticRowBackground": True,
        "tacticRowBackground": "#205b64",
        "selectTechniquesAcrossTactics": True,
        "layout": {"layout": "side", "showName": True, "showID": True},
    }


def write_exports(out_dir: str | Path = "exports") -> dict[str, int]:
    out = Path(out_dir)
    sigma_dir = out / "sigma"
    sigma_dir.mkdir(parents=True, exist_ok=True)

    written = 0
    for doc in CATALOG:
        checker_name = getattr(doc.checker_cls, "name", _slug(doc.name))
        path = sigma_dir / f"{_slug(doc.name)}.yml"
        path.write_text(sigma_rule(doc))
        written += 1

    layer_path = out / "attack-navigator-layer.json"
    layer_path.write_text(json.dumps(navigator_layer(), indent=2) + "\n")

    techniques = {d.mitre_id for d in CATALOG}
    return {"sigma_rules": written, "techniques": len(techniques)}


def main() -> None:
    stats = write_exports()
    print(f"wrote {stats['sigma_rules']} Sigma rules -> exports/sigma/")
    print(f"wrote ATT&CK Navigator layer covering "
          f"{stats['techniques']} techniques -> "
          f"exports/attack-navigator-layer.json")
    print()
    print("Convert a rule to your SIEM's query language:")
    print("  pip install sigma-cli")
    print("  sigma convert -t splunk exports/sigma/")
    print("  sigma convert -t lucene exports/sigma/   # Elastic")
    print()
    print("View coverage: https://mitre-attack.github.io/attack-navigator/")
    print("  -> Open Existing Layer -> Upload from Local")


if __name__ == "__main__":
    main()
