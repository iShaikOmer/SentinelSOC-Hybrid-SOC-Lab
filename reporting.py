"""Generate readable incident case notes; human validation required for every alert."""
from collections import Counter
from datetime import datetime, timezone
from typing import Any


def report_markdown(alerts: list[dict[str, Any]]) -> str:
    counts = Counter(a['severity'] for a in alerts)
    lines = [
        '# Synthetic SOC Investigation Report', '',
        '> LAB ONLY: All events, accounts, endpoints, and IPs in this case study are synthetic.',
        '> These detections do not establish that a real security incident occurred.', '',
        '## Overview', '',
        f'- Potential alerts requiring analyst validation: **{len(alerts)}**',
        f'- Severity breakdown: Critical **{counts["Critical"]}**; High **{counts["High"]}**; Medium **{counts["Medium"]}**',
        '- Data sources: simulated Microsoft Entra sign-in export and Windows Security Event export',
        '- Automation status: **offline simulation only**; no Azure Logic Apps are deployed', '',
        '## Detection findings', ''
    ]
    for i, a in enumerate(alerts, 1):
        lines += [f'### {i}. {a["title"]}', '',
                  f'- Rule: `{a["rule_id"]}` | Severity: **{a["severity"]}** | MITRE: `{a["mitre_technique"]}`',
                  f'- Observed: `{a["observed_at_utc"]}`',
                  '- Key evidence (synthetic):']
        lines += [f'  - `{key}`: `{value}`' for key, value in a['evidence'].items()]
        lines += [f'- Analyst action: {a["analyst_next_step"]}',
                  f'- Disposition: **{a["status"]}**', '']
    lines += ['## Analyst triage sequence', '',
              '1. Confirm log ingestion, time zones, data quality and rule fidelity.',
              '2. Correlate IP/account/host across Entra ID, Defender XDR and Windows logs.',
              '3. Verify the events against change tickets and legitimate administrator activity.',
              '4. Determine severity, scope and potential business impact with the incident commander.',
              '5. Request authorization before any destructive/disruptive containment action.',
              '6. Create a ticket, preserve evidence, document stakeholder notifications and next steps.', '',
              '## Limitations', '',
              '- Synthetic evidence cannot be used to claim real incident detection, MTTD, MTTR or false-positive reduction.',
              '- A generated detection is a lead requiring investigation, not confirmation of compromise.',
              '- KQL samples are separate cloud deployment examples; this local harness does not execute KQL.', '']
    return '\n'.join(lines)
