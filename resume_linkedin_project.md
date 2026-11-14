# Recruiter-facing project description

## Add to resume after verifying the demonstration works on your computer

**Personal Project — Hybrid SOC Threat Detection & Incident Triage Lab** | Microsoft Sentinel (KQL examples), Python, Windows Events, Microsoft Entra logs, MITRE ATT&CK

- Built an **offline, synthetic** SOC detection lab that correlates Entra sign-in and Windows Security Event telemetry, generating candidate incidents for password spraying, post-spray logins, encoded PowerShell and privileged group changes.
- Authored **five KQL query examples** aligned to Microsoft Sentinel schema and mapped **four detection scenarios** to MITRE ATT&CK; documented investigation procedures, tuning assumptions, and a human-approval SOAR design.
- Implemented deterministic fixture generation, machine-readable case notes, an interactive offline dashboard, and **six automated checks** including negative controls to validate detection logic.

**Do not write:** “Reduced false positives by X%” or “deployed Azure Logic Apps in production” unless you actually validate these claims independently.

## LinkedIn Projects section

**Title:** Hybrid SOC Detection & Automated Triage Lab — Sentinel / KQL / MITRE ATT&CK

**Description:** Created a GitHub-ready lab using synthetic identity and Windows event logs to demonstrate SOC L2 triage. Includes four example detection scenarios, five KQL searches, offline correlation and incident reporting, a browser dashboard, tests, and a non-destructive Azure Logic Apps design. This is a personal demonstration, not production experience.

**Skills:** Microsoft Sentinel, KQL, SIEM, SOC Operations, Threat Hunting, MITRE ATT&CK, Incident Response, Azure Logic Apps, Microsoft Entra ID, Windows Event Logs, Python.

## Suggested GitHub repository name

`sentinelsoc-detection-triage-lab`

## Interview demonstration — 60 seconds

1. Explain the attack hypothesis (password spraying and subsequent success).
2. Run `python3 scripts/run_demo.py` and point to **AUTH-002** as the highest-priority lead.
3. Show `detections/kql/01_password_spray.kql` and the threshold logic.
4. Show the negative-control test for repeated password errors by one account.
5. Open `outputs/incident_report.md` to explain evidence, validation and approval gate.
6. Explain which parts run offline versus which Azure components remain deployment designs.
