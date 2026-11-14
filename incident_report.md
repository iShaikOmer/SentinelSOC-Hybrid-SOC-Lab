# Synthetic SOC Investigation Report

> LAB ONLY: All events, accounts, endpoints, and IPs in this case study are synthetic.
> These detections do not establish that a real security incident occurred.

## Overview

- Potential alerts requiring analyst validation: **4**
- Severity breakdown: Critical **1**; High **2**; Medium **1**
- Data sources: simulated Microsoft Entra sign-in export and Windows Security Event export
- Automation status: **offline simulation only**; no Azure Logic Apps are deployed

## Detection findings

### 1. Successful sign-in after password spray pattern

- Rule: `AUTH-002` | Severity: **Critical** | MITRE: `T1110.003 / T1078`
- Observed: `2026-11-12T09:18:00Z`
- Key evidence (synthetic):
  - `ip`: `198.51.100.45`
  - `account`: `admin@example.test`
  - `spray_failed_signins`: `10`
  - `spray_distinct_accounts`: `5`
- Analyst action: Treat as potential account compromise: validate authentication/MFA, session and device context; escalate and seek approval for session revocation or account reset.
- Disposition: **Needs human validation**

### 2. Multi-account password spray pattern

- Rule: `AUTH-001` | Severity: **High** | MITRE: `T1110.003`
- Observed: `2026-11-12T09:09:00Z`
- Key evidence (synthetic):
  - `ip`: `198.51.100.45`
  - `failed_signins`: `10`
  - `distinct_users`: `5`
  - `accounts`: `['admin@example.test', 'finance@example.test', 'helpdesk@example.test', 'hr@example.test', 'security@example.test']`
  - `window_start`: `2026-11-12T09:00:00Z`
  - `window_end`: `2026-11-12T09:09:00Z`
- Analyst action: Validate the source and user activity; inspect Conditional Access/MFA and associated sign-ins; request identity containment approval if suspicious.
- Disposition: **Needs human validation**

### 3. Account added to a security-enabled group

- Rule: `IDENTITY-001` | Severity: **High** | MITRE: `T1098.007`
- Observed: `2026-11-12T09:30:00Z`
- Key evidence (synthetic):
  - `host`: `DC-01`
  - `actor`: `EXAMPLE\svc-admin`
  - `added_member`: `EXAMPLE\test-user`
  - `group`: `Domain Admins`
  - `event_id`: `4728`
- Analyst action: Verify group sensitivity and approved change ticket; contact the identity owner. Do not remove membership automatically without authorization.
- Disposition: **Needs human validation**

### 4. Potentially suspicious PowerShell execution

- Rule: `ENDPOINT-001` | Severity: **Medium** | MITRE: `T1059.001`
- Observed: `2026-11-12T09:24:00Z`
- Key evidence (synthetic):
  - `host`: `WS-ENG-01`
  - `account`: `EXAMPLE\analyst`
  - `process`: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`
  - `command_line`: `powershell.exe -NoProfile -EncodedCommand [synthetic-redacted]`
- Analyst action: Review the parent process, script content if available, execution context, Defender timeline and approved administration activity before containment.
- Disposition: **Needs human validation**

## Analyst triage sequence

1. Confirm log ingestion, time zones, data quality and rule fidelity.
2. Correlate IP/account/host across Entra ID, Defender XDR and Windows logs.
3. Verify the events against change tickets and legitimate administrator activity.
4. Determine severity, scope and potential business impact with the incident commander.
5. Request authorization before any destructive/disruptive containment action.
6. Create a ticket, preserve evidence, document stakeholder notifications and next steps.

## Limitations

- Synthetic evidence cannot be used to claim real incident detection, MTTD, MTTR or false-positive reduction.
- A generated detection is a lead requiring investigation, not confirmation of compromise.
- KQL samples are separate cloud deployment examples; this local harness does not execute KQL.
