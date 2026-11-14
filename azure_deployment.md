# Optional deployment guide — Microsoft Sentinel (authorized lab only)

**Status:** Instructions supplied; no deployment or Azure execution is performed by this portfolio package.

## Prerequisites

- Your own Azure tenant and subscription with billing visibility; Azure/Sentinel ingestion and retention may cost money.
- Appropriate permissions for a Log Analytics workspace, Microsoft Sentinel, data connectors and analytics rule creation.
- A safe test data source. Do not copy employer or client log data into a personal tenant.
- Consent/permissions for all testing. Never use a company account or test production systems without approval.

## Phase A — data collection

1. Create or select a Log Analytics workspace in your own subscription.
2. Enable Microsoft Sentinel on that workspace; use the Microsoft Defender portal path where available.
3. Connect **Microsoft Entra ID sign-in logs** via supported data connector and verify ingestion to `SigninLogs`.
4. If you have a test Windows VM, onboard it through the appropriate Azure monitoring/security data collection configuration and ensure `SecurityEvent` has the required events.
5. For Windows event 4688, enable process creation auditing and command-line collection in your **own** isolated lab if appropriate. Without command-line auditing, the PowerShell query will not be useful.
6. Validate data collection using read-only queries:

```kql
SigninLogs | take 5
```

```kql
SecurityEvent | where EventID in (4688, 4728, 4732, 4756) | take 5
```

## Phase B — detections

1. Open `detections/kql/01_password_spray.kql` and execute it in your own Log Analytics Logs area.
2. Check table names, permissions, field population, ingestion delays and query time ranges.
3. Review the returned data manually; tune service-principal, allowlist, break-glass, NAT and failure-code considerations.
4. In **Microsoft Sentinel → Analytics**, create a scheduled analytics rule from validated KQL. The exact portal UI can change.
5. Set reasonable query frequency/lookback, incident grouping, entity mapping (IP and account), rule descriptions and severity. Avoid repeated duplicate alerts.
6. Repeat for each KQL detection, evaluating the signal quality before enabling incident creation.
7. Use `05_sentinel_soc_workbook.kql` to build a simple workbook trend chart: successful vs failed sign-ins by hour.

**Limitations:** The offline fixtures cannot be uploaded as-is to a production `SigninLogs` table. Microsoft manages table ingestion schemas. For a fully isolated query demonstration, use a KQL `datatable` or an authorized custom log table rather than pretending your CSV is native Entra telemetry.

## Phase C — automation (human-in-the-loop)

Follow `automation/logic_apps_blueprint.md` and Microsoft guidance on incident-triggered playbooks. Start with tagging and evidence summaries; test that repeated triggers do not duplicate notifications. Use Key Vault or managed identities where supported. Never hard-code secrets.

## Phase D — evidence for interviews

Save sanitized screenshots from your own authorized lab showing:

- Analytics rule name, KQL and returned record(s)
- Incident entities and investigation chronology
- Tuning notes and a negative-control example
- Workbook showing log trends
- Logic Apps run history (only if actually deployed)

Record honestly whether something was implemented in a real Azure tenant, implemented in the Python offline lab, or was only designed/documented.

## Source docs

- https://learn.microsoft.com/en-us/azure/sentinel/scheduled-rules-overview
- https://learn.microsoft.com/en-us/azure/sentinel/create-manage-use-automation-rules
- https://learn.microsoft.com/en-us/azure/sentinel/automation/create-playbooks
- https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/signinlogs
- https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/securityevent
