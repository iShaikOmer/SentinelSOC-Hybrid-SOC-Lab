# SOC L2 triage & incident handling runbook

Applies to the **synthetic** SentinelSOC lab. This runbook illustrates a transferable workflow, not an employer-specific procedure.

## 1. Initial validation (L1 → L2)

- Capture alert ID, detection name, severity, first/last seen, affected assets and raw log references.
- Verify whether the data is stale, duplicated or affected by time-zone/ingestion lag.
- Assess criticality of the account or host and customer/business context.
- Create a working hypothesis; note alternative explanations (maintenance, user typo, scripted administration).

## 2. Evidence collection

**For an identity spray:** group failed logins by source IP, user, 30-minute window and failure reason. Confirm whether many distinct accounts were targeted. Investigate successful sign-ins that followed from that source. Review Conditional Access decisions, MFA challenge, unusual device/location, registered devices, mailbox audit activity, and corresponding EDR evidence if available.

**For suspicious PowerShell:** confirm event 4688 collection, full command-line capture, execution parent, signer, integrity level, host role, script policy, scheduled tasks and Defender timeline. Encoded commands may be legitimate; check the change window and approved administrative tools.

**For privileged group changes:** identify group/member/actor and whether the action belongs to an approved provisioning or access review. Do not treat every membership change as malicious.

## 3. Severity decision and escalation

| Example | Initial lab priority | Next action |
|---|---|---|
| Multiple failed sign-ins to many users | High | Identity-focused investigation; check spray context |
| Success after spray-like activity | Critical | Escalate immediately for potential account compromise validation |
| PowerShell with encoded command marker | Medium | Confirm command context and endpoint corroboration |
| Security group addition | High | Validate sensitive group and approved change ticket |

Labels are training defaults, not universal severity rules. Reassess based on actual evidence and impact.

## 4. Containment and recovery

- Share evidence and obtain approval before session revocation, password reset, endpoint isolation, IP blocking or role removal.
- Preserve evidence and chain-of-custody requirements for formal investigations.
- Track containment owner, timestamp, business impact and recovery checks.
- Escalate to incident commander / senior responders under actual organization procedures.

## 5. Closure and tuning

1. Record final classification and specific evidence.
2. Update affected user, application, device and IOC lists.
3. Add tuning suggestion and a regression test for legitimate noise.
4. Capture timestamps **only from real cases** when computing MTTD/MTTR.
5. Confirm stakeholder closure and root cause/remediation follow-up.
