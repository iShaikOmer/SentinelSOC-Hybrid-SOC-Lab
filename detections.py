"""Read-only SOC lab detections against synthetic CSV exports.

All sample IPs belong to RFC 5737 documentation ranges. No live environment is queried.
"""
from __future__ import annotations

import csv
from datetime import datetime, timedelta, timezone
from pathlib import Path
from collections import defaultdict
from typing import Any


def utc(value: str) -> datetime:
    t = datetime.fromisoformat(value.replace('Z', '+00:00'))
    return t if t.tzinfo else t.replace(tzinfo=timezone.utc)


def load_csv(path: str | Path) -> list[dict[str, str]]:
    with open(path, newline='', encoding='utf-8') as file:
        return list(csv.DictReader(file))


def make_alert(code: str, title: str, severity: str, mitre: str, time: str,
               evidence: dict[str, Any], recommendation: str) -> dict[str, Any]:
    return {'rule_id': code, 'title': title, 'severity': severity,
            'mitre_technique': mitre, 'observed_at_utc': time,
            'evidence': evidence, 'analyst_next_step': recommendation,
            'status': 'Needs human validation'}


def password_spray(signins: list[dict[str, str]], min_failures: int = 10,
                   min_users: int = 5, window_minutes: int = 30) -> list[dict[str, Any]]:
    """Detect >= min_failures across >= min_users from one IP in sliding window."""
    by_ip = defaultdict(list)
    for row in signins:
        if row['ResultType'] != '0':
            by_ip[row['IPAddress']].append(row)
    result = []
    for ip, rows in by_ip.items():
        rows = sorted(rows, key=lambda x: utc(x['TimeGenerated']))
        left = 0
        best = None
        for right, row in enumerate(rows):
            while (utc(row['TimeGenerated']) - utc(rows[left]['TimeGenerated'])
                   > timedelta(minutes=window_minutes)):
                left += 1
            current = rows[left:right + 1]
            users = sorted({r['UserPrincipalName'] for r in current})
            if len(current) >= min_failures and len(users) >= min_users:
                best = (row, current, users)
                break
        if best:
            row, current, users = best
            result.append(make_alert(
                'AUTH-001', 'Multi-account password spray pattern', 'High', 'T1110.003',
                row['TimeGenerated'],
                {'ip': ip, 'failed_signins': len(current), 'distinct_users': len(users),
                 'accounts': users, 'window_start': current[0]['TimeGenerated'],
                 'window_end': current[-1]['TimeGenerated']},
                'Validate the source and user activity; inspect Conditional Access/MFA and associated sign-ins; request identity containment approval if suspicious.'
            ))
    return result


def spray_followed_by_success(signins: list[dict[str, str]],
                              spray_alerts: list[dict[str, Any]],
                              window_minutes: int = 30) -> list[dict[str, Any]]:
    """Correlate confirmed spray-like IP with subsequent successful login; not proof of compromise."""
    found = []
    successes = [s for s in signins if s['ResultType'] == '0']
    for spray in spray_alerts:
        end = utc(spray['evidence']['window_end'])
        ip = spray['evidence']['ip']
        candidate = sorted((s for s in successes if s['IPAddress'] == ip and
                          end <= utc(s['TimeGenerated']) <= end + timedelta(minutes=window_minutes)),
                          key=lambda s: s['TimeGenerated'])
        if candidate:
            hit = candidate[0]
            found.append(make_alert(
                'AUTH-002', 'Successful sign-in after password spray pattern', 'Critical',
                'T1110.003 / T1078', hit['TimeGenerated'],
                {'ip': ip, 'account': hit['UserPrincipalName'],
                 'spray_failed_signins': spray['evidence']['failed_signins'],
                 'spray_distinct_accounts': spray['evidence']['distinct_users']},
                'Treat as potential account compromise: validate authentication/MFA, session and device context; escalate and seek approval for session revocation or account reset.'
            ))
    return found


def suspicious_powershell(windows: list[dict[str, str]]) -> list[dict[str, Any]]:
    results = []
    markers = ('encodedcommand', 'frombase64string', 'downloadstring')
    for row in windows:
        exe = row.get('NewProcessName', '').lower()
        cmd = row.get('CommandLine', '').lower()
        if row['EventID'] == '4688' and ('powershell' in exe or 'pwsh' in exe) and any(m in cmd for m in markers):
            results.append(make_alert(
                'ENDPOINT-001', 'Potentially suspicious PowerShell execution', 'Medium',
                'T1059.001', row['TimeGenerated'],
                {'host': row['Computer'], 'account': row['Account'],
                 'process': row['NewProcessName'], 'command_line': row['CommandLine']},
                'Review the parent process, script content if available, execution context, Defender timeline and approved administration activity before containment.'
            ))
    return results


def privileged_group_changes(windows: list[dict[str, str]]) -> list[dict[str, Any]]:
    results = []
    for row in windows:
        if row['EventID'] in ('4728', '4732', '4756'):
            results.append(make_alert(
                'IDENTITY-001', 'Account added to a security-enabled group', 'High',
                'T1098.007', row['TimeGenerated'],
                {'host': row['Computer'], 'actor': row['Account'],
                 'added_member': row['MemberName'], 'group': row['TargetUserName'],
                 'event_id': row['EventID']},
                'Verify group sensitivity and approved change ticket; contact the identity owner. Do not remove membership automatically without authorization.'
            ))
    return results


def run_all(signins: list[dict[str, str]], windows: list[dict[str, str]]) -> list[dict[str, Any]]:
    spray = password_spray(signins)
    alerts = spray + spray_followed_by_success(signins, spray)
    alerts += suspicious_powershell(windows)
    alerts += privileged_group_changes(windows)
    priority = {'Critical': 0, 'High': 1, 'Medium': 2, 'Low': 3}
    return sorted(alerts, key=lambda x: (priority[x['severity']], x['observed_at_utc']))
