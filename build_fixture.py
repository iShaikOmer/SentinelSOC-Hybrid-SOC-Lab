"""Deterministic synthetic fixtures. Writes CSV; does not connect to any service."""
from pathlib import Path
import csv
from datetime import datetime, timedelta, timezone

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / 'data'
DATA.mkdir(parents=True, exist_ok=True)
BASE = datetime(2026, 11, 12, 9, 0, tzinfo=timezone.utc)


def stamp(minutes: int) -> str:
    return (BASE + timedelta(minutes=minutes)).strftime('%Y-%m-%dT%H:%M:%SZ')


def dump(name: str, columns: list[str], rows: list[dict[str, str]]) -> None:
    with open(DATA / name, 'w', encoding='utf-8', newline='') as file:
        writer = csv.DictWriter(file, fieldnames=columns)
        writer.writeheader()
        writer.writerows(rows)


signin = []
accounts = ['admin', 'finance', 'helpdesk', 'hr', 'security', 'operations']
# Password spray pattern: 12 failures against six identities from the same TEST-NET-2 address.
for i, account in enumerate(accounts):
    for j in range(2):
        signin.append(dict(TimeGenerated=stamp(i*2+j),
                           UserPrincipalName=f'{account}@example.test', IPAddress='198.51.100.45',
                           ResultType='50126', AppDisplayName='Microsoft 365'))
# A successful sign-in AFTER the spray pattern: the analyst must investigate, not assume compromise.
signin.append(dict(TimeGenerated=stamp(18), UserPrincipalName='admin@example.test',
                   IPAddress='198.51.100.45', ResultType='0', AppDisplayName='Microsoft 365'))
# Negative control: single user enters incorrect password repeatedly (not cross-account spray).
for i in range(6):
    signin.append(dict(TimeGenerated=stamp(2+i), UserPrincipalName='alice@example.test',
                       IPAddress='203.0.113.20', ResultType='50126', AppDisplayName='HR Portal'))
# Normal legitimate sign-in from a different source.
signin.append(dict(TimeGenerated=stamp(21), UserPrincipalName='bob@example.test',
                   IPAddress='192.0.2.30', ResultType='0', AppDisplayName='Microsoft 365'))
signin.sort(key=lambda x: x['TimeGenerated'])
dump('signin_logs.csv', ['TimeGenerated','UserPrincipalName','IPAddress','ResultType','AppDisplayName'], signin)

windows = [
    dict(TimeGenerated=stamp(24), Computer='WS-ENG-01', EventID='4688',
         Account='EXAMPLE\\analyst', NewProcessName=r'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe',
         CommandLine='powershell.exe -NoProfile -EncodedCommand [synthetic-redacted]',
         MemberName='', TargetUserName=''),
    dict(TimeGenerated=stamp(25), Computer='WS-OPS-02', EventID='4688',
         Account='EXAMPLE\\operator', NewProcessName=r'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe',
         CommandLine='powershell.exe -NoProfile -Command Get-Date',
         MemberName='', TargetUserName=''),
    dict(TimeGenerated=stamp(30), Computer='DC-01', EventID='4728',
         Account='EXAMPLE\\svc-admin', NewProcessName='', CommandLine='',
         MemberName='EXAMPLE\\test-user', TargetUserName='Domain Admins'),
    dict(TimeGenerated=stamp(32), Computer='DC-01', EventID='4624',
         Account='EXAMPLE\\operator', NewProcessName='', CommandLine='',
         MemberName='', TargetUserName=''),
]
dump('windows_events.csv', ['TimeGenerated','Computer','EventID','Account','NewProcessName','CommandLine','MemberName','TargetUserName'], windows)
print(f'Wrote {len(signin)} synthetic sign-ins and {len(windows)} Windows events')
