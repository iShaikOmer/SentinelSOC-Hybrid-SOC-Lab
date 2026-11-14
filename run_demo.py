"""Local SOC lab demo: zero third-party dependencies and zero outbound calls."""
from pathlib import Path
import sys
import json

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from soc_lab.detections import load_csv, run_all  # noqa: E402
from soc_lab.reporting import report_markdown  # noqa: E402


def main() -> int:
    signin = load_csv(ROOT / 'data' / 'signin_logs.csv')
    windows = load_csv(ROOT / 'data' / 'windows_events.csv')
    alerts = run_all(signin, windows)
    out = ROOT / 'outputs'
    out.mkdir(exist_ok=True)
    (out / 'incidents.json').write_text(json.dumps(alerts, indent=2) + '\n', encoding='utf-8')
    (out / 'incident_report.md').write_text(report_markdown(alerts), encoding='utf-8')
    print('SOC Lab — synthetic data only | no network calls')
    print(f'Read {len(signin)} sign-ins and {len(windows)} Windows event records')
    print(f'Found {len(alerts)} candidate alerts (each requires human validation):')
    for alert in alerts:
        print(f'  {alert["severity"]:<8} {alert["rule_id"]:<14} {alert["title"]}')
    print('Saved outputs/incidents.json and outputs/incident_report.md')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
