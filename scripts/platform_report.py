"""Record the actual machine and test evidence; never infer Windows support from CI YAML."""
import argparse
import json
import platform
import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    evidence = Path('reports/pytest.xml')
    totals = None
    if evidence.exists():
        root = ET.parse(evidence).getroot()
        suites = [root] if root.tag == 'testsuite' else list(root.iter('testsuite'))
        totals = {key: sum(int(s.get(key, 0)) for s in suites) for key in ['tests', 'failures', 'errors', 'skipped']}
    report = {'platform': platform.platform(), 'system': platform.system(),
              'windows_version': platform.win32_ver(),
              'windows_kernel': list(sys.getwindowsversion()) if sys.platform == 'win32' else None, 'python': platform.python_version(),
              'machine': platform.machine(), 'rust': subprocess.check_output(['rustc', '--version'], text=True).strip(),
              'pytest': totals, 'scope': 'Machine metadata plus pytest XML only. Preserve CI Rust/browser logs as separate evidence.'}
    args.output.write_text(json.dumps(report, indent=2) + '\n')


if __name__ == '__main__':
    main()
