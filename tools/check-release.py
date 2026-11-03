"""Retain reproducible local validation, including the actual continuity metrics."""
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
from datetime import datetime, timezone

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from gamebond import __version__

result = subprocess.run([sys.executable, '-m', 'unittest', 'discover', '-s', 'tests', '-q'],
                        cwd=ROOT, text=True, capture_output=True)
summary = result.stderr + result.stdout
(ROOT / f'evidence/validation-{__version__}.log').write_text(summary, encoding='utf-8')
metrics = [json.loads(line.split(': ', 1)[1]) for line in result.stdout.splitlines()
           if line.startswith('Gameplay continuity regression: ')]
count = re.search(r'Ran (\d+) tests', result.stderr)
report = dict(version=__version__, observed_at=datetime.now(timezone.utc).isoformat(),
              passed=result.returncode == 0, tests=int(count[1]) if count else None,
              continuity=metrics, physical_links_tested=False,
              source_sha256={p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                             for p in sorted((ROOT/'gamebond').glob('*.py'))})
(ROOT / f'evidence/validation-{__version__}.json').write_text(json.dumps(report, indent=2)+'\n')
print(json.dumps(dict(version=__version__, passed=report['passed'], tests=report['tests'],
                     continuity_runs=len(metrics))))
if result.returncode:
    print(summary)
sys.exit(result.returncode)
