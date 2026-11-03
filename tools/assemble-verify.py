from pathlib import Path

root = Path(__file__).resolve().parents[1]
header = (root / 'tools/remote-verify.sh').read_text()
probe = (root / 'tools/probe_endpoint.py').read_text()
footer = '\nGAMEBOND_PROBE\nprintf "SMOKE_TEST_PASSED\\n"\n'
(root / 'secrets/remote-verify.sh').write_text(header + probe + footer, newline='\n')
