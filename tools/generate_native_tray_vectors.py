"""Record gamebond.tray.TrayAgent.update behaviour (icon colour, tooltip, menu label,
whether the icon was redrawn) for random update sequences, with pystray/PIL stubbed.
Writes native-edge/tray/testdata/vectors.json.gz."""
import gzip
import json
import random
import sys
import types
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


class Icon:
    def __init__(self, name, icon, title, menu=None):
        self.icon, self.title, self.menu, self.updates, self.visible = icon, title, menu, 0, True

    def run_detached(self): pass
    def stop(self): pass
    def update_menu(self): self.updates += 1


class MenuItem:
    def __init__(self, text, action, default=False, enabled=True):
        self.text, self.action, self.enabled = text, action, enabled


class Menu:
    SEPARATOR = object()

    def __init__(self, *items): self.items = items


class Img:
    @staticmethod
    def new(mode, size, color): return types.SimpleNamespace(color=color)


class Draw:
    def __init__(self, image): self.image = image

    def rounded_rectangle(self, *a, **k): self.image.color = k['fill']
    def line(self, *a, **k): pass


sys.modules['pystray'] = types.SimpleNamespace(Icon=Icon, MenuItem=MenuItem, Menu=Menu)
pil = types.ModuleType('PIL')
pil.Image, pil.ImageDraw = types.SimpleNamespace(new=Img.new), types.SimpleNamespace(Draw=Draw)
sys.modules['PIL'], sys.modules['PIL.Image'], sys.modules['PIL.ImageDraw'] = pil, pil.Image, pil.ImageDraw
from gamebond.tray import TrayAgent  # noqa: E402

rng = random.Random(4242)
STATES = ['idle', 'starting', 'connecting', 'running', 'running', 'running', 'stopping', 'stopped', 'failed', 'restarting']


def runtime():
    if rng.random() < .12:
        return None
    paths = []
    for _ in range(rng.choice([0, 1, 1, 2, 2, 3])):
        p = {'healthy': rng.choice([True, True, False, 0, 1, None])}
        if rng.random() < .3:
            p['enabled'] = rng.choice([True, False, 0, 1, None])
        paths.append(p)
    rt = {'state': rng.choice(STATES), 'peer': [rng.choice(['195.154.119.136', '10.0.0.1', 'host']), 4433]}
    if rng.random() < .95:
        rt['transport'] = {'paths': paths}
    if rng.random() < .05:
        del rt['state']
    return rt


sequences = []
for _ in range(400):
    agent = TrayAgent(lambda name: None)
    steps = []
    for _ in range(rng.randint(1, 14)):
        rt, busy, problem = runtime(), rng.random() < .25, rng.choice([None, None, None, 'x', ''])
        before = agent.icon.updates
        agent.update(rt, busy, problem)
        item = agent.icon.menu.items[1]
        steps.append({'runtime': rt, 'busy': busy, 'problem': problem,
                      'redrawn': agent.icon.updates != before, 'color': agent.icon.icon.color, 'title': agent.icon.title,
                      'toggle': item.text(None), 'toggle_enabled': item.enabled(None)})
    sequences.append(steps)
dest = ROOT / 'native-edge/tray/testdata'
dest.mkdir(parents=True, exist_ok=True)
with gzip.open(dest / 'vectors.json.gz', 'wt', encoding='utf-8') as f:
    json.dump(sequences, f)
print(len(sequences), sum(len(s) for s in sequences))
