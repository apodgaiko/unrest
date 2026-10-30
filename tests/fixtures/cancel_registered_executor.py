"""One registered direct child; the real run worker owns its final wait."""
from pathlib import Path
import subprocess
import sys


def execute(operation, arguments, context):
    child=subprocess.Popen([sys.executable,str(Path(__file__).with_name('cancel_registered_child.py'))],
        stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    context.register_descendant(child.pid)
    root=str(Path.cwd())
    return {'harnessRoot':root,'projectId':'project','projectRoot':root,'state':{'state':'done'}}
