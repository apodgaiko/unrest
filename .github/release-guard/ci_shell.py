"""Transport only the two literal release checks into their native domains."""
import os
from pathlib import Path
import subprocess
import sys


def main():
    if os.environ.get('GITHUB_ACTIONS')!='true' or len(sys.argv)!=2:
        raise RuntimeError('CI literal command transport requires GitHub Actions')
    script=Path(sys.argv[1]).read_text().strip()
    root=Path('/tmp')/('unrest-native-control-'+str(int(os.environ['GITHUB_RUN_ID']))+'-'+str(int(os.environ['GITHUB_RUN_ATTEMPT'])))/'guard-native-control'
    python=str(Path.cwd()/'.venv/bin/python')
    if script=='env -u CODEX_PATH uv run pytest -q':
        vector=[str(root/'support/source_host.py'),str(root/'binding.json')]
        deadline='7240'
    elif script=='uv run python tools/check_distribution.py dist':
        vector=[str(root/'support/package_check.py'),str(root/'binding.json')]
        deadline='180'
    else:
        raise RuntimeError('unknown release command; no execution permission')
    return subprocess.call(['sudo','-n','env','-i','PATH=/usr/bin:/bin','/usr/bin/timeout',
        '--signal=TERM','--kill-after=5',deadline,python,'-I','-B',*vector])


if __name__=='__main__':
    raise SystemExit(main())
