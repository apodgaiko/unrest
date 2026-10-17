"""Build/seal the finite CPython entry against the pinned image's real ABI."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import sysconfig

ROOT = Path('/opt/source-guard')
ENTRY = Path('/usr/local/bin/python-primary-audit')


def pin(path: Path) -> dict[str, str]:
    return {'path': str(path), 'sha256': hashlib.sha256(path.read_bytes()).hexdigest()}


def main() -> None:
    compiler = Path(shutil.which('gcc') or '/missing').resolve(strict=True)
    header = pin(ROOT / 'primary_entry.py')['sha256']
    includes = shlex.split(subprocess.check_output(['python3-config', '--includes'], text=True))
    linker = shlex.split(subprocess.check_output(['python3-config', '--embed', '--ldflags'], text=True))
    argv = [str(compiler), '-O2', '-Wall', '-Wextra', '-Werror', *includes,
            '-DENTRY_SOURCE_SHA256="' + header + '"', str(ROOT / 'primary_entry.c'),
            '-Wl,-rpath,/usr/local/lib', *linker, '-o', str(ENTRY)]
    subprocess.run(argv, check=True)
    record = {'source': pin(ROOT / 'primary_entry.c'), 'bootstrap': pin(ROOT / 'primary_entry.py'),
              'entry': pin(ENTRY), 'compiler': pin(compiler),
              'stock_runtime': pin(Path(sys.executable).resolve()),
              'library': pin(Path('/usr/local/lib/libpython3.13.so.1.0')),
              'compiler_argv': argv, 'version': sys.version,
              'soabi': sysconfig.get_config_var('SOABI')}
    (ROOT / 'primary-entry-binding.json').write_text(json.dumps(record, sort_keys=True) + '\n')


def verify() -> dict:
    record = json.loads((ROOT / 'primary-entry-binding.json').read_bytes())
    for key in ('source', 'bootstrap', 'entry', 'compiler', 'stock_runtime', 'library'):
        if pin(Path(record[key]['path'])) != record[key]:
            raise RuntimeError('native CPython entry input drift')
    for name, key in (('primary_entry.c', 'source'), ('primary_entry.py', 'bootstrap')):
        if pin(Path('/guard') / name)['sha256'] != record[key]['sha256']:
            raise RuntimeError('native CPython entry support drift')
    if (record['entry']['path'] != str(ENTRY) or record['version'] != sys.version
            or record['soabi'] != sysconfig.get_config_var('SOABI')
            or record['soabi'] != 'cpython-313-x86_64-linux-gnu'):
        raise RuntimeError('native CPython entry ABI drift')
    return record


if __name__ == '__main__':
    main()
