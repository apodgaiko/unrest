"""Seal the compiler/runtime/source binding of the Linux profile predicate."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import shutil
import sys
import sysconfig


def pin(path: Path) -> dict[str, str]:
    return {'path': str(path), 'sha256': hashlib.sha256(path.read_bytes()).hexdigest()}


def main() -> None:
    root = Path('/opt/source-guard')
    compiler = Path(shutil.which('gcc') or '/missing').resolve(strict=True)
    record = {'source': pin(root / 'profile_gate.c'), 'module': pin(root / 'profile_gate.so'),
              'compiler': pin(compiler), 'runtime': pin(Path(sys.executable).resolve()),
              'version': sys.version, 'soabi': sysconfig.get_config_var('SOABI')}
    (root / 'binding.json').write_text(json.dumps(record, sort_keys=True) + '\n')


def verify() -> dict:
    root = Path('/opt/source-guard')
    record = json.loads((root / 'binding.json').read_bytes())
    for key in ('source', 'module', 'compiler', 'runtime'):
        if pin(Path(record[key]['path'])) != record[key]:
            raise RuntimeError('native profile compiler/runtime/module drift')
    if (record['source']['path'] != str(root / 'profile_gate.c')
            or record['module']['path'] != str(root / 'profile_gate.so')
            or record['runtime']['path'] != str(Path(sys.executable).resolve())
            or record['source']['sha256'] != pin(Path('/guard/profile_gate.c'))['sha256']
            or record['soabi'] != sysconfig.get_config_var('SOABI')
            or record['soabi'] != 'cpython-313-x86_64-linux-gnu'):
        raise RuntimeError('native profile source/ABI binding refused')
    return record


if __name__ == '__main__':
    main()
