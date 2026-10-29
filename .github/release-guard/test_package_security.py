"""Pinned original matrix parity and provenance readiness; no execution claim."""
import ast
from pathlib import Path
from types import SimpleNamespace

import pytest

from content_manifest import Refused
from launch_policy import source_unit
import package_security as security

ROOT=next(p for p in Path(__file__).resolve().parents if (p/'pyproject.toml').is_file())


def test_matrix_builder_matches_every_original_operand_without_executing_a_child(tmp_path):
    unit=source_unit(ROOT,security.TEST,security.PIN,('_run_cli_matrix',))
    captured=[]
    def run(argv,**kwargs):
        captured.append((argv,kwargs))
        output=('<redacted:OPENAI_API_KEY> is not one of' if 'OPENAI_API_KEY' in kwargs['env'] else
                'ordinary-unsupported-provider claude codex')
        return SimpleNamespace(returncode=2,stdout=output)
    namespace={'Path':Path,'subprocess':SimpleNamespace(run=run,PIPE=-1,STDOUT=-2)}
    exec(compile(ast.Module(body=[unit],type_ignores=[]),security.TEST,'exec'),namespace)
    cwd=tmp_path/'quoted\'s-copy'
    cwd.mkdir()
    bootstrap=f'import sys; sys.path[:0]=[{str(cwd/"src")!r}, "/dependencies"]; '
    namespace['_run_cli_matrix'](python=Path('/native'),bootstrap=bootstrap,cwd=cwd,environment={'PATH':'/bin'})
    assert len(captured)==10
    for index,(argv,kwargs) in enumerate(captured):
        assert argv[:4]==['/native','-S','-c',security.matrix_program(ROOT,bootstrap,cwd/'precommand-callback-trap')]
        assert argv[4:]==['init',security.OPTIONS[index] if index<9 else '--worker-provider',
            security.SENTINEL if index<9 else 'ordinary-unsupported-provider']
        assert kwargs['cwd']==cwd and kwargs['timeout']==30
        assert ('OPENAI_API_KEY' in kwargs['env'])==(index<9)


@pytest.mark.parametrize('mutation',['missing','not-consumed','no-terminal','body','wrong-status','not-waited',None])
def test_pending_fixture_binding_never_counts_as_completed_provenance(mutation):
    row={'consumed':mutation!='not-consumed','pid':2,'security_status':0}
    actor={'birth':object(),'token':'bound','body_ready':mutation!='body'}
    terminal=None if mutation=='no-terminal' else (4,0,1 if mutation=='wrong-status' else 0)
    host=SimpleNamespace(fixture_roots={} if mutation=='missing' else {'<installed-provenance>':row},actors={2:actor},
        ledger=SimpleNamespace(process=lambda birth:SimpleNamespace(terminal=terminal),
            reaped=lambda birth,token:mutation!='not-waited'))
    if mutation is None:
        assert security.provenance(host) is row
    else:
        with pytest.raises(Refused,match='actual provenance'):
            security.provenance(host)
