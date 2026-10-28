"""Source-derived startup declarations for unchanged bootstrap cases.

Trusted bootstrap supplies immutable source units, runtime and owned-root
identity plus authenticated case selection. This module selects intent only;
the kernel stop, native prebody entry, endpoint seal and actual waits remain
separate mandatory boundaries. There is no legacy resolver fallback.
"""
from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
from typing import Any

from bootstrap_cases import BOOTSTRAP, configuration, wrapper
from content_manifest import Refused
from controlled_cases import CASES as CONTROLLED, backend as controlled_backend, backend_path, configuration_items, configured as is_configured
from launch_policy import Expected, Rule, render

SESSION = 'src/unrest_harness/experimental_session.py'
TEST = 'tests/test_experimental_bootstrap.py'
ACP = 'tests/fixtures/controlled_python_acp.py'
SESSION_PIN = '7a3df1d049cd8a72aac48bc376154f7701335397ad8a0e0634cf2d0a9509cbd2'
TEST_PIN = 'c81fc04a81ef3aa657c16a69627c4c6b80ba1012f9255d2a05b15557934a7383'
BACKEND_PIN = 'be7847ba715816b3f0cfdc9c29087b8751a998d160f616a5c08210c6ca404f53'
ACP_PIN = 'f5134a2d79b348b70b05a66566ff65d0049f102665200a22f3a6fcbd1c4f58be'
CASES = tuple('tests/test_experimental_bootstrap.py::' + name for name in (
    'test_actual_sequential_initialize_and_session_share_cutoff',
    'test_startup_subtracts_from_actual_inference_timeout'))
WRAPPER = 'import runpy,sys,time; p=sys.argv.pop(1); time.sleep(0.5); runpy.run_path(p,run_name="__main__")'
PATH_TYPE = type(Path('/'))




def path(value: Any) -> Path:
    if type(value) is not PATH_TYPE or not value.is_absolute() or str(value.resolve()) != str(value):
        raise Refused('startup canonical path')
    return value



@dataclass(frozen=True)
class Intent:
    original: Expected
    translated_argv: tuple[str, ...]
    original_source_line: int
    script_sha256: str | None


def expected_entry(case,checkout,home,native,native_pin,*,backend,relay=None):
    if type(case) is not str or case not in (*BOOTSTRAP,*CONTROLLED) or type(backend) is not bool:
        raise Refused('controlled entry declaration')
    checkout,home = path(checkout),path(home)
    configured = is_configured(case)
    servers,skills = configuration_items(case,home)
    options,config = configuration(checkout,home,servers=servers,skills=skills) if configured else ([],None)
    environment = {'HOME':str(home),'CODEX_HOME':str(home/'codex'),'TMPDIR':str(home/'tmp'),'PATH':'/usr/bin:/bin'}
    if config is not None:
        environment.update(CODEX_HOME=str(home.parent.parent.parent/'subscription'),CODEX_CONFIG=config)
    if backend:
        script = backend_path(case,home.parent) if case in CONTROLLED else home.parent/'fake-app-server'
        pin = controlled_backend(case)[0] if case in CONTROLLED else BACKEND_PIN
        source = (native,str(script),*options,'app-server')
        delay = None if case in CONTROLLED else wrapper(case)
        vector = (native,'-c',delay,*source[1:]) if delay is not None else source
        kind,reference = ('python-command',None) if delay is not None else ('python-script',pin)
    else:
        if (type(relay) is not list or len(relay) != 4
                or any(type(relay[i]) is not int or not 0 < relay[i] <= 65535 for i in (0,2))
                or any(type(relay[i]) is not str or len(relay[i]) != 64
                    or any(char not in '0123456789abcdef' for char in relay[i]) for i in (1,3))):
            raise Refused('controlled entry acquired relay')
        pin = ACP_PIN
        source = vector = (native,str(checkout/ACP),'--controlled-local-acp-v1')
        kind,reference = 'python-script',pin
        environment.update(CODEX_PATH=str(home.parent/'fixed-relay'),INITIAL_AGENT_MODE='read-only',SYNTHETIC_RELAY=json.dumps(relay))
    rule = Rule('controlled-startup:'+('backend' if backend else 'acp'),SESSION+':_open_role_owned',(case,),
        native,native_pin,vector,tuple(sorted(environment.items())),str(home),kind,reference)
    return render(rule,case,rule.owner,{},{}),source,pin
