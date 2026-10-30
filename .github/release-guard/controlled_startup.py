"""Source-derived startup declarations for unchanged bootstrap cases.

Trusted bootstrap supplies immutable source units, runtime and owned-root
identity plus authenticated case selection. This module selects intent only;
the kernel stop, native prebody entry, endpoint seal and actual waits remain
separate mandatory boundaries. There is no legacy resolver fallback.
"""
from __future__ import annotations

import json

from bootstrap_cases import configuration, wrapper, declaration
from content_manifest import Refused, is_sha256
from controlled_cases import eligible as CONTROLLED, backend_path, BACKENDS, SERVERS
from launch_policy import build_expected

ACP = 'tests/fixtures/controlled_python_acp.py'
BACKEND_PIN = 'be7847ba715816b3f0cfdc9c29087b8751a998d160f616a5c08210c6ca404f53'
ACP_PIN = 'f5134a2d79b348b70b05a66566ff65d0049f102665200a22f3a6fcbd1c4f58be'
def expected_entry(case,checkout,home,native,native_pin,*,backend,relay=None,variant=0,backend_pin=None):
    if type(variant) is not int or variant not in range(4):
        raise Refused('controlled finite configuration variant')
    configured=variant!=0 if CONTROLLED(case) else declaration(case).configured
    servers=SERVERS if variant>=2 else ()
    skills=(str(home.parent.parent.parent/'subscription/skills/example/SKILL.md'),) if variant==3 else ()
    options,config = configuration(checkout,home,servers=servers,skills=skills) if configured else ([],None)
    environment = {'HOME':str(home),'CODEX_HOME':str(home/'codex'),'TMPDIR':str(home/'tmp'),'PATH':'/usr/bin:/bin'}
    if config is not None:
        environment.update(CODEX_HOME=str(home.parent.parent.parent/'subscription'),CODEX_CONFIG=config)
    if backend:
        script = backend_path(case,home.parent) if CONTROLLED(case) else home.parent/'fake-app-server'
        pin = backend_pin if CONTROLLED(case) else BACKEND_PIN
        if CONTROLLED(case) and BACKENDS.get(pin)!=script.name:
            raise Refused('controlled independent backend pin')
        source = (native,str(script),*options,'app-server')
        delay = None if CONTROLLED(case) else wrapper(case)
        vector = (native,'-c',delay,*source[1:]) if delay is not None else source
        kind,reference = ('python-command',None) if delay is not None else ('python-script',pin)
    else:
        if (type(relay) is not list or len(relay) != 4
                or any(type(relay[i]) is not int or not 0 < relay[i] <= 65535 for i in (0,2))
                or any(not is_sha256(relay[i]) for i in (1,3))):
            raise Refused('controlled entry acquired relay')
        pin = ACP_PIN
        source = vector = (native,str(checkout/ACP),'--controlled-local-acp-v1')
        kind,reference = 'python-script',pin
        environment.update(CODEX_PATH=str(home.parent/'fixed-relay'),INITIAL_AGENT_MODE='read-only',SYNTHETIC_RELAY=json.dumps(relay))
    return build_expected(
        case,
        native, native_pin,
        vector,
        tuple(sorted(environment.items())),
        str(home), kind, reference,
    ),source,pin
