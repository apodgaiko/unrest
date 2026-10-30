"""Six original local ACP nodes beneath the exact measurement RunControl workers."""
import json
import os
from pathlib import Path

from content_manifest import Refused as Refused, read_regular, refuse_if
from control_transport import unique
from launch_policy import source_unit
from run_worker_launch import MEASUREMENT_PROJECT as PROJECT

PROJECT_STEPS=((1,'start_project',()),(1,'submit_plan',()),(1,'advance_project',('work','validate')),
    (6,'start_project',()),(6,'submit_plan',()),(6,'advance_project',('work','validate')),
    (6,'decide_attention',()),(6,'advance_project',('work','validate')))
MOCK='tests/mock_measurement_acp.py'
PINS={'tests/mock_measurement_acp.py': '47d099bd120a96d86d1e052567744be63b3c103a11a043ad40976776d1f400dd'}


def owner(host,actor):
    rows=[row for row in host.intents.values() if row['case']==PROJECT and row['role']=='fixed-inline'
        and row.get('measurement_roles') and row.get('birth')==actor['birth'] and row['token']==actor['token']]
    refuse_if(host.case!=PROJECT or actor['role']!='fixed-inline' or not actor['body_ready']
            or len(rows)!=1 or not host.executed(rows[0]), 'measurement nested original worker identity')
    return rows[0]


def record(path):
    body,_,_=read_regular(path,65536,uid=20000,forbidden=0o6022)
    return json.loads(body,object_pairs_hook=unique)



def nested(host,actor,raw):
    parent=owner(host,actor)
    checkout=Path(host.meta['checkout'])
    home=Path(parent['cwd'])
    from node_environment import project_path
    project=project_path(home,parent['run_project'])
    from collections import Counter
    roles=Counter(parent['measurement_roles'])
    source_unit(checkout,MOCK,PINS[MOCK])
    from node_launch import proposal
    return proposal(host,actor,raw,home.parent/'workspace',{'LANG':'C.UTF-8','PATH':os.defpath},
        home,project.name,roles,checkout/MOCK,PINS[MOCK],(),6,{},'mock-acp')
