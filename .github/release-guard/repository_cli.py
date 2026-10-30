"""Exact copied-repository CLI checks; imports normalize to equal sealed bytes."""
from pathlib import Path

from content_manifest import Refused as Refused, refuse_if
from git_policy import image
from launch_policy import source_unit,build_expected,admit_expected
from owned_fixture import retain

TEST='tests/test_repository_contract.py'
OWNERS=tuple(TEST+'::test_'+name for name in (
    'ci_constant_dead_guards_fail_through_candidate_cli',
    'ci_literal_dead_shell_branches_fail_through_candidate_cli',
    'ci_live_or_dynamic_guards_remain_accepted_through_candidate_cli',
    'ci_dynamic_or_alternate_shell_branches_remain_accepted'))


def eligible(case):
    return type(case) is str and case.split('[',1)[0] in OWNERS


def proposal(host,actor,raw):
    from fixed_inline import PINS
    from prepared_distribution import tree
    from console_entries import script,normalized
    case=host.case
    checkout=Path(host.meta['checkout'])
    source_unit(checkout,TEST,PINS[TEST])
    refuse_if(not eligible(case) or raw['stdin'] is not None, 'repository CLI closed case and input')
    cwd=Path(raw['cwd'])
    base=retain(host,cwd.parent, 20000)
    refuse_if(cwd!=base/'repository' or cwd.resolve()!=cwd, 'repository CLI original owned directory')
    records=[row for row in host.intents.values() if row['case']==case]
    env={**host.meta_environment(),'PYTEST_VERSION':'9.0.2','PYTEST_CURRENT_TEST':case+' (call)'}
    runtime=Path(host.meta['runtime_root'])
    fields={}
    if actor['role']=='root':
        host.root_only(actor)
        console=bool(records)
        refuse_if(len(records)!=(1 if console else 0) or console and not host.ledger.reaped(records[0]['birth'],records[0]['token']), 'repository CLI init and original parent wait')
        if console:
            refuse_if(tree(cwd/'src')!=tree(checkout/'src'), 'repository CLI copied source differs')
            executable=str(runtime/'bin/unrest')
            vector=(executable,'check-repository')
            env['PYTHONPATH']=str(cwd/'src')
            _,payload=script(host,'unrest')
            fields={'python_vector':normalized(runtime,Path(host.meta['dependencies']),'unrest',vector[1:]),
                    'fixed_operation':'check','repository_cli':str(cwd)}
            role,pin='fixed-inline',host.binding['entry']['sha256']
        else:
            executable,vector,role,pin,payload='/usr/bin/git',('git','init','--quiet'),'git-fixed',image(),None
    else:
        parent=[row for row in records if row['role']=='fixed-inline' and row['consumed']
                and row.get('birth')==actor['birth'] and row['token']==actor['token'] and row.get('repository_cli')==str(cwd)]
        refuse_if(actor['role']!='fixed-inline' or not actor['body_ready'] or len(parent)!=1 or len(records)!=2, 'repository CLI exact console query owner')
        executable,vector,role,pin,payload='/usr/bin/git',('git','-C',str(cwd),'rev-parse','--show-toplevel'),'git-fixed',image(),None
        env['PYTHONPATH']=str(cwd/'src')
    expected=build_expected(case,executable,pin,vector,tuple(sorted(env.items())),str(cwd),'native')
    refuse_if(raw['executable']!=executable, 'repository CLI exact executable')
    return admit_expected(host,actor,raw,expected,role,[executable,*vector[1:]],payload,maximum=2 if role=='git-fixed' else 1,fields=fields)
