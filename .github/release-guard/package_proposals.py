"""Observer-selected distribution inputs and finite original process declarations."""
import os
from pathlib import Path
import stat

from content_manifest import Refused, read_regular, _directory_key, _key
from launch_policy import admit_expected,build_expected
from package_cases import POSITIVE, NEGATIVE, MUTATIONS, FIRST, LIFECYCLE, literal, CONTRACT, SECURITY_CASES
from archive_leaf import CHECKER_COMMAND, LEAF_COMMAND

SOURCE_UID=20000
PREPARED_UID=0


def inputs(host):
    from prepared_distribution import observer_inputs
    return observer_inputs(host)


def owned(path,root,prefix):
    info=path.stat(follow_symlinks=False)
    suffix=path.name[len(prefix):]
    if (str(path.resolve())!=str(path) or path.parent!=root/'pytest' or not path.name.startswith(prefix)
            or not suffix.isascii() or not suffix.isdigit() or not stat.S_ISDIR(info.st_mode)
            or info.st_uid!=SOURCE_UID or stat.S_IMODE(info.st_mode)!=0o700):
        raise Refused('package exact owned fixture root')
    return list(_directory_key(info))


def snapshot(host,actor,payload):
    from source_observer import shape
    from archive_snapshot import acquire
    shape(payload,('path',))
    host.launch_owner(actor)
    case=host.case
    if (not actor['body_ready'] or case in host.fixture_roots
            or (actor['role']=='root' and case not in NEGATIVE)
            or (actor['role']!='root' and (actor['role']!='archive-checker' or case!=POSITIVE))):
        raise Refused('archive snapshot original actor and case')
    if type(payload['path']) is not str:
        raise Refused('archive snapshot path primitive')
    source=Path(payload['path'])
    data=inputs(host)
    expected_name=next(data['dist'].glob('*.tar.gz')).name.removesuffix('.tar.gz')
    if str(source.resolve())!=str(source) or source.name!=expected_name:
        raise Refused('archive original extracted root')
    if case in NEGATIVE:
        owned(source.parent,Path(host.meta['owned']),case.split('::')[1][:30])
    elif (source.parent.parent!=Path(host.meta['owned'])/'tmp'
            or not source.parent.name.startswith('unrest-sdist-check-')
            or source.parent.stat().st_uid!=SOURCE_UID or stat.S_IMODE(source.parent.stat().st_mode)!=0o700):
        raise Refused('archive original temporary extraction')
    token=os.urandom(16).hex()
    target=host.directory/('snapshot-'+token)
    kind=NEGATIVE.get(case,'normal')
    sealed=acquire(source,data['extracted'],target,kind)
    document={'schema':'unrest.archive-snapshot.v1','case':case,'kind':kind,'root':str(target),'snapshot':sealed}
    host.fixture_roots[case]={'document':document,'parent':actor['birth'],'token':actor['token']}
    return {'ok':True,'path':str(target)}


def environment(host,case,phase):
    return {**host.meta_environment(),'PYTEST_VERSION':'9.0.2','PYTEST_CURRENT_TEST':case+' ('+phase+')'}


def archive_inputs(path,case):
    uid=PREPARED_UID if case==POSITIVE else SOURCE_UID
    before=path.stat(follow_symlinks=False)
    names=sorted(item.name for item in path.iterdir())
    if (str(path.resolve())!=str(path) or not stat.S_ISDIR(before.st_mode) or before.st_uid!=uid
            or before.st_mode&0o6022 or case!=POSITIVE and len(names)!=2
            or len(list(path.glob('*.whl')))!=1 or len(list(path.glob('*.tar.gz')))!=1):
        raise Refused('archive original two-member directory')
    rows=[]
    for name in names:
        _,info,pin=read_regular(path/name,4*1024*1024,uid=uid,forbidden=0o6022,retain=False)
        rows.append([name,list(_key(info)),pin])
    if list(_directory_key(path.stat(follow_symlinks=False)))!=list(_directory_key(before)):
        raise Refused('archive input directory race')
    return [str(path),list(_directory_key(before)),rows]


def retained_archive(row,case):
    if archive_inputs(Path(row[0]),case)!=row:
        raise Refused('archive admitted input generation changed')


def proposal(host,actor,raw):
    if host.case in SECURITY_CASES:
        from package_security import proposal as security_proposal
        return security_proposal(host,actor,raw)
    case=host.case
    if raw['stdin'] is not None:
        raise Refused('package undeclared stdin')
    data=inputs(host)
    native,pin=host.binding['entry']['path'],host.binding['entry']['sha256']
    checkout,owned_root=Path(host.meta['checkout']),Path(host.meta['owned'])
    leaf=actor['role']=='archive-checker' or case in NEGATIVE
    archive_data=None
    if leaf:
        state=host.fixture_roots.get(case)
        if (state is None or state['parent']!=actor['birth'] or state['token']!=actor['token']
                or actor['role']=='archive-checker' and case!=POSITIVE):
            raise Refused('archive leaf original parent and snapshot')
        cwd=state['document']['root']
        env=environment(host,case,'call') if actor['role']=='root' else dict(actor['profile']['environment'])
        if actor['role']=='archive-checker':
            for name in ('PYTEST_PLUGINS','PYTEST_ADDOPTS'):
                env.pop(name,None)
        env.pop('PYTHONPATH',None)
        env.pop('CODEX_PATH',None)
        env.update(PYTHONPATH='src',PYTEST_DISABLE_PLUGIN_AUTOLOAD='1')
        code=literal(checkout,'tools/check_distribution.py',None,'_PYTEST_PROBE')
        argv=(native,'-c',code,str(checkout))
        vector=[native,'-I','-S','-c',LEAF_COMMAND,str(checkout)]
        role='archive-leaf'
    elif case==POSITIVE or case in MUTATIONS:
        host.root_only(actor)
        path=data['dist'] if case==POSITIVE else Path(raw['argv'][-1])
        if case in MUTATIONS:
            owned(path.parent,owned_root,case.split('::')[1].split('[')[0][:30])
            if path.name!=MUTATIONS[case][0]:
                raise Refused('archive exact original mutation directory')
        expected_names=sorted(item.name for item in data['dist'].iterdir() if item.name.endswith(('.whl','.tar.gz')))
        if case in MUTATIONS and sorted(item.name for item in path.iterdir())!=expected_names:
            raise Refused('archive exact original filenames')
        archive_data=archive_inputs(path,case)
        env=environment(host,case,'call')
        if case==POSITIVE:
            env['PYTHONPATH']=str(checkout/'src')
        cwd=str(checkout)
        argv=(native,'tools/check_distribution.py',str(path))
        vector=[native,'-I','-S','-c',CHECKER_COMMAND,str(path)]
        role='archive-checker'
    elif case in (FIRST,LIFECYCLE):
        host.root_only(actor)
        workspace=Path(raw['cwd'])
        identity=owned(workspace,owned_root,'candidate-distribution')
        current=[str(workspace),identity]
        if host.fixture_roots.setdefault('<installed-workspace>',current)!=current:
            raise Refused('installed shared fixture generation')
        if case==LIFECYCLE:
            code=literal(checkout,CONTRACT,'_run_installed_lifecycle','script')
            probe=workspace/'lifecycle-probe'
            info=probe.stat(follow_symlinks=False)
            if probe.resolve()!=probe or not stat.S_ISDIR(info.st_mode) or info.st_uid!=SOURCE_UID or info.st_mode&0o6022:
                raise Refused('installed owned lifecycle state root')
            tail=(str(probe),str(checkout),str(data['installed_site']),str(data['dependency_site']))
            env=environment(host,case,'call')
        else:
            code=literal(checkout,'tests/contracts/conftest.py',None,'PROVENANCE_BODY')
            tail=(str(data['installed_site']),str(data['dependency_site']))
            env=environment(host,case,'setup')
            env.setdefault('UV_CACHE_DIR','/tmp/unrest-worker-uv-cache')
            env.setdefault('UV_OFFLINE','1')
        env.pop('PYTHONPATH',None)
        cwd=str(workspace)
        argv=(native,'-S','-c',code,*tail)
        vector=[native,'-I','-S','-c',code,*tail]
        role='archive-installed'
    else:
        raise Refused('package exact original launch case')
    value=build_expected('package:'+role,case,native,pin,argv,tuple(sorted(env.items())),cwd,
        'native' if role=='archive-checker' else 'python-command')
    answer=admit_expected(host,actor,raw,value,role,vector,
        fields={'package_inputs':archive_data})
    if answer is not None and case==FIRST:
        row=host.intents[answer['ticket']]
        row.update(security_status=0,security_operation='provenance')
        host.fixture_roots['<installed-provenance>']=row
    return answer
