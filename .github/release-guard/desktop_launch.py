"""One disposable stdio desktop fixture and its own process-start query."""
from pathlib import Path
import stat

from content_manifest import Refused
from git_observer import image
from launch_policy import build_expected

CASE = 'tests/test_v046_desktop_fixture.py::test_actual_stdio_response_binds_fixture_process_and_candidate'
TOOL = 'tools/v046_desktop_fixture.py'
PIN = '1f9dc20dba475782fd30812148a318dfbb644623ee68aeaa91331f32a7f485e6'
OWNER = 20000


def directory(path, owned):
    root=Path(path)
    parent=root.parent
    info=root.stat(follow_symlinks=False)
    outer=parent.stat(follow_symlinks=False)
    prefix=CASE.split('::')[1][:30]
    suffix=parent.name[len(prefix):]
    if (str(root.resolve())!=path or root.name!='desktop' or parent.parent!=owned/'pytest'
            or not parent.name.startswith(prefix) or not suffix.isascii() or not suffix.isdigit()
            or any(not stat.S_ISDIR(row.st_mode) or row.st_uid!=OWNER or stat.S_IMODE(row.st_mode)!=0o700 for row in (info,outer))):
        raise Refused('desktop exact owned fixture directory')
    return path,info.st_dev,info.st_ino,info.st_mode,info.st_uid,outer.st_dev,outer.st_ino


def retained(host):
    row=host.fixture_roots.get(CASE)
    if row is None or directory(row[0],Path(host.meta['owned']))!=row:
        raise Refused('desktop fixture generation')
    return Path(row[0])


def proposal(host,actor,raw):
    if host.case!=CASE or raw['stdin'] is not None:
        raise Refused('desktop exact case and input')
    records=[row for row in host.intents.values() if row['case']==CASE]
    query=actor['role']=='desktop'
    if not query:
        host.root_only(actor)
        if records:
            raise Refused('desktop sole server')
        row=directory(raw['cwd'],Path(host.meta['owned']))
        if host.fixture_roots.setdefault(CASE,row)!=row:
            raise Refused('desktop root replacement')
    root=retained(host)
    native=host.binding['entry']['path']
    if query:
        servers=[row for row in records if row['role']=='desktop' and row['consumed']
                 and row['pid']==actor['birth'].pid and row['birth']==actor['birth'] and row['token']==actor['token']]
        if len(records)!=1 or len(servers)!=1 or not actor['body_ready']:
            raise Refused('desktop sole responding process query')
        if str(Path('/bin/ps').resolve(strict=True))!='/usr/bin/ps':
            raise Refused('desktop system ps alias changed')
        role,exe,pin,kind='ps','/usr/bin/ps',image('/usr/bin/ps'),'native'
        argv=('/bin/ps','-p',str(actor['birth'].pid),'-o','lstart=')
        environment={'HOME':str(root/'user'),'PATH':'/usr/bin:/bin','LANG':'C.UTF-8',
            'UNREST_HOME':str(root/'home'),'UNREST_PROJECTS_DIR':str(root/'home/projects'),'PYTHONDONTWRITEBYTECODE':'1'}
        reference=None
    else:
        role,exe,pin,kind='desktop',native,host.binding['entry']['sha256'],'python-script'
        argv=(native,'-I',str(Path(host.meta['checkout'])/TOOL),'serve','--root',str(root))
        environment={'HOME':str(root/'user'),'PATH':'/usr/bin:/bin'}
        reference=PIN
    value=build_expected('desktop:'+role,CASE,exe,pin,argv,tuple(sorted(environment.items())),str(root),kind,reference)
    if raw['argv']!=list(value.argv) or raw['environment']!=dict(value.environment) or raw['cwd']!=value.cwd:
        raise Refused('desktop exact original operands')
    vector=[exe,*argv[1:]] if query else [exe,'-I','-S',*argv[2:]]
    answer=host.admit_launch(actor,value,role,vector,reference)
    return None if answer is None else {**answer,'translated':vector,'rule':value.rule}
