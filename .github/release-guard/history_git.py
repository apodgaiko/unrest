"""Readonly commands over the closed public-history projection; no Git helpers."""
from pathlib import Path

from content_manifest import Refused
from launch_policy import source_unit,build_expected,admit_expected
from owned_fixture import retain
from public_git import FM000

BINDING='tests/test_release_binding.py'
V021='tests/test_v021_release_records.py'
V045='tests/test_v045_release_records.py'
CLI=V045+'::test_binding_cli_accepts_active_manifest_and_refuses_wrong_digest'
TOOL='tools/release_binding.py'
TOOL_PIN='c40638ed9b7b00e2ca831bd29c909c78672bb91017d21ad13c283143989f43a2'
PUBLISHED='5a3d568aa881c746432b7034597bbb8a1ffe025f'
CATALOG={
    BINDING:('test_binding_uses_only_candidate_regular_files','test_binding_rejects_coherent_fake_digest',
        'test_current_candidate_binding_hashes_exact_current_source','test_v02_carriers_are_byte_identical_to_the_v020_tag',
        'test_v030_carriers_are_byte_identical_to_the_v030_tag','test_v031_carriers_are_byte_identical_to_the_v031_tag',
        'test_v045_manifest_binds_only_its_published_source'),
    V021:('test_fm000_proposal_artifacts_remain_exact_historical_provenance','test_v021_candidate_had_no_forbidden_v03_runtime_surface'),
    V045:('test_v040_release_carriers_remain_exact_tag_bytes',),
}
CASES=(*tuple(file+'::'+name for file,names in CATALOG.items() for name in names),CLI)
PINS={'tests/test_release_binding.py': '2db77fb31af6b7e536420a16aaa92fc237404570d0f97df37f374fed788c2d0f', 'tests/test_v021_release_records.py': '7d5f90c969295c019e515133cca6abbb2458882c53b43a7bee3c59ca44a95ee5', 'tests/test_v045_release_records.py': 'be9693d6ad6937f0080f6022d3db602ad8530c0d24f8528b85ebc3ee4c492da4'}


def commands(checkout,case):
    file,name=case.split('::')
    source_unit(checkout,file,PINS[file],(name,))
    if case==CLI or name in CATALOG[BINDING][:3]:
        return [('ls-files','--stage','-z'),('ls-files','--others','--exclude-standard','-z')]
    versions={'test_v02_carriers_are_byte_identical_to_the_v020_tag':('0.2', '0.2.0',('manifest.json','review-audit.json','evidence-crosswalk.json','md','rollback.md')),
        'test_v030_carriers_are_byte_identical_to_the_v030_tag':('0.3.0','0.3.0',('manifest.json','md','rollback.md')),
        'test_v031_carriers_are_byte_identical_to_the_v031_tag':('0.3.1','0.3.1',('manifest.json','burden.json','md','rollback.md'))}
    if name in versions:
        stem,tag,suffixes=versions[name]
        return [('show','v'+tag+':docs/release/lean-core-v'+stem+('.md' if suffix=='md' else '-'+suffix)) for suffix in suffixes]
    if name=='test_v045_manifest_binds_only_its_published_source':
        return [('ls-tree','-r','-z',PUBLISHED),('archive',PUBLISHED),
            *(('show',PUBLISHED+':docs/release/lean-core-v0.4.5'+suffix) for suffix in ('-manifest.json','.md','-rollback.md'))]
    if name==CATALOG[V045][0]:
        return [('show','v0.4.0:'+str(path.relative_to(checkout))) for path in sorted((checkout/'docs/release').glob('lean-core-v0.4.0*'))]
    if name==CATALOG[V021][1]:
        commit='d14054605fdb9890f2c78395f8d08b532dbc5dc7'
        return [('rev-parse','v0.2.1^{commit}'),('diff','--name-only',FM000,commit)]
    roots=('docs/v03/contracts','tests/fixtures/v03_decisions','docs/decisions')
    paths=sorted(path for root in roots for path in (checkout/root).rglob('*') if path.is_file()
        and (root!='docs/decisions' or path.name.startswith('ADR-030')))
    return [('merge-base','--is-ancestor',FM000,'HEAD'),*(('ls-tree','-r',FM000,'--',root) for root in roots),
        *(('rev-parse',FM000+':'+str(path.relative_to(checkout))) for path in paths)]


def proposal(host,actor,raw):
    from git_observer import HOME_CONFIG,regular,image
    checkout=Path(host.meta['checkout'])
    if host.case==CLI:
        if raw['argv'][0]==host.binding['entry']['path']:
            return cli_proposal(host,actor,raw)
        if actor['role']!='fixed-inline' or actor['case']!=CLI or not actor['body_ready']:
            raise Refused('history original CLI parent')
        records=[value for value in host.intents.values() if value['role']=='fixed-inline'
            and value['case']==CLI and value['token']==actor['token'] and value.get('birth')==actor['birth'] and value['consumed']]
        if len(records)!=1 or raw['cwd']!=records[0]['binding_repository']:
            raise Refused('history original CLI repository')
        metadata=Path(raw['cwd'])/'.git'
        if (metadata.resolve()!=metadata or {path.name for path in metadata.iterdir()}!={'HEAD','objects','refs'}
                or regular(metadata/'HEAD')!=b'ref: refs/heads/main\n'
                or any(path.is_symlink() or not path.is_dir() or list(path.iterdir()) for path in (metadata/'objects',metadata/'refs'))):
            raise Refused('binding CLI exact empty metadata')
    else:
        host.root_only(actor)
    if raw['executable']!='/usr/bin/git' or raw['stdin'] is not None or tuple(raw['argv'][1:]) not in commands(checkout,host.case):
        raise Refused('history exact readonly command')
    if regular(Path(host.meta['owned'])/'home/.gitconfig',uid=20001)!=HOME_CONFIG:
        raise Refused('history protected home configuration')
    previous=[value for value in host.intents.values() if value['case']==host.case and value['role']=='git-custody']
    if any(not value['consumed'] or not host.ledger.reaped(value['birth'],value['token']) for value in previous):
        raise Refused('history previous actual parent wait')
    environment={**host.meta_environment(),'PYTEST_VERSION':'9.0.2','PYTEST_CURRENT_TEST':host.case+' (call)'}
    expected=build_expected('history:git',host.case,'/usr/bin/git',image(),tuple(raw['argv']),
        tuple(sorted(environment.items())),raw['cwd'] if host.case==CLI else str(checkout),'native')
    return admit_expected(host,actor,raw,expected,'git-custody',['/usr/bin/git',*raw['argv'][1:]],maximum=128)


def cli_proposal(host,actor,raw):
    host.root_only(actor)
    checkout=Path(host.meta['checkout'])
    source_unit(checkout,V045,PINS[V045],(CLI.split('::')[1],))
    source_unit(checkout,TOOL,TOOL_PIN)
    argv=raw['argv']
    if len(argv)!=7 or raw['stdin'] is not None:
        raise Refused('binding CLI original argument count')
    root=retain(host,Path(argv[4]).parent,CLI.split('::')[1][:30],20000)
    repository=root/'repository'
    if repository.resolve()!=repository or (repository/'.git').resolve()!=repository/'.git':
        raise Refused('binding CLI repository alias')
    previous=[value for value in host.intents.values() if value['case']==CLI]
    if any(not value['consumed'] or not host.ledger.reaped(value['birth'],value['token']) for value in previous):
        raise Refused('binding CLI previous actual wait')
    ordinal=sum(value['role']=='fixed-inline' for value in previous)
    if ordinal>=2:
        raise Refused('binding CLI original two invocations')
    native,pin=host.binding['entry']['path'],host.binding['entry']['sha256']
    vector=(native,'-B',str(checkout/TOOL),'--repository',str(repository),'--check-manifest',str(root/('active-manifest.json' if ordinal==0 else 'wrong-manifest.json')))
    environment={**host.meta_environment(),'PYTEST_VERSION':'9.0.2','PYTEST_CURRENT_TEST':CLI+' (call)'}
    expected=build_expected('binding:cli',CLI,native,pin,vector,tuple(sorted(environment.items())),str(checkout),'python-script',TOOL_PIN)
    return admit_expected(host,actor,raw,expected,'fixed-inline',[native,'-I','-S',*vector[2:]],TOOL_PIN,maximum=2,
        fields={'fixed_operation':'check','binding_repository':str(repository),'binding_status':ordinal})
