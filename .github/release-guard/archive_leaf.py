"""Run the original checker/probe with truthful observer-owned input provenance."""
import importlib.util
import sys
from pathlib import Path

from content_manifest import Refused
from package_cases import literal, PINS, NEGATIVE

CHECKER_COMMAND='from archive_leaf import checker_main;checker_main()'
LEAF_COMMAND='from archive_leaf import main;raise SystemExit(main())'


def oracle(policy):
    path=Path(policy.profile['checkout'])/'tools/check_distribution.py'
    from source_profile import digest
    if digest(path)!=PINS['tools/check_distribution.py']:
        raise Refused('archive original checker bytes')
    specification=importlib.util.spec_from_file_location('original_archive_checker',path)
    result=importlib.util.module_from_spec(specification)
    specification.loader.exec_module(result)
    return result


def checker_main():
    from source_entry import ACTIVE
    from prepared_distribution import Provider
    if ACTIVE is None or ACTIVE.profile['role']!='archive-checker':
        raise Refused('archive checker native role')
    module=oracle(ACTIVE)
    original=module._run_extracted_restart_oracle
    def run(root,**kwargs):
        return original(Provider(ACTIVE).snapshot(root),**kwargs)
    module._run_extracted_restart_oracle=run
    sys.argv=[str(Path(ACTIVE.profile['checkout'])/'tools/check_distribution.py'),ACTIVE.profile['argv'][5]]
    module.main()


def main():
    from source_entry import ACTIVE
    from source_root import local_cases
    from postbuild_root import CASES
    import pytest
    if ACTIVE is None or ACTIVE.profile['role']!='archive-leaf':
        raise Refused('archive leaf native role')
    policy=ACTIVE
    kind=NEGATIVE.get(policy.case,'normal')
    if any(name=='unrest_harness' or name.startswith('unrest_harness.') for name in sys.modules):
        raise Refused('archive package preloaded before probe')
    leaf=local_cases(policy,CASES,normal_outcomes=kind=='missing-corpus')
    original=pytest.main
    called=False
    def run(args,plugins):
        nonlocal called
        if called or args!=['-q','tests/test_persistence_schema_v1.py']:
            raise Refused('archive original fifteen-case invocation')
        called=True
        return original(args,plugins=[*plugins,leaf])
    pytest.main=run
    sys.argv=[policy.profile['native'],policy.profile['checkout']]
    code=None
    missing=False
    try:
        probe=literal(Path(policy.profile['checkout']),'tools/check_distribution.py',None,'_PYTEST_PROBE')
        exec(compile(probe,'<original-distribution-probe>','exec'),{'__name__':'__main__'})
    except ModuleNotFoundError as exc:
        if kind!='missing-package' or exc.name!='unrest_harness' or called or 'unrest_harness' in sys.modules:
            raise
        code=1
        missing=True
    except SystemExit as exc:
        code=exc.code
    finally:
        pytest.main=original
    return finish(policy,kind,code,leaf,missing,called)


def finish(policy,kind,code,leaf,missing,called):
    from postbuild_root import CASES
    expected=1 if kind!='normal' else 0
    phases={'setup':'passed','call':'failed' if kind=='missing-corpus' else 'passed','teardown':'passed'}
    if (kind not in ('normal','missing-corpus','missing-package') or isinstance(code,bool) or not isinstance(code,int)
            or policy.poison or code!=expected or (kind=='missing-package' and (not missing or leaf.completed or leaf.reports or called))
            or kind!='missing-package' and (missing or not called or tuple(leaf.completed)!=CASES or any(leaf.reports.get(case)!=phases for case in CASES))):
        raise Refused('archive actual original outcome incomplete')
    policy.client.request('archive-result',{'kind':kind,'count':0 if kind=='missing-package' else 15,
        'failed':15 if kind=='missing-corpus' else 0,'exit':expected})
    return expected
