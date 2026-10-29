"""Finite original distribution and installed-package cases and literal bodies."""

from launch_policy import source_unit,literal as source_literal

from package_security import CASES as SECURITY_CASES

TEST='tests/test_distribution_check.py'
POSITIVE=TEST+'::test_checker_builds_and_executes_15_cases_with_extracted_provenance'
NEGATIVE={TEST+'::test_extracted_oracle_cannot_borrow_an_omitted_fixture':'missing-corpus',
          TEST+'::test_extracted_oracle_cannot_import_from_forced_checkout_path':'missing-package'}
MEMBERS=('tests/fixtures/persistence_schema_v1/corpus.json',
    'tests/fixtures/persistence_schema_v1/generation-transcript.json',
    'tests/fixtures/persistence_schema_v1/legacy-validation-handoff.json',
    'tests/fixtures/persistence_schema_v1/legacy-work-handoff.json',
    'tests/fixtures/persistence_schema_v1/manifest.json','tests/test_persistence_schema_v1.py',
    'tools/generate_legacy_handoff_fixtures.py')
MUTATIONS={TEST+'::test_checker_rejects_each_missing_or_changed_oracle_member['+kind+'-'+member+']':(kind,member)
           for kind in ('omitted','changed') for member in MEMBERS}
DISTRIBUTION=(POSITIVE,*MUTATIONS,*NEGATIVE)
CONTRACT='tests/contracts/test_lean_package.py'
FIRST=CONTRACT+'::test_reference_contract_scenario[VAL-PACKAGE-001__packaged-policy-is-versioned-and-loadable]'
LIFECYCLE=CONTRACT+'::test_reference_contract_scenario[VAL-PACKAGE-003__installed-lifecycle-restarts-and-persists]'
REFERENCES=('tests/test_capability_policy.py::test_cli_safe_init_round_trips_policy_and_never_persists_secrets',
    'tests/test_server.py::test_redacted_mcp_handoffs_survive_restart_and_mirroring')
CASES=(*DISTRIBUTION,FIRST,LIFECYCLE,*SECURITY_CASES)
GROUPS={'security3':SECURITY_CASES,'distribution17':DISTRIBUTION,'package-contracts4':(*REFERENCES,FIRST,LIFECYCLE)}
PINS={'tests/contracts/conftest.py': '397631196d19b0060ab5042601888f502982e227c9c6feb3448e26f1b4006567', 'tests/contracts/test_lean_package.py': '8d4f3fe06f1aadb67e04c20fbcbf1c1749a4c4fe660ab48aaa8d65686bf2b8de', 'tests/test_distribution_check.py': '4f71d34b55bb0f1b94b9cba976246a204301f1e0e821e5f7928924b351b61232', 'tools/check_distribution.py': '384f0c545be75553d389df4dfbcdd08c2f1249f61131f5cf7a19e538c1b56e61'}


def literal(checkout,path,name,variable):
    return source_literal(source_unit(checkout,path,PINS[path],() if name is None else (name,)),variable)


def count(case,host=None):
    if case in SECURITY_CASES:
        from package_security import count as security_count
        return security_count(host)
    return 2 if case==POSITIVE else 1 if case in (*MUTATIONS,*NEGATIVE,FIRST,LIFECYCLE) else 0
