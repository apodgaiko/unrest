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
CASES=(*DISTRIBUTION,FIRST,LIFECYCLE,*SECURITY_CASES)
PINS={'tests/contracts/conftest.py': '397631196d19b0060ab5042601888f502982e227c9c6feb3448e26f1b4006567', 'tests/contracts/test_lean_package.py': '8d4f3fe06f1aadb67e04c20fbcbf1c1749a4c4fe660ab48aaa8d65686bf2b8de', 'tests/test_distribution_check.py': '4f71d34b55bb0f1b94b9cba976246a204301f1e0e821e5f7928924b351b61232', 'tools/check_distribution.py': 'e6a6e5476914f378fb74ae1bfed5f9591b6b94876e181ceeac638cdf3aa3a536'}


def literal(checkout,path,name,variable):
    return source_literal(source_unit(checkout,path,PINS[path],() if name is None else (name,)),variable)

