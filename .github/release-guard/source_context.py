"""Install finite multiprocessing hooks after original case discovery."""

def install(policy):
    from multiprocess_entry import ALL_CASES
    if any(case in ALL_CASES for case in policy.profile['cases']):
        from multiprocess_hooks import install
        install(policy)
