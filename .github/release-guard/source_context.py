"""Install the finite multiprocessing hooks after original case discovery."""

class Context:
    def __init__(self,policy):
        self.policy=policy

    def install(self):
        from multiprocess_entry import ALL_CASES
        if any(case in ALL_CASES for case in self.policy.profile['cases']):
            from multiprocess_hooks import install
            install(self.policy)
