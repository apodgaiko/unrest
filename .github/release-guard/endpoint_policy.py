"""Unix pair owner epochs; TCP routing is ordinary isolated loopback traffic."""
from dataclasses import dataclass
from content_manifest import Refused
from process_ledger import Birth,Ledger,fail_closed,text


@dataclass(frozen=True)
class Owner:
    birth: Birth
    token: str
    generation: int


class Endpoints:
    def __init__(self,ledger: Ledger):
        self.ledger=ledger
        self.poison=[]
        self.retired=set()

    def owner(self, owner: Owner, case: str, *, body: bool) -> None:
        if self.poison or self.ledger.poison or type(owner) is not Owner or case in self.retired:
            raise Refused('endpoint poisoned or unknown owner')
        process = self.ledger.process(owner.birth)
        if (type(owner.token) is not str or type(owner.generation) is not int
                or owner.token != process.token or owner.generation != process.generation
                or process.registered_generation != process.generation or process.case != case
                or process.exit is not None or process.terminal is not None
                or process.stage not in (('body-ready',) if body else ('core-ready', 'body-ready'))):
            raise Refused('endpoint owner epoch or readiness')

    @fail_closed
    def retire_case(self, case: str) -> None:
        text(case)
        if case in self.retired:
            raise Refused('endpoint retirement has outstanding admission')
        # Revoke capabilities, preserving observations; this does not assert FD close.
        self.retired.add(case)
