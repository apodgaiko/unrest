"""Two controlled followers of a SIGKILLed owner; no original wait is invented."""
from approval_launch import CRASH
from content_manifest import Refused
from linux_observation import process_identity
from process_ledger import Birth


def followers(host):
    from source_observer import bound_intent
    workers=[actor for actor in host.actors.values() if actor['case']==host.case
             and (row:=bound_intent(host,actor)) is not None and row.get('approval_worker') is True]
    if not workers:
        return None,[]
    if len(workers)!=1:
        raise Refused('approval crash unique admitted worker')
    worker=workers[0]
    children=[actor for actor in host.actors.values() if actor['case']==host.case
        and actor['role'] in ('mcp','approval-adapter')
        and host.ledger.process(actor['birth']).parent==worker['birth']]
    return worker,children


def refresh(host):
    if host.case not in CRASH:
        return
    # Called at the held kernel exit stop too: namespace links still exist.
    from composed_adoption import wait_request
    worker,children=followers(host)
    if worker is None:
        return
    owner=host.ledger.process(worker['birth'])
    if owner.exit is None:
        return
    if owner.exit[1]!=9 or 9 not in worker['signals']:
        raise Refused('approval follower requires attributed owner SIGKILL')
    for actor in children:
        process=host.ledger.process(actor['birth'])
        if process.adopted_identity is not None:
            if process.terminal is not None:
                wait_request(host,actor,process)
            continue
        if process.exit is not None or process.terminal is not None:
            raise Refused('approval follower missed live adoption observation')
        try:
            observed=process_identity(actor['birth'].pid)
        except (FileNotFoundError,ProcessLookupError):
            continue
        if Birth.read(observed).parent!=1:
            if Birth.read(observed).parent!=worker['birth'].pid:
                raise Refused('approval follower unexpected kernel parent')
            continue
        from source_observer import bound_intent
        row=bound_intent(host,actor)
        if (row is None or not actor['body_ready'] or not host.executed(row)
                or any(observed['namespaces'][key]!=actor['profile'][field] for key,field in
                    (('pid','pid_namespace'),('mnt','mount_namespace'),('net','network_namespace')))):
            raise Refused('approval follower exact ready generation')
        host.ledger.adopt(actor['birth'],observed,follower=worker['birth'])


def exiting(host,pid):
    if host.case not in CRASH:
        return True
    worker,children=followers(host)
    if worker is None:
        return True
    actor=next((actor for actor in children if actor['birth'].pid==pid),None)
    owner=host.ledger.process(worker['birth'])
    if actor is None or owner.exit is None:
        return True
    if not actor['body_ready'] or not host.executed(actor['intent']):
        raise Refused('approval follower exit before ready generation')
    return host.ledger.process(actor['birth']).adopted_identity is not None


def certified_owner(host):
    worker,children=followers(host)
    if worker is None:
        raise Refused('approval follower missing owner')
    process=host.ledger.process(worker['birth'])
    if (len(children)!=2 or not host.ledger.reaped(worker['birth'],worker['token'])
            or process.terminal[2]!=-9 or 9 not in worker['signals']
            or any(host.ledger.process(actor['birth']).adopted_identity is None for actor in children)):
        raise Refused('approval follower owner actual root wait')
    return children
