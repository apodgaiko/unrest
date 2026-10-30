"""Two controlled followers of a SIGKILLed owner; no original wait is invented."""
from approval_launch import CRASH
from content_manifest import Refused as Refused, refuse_if
from linux_observation import process_identity
from process_ledger import Birth


def followers(host):
    from source_observer import bound_intent
    workers=[actor for actor in host.actors.values() if actor['case']==host.case
             and (row:=bound_intent(host,actor)) is not None and row.get('approval_worker') is True]
    if not workers:
        return None,[]
    refuse_if(len(workers)!=1, 'approval crash unique admitted worker')
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
    refuse_if(owner.exit[1]!=9 or 9 not in worker['signals'], 'approval follower requires attributed owner SIGKILL')
    for actor in children:
        process=host.ledger.process(actor['birth'])
        if process.adopted_identity is not None:
            if process.terminal is not None:
                wait_request(host,actor,process)
            continue
        refuse_if(process.exit is not None or process.terminal is not None, 'approval follower missed live adoption observation')
        try:
            observed=process_identity(actor['birth'].pid)
        except (FileNotFoundError,ProcessLookupError):
            continue
        if Birth.read(observed).parent!=1:
            refuse_if(Birth.read(observed).parent!=worker['birth'].pid, 'approval follower unexpected kernel parent')
            continue
        from source_observer import bound_intent
        row=bound_intent(host,actor)
        refuse_if(row is None or not actor['body_ready'] or not host.executed(row)
                or any(observed['namespaces'][key]!=actor['profile'][field] for key,field in
                    (('pid','pid_namespace'),('mnt','mount_namespace'),('net','network_namespace'))), 'approval follower exact ready generation')
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
    refuse_if(not actor['body_ready'] or not host.executed(actor['intent']), 'approval follower exit before ready generation')
    return host.ledger.process(actor['birth']).adopted_identity is not None


def certified_owner(host):
    worker,children=followers(host)
    refuse_if(worker is None, 'approval follower missing owner')
    process=host.ledger.process(worker['birth'])
    refuse_if(len(children)!=2 or not host.ledger.reaped(worker['birth'],worker['token'])
            or process.terminal[2]!=-9 or 9 not in worker['signals']
            or any(host.ledger.process(actor['birth']).adopted_identity is None for actor in children), 'approval follower owner actual root wait')
    return children
