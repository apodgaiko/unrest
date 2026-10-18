"""Fresh READY acquisition for the exact PRIMARY package producer pair."""
from __future__ import annotations

import types


def install(supervisor, producers):
    from linux_supervisor import Supervisor
    from primary_package_build import PackageProducers
    if (type(supervisor) is not Supervisor or type(producers) is not PackageProducers
            or producers.supervisor is not supervisor
            or supervisor.authenticate.__func__ is not Supervisor.authenticate):
        raise RuntimeError('primary_package_ready_owner')
    original = supervisor.authenticate

    def authenticate(owner, request, events):
        if owner is not supervisor or original.__self__ is not owner:
            raise RuntimeError('primary_package_ready_binding')
        child = producers.children.get(request.get('pid'))
        saved = owner.registered.get(request.get('pid'))
        if (request.get('kind') == 'ready' and child is not None and saved is not None
                and child['token'] == saved['token'] == request.get('token')
                and child['identity'] == saved['identity'] and 'ready_pins' in saved
                and not any(event['kind'] == 'ready' and event['owner_pid'] == request['pid']
                            and event['token'] == request['token'] for event in events)):
            events = owner.events()
        return original(request, events)

    supervisor.authenticate = types.MethodType(authenticate, supervisor)
