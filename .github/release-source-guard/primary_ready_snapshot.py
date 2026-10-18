"""Current READY journal acquisition for the observer's own PRIMARY producers."""
from __future__ import annotations

import types

from linux_producers import NativeProducers
from linux_supervisor import Supervisor


def install(supervisor, producers):
    if (type(supervisor) is not Supervisor or type(producers) is not NativeProducers
            or producers.supervisor is not supervisor
            or supervisor.authenticate.__func__ is not Supervisor.authenticate):
        raise RuntimeError('primary_ready_snapshot_owner')
    original = supervisor.authenticate

    def authenticate(owner, request, events):
        if owner is not supervisor or original.__self__ is not owner:
            raise RuntimeError('primary_ready_snapshot_binding')
        child = producers.children.get(request.get('pid'))
        saved = owner.registered.get(request.get('pid'))
        if (request.get('kind') == 'ready' and child is not None and saved is not None
                and child['token'] == saved['token'] == request.get('token')
                and child['identity'] == saved['identity'] and 'ready_pins' in saved
                and not any(event['kind'] == 'ready' and event['owner_pid'] == request['pid']
                            and event['token'] == request['token'] for event in events)):
            # The producer may append READY after the tick's initial census.
            # Original authentication still consumes current birth and all pins.
            events = owner.events()
        return original(request, events)

    supervisor.authenticate = types.MethodType(authenticate, supervisor)
