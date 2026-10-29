"""Observer-owned serial broker contexts for the original ROOT refusal cases."""
from __future__ import annotations

import hashlib
from pathlib import Path

from content_manifest import Refused
from controlled_cases import ROOT_HTTP, INITIALIZED_HTTP
from source_observer import shape, number
from endpoint_policy import Route
from socket_observation import acquire_tcp


def context(observer,actor,kind,payload):
    observer.root_only(actor)
    if observer.case not in ROOT_HTTP:
        raise Refused('root HTTP undeclared case')
    shape(payload,('ordinal','listener','scope') if kind == 'root-http-open' else ('ordinal',))
    ordinal = number(payload['ordinal'],1)
    key = observer.case,ordinal
    if kind == 'root-http-close':
        state = observer.http_contexts.get(key)
        if (state is None or not state['active']
                or any(ticket.route.name == state['route'] for ticket in observer.endpoints.tickets.values())):
            raise Refused('root HTTP active context or unfinished reciprocal join')
        state['active'] = False
        return {'ok':True}
    states = [state for (case,_),state in observer.http_contexts.items() if case == observer.case]
    if (ordinal != len(states)+1 or ordinal > (2 if observer.case == INITIALIZED_HTTP else 1)
            or any(state['active'] for state in states) or type(payload['scope']) is not str):
        raise Refused('root HTTP exact serial context frontier')
    scope = Path(payload['scope'])
    if (not scope.is_absolute() or str(scope.resolve()) != str(scope) or scope.name != 'owner'
            or scope.parent.name != ('probe' if observer.case == INITIALIZED_HTTP else 'campaign')
            or not scope.is_relative_to(Path(observer.meta['owned'])/'pytest')):
        raise Refused('root HTTP original broker scope')
    slot = observer.listeners.get(observer.listener_key(observer.case,'broker',str(scope)))
    descriptor = number(payload['listener'])
    listener = acquire_tcp(actor['birth'],descriptor)
    if slot is None or slot['socket'].fd != descriptor or listener != slot['socket']:
        raise Refused('root HTTP original broker listener generation')
    name = actor['token']+':http:'+hashlib.sha256(observer.case.encode()).hexdigest()+':'+str(ordinal)
    route = Route(name,observer.case,observer.owner(actor),observer.owner(actor),listener.local[1])
    sharing = listener if any(value.port == route.port and value.case not in observer.endpoints.retired
                              for value in observer.endpoints.routes.values()) else None
    observer.endpoints.declare(route,shared_listener=sharing)
    observer.endpoints.listen(name,listener)
    observer.http_contexts[key] = {'active':True,'route':name,'port':listener.local[1],
                                  'maximum':1 if ordinal == 2 else 3}
    return {'ok':True,'port':listener.local[1]}


def connection(observer,actor,payload,port):
    observer.root_only(actor)
    ordinal = number(payload['context'],1)
    state = observer.http_contexts.get((observer.case,ordinal))
    if state is None or not state['active'] or state['port'] != port:
        raise Refused('root HTTP absent retired or foreign context')
    return state['route'],state['maximum']


def retained(observer,connection,observed):
    states = [state for state in observer.http_contexts.values() if state['route'] == connection.ticket.route.name]
    if states and (len(states) != 1 or not states[0]['active'] and observed.binding() == connection.client.binding()):
        raise Refused('root HTTP retired client payload')
