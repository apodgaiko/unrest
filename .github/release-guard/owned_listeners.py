"""Actual same-case root listeners; application handshake topology is not proof."""
from content_manifest import Refused
from endpoint_policy import Route


def find(host,port,owner):
    from socket_observation import acquire_tcp
    if type(port) is not int or not 0<port<=65535:
        raise Refused('owned listener literal port')
    live=[]
    for slot in host.listeners.values():
        saved=slot['socket']
        if slot['case']!=host.case or slot['tag']!='owned' or saved.owner!=owner or saved.local!=('127.0.0.1',port):
            continue
        try:
            current=acquire_tcp(owner,saved.fd)
        except OSError:
            continue
        if current==saved and current.state==10:
            live.append(saved)
    if len(live)!=1:
        raise Refused('owned listener unique live generation')
    return live[0]


def route(host,actor,port,server):
    listener=find(host,port,server['birth'])
    name=actor['token']+':owned:'+host.case+':'+str(port)+':'+str(listener.cookie)
    if name not in host.endpoints.routes:
        sharing=listener if any(value.port==port and host.endpoints.route_active(value) for value in host.endpoints.routes.values()) else None
        host.endpoints.declare(Route(name,host.case,host.owner(server),host.owner(actor),port),shared_listener=sharing)
        host.endpoints.listen(name,listener)
    return name


def budget(host,actor,maximum):
    owner=host.owner(actor)
    total=sum(count for name,count in host.connected_routes.items()
              if host.endpoints.routes[name].case==host.case and host.endpoints.routes[name].client==owner)
    if total>=maximum:
        raise Refused('owned listener finite client connection total')
