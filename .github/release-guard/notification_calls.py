"""Prepared notification signal chain; no task scanning or generic signal authority."""
from __future__ import annotations

import importlib
import signal
from pathlib import Path
import types

from content_manifest import Refused
from controlled_cases import PINS
from controlled_startup import dictionary, path
from source_owner import Link, active_frames, frame_fields, _namespace, _safe_code

TEST = 'tests/test_experimental_notifications.py'
QUALIFIED = 'test_controlled_process_http_revocation_and_warning_privacy'


def closure(function):
    if type(function) is not types.FunctionType:
        raise Refused('notification original wrapper type')
    _safe_code(function.__code__)
    return dict(zip(function.__code__.co_freevars,
                    (cell.cell_contents for cell in function.__closure__ or ()), strict=True))


def prepare(calls):
    module = importlib.import_module('tests.test_experimental_notifications')
    unit = calls.unit(TEST,module,'pytest')
    if calls.pins[TEST] != PINS[TEST]:
        raise Refused('notification original source pin')
    function = _namespace(module)[QUALIFIED]
    turn = _namespace(calls.session)['_TurnClient']
    original = _namespace(turn)['_write']
    calls.anchors['notification-original-write'] = original
    original_owner = calls.session_unit.owner(calls.session,original,'_TurnClient._write',
        (Link(calls.session,'_TurnClient',turn),Link(calls.anchors,'notification-original-write',original)),closure=(turn,))
    calls.notification = (module,unit,calls.owner(unit,module,function,QUALIFIED,
        (Link(module,QUALIFIED,function),)),turn,original_owner,
        _namespace(calls.session)['_Role'],_namespace(calls.session)['TurnBroker'])


def signal_owner(calls):
    module,unit,test,turn,original,role_type,broker_type = calls.notification
    when,status = calls.policy.case.rsplit('[',1)[1][:-1].rsplit('-',1)
    if when not in ('parked','before-send') or status not in ('connecting','connected','errored','unknown'):
        raise Refused('notification selected signal phase')
    params = _namespace(calls.case_item.callspec.params)
    if (type(params.get('when')) is not str or params['when'] != when
            or type(params.get('status')) is not str or params['status'] != status
            or calls.startup.case != calls.policy.case or calls.startup.root_key() != calls.startup.root_identity):
        raise Refused('notification selected original fixture parameters or generation')
    original.verify_binding()
    write = _namespace(turn).get('_write')
    retained = closure(write)
    if (set(retained) != {'original_write','owner','requests','transition','when'}
            or retained['original_write'] is not original.function
            or type(retained['when']) is not str or retained['when'] != when):
        raise Refused('notification retained original write chain')
    write_owner = unit.owner(module,write,QUALIFIED+'.<locals>.write',(Link(turn,'_write',write),),
        closure=tuple(retained[name] for name in write.__code__.co_freevars))
    write_owner.verify_binding()
    transition = retained['transition']
    values = closure(transition)
    if set(values) != {'owner','saw_remote','signal'} or values['signal'] is not signal:
        raise Refused('notification transition closure')
    instance = values['owner']
    if retained['owner'] is not instance:
        raise Refused('notification write/transition owner join')
    if type(instance) is not calls.startup.base:
        raise Refused('notification retained owner type')
    owner = dictionary(instance,calls.startup.base)
    root = path(owner.get('root'))
    if (calls.startup.owners.get(str(root)) is not instance or root.name != 'owner'
            or root.parent.name != 'campaign' or not root.is_relative_to(Path(calls.profile['owned'])/'pytest')):
        raise Refused('notification original owner generation')
    selected = unit.owner(module,transition,QUALIFIED+'.<locals>.transition',
        (Link(write,write.__code__.co_freevars.index('transition'),transition,'cell'),),
        closure=tuple(values[name] for name in transition.__code__.co_freevars))
    frames = active_frames()
    try:
        selected.current(frames,line=254)
        if when == 'parked':
            frame = test.current(frames,line=278)
            local = frame_fields(frame)
            if (local.get('owner') is not instance or type(local.get('status')) is not str
                    or local['status'] != status or type(local.get('when')) is not str or local['when'] != when):
                raise Refused('notification original parked parameter')
            calls.test_owner.current(frames,line=278 if calls.tests is module else 41)
        else:
            frame = write_owner.current(frames,line=259)
            local = frame_fields(frame)
            roles = _namespace(owner.get('roles'))
            role = roles.get('worker')
            broker = owner.get('broker')
            message = _namespace(local.get('msg'))
            if (type(role) is not role_type or dictionary(role,role_type).get('client') is not local.get('self')
                    or type(message.get('method')) is not str or message['method'] != 'session/prompt'
                    or type(broker) is not broker_type or dictionary(broker,broker_type).get('_active') is None):
                raise Refused('notification original prompt client or active broker')
        return instance
    finally:
        del frames
