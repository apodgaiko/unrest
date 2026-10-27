"""Original fresh controlled ProviderConfig binding for fresh bootstrap and controlled probes."""
from __future__ import annotations

import importlib
from pathlib import Path
import types

from bootstrap_cases import CATALOGUE, CATALOGUE_PIN, CONFIG_PIN, CONFIG_SOURCE
from content_manifest import Refused
from controlled_cases import configured, configuration_items, POPULATED
from source_owner import Link, Owner, prepare
from source_profile import digest


class Binding:
    def __init__(self, checkout):
        self.checkout = checkout
        self.module = importlib.import_module('unrest_harness.experimental_provider_config')
        self.provider, self.inputs = self.module.ProviderConfig, self.module.CommonInputs
        file = checkout / CONFIG_SOURCE
        mode = 'beartype-passive' if type(self.module.__loader__).__name__ == 'BeartypeSourceFileLoader' else 'plain'
        self.unit = prepare(file.read_bytes(), str(file), self.module.__name__, mode, CONFIG_PIN)
        self.owners = []
        for cls, name in ((self.provider, 'overrides'), (self.provider, 'argv'), (self.provider, 'thread_config'),
                          (self.inputs, 'verify'), (self.inputs, '_observe'), (self.inputs, '_runtime_context'),
                          (self.module, '_toml')):
            function = vars(cls)[name]
            if type(function) is not types.FunctionType:
                raise Refused('bootstrap configuration original method')
            qualified = name if cls is self.module else cls.__name__ + '.' + name
            codes = [code for code in self.unit.codes if code.co_qualname == qualified]
            if len(codes) != 1:
                raise Refused('bootstrap configuration lexical method')
            self.owners.append(Owner(self.unit, self.module, function, qualified, codes[0].co_firstlineno,
                (1, 100000), (Link(cls, name, function),), defaults=function.__defaults__,
                keyword_defaults=tuple(sorted((function.__kwdefaults__ or {}).items()))))
        self.descriptors = {cls: vars(cls)['__dict__'] for cls in (self.provider, self.inputs)}

    def record(self, instance, cls):
        descriptor = self.descriptors[cls]
        if (type(instance) is not cls or type(descriptor) is not types.GetSetDescriptorType
                or vars(cls).get('__dict__') is not descriptor):
            raise Refused('bootstrap configuration object identity')
        values = descriptor.__get__(instance, cls)
        if type(values) is not dict or any(type(key) is not str for key in values):
            raise Refused('bootstrap configuration instance dictionary')
        return values

    def check(self, config, root, case):
        if not configured(case) or type(root) is not type(Path('/')) or root.name != 'owner':
            raise Refused('bootstrap configured case or root')
        for owner in self.owners:
            owner.verify_binding()
        if self.module.ProviderConfig is not self.provider or self.module.CommonInputs is not self.inputs:
            raise Refused('bootstrap configuration class substitution')
        values = self.record(config, self.provider)
        context, probe = root.parent.parent, root.parent
        populated = case in POPULATED
        servers, skills = configuration_items(case, root/'worker')
        if probe != context / ('campaign' if populated else 'probe'):
            raise Refused('bootstrap configuration runtime root')
        if (type(values.get('codex_home')) is not type(root) or values['codex_home'] != context / 'subscription'
                or type(values.get('user_home')) is not type(root) or values['user_home'] != context / 'user'
                or type(values.get('skills')) is not set or any(type(v) is not str for v in values['skills']) or values['skills'] != set(skills)
                or type(values.get('servers')) is not set or any(type(v) is not str for v in values['servers']) or values['servers'] != set(servers)
                or type(values.get('global_instructions')) is not str or values['global_instructions'] != ('default' if populated else 'absent')
                or any(name in values for name in ('argv', 'overrides', 'thread_config'))):
            raise Refused('bootstrap fresh controlled configuration')
        inputs = values.get('inputs')
        observed = self.record(inputs, self.inputs)
        if (type(observed.get('runtime_root')) is not type(root) or observed['runtime_root'] != probe
                or any(name in observed for name in ('verify', '_observe', '_runtime_context'))):
            raise Refused('bootstrap configuration input verifier')
        paths = observed.get('paths')
        if type(paths) is not tuple or any(type(path) is not type(root) for path in paths):
            raise Refused('bootstrap configuration input paths')
        catalogue = self.checkout / CATALOGUE
        expected = [context / 'system/config.toml', context / 'subscription/config.toml']
        expected.extend(parent / '.codex/config.toml' for parent in reversed(probe.parents))
        expected.extend((probe / '.codex/config.toml', probe / 'config.toml'))
        expected.extend((context / 'subscription/skills', context / 'user/.agents/skills', context / 'system/skills'))
        expected.extend(parent / '.agents/skills' for parent in (*reversed(probe.parents), probe))
        expected.extend(parent / '.codex/skills' for parent in (*reversed(probe.parents), probe))
        expected.extend((catalogue, context / 'subscription/AGENTS.override.md', context / 'subscription/AGENTS.md',
                         context / 'subscription/rules', context / 'system/requirements.toml', context / 'system/managed_config.toml'))
        if paths != tuple(sorted(set(expected))) or digest(catalogue) != CATALOGUE_PIN:
            raise Refused('bootstrap exact configuration footprint')
        allowed = {}
        if populated:
            allowed = {context/'subscription/config.toml': '7a2eb35bea6e5e0282f5f12864519df3c9d78f349b67344c88244b040178a83c',
                       context/'subscription/AGENTS.md': 'b5885d7026d7c855db9f9ed50b5ca08b1910de6a6df541fcb1901b6dd40ddf67'}
        skill_root = context/'subscription/skills'
        for path in paths:
            if path in allowed:
                if digest(path) != allowed[path]:
                    raise Refused('controlled populated input bytes')
            elif path == skill_root and skills:
                if (path.is_symlink() or not path.is_dir() or sorted(p.name for p in path.iterdir()) != ['example']
                        or (path/'example').is_symlink() or not (path/'example').is_dir()
                        or sorted(p.name for p in (path/'example').iterdir()) != ['SKILL.md']
                        or digest(path/'example/SKILL.md') != '58e2c156770a078bbb226f8c8c4aa0b10cdc41b53b76d999d356de9bc72331e1'):
                    raise Refused('controlled exact disabled skill input')
            elif path != catalogue and path.exists():
                raise Refused('bootstrap unexpected configuration input')
        # Execute the unchanged product's original bounded verifier as well;
        # point-in-time hashes alone never replace its membership/absence rules.
        self.inputs.verify(inputs)
