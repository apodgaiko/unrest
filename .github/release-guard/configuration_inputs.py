"""Filesystem footprint of the finite configured fixtures, independent of Python objects."""

from bootstrap_cases import CATALOGUE,CATALOGUE_PIN
from content_manifest import Refused
from controlled_cases import configured,configuration_items,POPULATED
from source_profile import digest


def check_inputs(checkout,home,case):
    if not configured(case):
        return
    root=home.parent
    context,probe=root.parent.parent,root.parent
    populated=case in POPULATED
    if root.name!='owner' or probe!=context/('campaign' if populated else 'probe'):
        raise Refused('configured fixture root')
    _,skills=configuration_items(case,home)
    catalogue=checkout/CATALOGUE
    expected=[context/'system/config.toml',context/'subscription/config.toml']
    expected.extend(parent/'.codex/config.toml' for parent in reversed(probe.parents))
    expected.extend((probe/'.codex/config.toml',probe/'config.toml'))
    expected.extend((context/'subscription/skills',context/'user/.agents/skills',context/'system/skills'))
    expected.extend(parent/'.agents/skills' for parent in (*reversed(probe.parents),probe))
    expected.extend(parent/'.codex/skills' for parent in (*reversed(probe.parents),probe))
    expected.extend((catalogue,context/'subscription/AGENTS.override.md',context/'subscription/AGENTS.md',
                     context/'subscription/rules',context/'system/requirements.toml',context/'system/managed_config.toml'))
    if digest(catalogue)!=CATALOGUE_PIN:
        raise Refused('configured catalogue bytes')
    allowed={} if not populated else {
        context/'subscription/config.toml':'7a2eb35bea6e5e0282f5f12864519df3c9d78f349b67344c88244b040178a83c',
        context/'subscription/AGENTS.md':'b5885d7026d7c855db9f9ed50b5ca08b1910de6a6df541fcb1901b6dd40ddf67'}
    skill_root=context/'subscription/skills'
    for path in sorted(set(expected)):
        if path in allowed:
            if digest(path)!=allowed[path]:
                raise Refused('configured populated input bytes')
        elif path==skill_root and skills:
            if (path.is_symlink() or not path.is_dir() or sorted(p.name for p in path.iterdir())!=['example']
                    or (path/'example').is_symlink() or not (path/'example').is_dir()
                    or sorted(p.name for p in (path/'example').iterdir())!=['SKILL.md']
                    or digest(path/'example/SKILL.md')!='58e2c156770a078bbb226f8c8c4aa0b10cdc41b53b76d999d356de9bc72331e1'):
                raise Refused('configured disabled skill input')
        elif path!=catalogue and (path.exists() or path.is_symlink()):
            raise Refused('configured unexpected input')
