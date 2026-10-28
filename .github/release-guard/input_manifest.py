"""Authenticate source and metadata reference bytes; no caller introspection."""
import hashlib
import json
from content_manifest import Refused
from control_transport import unique


def read(directory,profile):
    raw = (directory / 'source-manifest.json').read_bytes()
    if len(raw) > 16 * 1024 * 1024 or hashlib.sha256(raw).hexdigest() != profile['source_sha256']:
        raise Refused('root source manifest reference')
    manifest = json.loads(raw, object_pairs_hook=unique)
    envelope = type(manifest) is dict and manifest.get('schema') == 'unrest.source-inputs.v1'
    if '/native' in profile.get('mounts', {}) and not envelope:
        raise Refused('root native input envelope')
    if envelope:
        if (not {'schema','source'} < set(manifest)
                or not set(manifest) <= {'schema','source','git','native_metadata'}):
            raise Refused('root input envelope schema')
        if 'git' in manifest:
            git = manifest['git']
            if (type(git) is not dict or set(git) != {'schema','file_bound','files'}
                    or git['schema'] != 'unrest.git-inputs.v1' or type(git['file_bound']) is not int
                    or git['file_bound'] != 64*1024*1024 or type(git['files']) is not list
                    or not 0 < len(git['files']) <= 20000):
                raise Refused('root public Git manifest schema')
        if ('/native' in profile.get('mounts', {})) != ('native_metadata' in manifest):
            raise Refused('root native metadata generation mismatch')
        if 'native_metadata' in manifest:
            from native_metadata import validate
            validate(manifest['native_metadata'])
            if '/native' not in profile['mounts']:
                raise Refused('root native metadata missing readonly generation')
        manifest = manifest['source']
    if type(manifest) is not dict or set(manifest) != {'schema', 'files'} or manifest['schema'] != 'unrest.guard-content.v1':
        raise Refused('root source manifest schema')
    return {row['path']: row['sha256'] for row in manifest['files']}
