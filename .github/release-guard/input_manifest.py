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
    if ('/native' in profile.get('mounts',{})) != (envelope and 'native_metadata' in manifest):
        raise Refused('root native metadata generation mismatch')
    if envelope:
        manifest=manifest['source']
    if type(manifest) is not dict or set(manifest) != {'schema', 'files'} or manifest['schema'] != 'unrest.guard-content.v1':
        raise Refused('root source manifest schema')
    return {row['path']: row['sha256'] for row in manifest['files']}
