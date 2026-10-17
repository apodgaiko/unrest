"""Trusted read-only GitHub receipt lookup; never imported by the payload.

Only this repository's Actions API receives the ephemeral read token. Redirected
artifact downloads deliberately construct a new request without authorization.
"""
from __future__ import annotations

import json
import re
import urllib.error
import urllib.parse
import urllib.request

from checkpoint_receipt import ReceiptRefused, validate

API = 'https://api.github.com/repos/apodgaiko/unrest/'
MAX_ARCHIVE = 128 * 1024 * 1024


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class ActionsReader:
    def __init__(self, token):
        if not token or '\n' in token or '\r' in token:
            raise ReceiptRefused('minimal Actions read credential is missing')
        self.token = token

    def api(self, path):
        if not re.fullmatch(r'actions/[A-Za-z0-9_./?=&%-]+', path) or '..' in path:
            raise ReceiptRefused('unrecognized repository Actions read path')
        request = urllib.request.Request(API + path, headers={
            'Authorization': 'Bearer ' + self.token, 'Accept': 'application/vnd.github+json',
            'X-GitHub-Api-Version': '2022-11-28', 'User-Agent': 'unrest-source-checkpoint',
        })
        with urllib.request.urlopen(request, timeout=60) as response:
            body = response.read(8 * 1024 * 1024 + 1)
        if len(body) > 8 * 1024 * 1024:
            raise ReceiptRefused('Actions metadata exceeds its finite bound')
        return json.loads(body)

    def archive(self, artifact):
        artifact_id = artifact['id']
        if type(artifact_id) is not int or artifact_id <= 0:
            raise ReceiptRefused('invalid Actions artifact identity')
        request = urllib.request.Request(API + f'actions/artifacts/{artifact_id}/zip', headers={
            'Authorization': 'Bearer ' + self.token, 'Accept': 'application/vnd.github+json',
            'X-GitHub-Api-Version': '2022-11-28', 'User-Agent': 'unrest-source-checkpoint',
        })
        try:
            urllib.request.build_opener(NoRedirect).open(request, timeout=60)
        except urllib.error.HTTPError as response:
            if response.code != 302:
                raise ReceiptRefused('Actions artifact download was refused') from None
            location = response.headers.get('Location', '')
        else:
            raise ReceiptRefused('Actions artifact redirect is missing')
        parsed = urllib.parse.urlsplit(location)
        if (parsed.scheme != 'https' or parsed.username or parsed.password
                or not parsed.hostname or parsed.port not in (None, 443)
                or not (parsed.hostname.endswith('.blob.core.windows.net')
                        or parsed.hostname.endswith('.actions.githubusercontent.com'))):
            raise ReceiptRefused('unrecognized Actions artifact storage origin')
        # No authorization header follows the API's signed storage redirect.
        with urllib.request.build_opener(NoRedirect).open(
                urllib.request.Request(location), timeout=60) as storage:
            body = storage.read(MAX_ARCHIVE + 1)
        if len(body) > MAX_ARCHIVE:
            raise ReceiptRefused('Actions artifact exceeds its finite bound')
        return body


def lookup(reader, expected, current_run_id):
    """Return verified reuse, or None only when no full checkpoint was executed."""
    head = expected['head_sha']
    if not re.fullmatch('[0-9a-f]{40}', head) or type(current_run_id) is not int:
        raise ReceiptRefused('invalid frozen checkpoint identity')
    runs = reader.api('actions/workflows/ci.yml/runs?head_sha=' + head + '&per_page=100')
    if runs['total_count'] > 100:
        raise ReceiptRefused('same-commit workflow history exceeds the finite lookup bound')
    executed = []
    candidates = []
    for run in runs['workflow_runs']:
        if run['id'] == current_run_id:
            continue
        if run['head_sha'] != head or run['path'] != '.github/workflows/ci.yml':
            raise ReceiptRefused('Actions returned a different workflow or source commit')
        if run['event'] != 'push':
            continue
        if run['status'] != 'completed':
            raise ReceiptRefused('another same-commit primary execution has not settled')
        jobs = reader.api(f"actions/runs/{run['id']}/attempts/{run['run_attempt']}/jobs?per_page=100")
        if jobs['total_count'] > 100:
            raise ReceiptRefused('primary job history exceeds its finite lookup bound')
        primary = [job for job in jobs['jobs']
                   if job['name'] == 'primary source and package gate (py3.13)']
        if len(primary) != 1:
            raise ReceiptRefused('same-commit primary job identity is missing or ambiguous')
        source = [step for step in primary[0]['steps'] if step['name'] == 'v0.4.6 source suite']
        if len(source) == 1 and source[0]['conclusion'] == 'success':
            executed.append(run['id'])
        if run['conclusion'] != 'success':
            continue
        artifacts = reader.api(f"actions/runs/{run['id']}/artifacts?per_page=100")
        if artifacts['total_count'] > 100:
            raise ReceiptRefused('primary artifact set exceeds its finite lookup bound')
        name = f"unrest-v046-primary-{run['id']}-{run['run_attempt']}"
        matches = [artifact for artifact in artifacts['artifacts'] if artifact['name'] == name]
        if len(matches) != 1:
            raise ReceiptRefused('successful primary run has no unique original evidence artifact')
        artifact = matches[0]
        candidates.append(validate(reader.archive(artifact), artifact, run, jobs['jobs'], expected))
    if len(candidates) > 1:
        raise ReceiptRefused('multiple original full checkpoints exist for this commit')
    if candidates:
        return candidates[0]
    if executed:
        raise ReceiptRefused('a source checkpoint passed without complete package certification; do not rerun it')
    return None
