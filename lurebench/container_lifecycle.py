"""Ownership-checked OCI lifecycle under a trusted local runtime.

Never remove by name, a broad filter, or an unverified identifier. Uncertain
creation/cleanup retains recovery state and is not evidence of successful teardown.
"""

from __future__ import annotations

import functools
import re
import secrets
import subprocess
import time

from .container_image import execution_image
from .container_io import JsonLineSession
from .receipts import loads_strict_json

CONTROL_SECONDS = 10.0
OWNER_LABEL = 'org.lurebench.execution-owner'
_ID = re.compile(r'[a-f0-9]{64}')
_INSPECT = ('{"id":{{json .Id}},"image":{{json .Image}},"name":{{json .Name}},'
            '"owner":{{json (index .Config.Labels "' + OWNER_LABEL + '")}}}')


class OwnedContainer:
    def __init__(self, runtime: str, image_id: str):
        self.runtime = runtime
        self.image_id = image_id
        self.owner = secrets.token_hex(16)
        self.name = 'lurebench-' + self.owner
        self.container_id = None
        self.attempted = False
        self.closed = False

    def _error(self, message):
        return RuntimeError(f'{message}; inspect owned container {self.name}')

    def _run(self, arguments, deadline):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise self._error('OCI control deadline exceeded')
        try:
            result = subprocess.run(
                [self.runtime, *arguments], check=True, capture_output=True,
                stdin=subprocess.DEVNULL, text=True, encoding='utf-8', errors='strict',
                timeout=remaining,
            )
        except (OSError, subprocess.SubprocessError, UnicodeError) as exc:
            raise self._error('OCI control operation failed') from exc
        return result.stdout.strip()

    def _verify(self, identifier, deadline):
        raw = self._run(['container', 'inspect', '--format', _INSPECT, identifier], deadline)
        try:
            if len(raw.encode('utf-8')) > 4096:
                raise ValueError('oversized identity projection')
            value = loads_strict_json(raw.encode('utf-8'), max_nodes=16)
            if not isinstance(value, dict) or set(value) != {'id', 'image', 'name', 'owner'}:
                raise ValueError('invalid identity projection')
            actual_image = value['image']
            if self.runtime == 'podman' and isinstance(actual_image, str) and _ID.fullmatch(actual_image):
                actual_image = 'sha256:' + actual_image
            if (value['id'] != identifier or value['owner'] != self.owner
                    or actual_image != self.image_id or not isinstance(value['name'], str)
                    or value['name'].removeprefix('/') != self.name):
                raise ValueError('ownership or image mismatch')
        except (ValueError, TypeError) as exc:
            raise self._error('OCI container ownership could not be verified') from exc

    def create(self, options):
        if self.attempted or self.closed:
            raise self._error('OCI creation cannot be retried')
        deadline = time.monotonic() + CONTROL_SECONDS
        self.attempted = True
        identifier = self._run([
            'create', '--name', self.name, '--label', OWNER_LABEL + '=' + self.owner,
            *options, execution_image(self.runtime, self.image_id),
        ], deadline)
        if _ID.fullmatch(identifier) is None:
            raise self._error('OCI creation returned an invalid container ID')
        self.container_id = identifier
        self._verify(identifier, deadline)
        return [self.runtime, 'start', '--attach', '--interactive', identifier]

    def _find(self, deadline):
        selection = ('id=' + self.container_id if self.container_id is not None
                     else 'label=' + OWNER_LABEL + '=' + self.owner)
        raw = self._run(['container', 'ls', '--all', '--no-trunc', '--filter', selection,
                         '--format', '{{.ID}}'], deadline)
        if not raw:
            return None
        if (_ID.fullmatch(raw) is None
                or (self.container_id is not None and raw != self.container_id)):
            raise self._error('OCI lookup returned ambiguous or unexpected container IDs')
        return raw

    def close(self):
        if self.closed:
            return
        if not self.attempted:
            self.closed = True
            return
        deadline = time.monotonic() + CONTROL_SECONDS
        identifier = self._find(deadline)
        if identifier is None:
            if self.container_id is None:
                # A timed-out create request can complete at the daemon later.
                # Empty lookup is not proof that uncertain creation cannot occur.
                raise self._error('OCI creation outcome remains uncertain')
            self.closed = True
            return
        self._verify(identifier, deadline)
        self.container_id = identifier
        removed = self._run(['container', 'rm', '--force', '--volumes', identifier], deadline)
        if removed != identifier or self._find(deadline) is not None:
            raise self._error('OCI removal was not confirmed')
        self.closed = True


def exclusive_operation(method):
    """Reject concurrent adapter operations, including during lazy startup."""
    @functools.wraps(method)
    def wrapped(self, *args, **kwargs):
        if not self._operation_lock.acquire(blocking=False):
            raise RuntimeError('container adapter already has an active operation')
        try:
            return method(self, *args, **kwargs)
        finally:
            self._operation_lock.release()
    return wrapped


def close_adapter(adapter, label):
    errors = []
    if adapter._container is not None:
        try:
            adapter._container.close()
        except BaseException as exc:
            errors.append(exc)
    if adapter._process is not None:
        if adapter._session is None:
            adapter._session = JsonLineSession(adapter._process, label=label)
        try:
            adapter._session.close()
        except BaseException as exc:
            errors.append(exc)
    if errors:
        adapter._failed = True
        if len(errors) > 1:
            errors[0].add_note('Local runtime CLI/pipe cleanup also failed.')
        raise errors[0]
    adapter._container = None
    adapter._process = None
    adapter._session = None


def cleanup_after_failure(adapter, failure):
    adapter._failed = True
    try:
        adapter.close()
    except BaseException:
        failure._container_cleanup_failed = True
        name = adapter._container.name if adapter._container is not None else 'runtime CLI'
        failure.add_note(f'OCI cleanup incomplete; inspect {name}; retry cleanup, not evaluation.')
