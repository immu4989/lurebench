"""Opt-in real-daemon regression; use only the two reviewed synthetic fixtures."""

import json
import os
import re
import subprocess
import uuid

import pytest

from lurebench.boundary_container import BoundaryContainerMonitor
from lurebench.detectors.container import ContainerDetector
from lurebench.schema import Lure

pytestmark = pytest.mark.skipif(
    os.environ.get('LUREBENCH_TEST_DOCKER') != '1',
    reason='explicit Docker fixture verification is not enabled',
)


def docker(*arguments, check=True):
    return subprocess.run(['docker', *arguments], capture_output=True, text=True,
                          check=check, timeout=30)


def image_id(reference):
    result = docker('image', 'inspect', '--format', '{{.Id}}', reference).stdout.strip()
    assert re.fullmatch(r'sha256:[a-f0-9]{64}', result)
    return result


@pytest.fixture
def retagged_image(monkeypatch):
    original = image_id(os.environ.get(
        'LUREBENCH_IDENTITY_ORIGINAL', 'lurebench-identity-probe:original'))
    replacement = image_id(os.environ.get(
        'LUREBENCH_IDENTITY_REPLACEMENT', 'lurebench-identity-probe:replacement'))
    assert original != replacement
    owner = uuid.uuid4().hex
    alias = 'lurebench-identity-check:' + owner
    label = 'org.lurebench.identity-check'
    names = []
    popen = subprocess.Popen

    def launch(command, *args, **kwargs):
        if command[:2] == ['docker', 'create']:
            names.append(command[command.index('--name') + 1])
            command = command[:2] + ['--label', label + '=' + owner] + command[2:]
        elif command[:2] == ['docker', 'run']:
            name = 'lurebench-identity-' + owner + '-' + str(len(names))
            names.append(name)
            # Test ownership metadata only: production image selection and all
            # isolation flags remain unchanged, with no daemon socket mount.
            command = command[:2] + ['--name', name, '--label', label + '=' + owner] + command[2:]
        return popen(command, *args, **kwargs)

    assert docker('image', 'inspect', alias, check=False).returncode != 0
    docker('image', 'tag', original, alias)
    monkeypatch.setattr(subprocess, 'Popen', launch)
    try:
        yield alias, original, replacement, names
    finally:
        # Never prune or delete caller-provided images. Recheck exact test-owned
        # containers before stopping a synthetic fixture left by an assertion.
        for name in names:
            result = docker('container', 'inspect', name, check=False)
            if result.returncode:
                continue
            info, = json.loads(result.stdout)
            assert info['Config']['Labels'][label] == owner
            assert info['Image'] in {original, replacement}
            docker('container', 'rm', '--force', info['Id'])
        assert image_id(alias) in {original, replacement}
        docker('image', 'rm', alias)


@pytest.mark.parametrize('factory', [ContainerDetector, BoundaryContainerMonitor])
def test_real_tag_reassignment_cannot_change_admitted_image(retagged_image, factory):
    alias, original, replacement, names = retagged_image
    adapter = factory(alias, allow_mutable_image=True, timeout_seconds=5)
    assert adapter.image_id == original
    docker('image', 'tag', replacement, alias)
    assert image_id(alias) == replacement

    def invoke(instance):
        if factory is ContainerDetector:
            return instance.score(Lure(id='synthetic', text='Synthetic fixture', label=0,
                                       source='human', typology='benign', language='en',
                                       channel='email'))
        return instance({'events': []}, {})

    expected = 0.125 if factory is ContainerDetector else []
    try:
        for _ in range(2):
            assert invoke(adapter) == expected
            actual = docker('container', 'inspect', '--format', '{{.Image}}', names[-1]).stdout.strip()
            assert actual == adapter.image_id == original
            adapter.close()
    finally:
        adapter.close()

    # A new admission deliberately resolves the now-current tag to the new ID.
    with factory(alias, allow_mutable_image=True, timeout_seconds=5) as changed:
        assert changed.image_id == replacement
        assert invoke(changed) == (0.875 if factory is ContainerDetector else [{'changed': True}])


@pytest.mark.parametrize('factory', [ContainerDetector, BoundaryContainerMonitor])
@pytest.mark.parametrize('operation', ['close', 'timeout'])
def test_cleanup_removes_a_daemon_workload_that_cannot_handle_term(retagged_image, factory, operation):
    alias, _, _, names = retagged_image
    adapter = factory(alias, allow_mutable_image=True, timeout_seconds=0.5)

    def invoke():
        if factory is ContainerDetector:
            return adapter.score(Lure(id='synthetic', text='Synthetic fixture', label=0,
                                      source='human', typology='benign'))
        return adapter({'events': []}, {})

    try:
        invoke()
        identifier = docker('container', 'inspect', '--format', '{{.Id}}', names[-1]).stdout.strip()
        assert re.fullmatch(r'[a-f0-9]{64}', identifier)
        # Stop only this owned synthetic process so TERM cannot complete. KILL
        # remains effective; fixture cleanup runs even against the broken code.
        docker('kill', '--signal', 'STOP', identifier)
        if operation == 'timeout':
            with pytest.raises(TimeoutError):
                invoke()
        else:
            adapter.close()
        remaining = docker('container', 'ls', '--all', '--no-trunc',
                           '--filter', 'id=' + identifier, '--format', '{{.ID}}').stdout.strip()
        assert remaining == '', 'the daemon workload survived adapter cleanup'
    finally:
        adapter.close()
