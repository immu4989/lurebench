"""Deterministic daemon control seam shared by OCI protocol regression tests."""

import json
import subprocess

from lurebench.container_lifecycle import OWNER_LABEL


class FakeRuntime:
    def __init__(self, resolve, process_factory, *, available=None):
        self.resolve = resolve
        self.process_factory = process_factory
        self.available = available
        self.calls = []
        self.inspected = []
        self.created = []
        self.containers = {}
        self.counter = 0

    def install(self, monkeypatch):
        monkeypatch.setattr('shutil.which', lambda name: '/synthetic/' + name)
        monkeypatch.setattr(subprocess, 'run', self.run)
        monkeypatch.setattr(subprocess, 'Popen', self.launch)
        return self

    def run(self, command, **kwargs):
        self.calls.append(command)
        if command[1:3] == ['image', 'inspect']:
            self.inspected.append(command)
            output = self.resolve(command[-1])
            if command[0] == 'podman':
                output = output.removeprefix('sha256:')
        elif command[1] == 'create':
            self.created.append(command)
            selected = command[-1]
            if not selected.startswith('sha256:'):
                selected = 'sha256:' + selected
            if self.available is not None and selected not in self.available:
                raise subprocess.CalledProcessError(1, command)
            self.counter += 1
            output = f'{self.counter:064x}'
            label = command[command.index('--label') + 1]
            assert label.startswith(OWNER_LABEL + '=')
            self.containers[output] = {
                'id': output, 'image': selected,
                'name': command[command.index('--name') + 1],
                'owner': label.split('=', 1)[1], 'command': command,
            }
        elif command[1:3] == ['container', 'inspect']:
            item = self.containers[command[-1]]
            value = {key: item[key] for key in ('id', 'image', 'name', 'owner')}
            if command[0] == 'podman':
                value['image'] = value['image'].removeprefix('sha256:')
            output = json.dumps(value)
        elif command[1:3] == ['container', 'ls']:
            field = command[command.index('--filter') + 1]
            matches = [identifier for identifier, item in self.containers.items()
                       if field == 'id=' + identifier
                       or field == 'label=' + OWNER_LABEL + '=' + item['owner']]
            output = '\n'.join(matches)
        elif command[1:3] == ['container', 'rm']:
            output = self.containers.pop(command[-1])['id']
        else:
            raise AssertionError(command)
        return subprocess.CompletedProcess(command, 0, output + '\n', '')

    def launch(self, command, **kwargs):
        self.calls.append(command)
        assert command[1:4] == ['start', '--attach', '--interactive']
        item = self.containers[command[-1]]
        return self.process_factory(item['command'], item['image'])
