"""Unix-socket lifecycle must never claim or remove a replacement pathname."""

import os
import socket
import stat
import tempfile
import threading
from pathlib import Path
from types import SimpleNamespace

import pytest

from lurebench import runtime_service as service


@pytest.fixture
def socket_directory():
    # Stay below AF_UNIX path-length limits on macOS as well as Linux.
    with tempfile.TemporaryDirectory(prefix='lure-unix-') as temporary:
        yield Path(temporary)


def test_shutdown_preserves_replacement_file(socket_directory, monkeypatch):
    target = socket_directory / 'runtime.sock'

    def replace(_):
        target.unlink()
        target.write_bytes(b'synthetic replacement')

    monkeypatch.setattr(service._UnixHTTPServer, 'serve_forever', replace)
    service.serve_runtime(unix_socket=target)
    assert target.read_bytes() == b'synthetic replacement'


def test_application_startup_failure_preserves_replacement(socket_directory, monkeypatch):
    target = socket_directory / 'runtime.sock'

    def fail(*args, **kwargs):
        target.unlink()
        target.write_bytes(b'synthetic replacement')
        raise RuntimeError('synthetic startup failure')

    monkeypatch.setattr(service, 'RuntimeDecisionApplication', fail)
    with pytest.raises(RuntimeError, match='synthetic startup failure'):
        service.serve_runtime(unix_socket=target)
    assert target.read_bytes() == b'synthetic replacement'


def test_listen_failure_cleans_its_own_bound_socket(socket_directory, monkeypatch):
    target = socket_directory / 'runtime.sock'

    def fail(_):
        raise OSError('synthetic listen failure')

    monkeypatch.setattr(service._UnixHTTPServer, 'server_activate', fail)
    with pytest.raises(OSError, match='synthetic listen failure'):
        service.serve_runtime(unix_socket=target)
    assert not target.exists()


def test_application_interruption_closes_and_cleans_socket(socket_directory, monkeypatch):
    target = socket_directory / 'runtime.sock'

    def interrupt(*args, **kwargs):
        raise KeyboardInterrupt

    monkeypatch.setattr(service, 'RuntimeDecisionApplication', interrupt)
    with pytest.raises(KeyboardInterrupt):
        service.serve_runtime(unix_socket=target)
    assert not target.exists()


def test_shared_directory_is_refused_before_binding(socket_directory, monkeypatch):
    target = socket_directory / 'runtime.sock'
    os.chmod(socket_directory, 0o755)
    monkeypatch.setattr(service._UnixHTTPServer, 'serve_forever', lambda _: None)
    try:
        with pytest.raises(ValueError, match='private'):
            service.serve_runtime(unix_socket=target)
        assert not target.exists()
    finally:
        os.chmod(socket_directory, 0o700)


@pytest.mark.parametrize('kind', ['file', 'directory', 'symlink', 'dangling', 'socket'])
def test_close_never_removes_observed_replacement(socket_directory, kind):
    target = socket_directory / 'runtime.sock'
    saved = socket_directory / 'original.sock'
    other = socket_directory / 'other'
    other.write_bytes(b'preserve me')
    other.chmod(0o640)
    replacement = None
    server = service._UnixHTTPServer(str(target), service._Handler)
    descriptor = server._socket_path._fd
    try:
        target.rename(saved)
        if kind == 'file':
            target.write_bytes(b'replacement')
        elif kind == 'directory':
            target.mkdir()
        elif kind in {'symlink', 'dangling'}:
            target.symlink_to(other if kind == 'symlink' else socket_directory / 'absent')
        else:
            replacement = socket.socket(socket.AF_UNIX)
            replacement.bind(str(target))
        expected = target.lstat()
        server.server_close()
        assert service._UnixSocketPath._stamp(target.lstat()) == (
            service._UnixSocketPath._stamp(expected))
        assert other.read_bytes() == b'preserve me'
        assert stat.S_IMODE(other.stat().st_mode) == 0o640
        assert saved.is_socket()
        assert server.socket.fileno() == -1
        with pytest.raises(OSError):
            os.fstat(descriptor)
    finally:
        server.server_close()
        if replacement is not None:
            replacement.close()


def test_parent_rename_cleans_original_directory_not_new_path(socket_directory):
    parent = socket_directory / 'p'
    parent.mkdir(mode=0o700)
    target = parent / 's'
    moved = socket_directory / 'm'
    with service._UnixHTTPServer(str(target), service._Handler):
        parent.rename(moved)
        parent.mkdir(mode=0o700)
        target.write_bytes(b'new directory entry')
    assert not (moved / 's').exists()
    assert target.read_bytes() == b'new directory entry'


def test_relative_bind_is_anchored_before_cwd_changes(socket_directory, monkeypatch):
    monkeypatch.chdir(socket_directory)
    server = service._UnixHTTPServer('runtime.sock', service._Handler)
    other = socket_directory / 'other'
    other.mkdir(mode=0o700)
    sentinel = other / 'runtime.sock'
    sentinel.write_bytes(b'other working directory')
    try:
        monkeypatch.chdir(other)
        server.server_close()
        assert not (socket_directory / 'runtime.sock').exists()
        assert sentinel.read_bytes() == b'other working directory'
    finally:
        server.server_close()


@pytest.mark.parametrize('mutation', ['missing', 'mode', 'parent_mode'])
def test_missing_or_changed_metadata_is_not_reclaimed(socket_directory, mutation):
    target = socket_directory / 'runtime.sock'
    server = service._UnixHTTPServer(str(target), service._Handler)
    try:
        if mutation == 'missing':
            target.unlink()
        elif mutation == 'mode':
            target.chmod(0o640)
        else:
            socket_directory.chmod(0o755)
        server.server_close()
        assert target.exists() is (mutation != 'missing')
        assert server._socket_path._fd is None
    finally:
        socket_directory.chmod(0o700)
        server.server_close()


def test_close_is_idempotent_and_does_not_reacquire_path(socket_directory):
    target = socket_directory / 'runtime.sock'
    server = service._UnixHTTPServer(str(target), service._Handler)
    server.server_close()
    assert not target.exists()
    target.write_bytes(b'later entry')
    server.server_close()
    assert target.read_bytes() == b'later entry'


@pytest.mark.parametrize('kind', ['file', 'directory', 'symlink', 'dangling', 'socket'])
def test_existing_path_is_never_overwritten_or_chmodded(socket_directory, kind):
    target = socket_directory / 'runtime.sock'
    other = socket_directory / 'other'
    other.write_bytes(b'unchanged')
    other.chmod(0o640)
    incumbent = None
    if kind == 'file':
        target.write_bytes(b'existing')
    elif kind == 'directory':
        target.mkdir()
    elif kind in {'symlink', 'dangling'}:
        target.symlink_to(other if kind == 'symlink' else socket_directory / 'absent')
    else:
        incumbent = socket.socket(socket.AF_UNIX)
        incumbent.bind(str(target))
    expected = service._UnixSocketPath._stamp(target.lstat())
    try:
        with pytest.raises(FileExistsError):
            service.serve_runtime(unix_socket=target)
        assert service._UnixSocketPath._stamp(target.lstat()) == expected
        assert stat.S_IMODE(other.stat().st_mode) == 0o640
    finally:
        if incumbent is not None:
            incumbent.close()


@pytest.mark.parametrize('mode', [0o750, 0o770, 0o777, 0o1700, 0o2700])
def test_non_private_parent_modes_fail_before_application(socket_directory, monkeypatch, mode):
    target = socket_directory / 'runtime.sock'
    socket_directory.chmod(mode)
    monkeypatch.setattr(service, 'RuntimeDecisionApplication',
                        lambda *a, **kw: pytest.fail('application created'))
    try:
        with pytest.raises(ValueError, match='private'):
            service.serve_runtime(unix_socket=target)
        assert not target.exists()
    finally:
        socket_directory.chmod(0o700)


@pytest.mark.parametrize('kind', ['symlink', 'file', 'missing', 'other_owner'])
def test_unsafe_parent_is_rejected(socket_directory, monkeypatch, kind):
    real = socket_directory / 'real'
    real.mkdir(mode=0o700)
    parent = socket_directory / 'parent'
    if kind == 'symlink':
        parent.symlink_to(real, target_is_directory=True)
    elif kind == 'file':
        parent.write_bytes(b'not a directory')
    elif kind == 'other_owner':
        parent.mkdir(mode=0o700)
        uid = os.geteuid()
        monkeypatch.setattr(service.os, 'geteuid', lambda: uid + 1)
    with pytest.raises((ValueError, OSError)):
        service.serve_runtime(unix_socket=parent / 's')
    assert list(real.iterdir()) == []


@pytest.mark.parametrize('address', ['', '.', '/', '../s', 'a/../s', '\x00abstract', 'a\x00b'])
def test_ambiguous_or_abstract_names_fail_without_directory_access(address, monkeypatch):
    monkeypatch.setattr(service.os, 'open', lambda *a, **kw: pytest.fail('directory opened'))
    with pytest.raises(ValueError, match='pathname'):
        service._UnixSocketPath(address)


def test_missing_required_platform_support_fails_closed(socket_directory, monkeypatch):
    monkeypatch.setattr(service.os, 'supports_dir_fd', set())
    with pytest.raises(NotImplementedError, match='directory-relative'):
        service._UnixSocketPath(socket_directory / 's')


def test_platform_without_nofollow_chmod_uses_private_parent(socket_directory, monkeypatch):
    monkeypatch.setattr(service.os, 'supports_follow_symlinks', set())
    target = socket_directory / 's'
    with service._UnixHTTPServer(str(target), service._Handler):
        assert stat.S_IMODE(target.stat().st_mode) == 0o600
    assert not target.exists()


def test_parent_replacement_between_open_and_bind_is_rejected(socket_directory, monkeypatch):
    parent = socket_directory / 'p'
    parent.mkdir(mode=0o700)
    moved = socket_directory / 'm'
    real_open = os.open
    opened = []

    def replacing_open(name, flags, *args, **kwargs):
        descriptor = real_open(name, flags, *args, **kwargs)
        if Path(name) == parent:
            opened.append(descriptor)
            parent.rename(moved)
            parent.mkdir(mode=0o700)
        return descriptor

    monkeypatch.setattr(service.os, 'open', replacing_open)
    with pytest.raises(ValueError, match='private'):
        service.serve_runtime(unix_socket=parent / 's')
    assert not (parent / 's').exists() and not (moved / 's').exists()
    assert len(opened) == 1
    with pytest.raises(OSError):
        os.fstat(opened[0])


@pytest.mark.parametrize('kind', ['file', 'symlink', 'socket'])
def test_replacement_before_chmod_is_preserved(socket_directory, monkeypatch, kind):
    target = socket_directory / 's'
    saved = socket_directory / 'original'
    other = socket_directory / 'other'
    other.write_bytes(b'sensitive synthetic file')
    other.chmod(0o640)
    original = service._UnixSocketPath.restrict_bound
    replacement = socket.socket(socket.AF_UNIX) if kind == 'socket' else None

    def replace(lease):
        target.rename(saved)
        if kind == 'file':
            target.write_bytes(b'replacement')
        elif kind == 'symlink':
            target.symlink_to(other)
        else:
            replacement.bind(str(target))
        original(lease)

    monkeypatch.setattr(service._UnixSocketPath, 'restrict_bound', replace)
    try:
        with pytest.raises(ValueError, match='changed before'):
            service.serve_runtime(unix_socket=target)
        assert os.path.lexists(target)
        assert stat.S_IMODE(other.stat().st_mode) == 0o640
        assert other.read_bytes() == b'sensitive synthetic file'
    finally:
        if replacement is not None:
            replacement.close()


def test_cleanup_failure_closes_descriptors_and_does_not_retry(socket_directory, monkeypatch):
    target = socket_directory / 's'
    server = service._UnixHTTPServer(str(target), service._Handler)
    descriptor = server._socket_path._fd

    def deny(*args, **kwargs):
        raise PermissionError('synthetic unlink failure')

    with monkeypatch.context() as fault:
        fault.setattr(service.os, 'unlink', deny)
        with pytest.raises(PermissionError, match='synthetic unlink'):
            server.server_close()
    assert server.socket.fileno() == -1
    with pytest.raises(OSError):
        os.fstat(descriptor)
    server.server_close()
    assert target.is_socket()


@pytest.mark.parametrize('failure', [OSError('startup'), KeyboardInterrupt(), SystemExit(7)])
def test_primary_failure_survives_cleanup_failure(monkeypatch, failure):
    closed = []

    def close():
        closed.append(True)
        raise OSError('private cleanup detail')

    def fail(*a, **kw):
        raise failure

    monkeypatch.setattr(service, '_TCPHTTPServer',
                        lambda *a, **kw: SimpleNamespace(server_close=close))
    monkeypatch.setattr(service, 'RuntimeDecisionApplication', fail)
    with pytest.raises(type(failure)) as caught:
        service.serve_runtime()
    assert caught.value is failure
    assert closed == [True]
    assert caught.value.__notes__ == [
        'Runtime cleanup failed; inspect the dedicated socket directory.']


def test_real_health_then_cleanup_and_restart(socket_directory):
    target = socket_directory / 's'
    with service._UnixHTTPServer(str(target), service._Handler) as server:
        server.application = SimpleNamespace(readiness=lambda: {'ready': True})
        assert stat.S_IMODE(target.stat().st_mode) == 0o600
        assert not os.get_inheritable(server._socket_path._fd)
        worker = threading.Thread(target=server.handle_request)
        worker.start()
        try:
            with socket.socket(socket.AF_UNIX) as client:
                client.settimeout(2.)
                client.connect(str(target))
                client.sendall(b'GET /health HTTP/1.1\r\n\r\n')
                response = bytearray()
                while data := client.recv(65536):
                    response.extend(data)
            assert response.startswith(b'HTTP/1.0 200')
        finally:
            worker.join(2.)
        assert not worker.is_alive()
    assert not target.exists()
    with service._UnixHTTPServer(str(target), service._Handler):
        assert target.is_socket()
    assert not target.exists()


def test_permission_setup_failure_cleans_captured_socket(socket_directory, monkeypatch):
    target = socket_directory / 's'
    leases = []

    def fail(lease):
        leases.append(lease)
        raise PermissionError('synthetic permission failure')

    monkeypatch.setattr(service._UnixSocketPath, 'restrict_bound', fail)
    with pytest.raises(PermissionError, match='synthetic permission'):
        service.serve_runtime(unix_socket=target)
    assert not target.exists()
    assert len(leases) == 1 and leases[0]._fd is None


def test_bind_collision_does_not_claim_new_incumbent(socket_directory, monkeypatch):
    target = socket_directory / 's'
    original = service.socketserver.UnixStreamServer.server_bind

    def collision(server):
        target.write_bytes(b'created after preflight')
        original(server)

    monkeypatch.setattr(service.socketserver.UnixStreamServer, 'server_bind', collision)
    with pytest.raises(OSError):
        service.serve_runtime(unix_socket=target)
    assert target.read_bytes() == b'created after preflight'


def test_concurrent_close_transfers_descriptor_ownership_once(socket_directory, monkeypatch):
    target = socket_directory / 's'
    server = service._UnixHTTPServer(str(target), service._Handler)
    descriptor = server._socket_path._fd
    entered, release = threading.Event(), threading.Event()
    original_stat = os.stat
    failures = []

    def stalled_stat(name, *args, **kwargs):
        if kwargs.get('dir_fd') == descriptor:
            entered.set()
            assert release.wait(2.)
        return original_stat(name, *args, **kwargs)

    def close():
        try:
            server.server_close()
        except BaseException as exc:
            failures.append(exc)

    monkeypatch.setattr(service.os, 'stat', stalled_stat)
    worker = threading.Thread(target=close)
    worker.start()
    try:
        assert entered.wait(1.)
        server.server_close()
        assert os.fstat(descriptor)  # Still owned by the first cleanup.
    finally:
        release.set()
        worker.join(2.)
    assert not worker.is_alive() and not failures
    with pytest.raises(OSError):
        os.fstat(descriptor)
    assert not target.exists()


@pytest.mark.parametrize('cleanup_fails', [False, True])
def test_cli_interruption_reports_cleanup_failure(socket_directory, monkeypatch, capsys,
                                                 cleanup_fails):
    from lurebench.cli import main

    target = socket_directory / 's'

    def deny(*args, **kwargs):
        raise PermissionError('PRIVATE_UNLINK_DETAIL')

    with monkeypatch.context() as fault:
        def interrupt(*args, **kwargs):
            if cleanup_fails:
                fault.setattr(service.os, 'unlink', deny)
            raise KeyboardInterrupt

        fault.setattr(service, 'RuntimeDecisionApplication', interrupt)
        assert main(['permit-serve', '--unix-socket', str(target)]) == (
            2 if cleanup_fails else 0)
    stderr = capsys.readouterr().err
    assert ('Runtime cleanup failed' in stderr) is cleanup_fails
    assert 'PRIVATE_UNLINK_DETAIL' not in stderr
    assert target.exists() is cleanup_fails


def test_cli_primary_failure_also_reports_failed_cleanup(socket_directory, monkeypatch, capsys):
    from lurebench.cli import main

    target = socket_directory / 's'

    def deny(*args, **kwargs):
        raise PermissionError('PRIVATE_UNLINK_DETAIL')

    with monkeypatch.context() as fault:
        def fail(*args, **kwargs):
            fault.setattr(service.os, 'unlink', deny)
            raise ValueError('synthetic startup failure')

        fault.setattr(service, 'RuntimeDecisionApplication', fail)
        assert main(['permit-serve', '--unix-socket', str(target)]) == 2
    stderr = capsys.readouterr().err
    assert 'synthetic startup failure' in stderr and 'Runtime cleanup failed' in stderr
    assert 'PRIVATE_UNLINK_DETAIL' not in stderr
    assert target.is_socket()
