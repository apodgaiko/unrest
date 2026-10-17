"""Frozen official Darwin arm64 Codex package; explicit location, no discovery."""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import stat

from .experimental_lease import LeaseRefused

CODEX_SHA256 = '09fa44fdc37a5fc70dc1ace31235f90468a2e193d0e85f7552eab068ea2582be'
CODEX_ARCHIVE_SHA256 = 'f73527ee09c6db869acbb37b709866b339ea74ef91d2de255e9c74ec960c6314'
# Official rust-v0.160.1 codex-package-aarch64-apple-darwin.tar.gz.
# Hash, byte length and permission bits bind the entire helper/resource layout.
_MEMBERS: dict[str, tuple[str, int, int]] = {
    'bin/codex': (
        '09fa44fdc37a5fc70dc1ace31235f90468a2e193d0e85f7552eab068ea2582be', 241556032, 0o755),
    'bin/codex-code-mode-host': (
        '6ac432b170e2c30f90de5af0da584def5201497a0d3d988d37dc58b951236b2f', 65358096, 0o755),
    'codex-package.json': (
        'ad2608c17f5098f66ce104c915ac56bbb5f59b034eb8bd9ff4759e2ceabf3413', 200, 0o644),
    'codex-path/rg': (
        '21c0dc01dea8097868918fdded08e0986a2396a2992fbadcb3091f02864d7810', 4030432, 0o755),
    'codex-resources/voice/NOTICE.md': (
        '40097a1799441051aa0b6645cdc819cceb19be73cdd265eb602aa2b15e0b1f48', 2403, 0o644),
    'codex-resources/voice/bin/codex-voice-host': (
        'e3d7569b9b4072b2b297bf10e6df76d18393f1f9077c29a6f6c0cb190f00f00c', 9900192, 0o755),
    'codex-resources/voice/lib/libffi.8.dylib': (
        'd1cd73e16711151960c054d0728aaf2bf5ff2f87468ba8225bcd08b7b5e93c4a', 136768, 0o755),
    'codex-resources/voice/lib/libgio-2.0.0.dylib': (
        '6b6c44e4be2141c7dad16bd1d6ff914cc81fa02cc0894fcdd9fef97dbd0d0ed5', 1866272, 0o755),
    'codex-resources/voice/lib/libglib-2.0.0.dylib': (
        'ac352e21b67d5917be3f1f02823afc9000c99a0db0afb41b33c25835130783cb', 1310992, 0o755),
    'codex-resources/voice/lib/libgmodule-2.0.0.dylib': (
        '30dcb8c1f94e348b5500ebbd10a5ad289886dcdb665ea70496a3ca85a886d308', 68912, 0o755),
    'codex-resources/voice/lib/libgobject-2.0.0.dylib': (
        '4623649f0091521f5f5585b3a38763f30bfdd96abae50a6935b7601c97be9ae2', 403088, 0o755),
    'codex-resources/voice/lib/libgstapp-1.0.0.dylib': (
        'e3d3c1035ad64f7d3438ba0cafc979ee9bae4021cdcd3fae7580954823a1dabb', 152608, 0o755),
    'codex-resources/voice/lib/libgstaudio-1.0.0.dylib': (
        'd63456e5328532986643e762337dd4de1920ab4cce3e6cc8811c68da94913e9d', 530400, 0o755),
    'codex-resources/voice/lib/libgstbase-1.0.0.dylib': (
        'fe9fcb4477b5ef61cbb391b0fc35f5746bfef1157033a7ec70244401f4cca311', 505968, 0o755),
    'codex-resources/voice/lib/libgstnet-1.0.0.dylib': (
        'ce787799e2c446e76b2a1ad51dfe4eaee5cbca98dcb2339c5a8eee9bd3976eee', 117008, 0o755),
    'codex-resources/voice/lib/libgstpbutils-1.0.0.dylib': (
        'f16ff6a4cbe2fd9ade54dac15a01ad44112dd7803e16a738b8a30d4fa130a609', 309856, 0o755),
    'codex-resources/voice/lib/libgstreamer-1.0.0.dylib': (
        '20717b2167aa26a402f68e46bac17735d97f4f76e1d9ffdc50675553f395a14c', 1304704, 0o755),
    'codex-resources/voice/lib/libgstrtp-1.0.0.dylib': (
        '63b42f98d24eafeedc237a2f319ba0dce9652f8b45c3ced2370c973ca56c5dc0', 205696, 0o755),
    'codex-resources/voice/lib/libgsttag-1.0.0.dylib': (
        '7537168f14723da523b80b98306668ac0d8aa1d10a7e99a28d2f423970b5b39a', 283696, 0o755),
    'codex-resources/voice/lib/libgstvideo-1.0.0.dylib': (
        'cac9c0a7b931c77d3537b37ee47f38c1614aa938c090d4f43ebb689f283c547e', 903664, 0o755),
    'codex-resources/voice/lib/libintl.8.dylib': (
        'd895a295cbc702555465505965ce59019c9cc6376351cee626ce9b9d13fa75f0', 50112, 0o755),
    'codex-resources/voice/lib/libopus.0.dylib': (
        'b4fc8b1f741aa0ecc042231eeeeb9d01bbef5ed26a1031f8f2ce2cb724f5532a', 504080, 0o755),
    'codex-resources/voice/lib/libpcre2-8.0.dylib': (
        'dc912aa13ef18c3f03f2595df2d8484f84136d05380e9c2225db91f8abff9fee', 456816, 0o755),
    'codex-resources/voice/lib/libz.1.dylib': (
        'ef3415ed52e111573b84e422830469f42c5a4948985838841bf58638d0448a0e', 123312, 0o755),
    'codex-resources/voice/licenses/LGPL-2.1.txt': (
        'ad2eec519ebd4b5df86ea84dff24ae3bfa2edea846a703b58902dd221ae375db', 26431, 0o644),
    'codex-resources/voice/licenses/Opus.txt': (
        '01e1167d54a096d123cf6dfbbeb19587278845c6481d2d66d545669846079551', 1945, 0o644),
    'codex-resources/voice/licenses/PCRE2.md': (
        '197d8a73ffee0d6b09adba2f9c677b5f5aede24edf89258a68e48248d010d811', 4011, 0o644),
    'codex-resources/voice/licenses/libffi.txt': (
        '17b64dc60f3b6897a60f971e288b973f655c2edcdf08b25f3c3dd5549857881c', 1132, 0o644),
    'codex-resources/voice/licenses/proxy-libintl.txt': (
        'd245807f90032872d1438d741ed21e2490e1175dc8aa3afa5ddb6c8e529b58e5', 25292, 0o644),
    'codex-resources/voice/licenses/sljit.txt': (
        '5f216505c0f6ea3273caec89e766eef93cdeb7bbb0c429f9360116d7c938feeb', 1444, 0o644),
    'codex-resources/voice/licenses/zlib.txt': (
        'e32ff4e00d9d94930537635291da39e7e612703334bf6fde8c7f1686fe8a45a2', 1002, 0o644),
    'codex-resources/voice/manifest.json': (
        'eed5b95ee90bab2269d83d691c4e6a7813ee097928269ca44f0b208bf4513faf', 4637, 0o644),
    'codex-resources/voice/plugins/libgstapp.dylib': (
        'bac84316717b36f63e0d765390311123a965cad27f001b5eb8a66d417cfca94d', 49872, 0o755),
    'codex-resources/voice/plugins/libgstaudioconvert.dylib': (
        '376303f12b63c1e51a5687ba3a981facd3888725ce55728a1724940d8ec3b17f', 93824, 0o755),
    'codex-resources/voice/plugins/libgstaudioresample.dylib': (
        '01fed09b76cf9cff10e9cf97588d06d5470ed406af80de66e182e64bb9bc9e85', 91840, 0o755),
    'codex-resources/voice/plugins/libgstcoreelements.dylib': (
        '9251149870658a49c1d39d600d7d6fecb0e5a1ce56b7500a9d2ec33658d4f544', 446608, 0o755),
    'codex-resources/voice/plugins/libgstopus.dylib': (
        '53473164999f20b5a3f3a114ff00b5b36ca28c338c38a155f50a8feb8795bf02', 131680, 0o755),
    'codex-resources/voice/plugins/libgstrtp.dylib': (
        'a191d01bd49fe2a25f5b1e31c40044f1926f9db43c06c0e4e1e7e1d2013d0e6a', 673888, 0o755),
    'codex-resources/voice/plugins/libgstrtpmanager.dylib': (
        '5a0fe1904800aec435c8e13a6b08a88b943bccb2d61172daa6ff293d5ec1331b', 527568, 0o755),
    'codex-resources/voice/runtime.json': (
        '04e457013a73f9e9eb230c0e2a992c39c35252b76f93b481aa1fa07270105e45', 14915, 0o755),
    'codex-resources/voice/sources.json': (
        'e2f6b124f6277e7c3c4f5c7cc8830c66190f671ad65e972bb2cc9507dbfcb937', 4911, 0o644),
    'codex-resources/zsh/bin/zsh': (
        '0eea87aedef0ac13b140a41fc4e6c489bfc1ffee021b1e654a0c3b05b3c6525a', 754208, 0o755),
}


def _identity(info: os.stat_result) -> tuple[int, ...]:
    return (info.st_dev, info.st_ino, info.st_mode, info.st_nlink,
            info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _scan(directory: int, prefix: str = '') -> None:
    expected = {name[len(prefix):].split('/')[0] for name in _MEMBERS if name.startswith(prefix)}
    if set(os.listdir(directory)) != expected:
        raise LeaseRefused('provider_package_members_mismatch')
    for name in sorted(expected):
        relative = prefix + name
        member = _MEMBERS.get(relative)
        flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
        if member is None:
            flags |= os.O_DIRECTORY
        fd = os.open(name, flags, dir_fd=directory)
        try:
            before = os.fstat(fd)
            if member is None:
                _scan(fd, relative + '/')
            else:
                digest, size, mode = member
                if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
                        or before.st_size != size or stat.S_IMODE(before.st_mode) != mode):
                    raise LeaseRefused('provider_package_member_mismatch')
                with os.fdopen(os.dup(fd), 'rb') as stream:
                    actual = hashlib.file_digest(stream, 'sha256').hexdigest()
                if actual != digest:
                    raise LeaseRefused('provider_package_member_mismatch')
            after = os.fstat(fd)
            current = os.stat(name, dir_fd=directory, follow_symlinks=False)
            if (_identity(before) != _identity(after) or (after.st_dev, after.st_ino) !=
                    (current.st_dev, current.st_ino)):
                raise LeaseRefused('provider_package_changed')
        finally:
            os.close(fd)
    if set(os.listdir(directory)) != expected:
        raise LeaseRefused('provider_package_members_mismatch')


def check_package(package: Path | None) -> Path:
    """Check every member without following links, including location ancestors.

    The caller must retain trusted custody between checks and execution; these
    observations are not OS isolation or an atomic filesystem/exec transaction.
    """
    if package is None:
        raise LeaseRefused('provider_package_required')
    if not package.is_absolute() or '..' in package.parts:
        raise LeaseRefused('provider_package_location_invalid')
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in package.parts[1:]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
        before = os.fstat(fd)
        _scan(fd)
        if _identity(before) != _identity(os.fstat(fd)):
            raise LeaseRefused('provider_package_changed')
    except OSError:
        raise LeaseRefused('provider_package_unsafe_or_unavailable') from None
    finally:
        os.close(fd)
    return package / 'bin/codex'
