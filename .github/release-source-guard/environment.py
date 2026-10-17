"""Trusted, locked dependency bootstrap; no project package or source execution."""
from __future__ import annotations

import hashlib
from pathlib import Path
import subprocess
import urllib.request
import uuid

BASE = "python@sha256:9a4a5ceafb4ddd7468a09ade0049463a7bd1acbefda52adee748544110fd032d"
UV_URL = (
    "https://files.pythonhosted.org/packages/9b/83/"
    "a0bdf4abf86ede79b427778fe27e2b4a022c98a7a8ea1745dcd6c6561f17/"
    "uv-0.9.5-py3-none-manylinux_2_17_x86_64.manylinux2014_x86_64.whl"
)
UV_SHA256 = "6507bbbcd788553ec4ad5a96fa19364dc0f58b023e31d79868773559a83ec181"


def build(root: Path, repository: Path, log: Path) -> str:
    """Build only from public pinned bootstrap and exact project lock metadata."""
    root.mkdir()
    wheel = root / UV_URL.rsplit("/", 1)[1]
    with urllib.request.urlopen(UV_URL, timeout=60) as response:
        wheel.write_bytes(response.read())
    if hashlib.sha256(wheel.read_bytes()).hexdigest() != UV_SHA256:
        raise RuntimeError("uv bootstrap wheel bytes differ")
    for name in ("uv.lock", "pyproject.toml"):
        (root / name).write_bytes((repository / name).read_bytes())
    (root / "dependency_closure.py").write_bytes(
        Path(__file__).with_name("dependency_closure.py").read_bytes()
    )
    for name in ('profile_gate.c', 'profile_gate_build.py'):
        (root / name).write_bytes(Path(__file__).with_name(name).read_bytes())
    (root / "Dockerfile").write_text(
        "FROM " + BASE + "\n"
        "COPY " + wheel.name + " /bootstrap/\n"
        "RUN python -m pip install --no-index --no-deps /bootstrap/*.whl "
        "&& rm -rf /bootstrap\n"
        "COPY pyproject.toml uv.lock /metadata/\n"
        "WORKDIR /metadata\n"
        "RUN UV_PROJECT_ENVIRONMENT=/opt/deps UV_PYTHON_DOWNLOADS=never "
        "UV_NO_CACHE=1 UV_LINK_MODE=copy "
        "uv sync --locked --no-install-project --all-groups --python /usr/local/bin/python\n"
        "RUN python -c \"from pathlib import Path; Path('/opt/deps/lib/python3.13/site-packages/unrest-source.pth').write_bytes(b'/source/src\\n')\"\n"
        "COPY dependency_closure.py /bootstrap/dependency_closure.py\n"
        "RUN python -I /bootstrap/dependency_closure.py /opt/deps /environment-closure.json "
        "&& rm -rf /bootstrap\n"
        "COPY profile_gate.c /opt/source-guard/profile_gate.c\n"
        "COPY profile_gate_build.py /bootstrap/profile_gate_build.py\n"
        "RUN gcc -shared -fPIC -O2 -Wall -Wextra -Werror $(python3-config --includes) "
        "/opt/source-guard/profile_gate.c -o /opt/source-guard/profile_gate.so "
        "&& python -I /bootstrap/profile_gate_build.py && rm -rf /bootstrap\n"
        "WORKDIR /\n"
    )
    image = "source-locked-environment:" + uuid.uuid4().hex
    with log.open("ab") as output:
        subprocess.run(["docker", "build", "--pull", "--tag", image, str(root)],
                       stdout=output, stderr=subprocess.STDOUT, check=True)
    return subprocess.check_output([
        "docker", "image", "inspect", "--format={{.Id}}", image,
    ], text=True).strip()
