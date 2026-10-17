"""Explicit local ACP selection; native converter execution is UNVERIFIED."""
from pathlib import Path
import sys

from unrest_harness.experimental_session import ControlledTransport


def controlled_transport() -> ControlledTransport:
    return ControlledTransport(
        Path(__file__).parent / 'fixtures/controlled_python_acp.py', Path(sys.executable))
