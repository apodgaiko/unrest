"""Extend finite SOURCE custody while retaining the original authority bytes."""

from __future__ import annotations

from primary_source_authority import SourceAuthority as OriginalSourceAuthority
from multiprocess_custody import exec_custody
from primary_dependency_authority import DependencySourceAuthority as OriginalDependencySourceAuthority


class OwnedMultiprocessCustody:
    def exec_descriptors(self, trace, pid, vector, environment, cwd):
        registration = self.bound.get(pid, {}).get("registration", {})
        if registration.get("class") not in {
            "source-multiprocess-tracker",
            "source-multiprocess-spawn",
        }:
            return super().exec_descriptors(trace, pid, vector, environment, cwd)
        try:
            return exec_custody(self, trace, pid, vector, environment, cwd)
        except BaseException:
            trace.poison.append("primary_source_multiprocess_custody")
            self.supervisor.poison("primary_source_multiprocess_custody")
            raise


class SourceAuthority(OwnedMultiprocessCustody, OriginalSourceAuthority):
    pass


class DependencySourceAuthority(OwnedMultiprocessCustody, OriginalDependencySourceAuthority):
    pass
