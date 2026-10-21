"""Extend finite SOURCE custody while retaining the original authority bytes."""

from __future__ import annotations

from primary_source_authority import SourceAuthority as OriginalSourceAuthority
from multiprocess_custody import exec_custody
from child_relative_custody import check as child_relative_check
from primary_dependency_authority import DependencySourceAuthority as OriginalDependencySourceAuthority


class OwnedMultiprocessCustody:
    def start(self, *args, **kwargs):
        from finite.launch_preflight_routes import ALIAS_PATH, SOURCE, PIN
        if self.manifest['product_pins'].get(SOURCE) == PIN:
            if ALIAS_PATH in self.manifest['runtime']['paths']:
                raise RuntimeError('launch_preflight_duplicate_alias')
            self.manifest['runtime']['paths'].append(ALIAS_PATH)
        result = super().start(*args, **kwargs)
        from journal_supervisor import JournalSupervisor
        JournalSupervisor.adopt(self.supervisor)
        self.supervisor.owned_trace = kwargs.get('trace')
        return result

    def tick(self, trace):
        if getattr(self, 'supervisor', None) is None:
            return super().tick(trace)
        from trace_tick_schedule import TickSchedule
        if not hasattr(self, '_source_tick_schedule'):
            self._source_tick_schedule = TickSchedule()
        if self._source_tick_schedule.due(trace, self.supervisor):
            result = super().tick(trace)
            self._source_tick_schedule.complete(trace)
            return result
        return None

    def resolve(self, trace, pid, path, vector, environment, cwd):
        if getattr(self, 'supervisor', None) is not None:
            # An exec decision never relies on an idle poll or prior census.
            super().tick(trace)
            if self.supervisor.poisoned or trace.poison:
                return False
            if hasattr(self, '_source_tick_schedule'):
                self._source_tick_schedule.complete(trace)
        result = super().resolve(trace, pid, path, vector, environment, cwd)
        if result is not False:
            return result
        from native_relative_custody import resolve
        if resolve(self, trace, pid, path, vector, environment, cwd):
            return True
        from candidate_git_custody import resolve as candidate_resolve
        if candidate_resolve(self, trace, pid, path, vector, environment, cwd):
            return True
        from invalid_format_custody import resolve as invalid_resolve
        if invalid_resolve(self, trace, pid, path, vector, environment, cwd):
            return True
        from registry_native_custody import resolve as registry_resolve
        if registry_resolve(self, trace, pid, path, vector, environment, cwd):
            return True
        from launch_preflight_custody import resolve as plan_resolve
        return plan_resolve(self, trace, pid, path, vector, environment, cwd)

    def exec_descriptors(self, trace, pid, vector, environment, cwd):
        if self.bound.get(pid, {}).get('registration', {}).get('class') == 'source-cohort2:invalid-format':
            trace.poison.append('invalid_format_unexpected_successful_exec')
            self.supervisor.poison('invalid_format_unexpected_successful_exec')
            raise RuntimeError('invalid_format_unexpected_successful_exec')
        child_relative_check(self, trace, pid, vector)
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
