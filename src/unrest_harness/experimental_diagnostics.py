"""Body-free startup observations. Vocabulary is fixed, never exception text."""
from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from contextvars import ContextVar
import time

from .experimental_lease import LeaseRefused

STAGES = frozenset('''broker_start owner_launch pin_check backend_spawn bridge_listen
adapter_spawn acp_initialize acp_session_new lifetime_connect bridge_connect ready
bridge_auth bridge_admission bridge_forward preflight_initialize config_read
requirements_read account_read effective_verify initialize_release owner_cleanup
bridge_cleanup coordinator_run initialize_frame_wait initialize_frame_received
initialize_write_wait initialize_write_complete initialize_response_wait
initialize_response_received unknown'''.split())
# Literal public refusal codes only; unknown arguments remain lease_refused.
REFUSALS = frozenset('''adapter_backend_thread_mismatch
adapter_version_mismatch
ambiguous_provider_selection
authentication_store_not_context
broker_file_changed
broker_file_invalid
broker_inventory_changed
broker_path_invalid
broker_unavailable
callback_or_session_violation
campaign_expired
campaign_provider_mismatch
campaign_stopped
candidate_authority_changed
candidate_context_not_text
candidate_context_too_large
candidate_not_sealed
candidate_replaced
candidate_resource_seal_changed
candidate_scope_changed
candidate_unavailable
capability_collision
cohort_attention
cohort_dispatch_stopped
cohort_no_progress
common_inputs_substituted
completion_attention
completion_missing_or_stale
continuity_lost
controlled_override_on_real_provider
controlled_rounds_invalid
cross_lane_resource_conflict
declared_input_changed
episode_active
episode_expired
episode_not_admissible
explicit_provider_selection_required
final_phase
fresh_final_gate_failed
fresh_generation_failed
git_custody_failed
git_output_bound
initial_candidate_not_base
integration_base_mismatch
integration_bytes_changed
integration_scope_collision
integration_source_changed
integration_staged_scope
invalid_capacity
invalid_episodes
invalid_first_ordinal
invalid_identity
invalid_lanes
invalid_owned_resources
invalid_resource_access
invalid_resource_footprint
invalid_session
invalid_synthetic_turn
invalid_turn_instruction
journal_unavailable
lane_turn_not_admissible
lease_unavailable
missing_owned_resources
missing_turn_instruction
mutation_not_drained
noncorrectable_attention
owned_resource_collision
parked_candidate_changed
pinned_adapter_node_missing
prompt_not_complete
provider_account_changed
provider_account_identity_changed
provider_broker_name_collision
provider_catalogue_mismatch
provider_common_inputs_changed
provider_common_inputs_required
provider_configuration_protocol_bound
provider_configuration_reader_limit
provider_configuration_eof
provider_configuration_unterminated_frame
provider_configuration_frame_bound
provider_configuration_frame_count_bound
provider_configuration_aggregate_bound
provider_configuration_protocol_invalid
provider_configuration_unresolved
provider_cross_thread_operation
provider_effective_configuration_mismatch
provider_effective_layers_unresolved
provider_effective_mcp_unresolved
provider_extra_thread
provider_initialize_required
provider_input_bound
provider_input_changed
provider_input_cycle
provider_input_location
provider_input_unreadable
provider_instruction_unresolved
provider_managed_auth_required
provider_managed_requirements_unresolved
provider_mcp_unresolved
provider_package_backend_mismatch
provider_package_changed
provider_package_location_invalid
provider_package_member_mismatch
provider_package_members_mismatch
provider_package_required
provider_package_unsafe_or_unavailable
provider_profile_unresolved
provider_protocol_bound
provider_protocol_invalid
provider_protocol_json_invalid
provider_protocol_envelope_fields
provider_configuration_response_id_mismatch
provider_configuration_error_response
provider_notification_unsupported
provider_notification_invalid
provider_role_outside_declared_runtime
provider_runtime_context_changed
provider_served_model_mismatch
provider_thread_configuration_changed
provider_thread_identity_invalid
provider_thread_mcp_changed
provider_thread_start_failed
provider_turn_permissions_changed
provider_undeclared_configuration_layer
provider_wrong_thread
recovery_seal_changed
resource_admission_stopped
resource_alias
resource_custody_binding
resource_declaration_changed
resource_lane_binding
resource_observation_bound
resource_permissions_changed
resource_replaced
resources_already_bound
retained_controls_unavailable
retained_session_capacity
reused_or_invalid_session_identity
seal_input_changed
seal_output_changed
send_not_admissible
session_stopped_during_launch
session_unavailable
staged_scope_changed
stale_broker_completion
stale_candidate
synthetic_session_quarantined
target_verdicts_invalid
transport_lost
trusted_process_opt_in_required
turn_already_reserved
turn_authority_denied
turn_budget
turn_expired
turn_not_active
turn_not_acknowledged
turn_not_admissible
undeclared_provider_runtime_context
unexpected_candidate_mutation
unobservable_input
unresolved_resource
unsafe_candidate_file
unsupported_custody_structure
unsupported_input
unsupported_provider
unsupported_provider_input
unsupported_provider_override
unsupported_provider_runtime_context
unsupported_resource
validation_identity_changed
write_scope_denied
write_too_large
wrong_opening_session'''.split())


TIMER_SCOPES = frozenset({
    'provider_preflight', 'acp_initialize_session', 'owner_launch', 'broker_start', 'bridge_auth',
    'lifetime_connect', 'bridge_connect'})

_launch_deadline: ContextVar[float | None] = ContextVar('launch_deadline', default=None)


class StartupTimeout(TimeoutError):
    """An expired owned timer, carried through enclosing waits unchanged."""

    def __init__(self, scope: str) -> None:
        super().__init__()
        self.scope = scope if scope in TIMER_SCOPES else 'unknown'


@asynccontextmanager
async def startup_timeout(seconds: float | None, scope: str) -> AsyncIterator[None]:
    outer = _launch_deadline.get()
    if seconds is None and outer is None:
        raise RuntimeError('startup deadline required')
    deadline = outer if seconds is None else asyncio.get_running_loop().time() + seconds
    assert deadline is not None
    async with startup_timeout_at(deadline, scope):
        yield


@asynccontextmanager
async def startup_timeout_at(deadline: float, scope: str) -> AsyncIterator[None]:
    outer = _launch_deadline.get()
    if outer is not None and outer <= deadline:
        deadline, scope = outer, 'owner_launch'
    token = _launch_deadline.set(deadline) if scope == 'owner_launch' else None
    timer = asyncio.timeout_at(deadline)
    try:
        async with timer:
            yield
    except TimeoutError:
        # A nested TimeoutError is not evidence that this timer expired.
        # External cancellation remains CancelledError and is never translated here.
        if timer.expired():
            raise StartupTimeout(scope) from None
        raise
    finally:
        if token is not None:
            _launch_deadline.reset(token)


def category(error: BaseException) -> str:
    if isinstance(error, LeaseRefused):
        # Do not invoke a user-defined __str__ or serialize arbitrary args.
        code = error.args[0] if len(error.args) == 1 else None
        return code if type(code) is str and code in REFUSALS else 'lease_refused'
    for kind, label in ((asyncio.CancelledError, 'cancelled'), (TimeoutError, 'timeout'),
                        (PermissionError, 'permission_denied'),
                        (asyncio.IncompleteReadError, 'unexpected_eof'),
                        (ConnectionError, 'connection_error'), (OSError, 'os_error'),
                        (ValueError, 'invalid_value')):
        if isinstance(error, kind):
            return label
    return 'exception'


@dataclass
class StartupDiagnostics:
    _stage: ContextVar[str] = field(default_factory=lambda: ContextVar(
        'startup_stage', default='owner_launch'), repr=False)
    events: list[str] = field(default_factory=list)
    failure: dict[str, str] | None = None
    cleanup: list[dict[str, str]] = field(default_factory=list)
    elapsed: list[float] = field(default_factory=list)
    _started: float = field(default_factory=time.monotonic, repr=False)

    def phase(self, stage: str) -> None:
        stage = stage if stage in STAGES else 'unknown'
        self._stage.set(stage)
        if len(self.events) < 32:
            self.events.append(stage)
            self.elapsed.append(max(0.0, time.monotonic() - self._started))

    def fail(self, error: BaseException, *, cleanup: bool = False) -> None:
        item = {'stage': self._stage.get(), 'category': category(error)}
        if isinstance(error, StartupTimeout):
            item['timer_scope'] = error.scope if error.scope in TIMER_SCOPES else 'unknown'
        if cleanup:
            if item not in self.cleanup and len(self.cleanup) < 16:
                self.cleanup.append(item)
        elif self.failure is None:
            self.failure = item

    def snapshot(self) -> dict[str, object]:
        return {'events': list(self.events), 'failure': self.failure,
                'elapsed_seconds': list(self.elapsed),
                'cleanup_errors': list(self.cleanup)}
