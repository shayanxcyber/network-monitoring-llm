"""Scoped model inspection/plan tools; none approves or changes a network."""
import hashlib
from pp_context import encoded
from pp_investigation_tools import json_tool, timestamp
from pp_response_operations import catalogue, command_plan, validate_parameters


class ResponseWorkspace:
    def __init__(self, evidence_workspace, scope=None):
        self.base = evidence_workspace
        self.scope = scope or {}
        self.base.context['capabilities'] = catalogue()
        self.base.context['response_scope'] = {
            'current_lab_bound': bool(self.scope.get('binding')),
            'selected_review_id': self.scope.get('review_id'),
            'authority': 'Inspection and plans only. Explicit operator approval is separate.',
            'offline_next_step': 'Use Current lab capture to create a fresh mapped review; do not replace an offline recommendation target silently.',
        }

    def __getattr__(self, name):
        return getattr(self.base, name)

    @property
    def tools(self):
        return self.base.tools + [json_tool(self.get_lab_status), json_tool(self.prepare_response_plan)]

    @property
    def tool_names(self):
        return self.base.tool_names | {'get_lab_status', 'prepare_response_plan'}

    def _record(self, kind, data):
        row = dict(kind=kind, observed_at=timestamp(), **data)
        alias = 'a'+hashlib.sha256(encoded(row)).hexdigest()[:16]
        row['id'] = self.digest+':'+alias
        self.base.aliases[row['id']] = alias
        self.base.aggregates[row['id']] = row
        return row

    def get_lab_status(self) -> dict:
        """Inspect the fixed current lab's identity/availability and mapping, not arbitrary hosts.
        Returns timestamped current state, separately from historical capture facts. No network change.
        """
        def operation():
            callback = self.scope.get('inspect')
            state = callback() if callback else {'available': False, 'reason': 'Current Linux broker is not connected to this application.'}
            binding = self.scope.get('binding')
            row = self._record('current_lab_state', dict(state=state, capture_binding=binding,
                selected_capture_is_current_lab=bool(binding),
                mapping_matches=bool(binding and state.get('lab', {}).get('generation') == binding.get('generation')),
                scope='Fixed disconnected lab only. This is a current broker observation, not packet evidence or approval.'))
            return [row], {'network_changed': False}
        return self.base._run('get_lab_status', {}, operation)

    def prepare_response_plan(self, operation: str, target: str, destination: str, port: int,
                              duration_seconds: int, rate_kbit: int = 0) -> dict:
        """Check an explicit operation/service/duration and show its fixed template. No approval or execution.

        Args:
            operation: block_source or rate_limit_service.
            target: Selected lab source 10.77.0.20, never the control or management host.
            destination: Lab service 10.77.0.10.
            port: TCP service 8080.
            duration_seconds: Explicit 5-120 second test duration.
            rate_kbit: Explicit 256-2048 rate for shaping, 0 for a block.
        """
        args = dict(operation=operation, target=target, destination=destination, port=port,
                    duration_seconds=duration_seconds, rate_kbit=rate_kbit)
        def build():
            parameters = validate_parameters(operation, target, destination, port, duration_seconds,
                                             None if rate_kbit == 0 else rate_kbit)
            # Placeholder has no execution identity. The exact proposal gets a new UUID.
            template = command_plan(parameters, '00000000-0000-4000-8000-000000000000')
            row = self._record('validated_operation_template', dict(parameters=parameters, template=template,
                current_lab_bound=bool(self.scope.get('binding')), approval_required=True,
                scope='Plan only. A fresh broker-issued capture, exact new proposal and operator approval are still required.'))
            return [row], {'network_changed': False, 'proposal_created': False}
        return self.base._run('prepare_response_plan', args, build)
