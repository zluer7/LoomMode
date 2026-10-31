"""Credential-free declarations and checked, Task-bound Decision choices.

Order/priority express preferences, never role authority or execution permission.
Only the two named transports have implementations in this version.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
import copy
import hashlib
import json
from pathlib import Path
from typing import Any

from loommode.workflow.errors import WorkflowError
from loommode.workflow.transitions import Node, FRESH_NODES, TASK_REQUIRED_NODES, TABLE


def digest(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=False,
                                    separators=(',', ':')).encode('utf-8')).hexdigest()


def scenario(node: Node) -> str:
    if node in FRESH_NODES:
        return 'fresh_review'
    if node in {Node.DISCUSS_NORMAL, Node.DISCUSSANT_DECISION_ANALYSIS,
                Node.DISCUSSANT_DECISION_IMPLEMENTATION_REVIEW}:
        return 'discussion'
    if node == Node.EXECUTOR_IMPLEMENT:
        return 'development'
    return 'judgment'


@dataclass(frozen=True)
class AIProfile:
    profile_id: str
    provider: str
    transport: str
    model: str
    reasoning_effort: str
    priority: int
    capabilities: tuple[str, ...]
    verification: str

    def as_dict(self):
        return asdict(self)


class ModelCatalog:
    def __init__(self, value: dict[str, Any]):
        if (not isinstance(value, dict) or set(value) != {'schema_version', 'preferences', 'profiles'}
                or value['schema_version'] != 1 or type(value['schema_version']) is not int
                or not isinstance(value['preferences'], str) or len(value['preferences']) > 16000
                or not isinstance(value['profiles'], list) or not 1 <= len(value['profiles']) <= 16):
            raise WorkflowError('invalid global model configuration')
        profiles = []
        keys = set(AIProfile.__dataclass_fields__)
        for item in value['profiles']:
            if (not isinstance(item, dict) or set(item) != keys
                    or any(not isinstance(item[k], str) or not item[k].strip() or len(item[k]) > 160
                           for k in keys - {'priority', 'capabilities'})
                    or type(item['priority']) is not int or not 0 <= item['priority'] <= 1000
                    or not isinstance(item['capabilities'], list) or not item['capabilities']
                    or any(not isinstance(cap, str) or cap not in {'discussion', 'fresh_review', 'development', 'judgment'}
                           for cap in item['capabilities'])
                    or len(set(item['capabilities'])) != len(item['capabilities'])
                    or item['verification'] not in {'UNVERIFIED', 'VERIFIED'}):
                raise WorkflowError('invalid model profile declaration')
            if item['profile_id'] in {p.profile_id for p in profiles}:
                raise WorkflowError('duplicate model profile id')
            # Unknown providers can be declared explicitly UNVERIFIED, not invoked.
            if item['transport'] == 'codex_app_server' and item['provider'] != 'codex':
                raise WorkflowError('Codex transport provider mismatch')
            if item['transport'] == 'deepseek_chat' and item['provider'] != 'deepseek':
                raise WorkflowError('DeepSeek transport provider mismatch')
            profiles.append(AIProfile(**{**item, 'capabilities': tuple(item['capabilities'])}))
        if profiles[0].transport != 'codex_app_server' or profiles[0].verification != 'VERIFIED':
            raise WorkflowError('first profile must preserve the verified Codex default')
        self.profiles, self.preferences = tuple(profiles), value['preferences']
        self.by_id = {p.profile_id: p for p in profiles}
        self.fingerprint = digest(value)

    @classmethod
    def load(cls, source: Path | dict[str, Any]):
        return cls(json.loads(source.read_text(encoding='utf-8')) if isinstance(source, Path) else source)

    def eligible(self, profile_id: str, node: Node) -> AIProfile:
        profile = self.by_id.get(profile_id)
        if profile is None:
            raise WorkflowError('Decision selected an unconfigured model profile')
        if profile.verification != 'VERIFIED' or scenario(node) not in profile.capabilities:
            raise WorkflowError('Decision selected an unverified or incapable model profile')
        if profile.transport not in {'codex_app_server', 'deepseek_chat'}:
            raise WorkflowError('selected provider transport is not implemented')
        if profile.transport == 'deepseek_chat' and scenario(node) not in {'discussion', 'fresh_review'}:
            raise WorkflowError('API profile has no verified development/judgment driver')
        return profile

    def public(self):
        return [{'ordinal': index + 1, **p.as_dict()} for index, p in enumerate(self.profiles)]


@dataclass(frozen=True)
class ModelSelection:
    profile: AIProfile
    evidence: dict[str, Any]


def prepare_model_selection_request(catalog: ModelCatalog, node: Node, state: dict[str, Any], materials=None):
    task_nature = ''
    intent_ref = state.get('formal_task_intent_ref')
    if intent_ref and (not materials or intent_ref not in materials):
        raise WorkflowError('Decision task nature requires the actual original Task Intent')
    if intent_ref and materials and intent_ref in materials:
        try:
            intent = json.loads(materials[intent_ref])
            task_nature = {key: intent.get(key) for key in ('goal', 'expected_result', 'acceptance_intent')}
        except (ValueError, AttributeError, TypeError):
            raise WorkflowError('Decision task nature requires valid original Task Intent') from None
    return {'activity': node.value, 'scenario': scenario(node),
               'project': state['project'], 'stage_id': state['stage_id'],
               'task_id': state.get('task_id'),
               'task_nature': task_nature,
               'preferences': catalog.preferences, 'catalog': catalog.public()}


class ModelRouter:
    """AI interprets preferences; this class verifies and retains Task choices.

    A selector is a Host-bound Decision callable, not a model-supplied callback.
    No preference means the existing Codex route without an extra model call.
    """
    def __init__(self, catalog: ModelCatalog, selector, driver):
        self.catalog, self.selector, self.driver = catalog, selector, driver
        self.task_catalogs = {}
        self.task_assignments = {}

    def select(self, node: Node, state: dict[str, Any], materials=None) -> ModelSelection:
        # A Task's original configuration is captured when its first actual role
        # dispatch begins. Stage/Task selection never inherits a completed Task's
        # residual ID or pays for preference interpretation without an Intent.
        task_key = (state.get('project'), state.get('stage_id'), state.get('task_id'))
        task_bound = node in TASK_REQUIRED_NODES and bool(task_key[-1]) and node in TABLE
        if not task_bound:
            return self._select(node, state, materials, self.catalog, use_preferences=False)
        if task_key not in self.task_catalogs:
            self.task_catalogs[task_key] = ModelCatalog({
                'schema_version': 1, 'preferences': self.catalog.preferences,
                'profiles': [{**p.as_dict(), 'capabilities': list(p.capabilities)}
                             for p in self.catalog.profiles]})
        catalog = self.task_catalogs[task_key]
        role = TABLE[node][0].value
        key = (*task_key, role)
        prior = self.task_assignments.get(key)
        if prior is not None:
            # Reuse identity, not permissions. Every dispatch still validates the
            # current activity's capability and the driver's actual Grant.
            evidence = {**copy.deepcopy(prior.evidence), 'activity': node.value,
                        'scenario': scenario(node), 'assignment_reused': True}
            try:
                profile = catalog.eligible(prior.profile.profile_id, node)
            except WorkflowError:
                self.driver.record_selection({**evidence, 'eligibility': 'REJECTED'})
                raise
            self.driver.record_selection(evidence)
            if profile.transport != 'codex_app_server':
                self.driver.ensure_dispatch_ready(profile.profile_id)
            return ModelSelection(profile, evidence)
        selected = self._select(node, state, materials, catalog)
        evidence = {**selected.evidence, 'assignment_reused': False,
            'task_assignment': {'project': task_key[0], 'stage_id': task_key[1],
                'task_id': task_key[2], 'role': role,
                'original_intent_ref': state.get('formal_task_intent_ref'),
                'selected_at_activity': node.value,
                'catalog_sha256': catalog.fingerprint,
                'profile_id': selected.profile.profile_id}}
        selected = ModelSelection(selected.profile, evidence)
        self.driver.record_selection(evidence)
        self.task_assignments[key] = ModelSelection(selected.profile, copy.deepcopy(evidence))
        return selected

    def _select(self, node, state, materials, catalog, *, use_preferences=True):
        request = prepare_model_selection_request(catalog, node, state, materials)
        if not use_preferences or not catalog.preferences.strip():
            raw = {'profile_id': catalog.profiles[0].profile_id,
                   'reason': 'No applicable Task preference; retain the existing Host route.'}
            origin = 'DEFAULT_CODEX'
        else:
            if not callable(self.selector):
                raise WorkflowError('natural-language preferences require an authorized Decision selector')
            raw = self.selector(request)
            origin = getattr(self.selector, 'selection_origin', 'HOST_SELECTOR_UNVERIFIED')
            if origin not in {'DECISION_AI', 'HOST_EXPLICIT', 'HOST_SELECTOR_UNVERIFIED'}:
                raise WorkflowError('invalid trusted Host selector provenance')
            if origin == 'DECISION_AI' and not isinstance(getattr(self.selector, 'last_invocation', None), dict):
                receipt = getattr(self.selector, 'last_receipt', None)
                if not (isinstance(receipt, dict) and receipt.get('success') is True
                        and receipt.get('terminal_status') == 'completed' and receipt.get('cleanup_status') == 'RELEASED'):
                    origin = 'HOST_SELECTOR_UNVERIFIED'
        if (not isinstance(raw, dict) or set(raw) not in ({'profile_id', 'reason'}, {'profile_id', 'reason', 'applies_to_activity'})
                or not isinstance(raw['profile_id'], str) or not isinstance(raw['reason'], str)
                or not raw['reason'].strip() or len(raw['reason']) > 4000
                or ('applies_to_activity' in raw and type(raw['applies_to_activity']) is not bool)):
            raise WorkflowError('invalid Decision model selection')
        applies = raw.get('applies_to_activity', origin != 'DEFAULT_CODEX')
        if not applies and raw['profile_id'] != catalog.profiles[0].profile_id:
            raise WorkflowError('non-applicable preference must retain the current default route')
        evidence = {'origin': origin, 'activity': node.value, 'scenario': scenario(node),
                    'profile_id': raw['profile_id'], 'reason': raw['reason'], 'original_selection': dict(raw),
                    'preference_applies_to_activity': applies,
                    'preferences_sha256': digest(catalog.preferences),
                    'catalog_sha256': catalog.fingerprint, 'request_sha256': digest(request)}
        source_invocation = getattr(self.selector, 'last_invocation', None) if origin == 'DECISION_AI' else None
        if isinstance(source_invocation, dict):
            evidence['decision_invocation'] = dict(source_invocation)
        elif origin == 'DECISION_AI':
            evidence['decision_invocation'] = {'provider': 'codex', 'receipt': dict(self.selector.last_receipt)}
        try:
            profile = catalog.eligible(raw['profile_id'], node)
        except WorkflowError:
            self.driver.record_selection({**evidence, 'eligibility': 'REJECTED'})
            raise
        evidence.update(provider=profile.provider, model=profile.model, eligibility='ELIGIBLE')
        self.driver.record_selection(evidence)
        if profile.transport != 'codex_app_server':
            self.driver.ensure_dispatch_ready(profile.profile_id)
        return ModelSelection(profile, evidence)

    @staticmethod
    def codex_override(selection, node, override):
        if selection.evidence['origin'] == 'DEFAULT_CODEX' or not selection.evidence.get('preference_applies_to_activity', True):
            return override
        if override:
            raise WorkflowError('explicit Codex override conflicts with Decision profile selection')
        return {'activity': node.value, 'model': selection.profile.model,
                'reasoning_effort': (None if selection.profile.reasoning_effort == 'activity_default'
                                     else selection.profile.reasoning_effort),
                'reason': selection.evidence['reason']}

    def invoke(self, selection, **kwargs):
        if selection.profile.transport == 'codex_app_server':
            raise WorkflowError('Codex selections use the existing runtime')
        return self.driver.invoke(selection=selection, **kwargs)

    def opinions(self, profile_ids, **kwargs):
        """Sequential isolated opinions; each receives the same objective input."""
        if (not isinstance(profile_ids, (tuple, list)) or not 1 <= len(profile_ids) <= 4
                or len(set(profile_ids)) != len(profile_ids)):
            raise WorkflowError('bounded distinct opinion profile ids required')
        node = kwargs['node']
        selections = []
        for pid in profile_ids:
            profile = self.catalog.eligible(pid, node)
            if profile.transport != 'deepseek_chat':
                raise WorkflowError('opinion collection requires an implemented API review profile')
            evidence = {'origin': 'DECISION_EXPLICIT_OPINIONS', 'profile_id': pid,
                        'provider': profile.provider, 'model': profile.model, 'activity': node.value,
                        'reason': 'Explicit Host-bound Decision request for independent opinions.',
                        'catalog_sha256': self.catalog.fingerprint,
                        'preferences_sha256': digest(self.catalog.preferences)}
            selections.append(ModelSelection(profile, evidence))
        results = []
        for selection in selections:
            self.driver.record_selection(selection.evidence)
            results.append(self.invoke(selection, **kwargs))
        return results
