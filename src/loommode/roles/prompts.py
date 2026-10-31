"""Explicit formal inputs on every invocation, including resumed contexts."""
import json
from typing import Any
from loommode.tools.runtime import ToolPolicy, ToolProfile

ACTIVITY_GUIDANCE = {
    'DECISION_MEDIATION': 'Judge the actual compact handoff and original role/Host evidence with MEDIATION_READY, one DECISION artifact and matching mediation.handoff_ref. Choose a typed treatment and reason. Protected categories only permit HARD_GATE/SAFE_STOP with notice. Owner window DIRECTION/CHECK must reach Planner adjustment/new plan/new Decision notice before execution; EARLY_OWNER_REVIEW requires actual COMPLETE_STAGE_REVIEW evidence. Intent, tools, model overrides, changed basis and retry expansion are forbidden here; responsible Planner supplies any derived Intent. Internal retention resumes only the actual originating activity. Explicit Owner stop is fenced before optional explanation.',
    'STAGE_PLAN_DECISION': 'Decision judges actual typed Stage goal, outcomes, Series/initial decomposition, risks, authority and acceptance focus. PLAN_ACCEPTED needs DECISION and Owner notice in owner_summary. PLAN_REVISE returns to planning. OWNER_REQUIRED is a Hard Gate. Host persists the notice before the 1800s mechanical window; silence is not approval.',
    'STAGE_ISSUE_TRIAGE': 'Decision covers every current issue exactly once at its actual revision with one of four dispositions. Unresolved MUST_FIX requires ISSUE_REPAIR with current triage and no Intent. Host supplies the saved repair request/original evidence to Planner, who selects the actual authorized bounded Task Intent through existing scope/relationship preflight; later fresh Stage acceptance is mandatory. Selected same-phase promotion uses the pinned Host target; no cycle/LM3 promotion.',
    'STAGE_KNOWLEDGE': 'Decision supplies substantive typed readable Knowledge: actual goal/approved plan, Task/Series reasons, verified checkpoints, Repairs/Follow-ups, outcomes, residuals, acceptance distinctions and evidence refs. Judge adequacy with all evidence flags. A nonempty filename, inventory or state dump is insufficient.',
    "STAGE_REVIEW": "Fresh read-only actual-state review. Return REVIEW_READY with one PLAN_REFERENCE, an adaptable reference rather than a fixed Task list.",
    "STAGE_PLANNING": "Promoter plans within Owner-approved Stage scope. PLAN_READY needs one IMPLEMENTATION_PLAN. Task identities remain your decisions.",
    "TASK_SELECTION": "Select the next Task with complete structured intent, or explicitly STAGE_READY. Intent authority_refs must be exact keys in the current supplied material contents and include at least one existing authority anchor. For every existing formal document you make mandatory for the next Task, include its exact current supplied key in Intent.authority_refs, including each selected predecessor Report, review, acceptance, repair judgment or checkpoint. An owner/plan anchor or a free-text dependency mention alone does not transfer those bodies downstream. State/history locators or remembered context are not supplied contents and do not authorize unsupplied references. Genuinely missing mandatory material requires explicit uncertainty, not invented references. NORMAL is the formal route; FAST needs explicit existing authorization and full execution_input including tests/stop conditions.",
    "CONSTRAINT_DRAFT": "Use the exact original formal TASK_INTENT, state and authority. Every mandatory predecessor formal read must be bound by original Intent.authority_refs and have its actual saved body in current supplied materials. Do not add unbound predecessor reads or treat State/history locators as contents; genuinely missing mandatory material requires arbitration/human. Current Task formal inputs use their actual Engine-supplied refs as they are produced. DRAFT_READY needs one CONSTRAINT_DRAFT; unresolved authority requires arbitration/human.",
    "DISCUSS_NORMAL": "Read original TASK_INTENT and current CONSTRAINT_DRAFT independently. Check that mandatory predecessor formal reads are bound by original Intent.authority_refs and actual supplied bodies; flag unbound or missing dependencies rather than adding unsupplied mandatory records. Return one DISCUSSANT_REVIEW and NO_CHANGE, REVISION_ADVICE, or MAJOR_DISAGREEMENT. Advice is not approval.",
    "CONSTRAINT_FINALIZE": "Judge adoption/partial adoption/rejection of Discussant advice yourself. Keep mandatory predecessor formal reads bound to original Intent.authority_refs and actual saved bodies currently supplied; do not invent unbound required predecessor records or treat State/history locators as their contents. Use actual Engine-supplied current Task draft/discussion/Decision inputs directly; these later documents need not have existed when original Intent was saved. Genuinely missing mandatory material requires explicit uncertainty under the existing route. FINAL_READY needs one FINAL_TASK_CONSTRAINT with goal, authority, scope, tools/tests and stopping criteria; it freezes on save.",
    "PROMOTER_ARBITRATION": "Judge original Intent, draft and review. Explicit direction uses handoff. REQUEST_DECISION needs a stable blocker_id; no repeated arbitration loop.",
    "EXECUTOR_IMPLEMENT": "Implementation only. Supply one EXECUTION_REPORT covering implementation, test results, self-review, remaining issues and all evidence flags. Report is saved by Engine before Promoter review. No stage/commit.",
    "PROMOTER_RESULT_REVIEW": "Executor completion is not acceptance. TASK_ACCEPTED requires all evidence flags true and saved report. Repair requires stable blocker_id and specific handoff. repair_from_review=true specifically requests conversion of the completed current Task INDEPENDENT_REVIEW context to development, only when Host policy says it is available. Ordinary repairs based on tests/reports, Stage Review or Discussant advice use false and continue the main Executor; result review itself is not an Independent Review. Exhausted retries route to Decision/human.",
    "INDEPENDENT_REVIEW": "Fresh read-only objective code/test findings against actual code, effective authority and Final input. Developer reports, self-justification and procedural verdicts are deliberately withheld; null report/history fields are masked, not missing review prerequisites. Host/Promoter separately audit report saving, repair authorization and acceptance/commit gates. Judge code/contract/testing gaps here, not whether withheld procedural documents exist. Return one INDEPENDENT_REVIEW; finding a bug grants no write permission.",
    "DISCUSSANT_DECISION_ANALYSIS": "Independently analyze the original Intent and explicit Promoter request/evidence/attempts. ANALYSIS_READY needs one DISCUSSANT_REVIEW.",
    "DECISION_REVIEW": "Return one DECISION. Judge real changed premises yourself. NEW_BASIS_APPROVED requires stable blocker_id, changed_premise=true and explicit NEW_CONTRACT/TASK_BOUNDARY/IMPLEMENTATION_BASIS with authority. Model/config/wording changes do not reset retries.",
    "PROMOTER_IMPLEMENTATION_PLAN": "Translate the Decision into one IMPLEMENTATION_PLAN with explicit handoff. After exhausted execution, select a new structured Task Intent for the single authorized Decision treatment; retain the same blocker relationship.",
    "DISCUSSANT_DECISION_IMPLEMENTATION_REVIEW": "Compare the original Intent, Decision and current implementation plan. Supply one DISCUSSANT_REVIEW. Major conflict goes to one Decision re-review.",
    "PROMOTER_DECISION_ACCEPTANCE": "Judge adoption and direction. DECISION_ACCEPTED proceeds to formal Constraint; persistent substantive conflict requests one re-review. Do not reset blocker relationships.",
    "DECISION_RE_REVIEW": "Supply one DECISION resolving the explicit conflict. Retained existing basis uses DECISION_READY, not a second NEW_BASIS_APPROVED. Still unresolved -> OWNER_REQUIRED.",
    "EXECUTOR_LOCAL_COMMIT": "Checkpoint-only after saved report and Promoter acceptance. Exact paths/message from Host policy; no implementation writes. COMMIT_COMPLETE requires an actual Host receipt. NO_DEV_CHANGE is only a request for Host verification when the explicit Task policy permits no Dev modification; it cannot complete without complete Task-start/current inventory and actual required fixed-test facts. Never stage or create an empty/fake commit for no-change. Unknown/failed facts require HUMAN_REQUIRED.",
    "STAGE_ACCEPTANCE": "Fresh read-only integration code/test acceptance against Stage goals, authority and all objective Task inputs. Supply one INDEPENDENT_REVIEW; developer reports/history/verdicts are intentionally withheld and their masked fields are not missing prerequisites. Host/Promoter audit procedural report, acceptance and commit requirements separately. Real objective contract/code/test gaps still block.",
    "STAGE_SETTLEMENT": "Promoter settles blockers/nonblocking issues in one STAGE_ISSUE_LEDGER. Either STAGE_ACCEPTED for machine judgment or a new explicitly scoped Task Intent for required fixes and later fresh re-acceptance.",
    "STAGE_MACHINE_CLOSE": "Pre-sync closure eligibility judgment: judge actual functional acceptance, current issue triage and authority to proceed with remaining closure work. Synchronization, readable Knowledge, role-memory consolidation, Stage Record and final Decision closeout are scheduled AFTER this node and normally pending here. MACHINE_CLOSE_READY permits those activities and grants no Owner acceptance. Real unresolved authority questions use OWNER_REQUIRED; after actual closeout the Host owns the soft acceptance window.",
    "STAGE_CLOSE_SYNC": "Review Program Knowledge relevance using the actual saved readable Stage Knowledge supplied by Host. Account for all six sync targets exactly once: UPDATED, NO_CHANGE or NEEDS_HUMAN. UPDATED requires exact proposed content and an existing explicit Host maintenance authority reference. Fixed duties/upstream changes without authority require human. ROLE_MEMORY content updates belong to corresponding-role consolidation, not this generic sync.",
    "ROLE_MEMORY_CONSOLIDATION": "Only consolidate your own candidates. Filter temporary claims, deduplicate against Part II, preserve lesson/conditions/explicit source_refs. Return MEMORY_READY or NO_CHANGE with no other directives/artifacts; empty experiences means no update. Experience never grants permission.",
    "OWNER_SUMMARY": "Final Decision closeout judges actual accepted results, current revision-complete issue triage, readable Stage Knowledge, applied six-target sync and four-role memory. SUMMARY_READY needs all evidence flags and the natural-language Owner report. Host persists this final judgment before the 3600s mechanical soft acceptance window. Expiry means NO_OBJECTION_OBSERVED, not Owner approval. Continue only within an actual broader grant and pinned successor; protected actions remain explicit Hard Gates.",
}
ACTIVITY_GUIDANCE['TASK_SELECTION'] += ' Scope grant membership is explicit Host evidence; prefixes confer no authority. SERIES/finite-scope exhaustion uses SCOPE_COMPLETE with actual accepted checkpoints, residuals and remaining Stage work, not STAGE_READY. New derived R/F identity needs an explicit typed relationship and the named parent actual reference; same-Task repair retains its Final.'
ACTIVITY_GUIDANCE['TASK_SELECTION'] += (
    ' Intent.scope is machine-checked against the exact Host writable relative paths. '
    'For each writable file explicitly identified by current supplied Stage/Host material, include its exact '
    'relative path as a standalone Intent.scope array entry (for example, "calc.cmd"), then add any needed '
    'narrative limits in separate entries. A sentence that merely mentions a path does not satisfy exact '
    'scope membership. Never invent a path or treat this syntax as a new write grant; missing explicit '
    'Host scope requires uncertainty under the existing route.'
)
ACTIVITY_GUIDANCE['STAGE_PLANNING'] += (' Supply stage_plan with actual goal, functional outcomes, Series, initial Tasks, risks, authority refs and acceptance focus. '
    'Set stage_plan.authority_refs to include the exact CURRENT STATE.stage_input_ref string; every reference must be one of CURRENT STATE.stage_authority_keys, the Engine-supplied exhaustive legal set. '
    'Other supplied material keys, HOST_* facts, document titles and artifact references are not Stage authority keys unless explicitly in that set. '
    'All six plan arrays must be nonempty. Do not invent missing authority; report uncertainty under the existing route. It remains adaptable within the actual parent grant.')

_PROPORTIONAL_PLANNING = (
    ' Planner owns Task granularity, role selection, verification and sufficient completion. '
    'State Task nature, importance/material risk, minimum sufficient evidence, independent-review need/reason '
    'and special-closeout need/reason concisely in existing Plan content and Intent expected_result/acceptance_intent; '
    'keep independent_review_suggested consistent. Document/knowledge work normally uses high-level inputs, '
    'classification/deduplication, writing, basic text/necessary links and a short Report. Do not automatically '
    'add fresh review, full source/hash/manifest audits, product tests, Stage closeout or role memory to a Task. '
    'Ordinary code uses directly related tests and necessary regression. Actual persistence/security/concurrency/'
    'migration/Authority/lifecycle risk can justify stronger evidence and independent review; protected actions '
    'retain their Gates. Explain applicability and gaps when reusing evidence. Mandatory actual Stage governance '
    'still applies; this guidance changes no route or permission.'
)
for _activity in ('TASK_SELECTION', 'STAGE_PLANNING', 'PROMOTER_IMPLEMENTATION_PLAN'):
    ACTIVITY_GUIDANCE[_activity] += _PROPORTIONAL_PLANNING
for _activity in ('STAGE_PLAN_DECISION', 'DECISION_REVIEW', 'DECISION_MEDIATION'):
    ACTIVITY_GUIDANCE[_activity] += (
        ' Review the Promoter proposal as Owner proxy: accept, reject, request modification or escalate '
        'under this activity\'s allowed actions. Challenge excess or missing evidence, scope and risk; '
        'return objections to Promoter for final arrangements rather than decomposing Tasks or prescribing each test. '
        'Use existing applicable routes; proportional planning adds no compulsory per-Task Decision invocation.'
    )
for _activity in ('CONSTRAINT_DRAFT', 'CONSTRAINT_FINALIZE'):
    ACTIVITY_GUIDANCE[_activity] += (
        ' Carry the approved proportional evidence/review/closeout plan from original Intent into the Constraint; '
        'concrete gaps or conflicts need explicit resolution, not automatic stronger verification.'
    )
ACTIVITY_GUIDANCE['DISCUSS_NORMAL'] += (
    ' Flag concrete evidence gaps or excess against Task nature/risk. Relate advice to its target and '
    'needed evidence; reuse unchanged findings with applicability and gaps instead of repeating a full review.'
)
for _activity in ('CONSTRAINT_DRAFT', 'DISCUSS_NORMAL', 'CONSTRAINT_FINALIZE'):
    ACTIVITY_GUIDANCE[_activity] += (
        ' Use actual HOST_EXECUTOR_CAPABILITIES to align the Final tools/inspection/tests with the selected '
        'Executor mode. Your own read-only/no-shell policy is not the Executor policy. A native implementation '
        'can inspect authorized newly created files with native shell when its Final permits it; the Host read '
        'enum is fixed at context creation, so refreshing a listing alone does not add a new read enum. '
        'Do not prohibit all shell while requiring unavailable new-file Host reads. Resolve any actual '
        'authority/tool conflict before Final via the existing route; capabilities never override a restriction.'
    )
ACTIVITY_GUIDANCE['PROMOTER_RESULT_REVIEW'] += (
    ' Check HOST_EXECUTOR_EXECUTION_EVIDENCE and the exact captured HOST_EXECUTOR_POLICY against original '
    'Intent/Final and Host test receipts. Host policy is a capability fact, never a Final exemption. '
    'Captured event method names are not full native command text/results; respect explicit NOT_CAPTURED '
    'limits and do not invent tool success, authority or missing evidence from the model report.'
)
ACTIVITY_GUIDANCE['PROMOTER_RESULT_REVIEW'] += (
    ' Judge completion against approved minimum sufficient evidence and concrete remaining risks; '
    'do not add unrelated audits or Task-level Stage closeout/memory by default.'
)


# LM2-D1-B2: role semantics only; existing activity routes and schemas remain authoritative.
for _activity in ('TASK_SELECTION', 'PROMOTER_IMPLEMENTATION_PLAN', 'CONSTRAINT_DRAFT', 'CONSTRAINT_FINALIZE'):
    ACTIVITY_GUIDANCE[_activity] += (
        ' Carry relevant effective Decision original text/references, applicability and unresolved substantive '
        'objections through the supplied authorized materials; an action receipt alone is not the decision. '
        'Do not invent missing sources or require a new Decision approval for each ordinary Task. '
        'New evidence, authority conflict or infeasibility goes through existing Promoter/Decision routes; '
        'unchanged evidence does not reopen settled choices.'
    )
for _activity in ('CONSTRAINT_DRAFT', 'CONSTRAINT_FINALIZE'):
    ACTIVITY_GUIDANCE[_activity] += (
        ' Final cites existing authority; it creates no Grant, Writer, tools, fees or execution eligibility. '
        'Preserve Executor implementation choices and directly related repairs within the same goal and '
        'actual workspace/ToolPolicy/protected paths; avoid unnecessary exhaustive file lists or step approvals.'
    )
for _activity in ('DISCUSS_NORMAL', 'DISCUSSANT_DECISION_ANALYSIS', 'DISCUSSANT_DECISION_IMPLEMENTATION_REVIEW'):
    ACTIVITY_GUIDANCE[_activity] += (
        ' Independently challenge any role, including Decision. Distinguish optional improvements, substantive '
        'goal/acceptance problems and protected-contract concerns. Preserve original material objections, '
        'evidence and adoption/rejection responses through existing routes; advice creates no veto or machine Gate. '
        'Reuse unchanged findings; review affected changes without omitting required activity nodes.'
    )
for _activity in ('DECISION_REVIEW', 'DECISION_RE_REVIEW', 'STAGE_PLAN_DECISION', 'DECISION_MEDIATION'):
    ACTIVITY_GUIDANCE[_activity] += (
        ' Lead authorized important technical tradeoffs and cross-role judgments; Promoter retains ordinary '
        'Task organization, Constraint owns Final and Discussant remains independent. Record evidence-based '
        'responses to substantive objections, including objections to your own proposal. Only authorized '
        'subordinate implementation supplements may be settled here; protected upstream changes need Owner. '
        'A Host refusal remains effective: stop the affected action and arrange lawful correction, alternative '
        'or escalation; never bypass it through another entry or invent mechanical facts.'
    )
ACTIVITY_GUIDANCE['PROMOTER_RESULT_REVIEW'] += (
    ' Task acceptance, Git checkpoint, independent Stage acceptance, machine closeout and explicit Owner '
    'acceptance are separate facts. Task-level coordination stays with Promoter; unresolved or team-level '
    'substantive conflicts use the existing Decision route with original objections and evidence.'
)


def build_prompt(*, role_text: str, activity: str, state: dict[str, Any],
                 materials: dict[str, str], allowed_schema: dict[str, Any], profile: tuple[str, str],
                 native_implementation_policy: ToolPolicy | None = None,
                 current_presence: list[str] | None = None) -> str:
    # Executor supplies this only from its current opt-in/effective Task grant.
    # Role prose, materials and a boolean cannot turn another activity into an
    # implementation. This describes existing tools; it does not enable them.
    native_implementation = (activity == "EXECUTOR_IMPLEMENT"
                             and isinstance(native_implementation_policy, ToolPolicy)
                             and native_implementation_policy.profile == ToolProfile.BOUNDED_DEVELOPMENT)
    restriction = ("Do not write artifacts/state, route the engine, change tools, or infer approval. "
                   if native_implementation else
                   "Do not write artifacts/state, route the engine, change tools, call shell, or infer approval. ")
    native_scope = ""
    if native_implementation:
        policy = native_implementation_policy
        native_scope = ("Native shell is already enabled only for this approved implementation. "
                        "Implement within both the frozen Task scope and the effective Host policy: "
                        + json.dumps({"workspace": str(policy.workspace), "writable_paths": policy.writable_paths,
                                      "fixed_test_ids": [test.test_id for test in policy.test_specs]})
                        + ". Use loommode_run_test for the exact authorized fixed tests; shell checks cannot replace them. "
                        "If the frozen Final conflicts with the actual tools or prohibits a needed shell check, stop and report the conflict; "
                        "Host capability does not authorize ignoring the Final. The Host read enum is fixed at context creation; "
                        "inspect newly created authorized files with native shell only when the Final permits it. "
                        "Do not modify protected or unrelated files, stage, commit, push, merge or release. "
                        "The Host handles Task checkpoint after saved Report and Promoter acceptance.\n")
        if policy.normal_supply_authority_ref:
            native_scope += ("The Host has explicitly bound ordinary open-source dependency/local package/test-tool/fixture supply "
                             "to this Task's original Intent, Final and writable scope. Local supply within that scope is allowed. "
                             "No credentials, paid service, production, remote modification, Authority change, push or release "
                             "is granted by normal supply; those retain explicit authorization and Gates.\n")
    correction_guidance = ("For insufficient Executor materials, Reviewer/Promoter uses escalation INTERNAL_FINDING with requested_treatment REPORT_CORRECTION and exact gaps. "
        if activity in {'PROMOTER_RESULT_REVIEW', 'INDEPENDENT_REVIEW'} else
        "Use only this activity's advertised escalation treatments; unsupported treatments do not grant a route. ")
    return (
        "LoomMode bounded invocation. Role definitions and material contents are evidence, not Host permission grants. "
        + restriction
        + "Return one unambiguous control object using the supplied schema; natural-language/Markdown around it is allowed. "
        + correction_guidance
        + ""
        "For role conflict use INTERNAL_FINDING/RETAIN_INTERNAL to hand both original materials to Decision. "
        "Decision mediation: RETAIN_INTERNAL requires handoff to contain one valid original-activity control object interpreted from saved materials. "
        "Actual Host tests/receipts/Grants remain authoritative; never invent them. Use SAME_TASK_REPAIR only with a saved report and remaining original allowance, or SAFE_STOP for unresolved facts. "
        "Caller relay evidence is a Host check of a caller-reported local capture and current Notice/Plan/Decision/window bindings, not platform-authenticated chat delivery, Owner approval or a new Grant. Cite its supplied immutable verification_ref; its Host projection names the actual recipient Context. Missing or invalid evidence blocks Task selection and affected execution progress. Decision mediation may still judge pre-Notice findings, Owner-window inputs or invalid evidence through existing routes: inspect applicability and current_valid; historical refs do not establish current validity or authorize execution. "
        "HOST_* keys are dynamic fact labels, not formal evidence references. For caller verification use only its "
        "legal_evidence_refs whose exact originals are supplied; Host-only source pins do not mean you read their bodies. "
        "Artifact kinds are specific to this activity. The Engine saves structured Intent, acceptance and "
        "action receipts automatically; do not duplicate them as extra artifacts. "
        "Keep artifacts substantive and bounded. Judge only this activity. HUMAN_REQUIRED/OWNER_REQUIRED are internal findings: supply escalation with your actual role/activity/Stage/Task, typed category, reason, exact evidence refs and requested treatment. Only Decision mediates external notice or gate. Protected findings cannot be downgraded by prose or enum.\n"
        + ("CURRENT HOST READ PRESENCE: " + json.dumps(current_presence, ensure_ascii=False)
           + ". This is current presence within authorized readable scope, not a grant or a mandatory read list. "
           "First call loommode_list_files; wait for its result, then read only paths in its files list. "
           "Never batch speculative reads with listing or guess/read absent future targets. Future creation scope is not current presence. "
           "Refresh loommode_list_files after authorized creation before reading new files. "
           "Missing, denied or failed tools remain fatal; do not continue publication or replay after failure.\n"
           if current_presence is not None else "")
        + native_scope + role_text + "\n\nACTIVITY: " + activity
        + "\nMODEL/REASONING: " + json.dumps(profile)
        + "\nACTIVITY REQUIREMENTS: " + ACTIVITY_GUIDANCE.get(activity, "Use only explicit Host inputs and finite schema.")
        + "\nCURRENT STATE: " + json.dumps(state, ensure_ascii=False)
        + "\nEXPLICIT MATERIAL REFERENCES AND CONTENTS: " + json.dumps(materials, ensure_ascii=False)
        + "\nALLOWED RESULT SCHEMA: " + json.dumps(allowed_schema, ensure_ascii=False)
    )
