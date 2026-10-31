# LoomMode 2.0.0 installation and bounded one-Task use

Read START_HERE.md and KNOWN_ISSUES.md first. Verify the exact 2.0.0 core ZIP,
sidecar and HANDOFF.json. This candidate awaits Owner acceptance and publication
GO. New runs use fresh authorization; earlier ended or UNKNOWN runs are never
replayed or refunded. Historical rc archives are separate frozen identities.

Read this entire file, README, rights/dependency/release notes and the actual
new device's project instructions. This package is an inert Apache-2.0
release candidate. **A real model run on this device needs later explicit Owner
authorization.** The previous development task, this guide and configuration
booleans are not that authorization. Do all offline steps first. Preserve any
existing project, Git changes, Authority, role experience, State and credentials.

## 1. Verify and inspect the device

Check the external ZIP SHA256 against its supplied `.sha256` sidecar, then
extract into a new directory, for example a path containing spaces. Do not
overwrite an existing checkout. Read `MANIFEST.json` and its checksum scheme:
the manifest excludes itself; SHA256SUMS covers payload plus manifest and
excludes itself; the external sidecar covers the ZIP. These records identify
bytes, not authenticity or permission. Obtain the hash through the authorized
handoff, not from an untrusted replacement archive.

Use PowerShell variables adapted to approved paths:

```powershell
$candidateRoot = (Resolve-Path 'C:\approved\LoomMode candidate').Path
$evidenceRoot = 'C:\approved\LoomMode verification evidence'
python --version
git --version
python -B "$candidateRoot\tools\agent_test_integrity.py" --directory $candidateRoot
```

Python must be>=3.11. Use an ordinary Windows user session and supported local
storage. The Host obtains its ownership directory from the **actual OS known
LocalAppData**; changing TEMP does not relocate it. App sandbox Package
LocalAppData, reparse namespaces and unsupported hardlinks/junctions are refused.
Use an approved ordinary environment, never weaken guards or change ACLs.
Keep candidate source read-only in practice; all logs/builds/venvs/live state
belong in separately approved directories. Never put live outputs in the source.

## 2. Offline install and tests (no model)

```powershell
python -m venv "$evidenceRoot\venv"
$testPython = "$evidenceRoot\venv\Scripts\python.exe"
& $testPython -m pip install --no-index --no-deps "$candidateRoot\wheels\loommode-2.0.0-py3-none-any.whl"
Push-Location $evidenceRoot
& $testPython -I -B -c "import loommode, importlib.metadata; from loommode.version import __version__; print(loommode.__file__, __version__, importlib.metadata.version('loommode'))"
Pop-Location
python -B "$candidateRoot\tools\agent_test_verify.py" --evidence "$evidenceRoot\offline checks" --temporary-root 'C:\approved\ATtmp01'
python -B "$candidateRoot\tools\agent_test_integrity.py" --directory $candidateRoot
```

Both directories must be absent. Choose a short new approved `--temporary-root`;
deep paths can exceed Windows legacy limits when receipt filenames are added.
Never change the LongPaths registry or ACLs. The runner permits only its exact
pinned Python plus local deterministic `tests/fixtures/fake_app_server.py` peer
for protocol fixtures. That peer is not Codex and makes no model/provider call.
The runner explicitly selects carried test classes; do not use broad integration discovery. It blocks real
app-server/model/provider entry points, uses disposable repositories and tests
real ordinary OS ownership, canonical assembly, refusals and cleanup. Its Python
binary/`--version`/transport fixtures are synthetic; passing is not Codex login,
protocol or Task acceptance. It records import origins and removes only verified
new fixture ownership directories after leases close. Raw failures remain evidence.
Missing filesystem permission stops affected checks. A relocation injection alone
does not satisfy genuine canonical assembly. Install imports must resolve to the
fresh venv; checkout entry/test imports to this candidate's `src`, never old Dev.

## 3. Prepare fresh isolated work only after later authorization

The later actual Owner instruction must identify the device/project, a new
Stage/one Task/caller, precise files, fixed tests, existing subscription route,
finite call/per-turn/total-time limits, expiry, legitimate notice relay, zero
additional direct-charge ceiling, permitted directories and stop conditions.
No Git commit/merge/push or public release is granted by these examples.

Create **new disjoint existing** Workspace, Records, Runtime and Original Inputs
directories; create a separate absent Generated Inputs target. Use a new tuple,
for example `AT1 / A / A1`, Stage `AT1-A1`, Task `AT1-A1-A1`. Do not reuse old
State/Registry/Records or a C5 Grant. Check links, permission, Git status and
known-folder preflight first. A fresh disposable Git repository may be initialized
only within that later authorized test workspace; keep its initial inventory clean.
This first-use helper does not initialize Git or write business files.

Create a tiny deterministic engineering target and immutable test script under
the exact later approved scope. For example, Owner may authorize implementing
`answer.py` with `answer()==42` and a prewritten `test_answer.py` that imports it
and asserts42. The fixed TestSpec must invoke the exact selected Python path with
`-B test_answer.py`, cwd `.`, timeout60. Only `answer.py` is writable; include both
files in readable paths and preserve the fixed test bytes. The task starts with
the actual files/clean Git inventory, not a claimed success. No seed code or
synthetic test result grants acceptance.

Save the actual later Owner message as an immutable original file. Supply a
separate actual Owner Stage Authority and resource supplement. The Stage Authority
must instruct the real planning/selection roles to use the one approved Task,
scope, goal and fixed test; require original `approved-resources` and
`resource-supplement` authority refs in Task Intent and all necessary originals
downstream. Preserve the normal fresh Stage review, Decision plan/notice, actual
30-minute review window, Draft/Discussant/Final and necessary fresh checks.
Explicitly distinguish model-visible current native admission facts from the
post-prompt Host-only seal: the model must not pretend to read its own later seal.
Require actual native fixed-test receipt, report and original Promoter Result Gate.
Stop at COMMIT_AUTHORIZATION with Git false; do not complete Stage acceptance by
inventing Owner events. Normal Stage acceptance/60-minute closeout remains separate.

Use `config/agent_test_request.example.json` and
`config/agent_test_resource.example.json` as **invalid placeholder schemas**.
Replace every placeholder only from actual paths, hashes and later authorization.
`owner_source`, `stage_authority`, `resource_authorization`, `resource_supplement`
are distinct independently supplied pinned originals. The resource file is an
exact machine transcription of that later actual permission, not automatically
generated approval; preserve the original message next to it for human review.
Its fixed refs are `owner-original`, `resource-supplement`, `prepared-inputs`.
Select a finite window long enough for the normal30-minute wait (example upper
bounds12turns/240seconds/7200total seconds are suggestions, never a grant).
Use timezone-aware authorized/expiry timestamps; the helper never extends them.

Locate the actual unlinked Codex executable and pin raw bytes. Query its version
only under the approved environment. Confirm legitimate installed sign-in/model
availability through the allowed normal route, without reading/copying auth files
or entering passwords. Version support declarations are not proof of compatibility.
The product's current profiles must also be available on that authorized route;
otherwise stop rather than guess a provider/model or paid fallback. Update only
the new requested configuration after an appropriate compatibility decision.

## 4. Generate inert pins, review, then explicitly activate

```powershell
python -B "$candidateRoot\tools\agent_test_setup.py" --request 'C:\approved\Original Inputs\request.json' --target 'C:\approved\Generated Inputs inert'
```

This creates config/hashes/factory/binding only. It does not start a Host, write
Owner approval/relay attestation, open State, allocate spend or call Codex. Read
SETUP.json and every generated file. `authority_authenticated=false` is deliberate:
mechanical pins cannot authenticate a chat message. Inspect actual authorization.
Static bootstrap preflight:

```powershell
$setup = Get-Content 'C:\approved\Generated Inputs inert\SETUP.json' -Raw | ConvertFrom-Json
python -B "$candidateRoot\tools\loommode_bootstrap_preflight.py" --config $setup.config.path --sha256 $setup.config.sha256
```

The config path/hash are taken from the exact SETUP.json. It must say
read-only/static, not authentication/Task success. After actual later authorization
and review, generate **another new** active input directory with
`agent_test_setup.py --request <same-reviewed-request> --target <new-active-inputs>
--activate --owner-source-sha256 <exact-original-owner-sha256>`.
Never edit old pins in place. That explicit operator action selects an already
authorized route; it does not create permission. Do not run this step during A2.

Active generated factory calls `bootstrap.create_host` under the canonical original
Writer lease, then configures **`supervisor.host`** Caller/Relay/native hooks and
returns the same registered `SupervisorHost`. OneTaskCaller consumes every model
attempt durably before dispatch, seals native actual Prompt once, claims once,
checks the same-client strict `ordinaryUsageAllowed=true`/chatgpt route and current
Context/source/deadline. Ordinary role/report-correction calls consume separate
budget; native preparation and dispatch share one reservation. Failed/unknown
attempts remain consumed. An occupied accounting directory or missing/changed
event chain refuses restart; there is no replay/resume/refund tool here.

Immutable resource/preparation/source pins remain in Original/Generated Inputs.
Evolving `Runtime/one-task-accounting` is separate and never pinned as an immutable
startup source. The preparation manifest pins actual request/helper source; no
configuration/hash cycle or copied developer ledger is used.

## 5. Real foreground canonical run and actual notice relay (separate authorization)

A6 operating correction is included in this rc.3 package: for a one-Task test
without Git permission, select manual mode **before the sole START**. Do not
start automatically and try to switch modes later: the live selection is fixed.

First use the checkout entry's read-only preflight with the active binding:

```powershell
python -B "$candidateRoot\tools\loommode.py" --binding 'C:\approved\Generated Inputs active\canonical-binding.json' --op preflight
python -B "$candidateRoot\tools\loommode.py" --binding 'C:\approved\Generated Inputs active\canonical-binding.json' --op serve
```

Serve is foreground; keep its actual process alive. It may connect only under the
active later grant. In another approved terminal or same-live API client, query
status and retain the exact displayed `revision`. Submit canonical frame
`{"op":"start","scope":"current_stage","expected_revision":"<actual revision>","automatic":false}`
through `--frame <JSON>` with the same binding (serve default attaches to the original
owner when a frame is supplied). Stage scope permits normal planning; caller and
the single Task policy refuse another Task. Do not fabricate a current_task before
selection. Inspect actual status; do not infer progress from a label.

Manual START selects the live delegation but dispatches no activity by itself.
Submit exactly one `{"op":"advance"}` at a time. Each canonical event invokes
the original `Host.advance(1)`. Await joined completion with bounded canonical
`wait` frames and factual `status`; require no in-flight operation, the expected
completed operation/sequence with `worker_joined=true`, and inspect the resulting
node before deciding whether another advance is allowed. A wait timeout or an
unrelated update is not completion. Never queue an unbounded advance loop or
use `resume`/`run` in manual mode. Do not invoke Engine/finite Host directly while
the original Supervisor retains ownership.

Keep the normal Stage/Notice/relay checks below. During `SOFT_REVIEW_WAIT`, the
specified single advance captures/verifies the actual relay without model
dispatch. The real 1800-second timer must still expire naturally. In manual
mode that event records expiry but does not dispatch Task Selection; after
checking the actual event and current state, explicitly advance one step again.

After the joined `PROMOTER_RESULT_REVIEW`, read and hash-check its registered
`ACCEPTANCE` with `action=TASK_ACCEPTED`. When the resulting node is
`COMMIT_AUTHORIZATION` and `local_commit_authorized=false`, **submit no further
advance**. Read status and normal-close the original Host. This is a legal idle
stop: the business node remains `COMMIT_AUTHORIZATION`, State remains `RUNNING`,
delegation remains `PENDING`, and Host goes `WAITING` to `CLOSED`. It does not
claim `TASK_COMPLETE`, a Git checkpoint, Stage acceptance or Owner acceptance.
Normal close joins workers and releases the Writer lease; it does not authorize
loading that State to resume later.

The original Commit Gate remains mandatory. Explicitly advancing into it without
the grant is refused and can leave `FAILED/UNKNOWN_EFFECTS`; do not use that
failure as the intended stop. There is no public canonical frame that hot-grants
Git permission, and bootstrap refuses a true local-commit flag. Plan approval,
Owner notice acknowledgement, wait/advance and model text are not commit grants.
Future Git work requires its own actual authorization and supported trusted
mechanism; this guide grants neither commit nor closed-State recovery.

At the live `SOFT_REVIEW_WAIT`, **read the actual Notice/Plan/Decision originals and
relay them to the Owner through the currently authorized chat channel**. Do not
send messages elsewhere without permission. Save the actual local capture only
after that relay, using this exact JSON schema:

```json
{"origin":"CALLER_LOCAL_NOTICE_RELAY_CAPTURE","project":"<actual>","stage_id":"<actual>","task_id":"<approved>","workspace":"<absolute>","caller_id":"<actual>","notice_ref":"<actual original ref>","plan_ref":"<actual original ref>","decision_ref":"<actual original ref>","window":{},"relayed_at_utc":"<actual aware timestamp>","valid_until_utc":"<within actual resource expiry>","owner_notice_relayed":true,"owner_accepted":false}
```

`window` is the unchanged original Host window object (including monotonic deadline),
not `{}`. Hash the immutable capture and exclusively write
`Runtime/notice-relay-selection.json` containing exactly `{"path":"<capture>","sha256":"<raw SHA256>"}`.
The helper only reads this selection; it never creates a relay attestation.
**Writing the selection does not wake the event-driven Supervisor.** Before the
unchanged original deadline, submit the exact canonical frame `{"op":"advance"}`
to that same live owner, for example through
`tools/loommode.py --binding <active-binding> --frame '{"op":"advance"}'`.
This queues the original joined `Host.advance(1)` route: while SOFT_REVIEW_WAIT
is still open, it captures/verifies the relay and dispatches no model. Await
the joined completion using the bounded canonical wait frame
`{"op":"wait","after_cursor":<last displayed cursor>,"timeout":5}`, then inspect
the actual `HOST_CALLER_RELAY_VERIFICATION` registered receipt and unchanged
window/deadline. Do not keep submitting advance events or wait until expiry to
make the first capture. A missing/failed receipt is a blocker, not delivered notice.
The live Host must admit it before the original deadline. The normal window then
expires naturally; silence is no objection within prior scope, never approval.
Missing/late/forged/changed capture stops selection. Do not shorten clocks or
fabricate `owner_accepted=true`. Host local verification is not platform authentication.

Retain that same foreground Host throughout the real role chain. Inspect raw
Task Intent/Final, current Context-bound Caller/Relay/native facts, immutable
reservation/seal/claim, fixed TestSpec execution receipt, original execution
report and Promoter result. Require actual `TASK_ACCEPTED`/Task Result Gate and
inspect the stop at COMMIT_AUTHORIZATION; do not replace it with an agent claim,
static preflight, model text or test fixture success. No Git is authorized.

## 6. Close and hand back raw evidence

Use canonical `--op status`, `--op close` on the original binding while live; close
must join owned workers and release the original lease. If strict status fails,
retain the exact original endpoint and use the existing diagnostic/safe-close
operations; do not create another Host or reload State to inspect it. Preserve
unknown effects and report them. Do not kill unrelated processes or clean unknown
files. Accounting is not deleted after a live test; retain it with evidence.

Save a new external report with device/OS/Python/Git/Codex version and binary pin,
archive/manifest/source hashes, actual authorization references and scope/limits,
commands/exit status/raw stdout/stderr, ordinary versus injected/synthetic bounds,
fresh Stage/Task identities, exact original Gate/report/test refs, consumption and
cleanup proof. Report actual failure/unrun facts and money cost UNKNOWN when no
bill evidence exists. Only a test on this second physical computer establishes
cross-device evidence; same-machine extraction does not. Task completion and Owner
acceptance are separate decisions. Stop after handback; no public upload, formal
release, next Task, credentials transfer or automatic Git action.

Use TEST_REPORT_TEMPLATE.md and ISSUES_TEMPLATE.md. Return the actual approved
primary HOST_STAGE_FAILURE/UNKNOWN, State/Context and accounting/cleanup evidence,
not just paths/hashes; original records stay unchanged. Check for sensitive data
before export; state clearly when an export was redacted or re-encoded and give
separate original/export hashes. Avoid venv/pip/binary dumps. Preserve the requested
model/effort, returned Context values and explicit turn/start values separately:
Context metadata alone does not establish the turn's actual requested effort.
Actual auth_mode/catalog/provider/endpoint not captured must be labeled unknown;
do not read credentials, launch new discovery, add a key/provider or infer an
authentication failure from a timeout. The retained durable failure observations include
only fixed safe transport_timing fields (wait phase/effective deadline/elapsed
before diagnosis/start-sent/ack), without raw stderr/prompts/account output.

## Suggested next-device Owner instruction (placeholders, not authorization)

The Owner may adapt and explicitly send the following on the next device. Do not
treat the text in this package as already approved:

> I authorize the fresh Codex to verify this Apache-2.0 candidate and perform one
> Codex-only engineering test on this physical Windows device. Use new approved
> directories `<candidate>`, `<workspace>`, `<records>`, `<runtime>`, `<original
> inputs>`, `<generated inputs>`, `<evidence>` and short `<temporary root>`;
> preserve all existing data. Stage `<new cycle-A1>`, Task `<new cycle-A1-A1>`,
> caller `<new caller>`. Implement only `<answer.py>` under the precise approved
> goal, preserving `<test_answer.py>` and running the fixed `<absolute Python>
> -B test_answer.py` test with cwd workspace and timeout60. Use only my existing
> legitimate Codex subscription/sign-in, no new direct charge/provider/fallback.
> Suggested limits to explicitly confirm or replace: at most12 model turns,
> 240seconds per turn, 7200seconds total, fixed authorized/expiry UTC `<actual
> timestamps>` including normal windows. Relay the actual Stage Notice/Plan/
> Decision to me here before the original deadline, preserving owner_accepted=false
> unless I separately give an actual applicable acceptance event. Save raw
> original results/Gates/accounting and close owned processes/leases. No Git
> commit/merge/push, credentials transfer, shared ACL/registry change, publication,
> old-State replay, other project or further Task. Stop affected hard blockers or
> unknown effects and report truthfully; ordinary permitted local fixes may be
> handled autonomously. This is a new authorization only when I actually send
> and approve these filled values; the prior D1 authorization does not cover it.
