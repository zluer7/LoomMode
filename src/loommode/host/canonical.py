"""One foreground Decision/Supervisor, with authenticated same-live local attach."""
from __future__ import annotations

import argparse
import copy
import hashlib
import hmac
import importlib.util
import inspect
import json
import os
import re
import secrets
import socket
import sys
import time
from dataclasses import replace
from pathlib import Path
from threading import Event, Lock, Thread, current_thread

from loommode.workflow.errors import WorkflowError
from loommode.workflow.state import identity, unique_json_object
from .driver import DecisionHost
from .ownership import WorkspaceLease, _LEASES, _check_namespace, _unlinked, runtime_preflight, workspace_identity
from .requests import DelegationRequest, OwnerRequest, request_from_text
from .state_view import StatusSnapshot
from .supervisor import SupervisorHost

_LIVE = {}
_LIVE_LOCK = Lock()
_MAX_FRAME = 1024 * 1024
_SHA = re.compile(r"[0-9a-f]{64}")


def _json(raw):
    return json.loads(raw, object_pairs_hook=unique_json_object)


def validate_binding(value: dict) -> dict:
    """Explicit trusted startup configuration; identity checks confer no grants."""
    keys = {"schema_version", "project", "stage_id", "workspace", "stage_authorization_ref",
            "stage_authorization_sha256", "decision_role", "grants", "runtime", "factory"}
    if not isinstance(value, dict) or set(value) not in (keys, keys | {"implementation"}) or type(value["schema_version"]) is not int or value["schema_version"] != 1:
        raise WorkflowError("explicit canonical binding schema required")
    result = copy.deepcopy(value)
    identity(value["project"])
    identity(value["stage_id"])
    result["workspace"] = workspace_identity(value["workspace"])
    if "implementation" in value:
        from .implementation import implementation_options
        implementation_options(value["implementation"])
    if value["decision_role"] != "Decision":
        raise WorkflowError("canonical entry must be Decision, never an ordinary Worker")
    if (not isinstance(value["stage_authorization_ref"], str) or not value["stage_authorization_ref"].strip()
            or not isinstance(value["stage_authorization_sha256"], str) or not _SHA.fullmatch(value["stage_authorization_sha256"])):
        raise WorkflowError("explicit Stage authority identity required")
    grants = value["grants"]
    if (not isinstance(grants, dict) or set(grants) != {"allow_progress", "allow_owner_events", "local_commit_authorized"}
            or any(type(grant) is not bool for grant in grants.values())):
        raise WorkflowError("explicit existing boolean Host grants required")
    factory = value["factory"]
    if not isinstance(factory, dict) or set(factory) != {"path", "sha256"}:
        raise WorkflowError("explicit pinned factory identity required")
    path = Path(factory["path"]).resolve(strict=True)
    if path.suffix != ".py" or hashlib.sha256(path.read_bytes()).hexdigest() != factory["sha256"]:
        raise WorkflowError("factory identity changed/unverified; factory was not executed")
    result["factory"]["path"] = str(path)
    runtime = value["runtime"]
    if not isinstance(runtime, dict):
        raise WorkflowError("explicit development or version-bound runtime required")
    if runtime.get("kind") == "development" and set(runtime) == {"kind", "source_root", "approval_ref"}:
        root = Path(runtime["source_root"]).resolve(strict=True)
        if not root.is_dir() or not isinstance(runtime["approval_ref"], str) or not runtime["approval_ref"].strip():
            raise WorkflowError("explicit approved development source binding required")
        result["runtime"]["source_root"] = str(root)
        for name, module in tuple(sys.modules.items()):
            if name == "loommode" or name.startswith("loommode."):
                origin = getattr(module, "__file__", None)
                if not origin or not Path(origin).resolve().is_relative_to(root):
                    raise WorkflowError("development runtime origin differs from canonical binding")
    elif runtime.get("kind") == "version_bound" and set(runtime) == {"kind", "fingerprint"}:
        from loommode_binding import assert_runtime_origins, verify_binding
        lock = verify_binding(result["workspace"])
        if runtime["fingerprint"] != lock["fingerprint"]:
            raise WorkflowError("project version binding fingerprint mismatch")
        assert_runtime_origins(lock)
    else:
        raise WorkflowError("unsupported/unvalidated canonical runtime binding")
    return result


def _check_host(host, binding):
    if not isinstance(host, SupervisorHost):
        raise WorkflowError("canonical factory must return DecisionHost or SupervisorHost")
    decision, engine = host.host, host.host.engine
    snapshot = decision._bound_snapshot()
    active = host.active_stage_binding()
    initial = getattr(host, '_canonical_initial_binding', None)
    if initial is None:
        if active['stage_id'] != binding['stage_id']:
            raise WorkflowError('canonical initial Stage binding mismatch')
        host._canonical_initial_binding = copy.deepcopy(binding)
    elif initial != binding:
        raise WorkflowError('canonical root authority/factory binding changed')
    if active['stage_id'] != binding['stage_id']:
        if not active['registered_handoff']:
            raise WorkflowError('active Stage was not registered/authorized handoff')
        host._validate_binding()
    else:
        active = binding
    text = engine.authority.get(active["stage_authorization_ref"])
    if (snapshot.view["project"] != binding["project"] or snapshot.view["stage_id"] != active["stage_id"]
            or workspace_identity(snapshot.view["workspace"]) != binding["workspace"]
            or engine.state.stage_input_ref != active["stage_authorization_ref"]
            or not isinstance(text, str) or hashlib.sha256(text.encode("utf-8")).hexdigest() != active["stage_authorization_sha256"]
            or decision.entry.projection.authority.get(active["stage_authorization_ref"]) != text
            or host._grants() != binding["grants"]):
        raise WorkflowError("canonical Host project/workspace/Stage/authority/grants mismatch")
    decision._assert_input_effects_known()
    return snapshot


class CanonicalFactoryContext:
    """The already-held original lease and one explicitly registered owned Host.

    Version-1 factories register as soon as the DecisionHost is assembled. They
    remain responsible for resources created before that registration.
    """
    def __init__(self, binding, writer_lease):
        self.writer_lease = writer_lease
        self._binding = binding
        self.host = None
        self.foreign_host = None
        self._verify_lease()

    def _verify_lease(self):
        lease = self.writer_lease
        if (type(lease) is not WorkspaceLease or not lease.held
                or lease.workspace != self._binding["workspace"]
                or _LEASES.get(lease.workspace) is not lease
                or lease._stream is None or lease._stream.closed):
            raise WorkflowError("canonical factory requires its original retained Writer lease")

    def register_host(self, host, *, native_locations=None):
        self._verify_lease()
        if self.host is not None:
            raise WorkflowError("canonical factory may register only one Host")
        if isinstance(host, DecisionHost):
            host = SupervisorHost(host)
        if not isinstance(host, SupervisorHost):
            raise WorkflowError("canonical factory must return DecisionHost or SupervisorHost")
        engine, lease = host.host.engine, self.writer_lease
        retained = getattr(engine, "_workspace_writer_lease", None)
        if (retained not in (None, lease) or lease.owner not in (None, engine)
                or host._workspace_lease not in (None, lease)):
            self.foreign_host = host
            raise WorkflowError("factory Host already has different Writer ownership")
        self.host = host  # Failure after this point has an owned cleanup target.
        if workspace_identity(host.entry.projection.workspace) != lease.workspace:
            raise WorkflowError("factory Host workspace differs from retained Writer lease")
        lease.owner = engine
        engine._workspace_writer_lease = lease
        host._workspace_lease = lease
        host._external_workspace_lease = True
        if "implementation" in self._binding:
            from .implementation import configure_implementation
            configure_implementation(host.host, lease, self._binding["implementation"], native_locations=native_locations)
        elif native_locations is not None:
            raise WorkflowError('trusted Native locations require explicit implementation selection')
        return host


def _load_factory(binding, context):
    path = Path(binding["factory"]["path"])
    # Recheck immediately before import; ownership has already been acquired.
    if hashlib.sha256(path.read_bytes()).hexdigest() != binding["factory"]["sha256"]:
        raise WorkflowError("factory bytes changed before import")
    name = "loommode_canonical_factory_" + secrets.token_hex(16)
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
        factory = module.create_host
        api = getattr(module, "CANONICAL_FACTORY_API", 0)
        if type(api) is not int or api not in (0, 1):
            raise WorkflowError("unsupported canonical factory API")
        if api == 0:
            # Preserve explicit legacy no-argument factories. Do not catch their
            # internal TypeError and retry a constructor with different inputs.
            inspect.signature(factory).bind()
            return factory()
        inspect.signature(factory).bind(canonical_context=context)
        host = factory(canonical_context=context)
        if context.host is None or host is not context.host:
            raise WorkflowError("version-1 factory must return its registered canonical Host")
        return host
    finally:
        sys.modules.pop(name, None)


def _metadata(path, binding=None):
    _unlinked(path)
    if not path.is_file() or path.stat().st_size > 65536:
        raise WorkflowError("unknown endpoint metadata; preserve it")
    value = _json(path.read_text(encoding="utf-8"))
    if (not isinstance(value, dict) or set(value) != {"format", "binding", "run_id", "host", "port", "token"}
            or value["format"] != "LOOMMODE_LOCAL_ENDPOINT_V1" or value["host"] != "127.0.0.1"
            or type(value["port"]) is not int or not 1 <= value["port"] <= 65535
            or not isinstance(value["token"], str) or not _SHA.fullmatch(value["token"])
            or not isinstance(value["binding"], dict)):
        raise WorkflowError("unknown/malformed endpoint metadata; preserve it")
    identity(value["run_id"])
    if binding is not None and value["binding"] != binding:
        raise WorkflowError("existing owner binding/factory mismatch; factory was not executed")
    return value


def _read_line(stream):
    line = stream.readline(_MAX_FRAME + 1)
    if not line or len(line) > _MAX_FRAME or not line.endswith(b"\n"):
        raise WorkflowError("missing/oversized local IPC frame")
    return _json(line)


class CanonicalClient:
    """A client disconnect is never Host close. Reuse retains the original Host."""
    def __init__(self, metadata, *, owner=None, created=False):
        self.metadata = metadata
        self.owner = owner
        self.created = created
        self.supervisor = owner.supervisor if owner is not None else None

    def request(self, frame):
        if self.owner is not None:
            value = self.owner.request(frame)
        else:
            nonce = secrets.token_hex(16)
            request = {"token": self.metadata["token"], "binding": self.metadata["binding"],
                       "run_id": self.metadata["run_id"], "nonce": nonce, "frame": frame}
            with socket.create_connection((self.metadata["host"], self.metadata["port"]), timeout=10) as connection:
                with connection.makefile("rwb") as stream:
                    stream.write(json.dumps(request, ensure_ascii=False, allow_nan=False).encode("utf-8") + b"\n")
                    stream.flush()
                    response = _read_line(stream)
            if (not isinstance(response, dict) or response.get("nonce") != nonce
                    or response.get("run_id") != self.metadata["run_id"] or response.get("binding") != self.metadata["binding"]):
                raise WorkflowError("local live ownership handshake failed")
            if response.get("error"):
                raise WorkflowError(response["error"])
            value = response["value"]
        if "canonical_entry" in value:
            value["canonical_entry"]["attachment"] = "CREATED" if self.created else "EXISTING"
        return value

    def status(self):
        return self.request({"op": "status"})

    def disconnect(self):
        """No owned process, worker or endpoint is closed by a client exit."""


class CanonicalHost:
    def __init__(self, supervisor, binding, lease):
        self.supervisor, self.binding, self.lease = supervisor, binding, lease
        self._rpc_lock = Lock()
        self._stop = Event()
        self._closed = Event()
        self._cleanup_error = None
        self._listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self._listener.bind(("127.0.0.1", 0))
            self._listener.listen(8)
        except BaseException:
            self._listener.close()
            raise
        self.metadata = {"format": "LOOMMODE_LOCAL_ENDPOINT_V1", "binding": binding,
                         "run_id": supervisor.run_id, "host": "127.0.0.1",
                         "port": self._listener.getsockname()[1], "token": secrets.token_hex(32)}
        self._path = lease.directory / "endpoint.json"
        self._thread = Thread(target=self._serve, name="loommode-local-entry-" + supervisor.run_id)

    def start(self):
        temporary = self._path.with_name(".endpoint." + self.metadata["token"] + ".tmp")
        try:
            with temporary.open("x", encoding="utf-8") as stream:
                os.chmod(temporary, 0o600)
                json.dump(self.metadata, stream, ensure_ascii=False, allow_nan=False)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, self._path)
            self._thread.start()
        finally:
            if temporary.exists():
                temporary.unlink()

    def status(self):
        value = self.supervisor.status()
        value["canonical_entry"] = {"identity": "Decision", "supervisor_run_id": self.supervisor.run_id,
            'active_stage_id': self.supervisor.host.engine.state.stage_id,
            "binding_status": "VALIDATED", "runtime_binding": copy.deepcopy(self.binding["runtime"]),
            "workspace": self.binding["workspace"], "lease_status": "HELD" if self.lease.held else "RELEASED",
            "current_writer": {"run_id": self.supervisor.run_id, "engine_in_flight": self.supervisor.host.engine.state.in_flight_activity}
                              if self.lease.held else None,
            "unavailable_reason": "CLOSED" if self._stop.is_set() else None,
            "resume_boundary": "SAME_LIVE_HOST_ONLY", "permissions_expanded": False}
        return value

    def diagnostic(self):
        """Fixed vocabulary only. Does not query business materials or bypass effects gates."""
        supervisor, engine = self.supervisor, self.supervisor.host.engine
        from loommode.workflow.transitions import Node
        with supervisor._condition:
            state = engine.state
            failure = supervisor._failure
            node = state.current_node if state.current_node in {n.value for n in Node} else 'UNKNOWN'
            operation = supervisor._operation
            worker = operation.thread if operation else None
            loop = supervisor._thread
            return {'status': 'SAFE_DIAGNOSTIC', 'run_id': supervisor.run_id,
                    'node': node, 'failed': node == 'FAILED' or failure is not None,
                    'activity_in_flight': bool(state.in_flight_activity),
                    'worker_alive': bool(worker and worker.is_alive()),
                    'supervisor_alive': bool(loop and loop.is_alive()),
                    'writer_held': self.lease.held,
                    'workers_started': supervisor._started_workers,
                    'workers_joined': supervisor._joined_workers,
                    'reason': 'FAILED_ACTIVITY' if node == 'FAILED' else 'HOST_FAILURE' if failure else 'NONE',
                    'failure_sha256': hashlib.sha256(str(failure).encode()).hexdigest() if failure else None,
                    'cleanup_proved': not self.lease.held and self._cleanup_error is None,
                    'business_recovery_authorized': False}

    def request(self, frame):
        with self._rpc_lock:
            if self._stop.is_set():
                raise WorkflowError("canonical Host is closed; no replay")
            if not isinstance(frame, dict):
                raise WorkflowError("canonical Owner frame must be an object")
            host, decision = self.supervisor, self.supervisor.host
            # Authenticated urgent stop has no grants/effects beyond fencing.
            # It must survive stale display or changed current evidence.
            if set(frame) == {'request'} and isinstance(frame['request'], dict) and frame['request'].get('kind') == 'GATE' and frame['request'].get('event') in {'PAUSE', 'OBJECT'}:
                fields = dict(frame['request'])
                for key in ('evidence_refs', 'check_focus'):
                    if key in fields:
                        fields[key] = tuple(fields[key])
                return host.pause_owner(OwnerRequest(**fields))
            if {'text'} <= set(frame) <= {'text', 'expected_revision'}:
                from .requests import urgent_stop_from_text
                state = decision.engine.state
                request = urgent_stop_from_text(frame['text'], project=state.project, stage_id=state.stage_id,
                                               task_id=state.task_id, expected_revision=frame.get('expected_revision'))
                if request is not None:
                    return host.pause_owner(request)
            if set(frame) == {"op"} and frame["op"] == "close":
                host.close()  # Fence and actual worker/loop join precede lease release.
                self._stop.set()
                self._wake()
                self._listener.close()
                self._finish()
                if self._cleanup_error:
                    raise WorkflowError("canonical cleanup failed; lease retained: " + self._cleanup_error)
                return self.status()
            if frame == {'op': 'diagnostic'}:
                return self.diagnostic()
            if frame == {'op': 'safe-close'}:
                host.close(diagnostic_only=True)
                self._stop.set()
                self._wake()
                self._listener.close()
                self._finish()
                if self._cleanup_error:
                    raise WorkflowError('canonical safety cleanup unproved; lease retained')
                return self.diagnostic()
            _check_host(self.supervisor, self.binding)
            if set(frame) == {"op"} and frame["op"] in {"status", "query"}:
                return self.status()
            snapshot = decision.entry.query()
            if {"op", "scope", "expected_revision"} <= set(frame) <= {"op", "scope", "expected_revision", "request_id", "automatic", "series_id", "series_plan_ref", 'scope_id', 'authority_ref', 'authority_sha256'} and frame["op"] == "start":
                if frame["expected_revision"] != snapshot.revision:
                    raise WorkflowError("delegation targets stale displayed facts; query before selecting scope")
                request = DelegationRequest.from_frame(snapshot, frame)
                value = host.start(request, automatic=frame.get("automatic", False),
                                   series_id=frame.get("series_id"), series_plan_ref=frame.get("series_plan_ref"))
            elif set(frame) == {"op"} and frame["op"] == "advance":
                value = host.submit(host.event())
            elif set(frame) == {"op"} and frame["op"] in {"resume", "run"}:
                value = host.resume()
            elif set(frame) == {"op"} and frame["op"] == "renew":
                value = host.request_renewal()
            elif set(frame) <= {"op", "after_cursor", "timeout"} and frame.get("op") == "wait":
                timeout = frame.get("timeout", 5)
                if type(timeout) not in {int, float} or not 0 <= timeout <= 5:
                    raise WorkflowError("IPC update wait must be bounded to 0..5 seconds")
                value = host.wait_for_update(frame.get("after_cursor", 0), timeout)
            elif {"text"} <= set(frame) <= {"text", "expected_revision"}:
                request = request_from_text(frame["text"], snapshot)
                if request is None:
                    raise WorkflowError("explicit canonical Owner request required")
                if request.kind in {"GATE", "CHECK", "DIRECTION"}:
                    request = replace(request, expected_revision=frame.get("expected_revision"))
                value = self._owner_request(request)
            elif set(frame) == {"request"} and isinstance(frame["request"], dict):
                fields = dict(frame["request"])
                for key in ("evidence_refs", "check_focus"):
                    if key in fields:
                        if not isinstance(fields[key], list):
                            raise WorkflowError("Owner references/focus must be arrays")
                        fields[key] = tuple(fields[key])
                value = self._owner_request(OwnerRequest(**fields))
            else:
                raise WorkflowError("unsupported canonical Owner frame")
            value["canonical_entry"] = self.status()["canonical_entry"]
            return value

    def _owner_request(self, request):
        if request.kind in {"STATUS", "ARTIFACT"}:
            return self.supervisor.host.handle(request)
        if self.supervisor._selection is None:
            return self.supervisor.host.handle(request)
        return self.supervisor.submit(self.supervisor.event(kind="OWNER", owner_request=request))

    def _wake(self):
        try:
            self._listener.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass

    def _serve(self):
        try:
            while not self._stop.is_set():
                try:
                    connection, _ = self._listener.accept()
                except OSError:
                    if self._stop.is_set():
                        break
                    raise
                with connection:
                    connection.settimeout(10)
                    with connection.makefile("rwb") as stream:
                        response = {}
                        authenticated = False
                        request = None  # Connection-local; malformed frames cannot reuse prior authentication.
                        try:
                            request = _read_line(stream)
                            if (not isinstance(request, dict) or set(request) != {"token", "binding", "run_id", "nonce", "frame"}
                                    or not isinstance(request["token"], str)
                                    or not hmac.compare_digest(request["token"], self.metadata["token"])
                                    or request["binding"] != self.binding or request["run_id"] != self.supervisor.run_id
                                    or not isinstance(request["nonce"], str) or len(request["nonce"]) != 32
                                    or set(request["nonce"]) - set('0123456789abcdef')):
                                raise WorkflowError("unauthenticated/mismatched local client")
                            authenticated = True
                            response = {"binding": self.binding, "run_id": self.supervisor.run_id, "nonce": request["nonce"]}
                            response["value"] = self.request(request["frame"])
                        except (WorkflowError, OSError, ValueError, TypeError, KeyError, RecursionError) as exc:
                            if isinstance(request,dict) and request.get('frame') in ({'op':'diagnostic'},{'op':'safe-close'}):
                                response['error']='canonical safety request refused'
                                response['error_code']='SAFETY_REQUEST_REFUSED'
                                response['error_sha256']=hashlib.sha256(str(exc).encode()).hexdigest()
                            elif authenticated:
                                response['error'] = str(exc)
                            else:
                                response['error'] = 'canonical request refused'
                                response['error_sha256'] = hashlib.sha256(str(exc).encode()).hexdigest()
                        try:
                            stream.write(json.dumps(response, ensure_ascii=False, allow_nan=False).encode("utf-8") + b"\n")
                            stream.flush()
                        except OSError:
                            pass  # A disconnected client owns no Host resources.
        finally:
            self._stop.set()
            self._listener.close()
            self._finish()
            self._closed.set()

    def _finish(self):
        if not self.lease.held:
            return
        try:
            self.supervisor.close(diagnostic_only=True)
            with self.supervisor._condition:
                loop = self.supervisor._thread
                if (loop is not None and loop.is_alive()) or self.supervisor._operation is not None:
                    raise WorkflowError("owned worker/loop join is unproved; workspace lease retained")
        except Exception as exc:
            self._cleanup_error = str(exc)
            return  # Actual join failure must never release a competing-writer lease.
        try:
            if self._path.exists() and _metadata(self._path) == self.metadata:
                self._path.unlink()  # Only our exact endpoint, while the lease is held.
        except (WorkflowError, OSError, ValueError, TypeError):
            pass  # Preserve changed/unknown metadata; never infer ownership.
        self.lease.release()
        if getattr(self.supervisor.host.engine, "_workspace_writer_lease", None) is self.lease:
            del self.supervisor.host.engine._workspace_writer_lease
        with _LIVE_LOCK:
            if _LIVE.get(self.binding["workspace"]) is self:
                _LIVE.pop(self.binding["workspace"])
        self._cleanup_error = None

    def close(self):
        if self._thread.ident is None:
            self._stop.set()
            self._wake()
            self._listener.close()
            self._finish()
            self._closed.set()
        elif not self._stop.is_set():
            self.request({"op": "close"})
        if self._thread.ident is not None and current_thread() is not self._thread:
            self._thread.join()
        if self._cleanup_error:
            self._finish()  # Explicit owned close retry, never worker replay.
        if self._cleanup_error:
            raise WorkflowError("canonical cleanup failed; lease retained: " + self._cleanup_error)

    def wait_closed(self):
        self._closed.wait()
        self._thread.join()
        if self._cleanup_error:
            raise WorkflowError("canonical cleanup failed; lease retained: " + self._cleanup_error)


def attach_canonical(binding: dict, endpoint, *, safety_only=False) -> CanonicalClient:
    """Pure authenticated client; explicit original endpoint never selects a runtime root."""
    binding = validate_binding(binding)
    path = Path(endpoint)
    if (not path.is_absolute() or path.name != "endpoint.json"
            or path.parent.name != hashlib.sha256(binding["workspace"].encode("utf-8")).hexdigest()):
        raise WorkflowError("explicit original workspace endpoint path required")
    _check_namespace(path)
    client = CanonicalClient(_metadata(path, binding))
    if type(safety_only) is not bool:
        raise WorkflowError('explicit safety attach flag required')
    held = client.request({'op':'diagnostic'})['writer_held'] if safety_only else client.status()['canonical_entry']['lease_status'] == 'HELD'
    if not held:
        raise WorkflowError("original live owner is unavailable; no replay")
    return client


def open_canonical(binding: dict, *, attach_only=False) -> CanonicalClient:
    binding = validate_binding(binding)
    runtime_preflight(binding["workspace"])  # No runtime writes/factory on wrong identity.
    lease = WorkspaceLease(binding["workspace"])
    if not lease.acquire():
        with _LIVE_LOCK:
            owner = _LIVE.get(binding["workspace"])
        if owner is not None:
            if owner.binding != binding:
                raise WorkflowError("existing owner binding/factory mismatch; factory was not executed")
            client = CanonicalClient(owner.metadata, owner=owner)
        else:
            path = lease.directory / "endpoint.json"
            # Startup publication race only; no process/PID inference or model polling.
            for _ in range(60):
                if path.exists():
                    break
                time.sleep(0.05)
            if not path.exists():
                raise WorkflowError("workspace has a live/unknown writer with no verified endpoint; factory was not executed")
            client = CanonicalClient(_metadata(path, binding))
        status = client.status()  # Authentication + live run identity, never PID/mtime.
        if status["canonical_entry"]["lease_status"] != "HELD":
            raise WorkflowError("original live owner is unavailable; no replay")
        return client
    host = owner = None
    context = CanonicalFactoryContext(binding, lease)
    try:
        path = lease.directory / "endpoint.json"
        if path.exists():
            _metadata(path, binding)  # Only proved owned, inactive metadata is reclaimable.
        if attach_only:
            raise WorkflowError("no live canonical Host; explicit foreground serve is required")
        host = _load_factory(binding, context)  # Ownership PRECEDES Engine/Adapter creation.
        if context.host is None:
            if isinstance(host, DecisionHost):
                host = SupervisorHost(host)
            host = context.register_host(host)
        elif host is not context.host:
            raise WorkflowError("factory returned a different Host than it registered")
        _check_host(host, binding)
        if host._selection is not None or getattr(host.host.engine, "_managed_host_owner", None) is not None:
            raise WorkflowError("factory must supply an unstarted live Host; saved managed runs cannot resume")
        if host.host.engine._busy or host.host.engine.state.in_flight_activity:
            raise WorkflowError("busy/unknown-effect factory Host cannot become canonical; no replay")
        owner = CanonicalHost(host, binding, lease)
        with _LIVE_LOCK:
            _LIVE[binding["workspace"]] = owner
        owner.start()
        return CanonicalClient(owner.metadata, owner=owner, created=True)
    except BaseException:
        if owner is not None:
            owner.close()
        else:
            host = context.host or host
            if isinstance(host, SupervisorHost) and host is not context.foreign_host:
                try:
                    host.close()
                    with host._condition:
                        if (host._thread is not None and host._thread.is_alive()) or host._operation is not None:
                            raise WorkflowError("owned worker/loop join is unproved")
                except BaseException as exc:
                    raise WorkflowError("factory cleanup unproved; Writer lease retained: " + str(exc)) from exc
                if getattr(host.host.engine, "_workspace_writer_lease", None) is lease:
                    del host.host.engine._workspace_writer_lease
            lease.release()
        raise


def main(argv=None):
    parser = argparse.ArgumentParser(description="Canonical Decision entry: foreground serve or same-live attach.")
    parser.add_argument("--binding", type=Path, required=True)
    parser.add_argument("--op", choices=("preflight", "serve", "status", "query", "close", "diagnostic", "safe-close"), default="serve")
    parser.add_argument("--frame", help="Explicit existing Owner JSON frame; attaches without constructing a Host.")
    parser.add_argument("--endpoint", type=Path,
                        help="Explicit original Host endpoint for pure authenticated attach; never creates a Host.")
    args = parser.parse_args(argv)
    client = None
    try:
        binding = _json(args.binding.read_text(encoding="utf-8"))
        if args.endpoint is not None and (args.op == "preflight" or (args.op == "serve" and args.frame is None)):
            raise WorkflowError("explicit endpoint permits only client operations; serve/preflight are forbidden")
        if args.op == "preflight":
            if args.frame is not None:
                raise WorkflowError("preflight does not accept an Owner frame")
            binding = validate_binding(binding)
            facts = runtime_preflight(binding["workspace"])
            print(json.dumps({"status": "PREFLIGHT_READ_ONLY", **facts,
                  "python": str(Path(sys.executable).resolve()), "runtime_binding": binding["runtime"],
                  "factory": binding["factory"]}, ensure_ascii=False), flush=True)
            return 0
        safety = args.op in {'diagnostic','safe-close'}
        if safety and (args.endpoint is None or args.frame is not None):
            raise WorkflowError('safety operations require explicit original endpoint and fixed frame')
        client = (attach_canonical(binding, args.endpoint, safety_only=safety) if args.endpoint is not None else
                  open_canonical(binding, attach_only=args.op != "serve" or args.frame is not None))
        frame = _json(args.frame) if args.frame is not None else {"op": "status" if args.op == "serve" else args.op}
        print(json.dumps(client.request(frame), ensure_ascii=False, allow_nan=False), flush=True)
        if client.created:
            client.owner.wait_closed()  # Foreground Host only, no daemon/service/replay.
        return 0
    except Exception as exc:
        if args.op in {'diagnostic','safe-close'}:
            print(json.dumps({'status':'UNAVAILABLE','reason':'SAFETY_REQUEST_REFUSED',
                              'error_sha256':hashlib.sha256(str(exc).encode()).hexdigest()}),flush=True)
        else:
            print(json.dumps({"status": "UNAVAILABLE", "canonical_entry": {"identity": "Decision", "binding_status": "UNAVAILABLE",
                  "unavailable_reason": str(exc), "permissions_expanded": False}, "error": str(exc)}, ensure_ascii=False), flush=True)
        return 2
    except KeyboardInterrupt:
        return 130
    finally:
        if client is not None:
            if client.created:
                client.owner.close()
            client.disconnect()
