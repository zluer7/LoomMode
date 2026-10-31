"""Windows ownership of one suspended Popen and its descendants, not a sandbox.

Uses documented Job Object accounting and ResumeThread. See docs/managed-cli.md.
The create/assign crash window remains a native-verification limitation.
"""
import ctypes
from ctypes import wintypes as w
import os
import subprocess
import time

from .process_stop import stop_owned_process


class JobError(OSError):
    pass


class _BasicLimit(ctypes.Structure):
    _fields_ = [("process_time", ctypes.c_longlong), ("job_time", ctypes.c_longlong), ("flags", w.DWORD),
                ("min_ws", ctypes.c_size_t), ("max_ws", ctypes.c_size_t), ("active_limit", w.DWORD),
                ("affinity", ctypes.c_size_t), ("priority", w.DWORD), ("scheduling", w.DWORD)]


class _Io(ctypes.Structure):
    _fields_ = [(name, ctypes.c_ulonglong) for name in ("read_ops", "write_ops", "other_ops", "read_bytes", "write_bytes", "other_bytes")]


class _ExtendedLimit(ctypes.Structure):
    _fields_ = [("basic", _BasicLimit), ("io", _Io), ("process_memory", ctypes.c_size_t),
                ("job_memory", ctypes.c_size_t), ("peak_process", ctypes.c_size_t), ("peak_job", ctypes.c_size_t)]


class _Accounting(ctypes.Structure):
    _fields_ = [(name, ctypes.c_longlong) for name in ("user", "kernel", "period_user", "period_kernel")] + [
        (name, w.DWORD) for name in ("faults", "total", "active", "terminated")]


class _ThreadEntry(ctypes.Structure):
    _fields_ = [("size", w.DWORD), ("usage", w.DWORD), ("tid", w.DWORD), ("pid", w.DWORD),
                ("base", w.LONG), ("delta", w.LONG), ("flags", w.DWORD)]


class OwnedJob:
    def __init__(self):
        if os.name != "nt":
            raise JobError("owned Windows Job support unavailable; no uncontrolled fallback")
        self.api = ctypes.WinDLL("kernel32", use_last_error=True)
        declarations = {
            "CreateJobObjectW": ([ctypes.c_void_p, w.LPCWSTR], w.HANDLE),
            "SetInformationJobObject": ([w.HANDLE, ctypes.c_int, ctypes.c_void_p, w.DWORD], w.BOOL),
            "QueryInformationJobObject": ([w.HANDLE, ctypes.c_int, ctypes.c_void_p, w.DWORD, ctypes.c_void_p], w.BOOL),
            "AssignProcessToJobObject": ([w.HANDLE, w.HANDLE], w.BOOL),
            "TerminateJobObject": ([w.HANDLE, w.UINT], w.BOOL),
            "CloseHandle": ([w.HANDLE], w.BOOL),
            "CreateToolhelp32Snapshot": ([w.DWORD, w.DWORD], w.HANDLE),
            "Thread32First": ([w.HANDLE, ctypes.POINTER(_ThreadEntry)], w.BOOL),
            "Thread32Next": ([w.HANDLE, ctypes.POINTER(_ThreadEntry)], w.BOOL),
            "OpenThread": ([w.DWORD, w.BOOL, w.DWORD], w.HANDLE),
            "ResumeThread": ([w.HANDLE], w.DWORD),
        }
        for name, (arguments, result) in declarations.items():
            function = getattr(self.api, name)
            function.argtypes, function.restype = arguments, result
        self.handle = None
        self.process = None
        self.assigned = False
        self.receipt = None
        self._handle_errors = []

    def launch(self, argv, *, cwd, env):
        try:
            # Allocate only after the caller owns this object, so even setup
            # failures retain a truthful handle-close receipt.
            self.handle = self.api.CreateJobObjectW(None, None)
            if not self.handle:
                raise JobError("CreateJobObject failed", ctypes.get_last_error())
            limits = _ExtendedLimit()
            limits.basic.flags = 0x2000  # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE; no breakaway.
            if not self.api.SetInformationJobObject(self.handle, 9, ctypes.byref(limits), ctypes.sizeof(limits)):
                raise JobError("SetInformationJobObject failed", ctypes.get_last_error())
            self.process = subprocess.Popen(argv, cwd=str(cwd), env=env, stdin=subprocess.PIPE,
                                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0,
                                            shell=False, close_fds=True,
                                            creationflags=subprocess.CREATE_NO_WINDOW | 0x4)  # CREATE_SUSPENDED
            if not self.api.AssignProcessToJobObject(self.handle, int(self.process._handle)):
                raise JobError("AssignProcessToJobObject failed", ctypes.get_last_error())
            self.assigned = True
            self._resume_initial_thread()
            return self.process
        except BaseException:
            self.stop()
            raise

    def _resume_initial_thread(self):
        snapshot = self.api.CreateToolhelp32Snapshot(0x4, 0)  # TH32CS_SNAPTHREAD
        if snapshot == ctypes.c_void_p(-1).value:
            raise JobError("thread snapshot failed", ctypes.get_last_error())
        thread = None
        try:
            entry = _ThreadEntry()
            entry.size = ctypes.sizeof(entry)
            tids = []
            more = self.api.Thread32First(snapshot, ctypes.byref(entry))
            while more:
                if entry.pid == self.process.pid:
                    tids.append(entry.tid)
                more = self.api.Thread32Next(snapshot, ctypes.byref(entry))
            if len(tids) != 1:
                raise JobError("suspended child initial thread ownership unproved")
            thread = self.api.OpenThread(0x2, False, tids[0])  # THREAD_SUSPEND_RESUME
            if not thread or self.api.ResumeThread(thread) != 1:
                raise JobError("resume initial thread failed", ctypes.get_last_error())
        finally:
            if thread and not self.api.CloseHandle(thread):
                self._handle_errors.append("initial thread handle close unproved")
            if not self.api.CloseHandle(snapshot):
                self._handle_errors.append("thread snapshot handle close unproved")

    def active_processes(self):
        info = _Accounting()
        if not self.handle or not self.api.QueryInformationJobObject(
                self.handle, 1, ctypes.byref(info), ctypes.sizeof(info), None):
            raise JobError("Job accounting unproved", ctypes.get_last_error())
        return info.active

    def stop(self, wait_seconds=2.0):
        if self.receipt is not None:
            return dict(self.receipt)
        receipt = {"pid": self.process.pid if self.process else None, "root_terminated": self.process is None,
                   "tree_terminated_confirmed": self.process is None, "job_handle_closed": not self.handle,
                   "unknown_side_effect": False, "ownership": "WINDOWS_JOB_NO_BREAKAWAY", "errors": list(self._handle_errors)}
        try:
            if self.process:
                if self.assigned:
                    if not self.api.TerminateJobObject(self.handle, 1):
                        raise JobError("TerminateJobObject failed", ctypes.get_last_error())
                    deadline = time.monotonic() + wait_seconds
                    while self.active_processes() and time.monotonic() < deadline:
                        time.sleep(.01)
                    receipt["tree_terminated_confirmed"] = self.active_processes() == 0
                    self.process.wait(timeout=wait_seconds)
                else:
                    # Initial thread was never resumed, therefore no descendants.
                    fallback = stop_owned_process(self.process, wait_seconds=wait_seconds)
                    receipt["tree_terminated_confirmed"] = fallback["root_terminated"]
                receipt["root_terminated"] = self.process.poll() is not None
        except (OSError, subprocess.TimeoutExpired) as exc:
            receipt["errors"].append(type(exc).__name__)
        finally:
            if self.handle:
                receipt["job_handle_closed"] = bool(self.api.CloseHandle(self.handle))
                self.handle = None
        receipt["unknown_side_effect"] = not all(receipt[key] for key in
            ("root_terminated", "tree_terminated_confirmed", "job_handle_closed")) or bool(receipt["errors"])
        self.receipt = receipt
        return dict(receipt)
