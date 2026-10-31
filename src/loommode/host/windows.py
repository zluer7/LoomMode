"""Host-owned one-shot production timers; callbacks only enqueue authenticated facts."""
from __future__ import annotations

import copy
import json
import time
import math
from queue import Empty, Queue
from threading import Timer
from uuid import uuid4

from loommode.workflow.errors import WorkflowError
from loommode.workflow.transitions import Node, WINDOW_NODES


def _schedule(delay, callback):
    timer = Timer(delay, callback)
    timer.daemon = True
    timer.start()
    return timer


class SoftWindows:
    def __init__(self, host, *, clock=time.monotonic, scheduler=_schedule, test_durations=None):
        self.host, self.clock, self.scheduler = host, clock, scheduler
        self.durations = (1800.0, 3600.0) if test_durations is None else tuple(test_durations)
        if len(self.durations) != 2 or any(type(v) not in {int, float} or not math.isfinite(v) or v < 0 for v in self.durations):
            raise WorkflowError('explicit bounded test window durations required')
        self.run_id = 'T' + uuid4().hex
        self.epoch = 0
        self.current = None
        self.timer = None
        self.events = Queue()
        self.notify = None
        self.applied = set()

    def arm(self):
        engine, state = self.host.engine, self.host.engine.state
        node = Node(state.current_node)
        if node not in WINDOW_NODES or self.host.stop_requested:
            return
        guard = getattr(self.host, '_assert_input_effects_known', None)
        if guard:
            guard()
        ref = state.stage_notice_ref if node == Node.SOFT_REVIEW_WAIT else state.stage_closeout_ref
        engine.artifacts.read(ref)  # Persistence failure cannot create a window.
        if self.current and (self.current['stage_id'], self.current['notice_ref']) == (state.stage_id, ref):
            return
        self.cancel()
        duration = self.durations[0 if node == Node.SOFT_REVIEW_WAIT else 1]
        event = {'origin': 'HOST_SOFT_WINDOW_EXPIRY', 'run_id': self.run_id, 'stage_epoch': self.epoch,
                 'stage_id': state.stage_id, 'window_id': 'S' + uuid4().hex,
                 'notice_ref': ref, 'node': node.value, 'deadline': self.clock() + duration,
                 'duration_seconds': duration}
        receipt = engine.artifacts.save('DECISION', json.dumps({**event, 'origin': 'HOST_SOFT_WINDOW_ARM'}, ensure_ascii=False))
        engine.artifacts.read(receipt)
        self.current = event

        def enqueue():
            self.events.put(copy.deepcopy(event))
            if self.notify:
                self.notify()

        self.timer = self.scheduler(duration, enqueue)

    def consume(self):
        if self.host.stop_requested or self.host.engine._busy or self.host.engine.state.in_flight_activity:
            return False
        guard = getattr(self.host, '_assert_input_effects_known', None)
        if guard:
            guard()
        changed = False
        while True:
            try:
                event = self.events.get_nowait()
            except Empty:
                break
            if (event != self.current or event['window_id'] in self.applied
                    or event['stage_epoch'] != self.epoch or self.clock() < event['deadline']
                    or self.host.stop_requested):
                continue
            self.host.engine.soft_window_expired(event)
            self.applied.add(event['window_id'])
            self.cancel()
            changed = True
        return changed

    def cancel(self):
        if self.timer is not None:
            self.timer.cancel()
        self.timer = None
        self.current = None

    def next_stage(self):
        self.cancel()
        self.epoch += 1

    def close(self):
        self.cancel()
