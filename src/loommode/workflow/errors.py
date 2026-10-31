class WorkflowError(ValueError):
    """Fail closed without retrying unknown side effects."""


class OutputProblem(WorkflowError):
    """A completed, known-effect turn needs material correction, never replay."""

    def __init__(self, reason, raw, context_ref, metadata=None):
        super().__init__(reason)
        self.raw, self.context_ref, self.metadata = raw, context_ref, metadata
