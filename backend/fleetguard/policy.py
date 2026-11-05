from __future__ import annotations


class PolicyError(Exception):
    def __init__(self, message: str, status: int = 400):
        super().__init__(message)
        self.message = message
        self.status = status


class AdapterUnavailable(PolicyError):
    def __init__(self, message: str):
        super().__init__(message, 501)
