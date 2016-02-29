import enum


class TransitionError(Exception):
    """Raised when a transition from one state to another is illegal"""

    def __init__(self, prev, next, msg):
        self.prev = prev
        self.next = next
        self.msg = msg


class JobState(enum.Enum):
    initialized = 1
    created = 2
    starting = 3
    up = 4
    terminating = 5
    down = 6
    destroyed = 7
    crashed = 8
    error = 9
