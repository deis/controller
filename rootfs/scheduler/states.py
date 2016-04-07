import enum


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
