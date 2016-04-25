import enum


class JobState(enum.Enum):
    initializing = 1
    creating = 2
    starting = 3
    up = 4
    terminating = 5
    down = 6
    destroyed = 7
    crashed = 8
    error = 9
