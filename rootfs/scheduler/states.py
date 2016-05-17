from enum import Enum, unique


class OrderedEnum(Enum):
    def __ge__(self, other):
        if self.__class__ is other.__class__:
            return self.value >= other.value

        return NotImplemented

    def __gt__(self, other):
        if self.__class__ is other.__class__:
            return self.value > other.value

        return NotImplemented

    def __le__(self, other):
        if self.__class__ is other.__class__:
            return self.value <= other.value

        return NotImplemented

    def __lt__(self, other):
        if self.__class__ is other.__class__:
            return self.value < other.value

        return NotImplemented


@unique
class PodState(OrderedEnum):
    initializing = 1
    creating = 2
    starting = 3
    up = 4
    terminating = 5
    down = 6
    destroyed = 7
    crashed = 8
    error = 9

    def __str__(self):
        """Return the name of the state"""
        return self.name
