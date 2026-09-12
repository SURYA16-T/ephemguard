from abc import ABC, abstractmethod
from typing import List

class CommandInjectionError(Exception):
    """Raised when a command injection attempt is detected."""
    pass

class BaseCommandGuard(ABC):
    """
    Abstract base class for command guards.
    """
    def __init__(self, allowed_commands: List[str]):
        """
        :param allowed_commands: A list of base command executables that are allowed.
        """
        self.allowed_commands = allowed_commands

    @abstractmethod
    def check_command(self, command: str) -> bool:
        """
        Parses and verifies a command string.
        Raises CommandInjectionError if malicious chaining or unallowed commands are found.
        Returns True if safe.
        """
        pass
