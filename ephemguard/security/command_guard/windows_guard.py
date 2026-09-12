import re
import shlex
from .base import BaseCommandGuard, CommandInjectionError

class WindowsCommandGuard(BaseCommandGuard):
    """
    WindowsCommandGuard uses regex and tokenization to prevent command chaining,
    pipes, and powershell encoded commands.
    """
    
    # Matches common shell operators in cmd and powershell: &, |, ;, >, <
    # Also matches powershell's new line or multiple statements if passed in one string
    CHAINING_PATTERN = re.compile(r'[&|;<>\n]')
    
    # Matches powershell encoded command flags (case-insensitive)
    # -EncodedCommand, -enc, -ec, -en, etc.
    ENCODED_CMD_PATTERN = re.compile(r'(?i)-(?:e|en|enc|enco|encod|encode|encoded|encodedc|encodedco|encodedcom|encodedcomm|encodedcomma|encodedcomman|encodedcommand)\b')

    def check_command(self, command: str) -> bool:
        if not command.strip():
            raise CommandInjectionError("Empty command")

        # Check for command chaining or redirection
        if self.CHAINING_PATTERN.search(command):
            raise CommandInjectionError("Command chaining/redirection operators are not allowed")
            
        # Check for powershell encoded commands
        if self.ENCODED_CMD_PATTERN.search(command):
            raise CommandInjectionError("Encoded commands are not allowed")

        # We can use shlex to tokenize the command for the base executable check
        # shlex.split with posix=False works reasonably well for basic Windows tokenization
        try:
            tokens = shlex.split(command, posix=False)
        except ValueError as e:
            raise CommandInjectionError(f"Failed to parse command: {e}")
            
        if not tokens:
            raise CommandInjectionError("No valid command found")
            
        executable = tokens[0]
        # Remove quotes if they exist around the executable
        if executable.startswith('"') and executable.endswith('"'):
            executable = executable[1:-1]
        elif executable.startswith("'") and executable.endswith("'"):
            executable = executable[1:-1]
            
        # Optional: strip .exe extension for comparison if needed, but we'll do an exact match 
        # or require .exe in allowed_commands depending on configuration.
        # Here we just strictly match what is provided in allowed_commands.
        if executable not in self.allowed_commands:
            # Try appending .exe just in case it's in the allowed list
            if f"{executable}.exe" in self.allowed_commands:
                pass
            else:
                raise CommandInjectionError(f"Command '{executable}' is not allowed")
                
        return True
