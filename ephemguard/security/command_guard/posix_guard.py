import bashlex
from .base import BaseCommandGuard, CommandInjectionError

class PosixCommandGuard(BaseCommandGuard):
    """
    PosixCommandGuard uses bashlex to parse the command line and prevent
    command chaining, pipelines, and command substitution.
    """
    def check_command(self, command: str) -> bool:
        try:
            parts = bashlex.parse(command)
        except Exception as e:
            raise CommandInjectionError(f"Failed to parse command: {e}")

        if not parts:
            raise CommandInjectionError("Empty command")

        # We want to ensure there's exactly one command execution, no chaining
        command_nodes = []
        
        class Visitor(bashlex.ast.nodevisitor):
            def __init__(self):
                self.operators = []
                self.substitutions = []
                
            def visitoperator(self, n, *args, **kwargs):
                self.operators.append(n)
                
            def visitcommandsubstitution(self, n, *args, **kwargs):
                self.substitutions.append(n)
                
            def visitcommand(self, n, *args, **kwargs):
                command_nodes.append(n)

        visitor = Visitor()
        for ast_tree in parts:
            visitor.visit(ast_tree)

        if visitor.operators:
            raise CommandInjectionError("Command chaining/operators are not allowed")
            
        if visitor.substitutions:
            raise CommandInjectionError("Command substitution is not allowed")

        if not command_nodes:
            raise CommandInjectionError("No valid command found")
            
        if len(command_nodes) > 1:
            raise CommandInjectionError("Multiple commands are not allowed")
            
        cmd_node = command_nodes[0]
        # Find the first word which is the executable
        executable = None
        for part in cmd_node.parts:
            if part.kind == 'word':
                executable = part.word
                break
                
        if not executable:
            raise CommandInjectionError("Could not determine executable name")
            
        if executable not in self.allowed_commands:
            raise CommandInjectionError(f"Command '{executable}' is not allowed")
            
        return True
