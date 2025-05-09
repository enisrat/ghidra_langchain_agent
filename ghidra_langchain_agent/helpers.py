# Internal Helpers to workaround Ghidra internals not passed to imports

import functools
import builtins
from ghidra.program.util import GhidraProgramUtilities
from ghidra.framework.main import AppInfo
from ghidra.program.flatapi import FlatProgramAPI
from ghidra.app.decompiler.flatapi import FlatDecompilerAPI
from jpype import JClass, JImplementationFor
from typing import List

# to regain flat api etc... until Pyghidra makes this available for imported modules??
active_tool = AppInfo.getActiveProject().getToolManager().getRunningTools()[0] # assumes there is only one tool open!!
prog = GhidraProgramUtilities.getCurrentProgram(active_tool)

F = FlatProgramAPI(prog)
D = FlatDecompilerAPI(F)

# add methods of flat api to globals
for e in dir( F ):
	try:
		if not e.startswith('_') and '__call__' in dir( getattr(F,e) ):
			globals()[e] = getattr(F,e)
	except:
		pass

for e in dir( D ):
	try:
		if not e.startswith('_') and '__call__' in dir( getattr(D,e) ):
			globals()[e] = getattr(D,e)
	except:
		pass


# recover console printer
cs = active_tool.getService( JClass("ghidra.app.services.ConsoleService") )

def _build_script_print(stdout):
    @functools.wraps(print)
    def wrapper(*objects, sep=' ', end='\n', file=None, flush=False):
        # ensure we get the same behavior if the file is closed
        if file is None:
            file = stdout
            # since write will be used, it won't flush on a line ending
            # force it for stdout in a GhidraScript
            flush = flush or end == '\n'
        return builtins.print(*objects, sep=sep, end=end, file=file, flush=flush)
    return wrapper

ghidra_console_printer = cs.getStdOut()
print = _build_script_print( ghidra_console_printer )