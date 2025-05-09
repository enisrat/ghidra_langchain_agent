
# Examples Agent
# @category: Examples.Python
# @runtime PyGhidra

import os
import sys

import re

from ghidra_langchain_agent import react_agent, tools
from importlib import reload
reload(react_agent)
reload(tools)

from ghidra.program.flatapi import FlatProgramAPI
from ghidra.app.decompiler.flatapi import FlatDecompilerAPI
from ghidra.program.model.symbol.SourceType import USER_DEFINED

F = FlatProgramAPI(getCurrentProgram())
D = FlatDecompilerAPI(F)

print(f"Current program name: {currentProgram.name}") # calls currentProgram.getName()

print("ENV:")
for e in os.environ.keys():
	if "OPENAI" in e or "OLLAMA" in e or "LANGSMITH" in e:
		print(f"{e}={os.environ[e]}")

from langchain_core.prompts import ChatPromptTemplate
from langchain_core.output_parsers import StrOutputParser

from langchain_core.messages import HumanMessage, SystemMessage
from langchain_core.runnables import RunnableConfig
import langgraph.prebuilt
# Import things that are needed generically
from langchain.pydantic_v1 import BaseModel, Field
from langchain.tools import BaseTool, StructuredTool, tool

from langchain_openai import ChatOpenAI
from langchain_ollama.llms import OllamaLLM
from langchain.globals import set_debug

set_debug(True)


llm = ChatOpenAI(model="llama3.3:24k", max_retries=5)

tools = [tools.rename_function, 
		 tools.show_call_site, 
		 tools.get_num_call_sites, 
		 tools.comment_function, 
		 tools.decompile_function]

ARCH="AARCH64"
PROGRAM_DESC=f"I have to reverse engineer this binary program in {ARCH} architecture. It is part of a firmware and thus we know it has been written by system programmers."

# Construct the ReAct agent
agent = react_agent.create_react_agent( llm, 
										tools, 
										sysprompt=react_agent.SYSTEM_MESSAGE_FUNC_RENAMING,
										llama33_quirk=True,
										debug=False)

#funcs_to_rename = [f for (f, _) in allFuncsXrefs()[:20]]
funcs_to_rename = [getFunctionContaining(currentAddress)]

human_msg = react_agent.HUMAN_MESSAGE_FUNC_RENAMING.partial(PROGRAM_DESC=PROGRAM_DESC)
react_agent.invoke_on_functions(	agent, 
									funcs_to_rename,
									human_msg,
									configurables={'num_lines': 20},
									trace = True )
