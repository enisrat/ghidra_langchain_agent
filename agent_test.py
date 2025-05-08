
# Examples Agent
# @category: Examples.Python
# @runtime PyGhidra

import os
import sys

import re

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

from importlib import reload
reload(langgraph.prebuilt)

set_debug(True)

def allFuncs():
	allf = []
	f = getFirstFunction()
	while f:
		if f:
			allf.append(f)
		f = getFunctionAfter(f)
	return allf

def allFuncsXrefs():
	all = allFuncs()
	all_x = [(f, len( getReferencesTo(f.getEntryPoint())) ) for f in all]
	all_x.sort(key=lambda x: x[1], reverse=True)
	return all_x


def filter_pseudo_for_llm(pseudo):
	def repl_warnings(m):
		if "Subroutine does not return" in m[0]:
			return m[0]
		else:
			return ""

	pseudo = re.sub(r'\/\* WARNING\: .*\*\/', repl_warnings, pseudo, re.DOTALL|re.MULTILINE)
	return pseudo

llm = ChatOpenAI(model="llama3.3:24k", max_retries=5)


@tool
def rename_function(old_name: str, new_name: str):
	"""Rename a function"""
	print(f"rename_function: {old_name}, {new_name}")
	f = getFunction(old_name)
	f.setName(new_name, USER_DEFINED)

@tool
def decompile_function(func_name: str, config: RunnableConfig) -> str:
	"""Decompile a function"""
	print(f"decompile_function: {func_name}")
	pseudo = "Not available."
	try:
		num_lines = config["configurable"]["num_lines"]
		f = getFunction(func_name)
		pseudo = D.decompile(f)
		pseudo = filter_pseudo_for_llm(pseudo)
		lines = pseudo.split("\n")
		if len(lines) > num_lines:
			pseudo = "/** This function is too big and has been cut off **/\n"+ "\n".join(lines[:num_lines]) + "\n..."
	except:
		pseudo = "Error decompling function."
	return pseudo

@tool
def get_num_call_sites(func_name: str) -> int:
	"""Return the number of function call sites in the whole binary"""
	print(f"get_num_call_sites: {func_name}")
	f = getFunction(func_name)
	return len(getReferencesTo(f.getEntryPoint()))

@tool
def show_call_site(func_name: str, index: int) -> str:
	"""Print one call site of a function"""
	print(f"show_call_site: {func_name}")
	f = getFunction(func_name)
	refs = getReferencesTo(f.getEntryPoint())

	if not refs:
		return "No call sites found."

	r = refs[index]
	fp = getFunctionContaining(r.fromAddress)
	pseudo = D.decompile(fp)
	lines = pseudo.split("\n")
	# find lines matching func_name:
	matches = [i for i, line in enumerate(lines) if func_name in line]
	m = matches[0]
	return "\n".join(lines[max(0,m-5):m+5])

@tool
def comment_function(func_name: str, comment: str):
	"""Adds a comment above function code block. Should concisely explain the function's purpose. It helps the human reverse engineer or AI assistant to better understand the function later on"""
	print(f"comment_function: {func_name}")
	f = getFunction(func_name)
	setPlateComment(f.getEntryPoint(), comment)



f = getFunctionContaining(currentAddress)

tools = [rename_function, show_call_site, get_num_call_sites, comment_function, decompile_function]

system_message = f"You are a helpful assistant in software reverse engineering. Your job is to assist a human reverse engineer working with the software reverse engineering framework Ghidra in small tasks exactly as requested. You have access to tools that will for example get decompiled code from the binary. Please make use of the tools as you see fit. Do not ask the user to use these tools, they are intended for AI. Think step by step. Each step should be small and you should always state your reasoning. Make proper use of the range of tools to get more information. Use one tool call in each step and observe and analyze the output in the next step and so on. At last you can use rename_function and/or add a comment for better explanation. If after your reasoning you are still really unsure about a proper function name, rather not rename it and say so."

ARCH="AARCH64"
PROGRAM_DESC=f"I have to reverse engineer this binary program in {ARCH} architecture. It is part of a firmware and thus we know it has been written by system programmers."


# Construct the ReAct agent
agent = langgraph.prebuilt.create_react_agent(llm, tools, prompt=system_message, llama33_quirk=True, debug=True)

for (f, _) in allFuncsXrefs()[:20]:#[(getFunctionContaining(currentAddress),1)]:
	cfg = {"configurable": {"thread_id": f"thread-{f.name}"}, "num_lines" : 20}
	messages = agent.invoke({"messages": [("user", f"{PROGRAM_DESC} Now your task is to look at the following function and decide whether you know what it does and rename it accordingly. Output of \"decompile_function\" for \"{f.name}\": \n{D.decompile(f)}")]}, config=cfg)

	print(f"Final Answer: {messages["messages"][-1].content}")
