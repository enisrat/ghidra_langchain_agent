
# Examples Agent
# @category: Examples.Python
# @runtime PyGhidra

import os
import sys

from ghidra.program.flatapi import FlatProgramAPI
from ghidra.app.decompiler.flatapi import FlatDecompilerAPI
from ghidra.program.model.symbol.SourceType import USER_DEFINED

F = FlatProgramAPI(getCurrentProgram())
D = FlatDecompilerAPI(F)

print(f"current program name: {currentProgram.name}") # calls currentProgram.getName()

print(f"ENV: {os.environ}")

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


llm = ChatOpenAI(model="llama3.3:24k")


@tool
def rename_function(old_name: str, new_name: str):
	"""Rename a function. Please provide both @param old_name and @param new_name"""
	print(f"rename_function: {old_name}, {new_name}")
	f = getFunction(old_name)
	f.setName(new_name, USER_DEFINED)

@tool
def decompile_function(func_name: str, config: RunnableConfig) -> str:
	"""Decompile a function. Please provide @param func_name"""
	print(f"decompile_function: {func_name}")
	num_lines = config["configurable"]["num_lines"]
	f = getFunction(func_name)
	pseudo = D.decompile(f)
	lines = pseudo.split("\n")
	if len(lines) > num_lines:
		pseudo = "/** This function is too big and has been cut off **/\n"+ "\n".join(lines[:num_lines]) + "\n..."
	#print(pseudo)
	return pseudo

@tool
def get_num_call_sites(func_name: str) -> int:
	"""Return number of call sites to a function"""
	print(f"get_num_call_sites: {func_name}")
	f = getFunction(func_name)
	return len(getReferencesTo(f.getEntryPoint()))

@tool
def show_call_site(func_name: str, index: int) -> str:
	"""Print one call site of the function func_name"""
	print(f"show_call_site: {func_name}")
	f = getFunction(func_name)
	refs = getReferencesTo(f.getEntryPoint())

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
	"""Adds a comment above function code block. Should explain the function's purpose. It helps the human reverse engineer or AI assistant to better understand the function later on."""
	print(f"comment_function: {func_name}")
	f = getFunction(func_name)
	setPlateComment(f.getEntryPoint(), comment)



f = getFunctionContaining(currentAddress)

tools = [rename_function, show_call_site, get_num_call_sites, comment_function, decompile_function]

system_message = f"You are a helpful assistant in software reverse engineering. Your job is to assist the human reverse engineer in small tasks exactly as requested. A binary program in AARCH64 architecture is the target. This binary is part of a firmware for a mobile device and thus you know it has been written by system programmers. You have access to tools that will get decompiled from the binary. Please make use of the tools as you see fit. Do not ask the user to use these tools, they are intended for AI. Think step by step. Each step should be small and you should always state your reasoning. Make proper use of tools to get more information. If you use tool calls in a step then you observe and analyze the output in the next step and so on. At last you can use rename_function or add a comment for better explanation. If after your reasoning you are still really unsure about a proper function name, rather not rename it and say so."


# Construct the ReAct agent
agent = langgraph.prebuilt.create_react_agent(llm, tools, prompt=system_message, llama33_quirk=True)

for (f, _) in allFuncsXrefs()[:10]:#[(getFunctionContaining(currentAddress),1)]:
	cfg = {"configurable": {"thread_id": f"thread-{f.name}"}, "num_lines" : 20}
	messages = agent.invoke({"messages": [("user", f"Now your task is to look at the following function and decide whether you know what it does and rename it accordingly. Here is your target, the decompiled function \"{f.name}\": \n{D.decompile(f)}")]}, config=cfg)

	print(f"Final Answer: {messages["messages"][-1].content}")
