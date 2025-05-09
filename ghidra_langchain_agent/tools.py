# Langchain / Langgraph tools and wrappers for Ghidra

import re

from ghidra.program.flatapi import FlatProgramAPI
from ghidra.app.decompiler.flatapi import FlatDecompilerAPI
from ghidra.program.model.symbol.SourceType import USER_DEFINED

from .helpers import *

from langchain_core.runnables import RunnableConfig
# Import things that are needed generically
from langchain.pydantic_v1 import BaseModel, Field
from langchain.tools import BaseTool, StructuredTool, tool


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

@tool
def rename_function(old_name: str, new_name: str, c: RunnableConfig):
	"""Rename a function"""
	if c["configurable"].get("trace", False):
		print(f"rename_function: {old_name}, {new_name}")
	f = getFunction(old_name)
	f.setName(new_name, USER_DEFINED)

@tool
def decompile_function(func_name: str, c: RunnableConfig) -> str:
	"""Decompile a function"""
	if c["configurable"].get("trace", False):
		print(f"decompile_function: {func_name}")
	pseudo = "Not available."
	try:
		num_lines = c["configurable"].get("num_lines",20)
		f = getFunction(func_name)
		pseudo = decompile(f)
		pseudo = filter_pseudo_for_llm(pseudo)
		lines = pseudo.split("\n")
		if len(lines) > num_lines:
			pseudo = "/** This function is too big and has been cut off **/\n"+ "\n".join(lines[:num_lines]) + "\n..."
	except:
		pseudo = "Not available."
	return pseudo

@tool
def get_num_call_sites(func_name: str, c: RunnableConfig) -> int:
	"""Return the number of function call sites in the whole binary"""
	if c["configurable"].get("trace", False):
		print(f"get_num_call_sites: {func_name}")
	f = getFunction(func_name)
	return len(getReferencesTo(f.getEntryPoint()))

@tool
def show_call_site(func_name: str, index: int, c: RunnableConfig) -> str:
	"""Print one call site of a function"""
	if c["configurable"].get("trace", False):
		print(f"show_call_site: {func_name}")
	f = getFunction(func_name)
	refs = getReferencesTo(f.getEntryPoint())

	if not refs:
		return "No call sites found."

	r = refs[index]
	fp = getFunctionContaining(r.fromAddress)
	pseudo = decompile(fp)
	lines = pseudo.split("\n")
	# find lines matching func_name:
	matches = [i for i, line in enumerate(lines) if func_name in line]
	m = matches[0]
	return "\n".join(lines[max(0,m-5):m+5])

@tool
def comment_function(func_name: str, comment: str, c: RunnableConfig):
	"""Adds a comment above function code block. Should concisely explain the function's purpose. It helps the human reverse engineer or AI assistant to better understand the function later on"""
	if c["configurable"].get("trace", False):
		print(f"comment_function: {func_name}")
	f = getFunction(func_name)
	setPlateComment(f.getEntryPoint(), comment)

