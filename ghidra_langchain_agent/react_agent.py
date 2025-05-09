
# Use Langgraph to create a new agent that can decompile functions and rename them

import re
import logging

import time
from langchain_core.prompts import PromptTemplate

from ghidra.program.flatapi import FlatProgramAPI
from ghidra.app.decompiler.flatapi import FlatDecompilerAPI
from ghidra.program.model.symbol.SourceType import USER_DEFINED

from .helpers import *

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

from .tools import *


# some prompt templates
SYSTEM_MESSAGE_FUNC_RENAMING ="You are a helpful assistant in software reverse engineering. Your job is to assist a human reverse engineer working with the software reverse engineering framework Ghidra in small tasks exactly as requested. You have access to tools that will for example get decompiled code from the binary. Please make use of the tools as you see fit. Do not ask the user to use these tools, they are intended for AI. Think step by step. Each step should be small and you should always state your reasoning. Make proper use of the range of tools to get more information. Use one tool call in each step and observe and analyze the output in the next step and so on. At last you can use rename_function and/or add a comment for better explanation. If after your reasoning you are still really unsure about a proper function name, rather not rename it and say so."

HUMAN_MESSAGE_FUNC_RENAMING = PromptTemplate.from_template("{PROGRAM_DESC} Now your task is to look at the following function and decide whether you know what it does and rename it accordingly. Output of \"decompile_function\" for \"{FUNC_NAME}\": \n{PSEUDO}")

PROGRAM_DESC_FIRMWARE="I have to reverse engineer this binary program in {ARCH} architecture. It is part of a firmware and thus we know it has been written by system programmers."


# Create a new agent
def create_react_agent(
		llm,
		tools,
		sysprompt=None,
		llama33_quirk=False,
		debug=False
	):
	logging.basicConfig(stream=ghidra_console_printer, encoding='utf-8', level=logging.DEBUG if debug else logging.WARNING)
	return langgraph.prebuilt.create_react_agent(llm, tools, prompt=sysprompt, llama33_quirk=llama33_quirk, debug=debug)

# Invoke the ReAct agent on an iterable of functions
# e.g.  allFuncsXrefs()[:20] or [(getFunctionContaining(currentAddress),1)]
def invoke_on_functions(agent, 
						functions,
						human_msg, 
						configurables={},
						trace = False):
	# Loop over all functions and invoke the ReAct agent on each one
	answers = {}
	for f in functions:
		threadid = f"{f.name}-{int(time.time())}"
		cfg = {"configurable": {"thread_id": f"{f.name}-{threadid}", "trace": trace}}
		cfg["configurable"].update(configurables)
		messages = agent.invoke({"messages": [("user", human_msg.format(FUNC_NAME=f.name, PSEUDO=decompile(f)))]}, config=cfg)
		answers[threadid] = {messages["messages"][-1].content}
		if trace:
			print(f"{threadid} final answer: {messages["messages"][-1].content}")

	return answers
