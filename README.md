# ghidra_langchain_agent

- Simple ghidra agent examples using `langchain`, `langgraph`
- Uses mods from [https://github.com/enisrat/langgraph](https://github.com/enisrat/langgraph)

## Usage

- Copy or symlink all Python scripts (including `ghidra_langchain_agent` folder) into `~/ghidra_scripts/`
- From __Ghidra__ install directory, run `support/pyghidraRun`
- Find the `venv` used by Pyghidra and find the `python` binary inside (e.g. `~/.config/ghidra/ghidra_11.3.2_PUBLIC/venv/bin/python3.12`)
- Get pip into the venv (e.g. run `get-pip.py` with above binary ...)
- Run `.../venv/bin/python... -m pip install -r requirements.txt` to install `langchain`, `langgraph`, ... into the __venv__
