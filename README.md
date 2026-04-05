[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0)
[![GitHub stars](https://img.shields.io/github/stars/Indspl0it/GhidraMCP)](https://github.com/Indspl0it/GhidraMCP/stargazers)

# GhidraMCP

A Model Context Protocol (MCP) server that exposes Ghidra's reverse engineering capabilities to LLMs. Enables AI-assisted binary analysis, decompilation, and annotation through any MCP client.

Forked from [LaurieWired/GhidraMCP](https://github.com/LaurieWired/GhidraMCP) with additional features, bug fixes, and headless mode support.

## Features

### Analysis
- Decompile functions by name or address (sync and async)
- Disassemble functions to assembly
- List functions, classes, imports, exports, namespaces, strings, and data items
- Search functions by name
- Get cross-references (to, from, and by function name)
- Get function call graphs (callers and callees)
- Search memory for byte patterns
- Read raw bytes at any address
- Get program metadata (architecture, compiler, format, SHA256, memory layout)

### Annotation
- Rename functions, variables, and data labels
- Set decompiler (pre), disassembly (EOL), and plate comments
- Set function prototypes and local variable types
- Create labels at addresses

### Data Types
- List, search, and browse available data types
- Create enums and structs
- Define data at addresses
- Apply structs to memory locations
- Clear defined data

### Headless Mode
- Run without Ghidra GUI via `analyzeHeadless`
- Full API parity (except GUI cursor-dependent endpoints)
- Ideal for servers, CI/CD pipelines, and remote access

## Installation

### Prerequisites
- [Ghidra](https://ghidra-sre.org) 12.0.x+
- Java 21+
- Python 3.10+

### Option 1: GUI Plugin

1. Download the latest release ZIP or [build from source](#building-from-source)
2. Open Ghidra
3. `File` -> `Install Extensions` -> click `+` -> select the ZIP
4. Restart Ghidra
5. Open a program in the CodeBrowser
6. Enable the plugin: `File` -> `Configure` -> `Developer` -> check `GhidraMCPPlugin`
7. The HTTP server starts automatically on port 8080

Optional: change the port in `Edit` -> `Tool Options` -> `GhidraMCP HTTP Server`

### Option 2: Headless Mode (No GUI)

For servers or headless environments:

```bash
./run_headless.sh /path/to/binary [port]
```

This uses Ghidra's `analyzeHeadless` to import, analyze, and start the MCP HTTP server. The script:
- Creates a temporary Ghidra project
- Auto-analyzes the binary
- Starts the HTTP API on the specified port (default: 8080)
- Keeps running until Ctrl+C

Example:
```bash
./run_headless.sh ./firmware.bin 8080
```

For an existing Ghidra project:
```bash
/usr/share/ghidra/support/analyzeHeadless /path/to/project ProjectName \
  -process BinaryName \
  -postScript GhidraMCPServerScript.java 8080 \
  -scriptPath ./ghidra_scripts \
  -noanalysis
```

### Python MCP Bridge

Install dependencies:
```bash
pip install "requests>=2,<3" "mcp>=1.2.0,<2"
```

Run the bridge (connects to the Ghidra HTTP server and exposes MCP tools):
```bash
python bridge_mcp_ghidra.py --ghidra-server http://127.0.0.1:8080/
```

## MCP Client Configuration

### Claude Code

Add to your project's `.mcp.json`:
```json
{
  "mcpServers": {
    "ghidra": {
      "command": "python",
      "args": ["/path/to/bridge_mcp_ghidra.py", "--ghidra-server", "http://127.0.0.1:8080/"]
    }
  }
}
```

### Claude Desktop

Edit `claude_desktop_config.json`:
```json
{
  "mcpServers": {
    "ghidra": {
      "command": "python",
      "args": ["/path/to/bridge_mcp_ghidra.py", "--ghidra-server", "http://127.0.0.1:8080/"]
    }
  }
}
```

### SSE Transport (Cline, etc.)

Start the bridge in SSE mode:
```bash
python bridge_mcp_ghidra.py --transport sse --mcp-host 127.0.0.1 --mcp-port 8081
```

Then connect your MCP client to `http://127.0.0.1:8081/sse`.

## Available MCP Tools

| Tool | Description |
|------|-------------|
| `get_program_info` | Program metadata, architecture, memory layout |
| `list_functions` | All functions with addresses |
| `list_methods` | Function names with pagination |
| `list_classes` | Namespace/class names |
| `list_segments` | Memory segments |
| `list_imports` | Imported symbols |
| `list_exports` | Exported symbols |
| `list_namespaces` | Non-global namespaces |
| `list_data_items` | Defined data labels and values |
| `list_strings` | Defined strings with optional filter |
| `list_data_types` | Available data types with optional filter |
| `search_functions_by_name` | Search functions by substring |
| `search_memory` | Search for hex byte patterns |
| `decompile_function` | Decompile by function name |
| `decompile_function_by_address` | Decompile by address |
| `decompile_function_async` | Non-blocking decompile (returns task_id) |
| `get_task_status` | Poll async task state |
| `get_task_result` | Get async task result |
| `disassemble_function` | Assembly listing for a function |
| `get_function_by_address` | Function info at address |
| `get_current_address` | Currently selected address (GUI only) |
| `get_current_function` | Currently selected function (GUI only) |
| `get_xrefs_to` | Cross-references to an address |
| `get_xrefs_from` | Cross-references from an address |
| `get_function_xrefs` | Cross-references to a function |
| `get_callees` | Functions called by a function |
| `get_callers` | Functions calling a function |
| `read_bytes` | Read raw hex bytes from memory |
| `get_data_at` | Data info at an address |
| `rename_function` | Rename function by name |
| `rename_function_by_address` | Rename function by address |
| `rename_variable` | Rename local variable |
| `rename_data` | Rename data label |
| `set_decompiler_comment` | Set pre-comment (decompiler) |
| `set_disassembly_comment` | Set EOL comment (disassembly) |
| `set_plate_comment` | Set plate comment (banner) |
| `set_function_prototype` | Set function signature |
| `set_local_variable_type` | Set variable data type |
| `define_data` | Define data type at address |
| `clear_data` | Clear defined data at address |
| `create_label` | Create symbol/label at address |
| `create_enum` | Create enum data type |
| `create_struct` | Create struct data type |
| `apply_struct` | Apply struct at address |

## Building from Source

1. Copy Ghidra JARs to `lib/`:
```bash
GHIDRA_HOME=/path/to/ghidra
cp $GHIDRA_HOME/Ghidra/Features/Base/lib/Base.jar lib/
cp $GHIDRA_HOME/Ghidra/Features/Decompiler/lib/Decompiler.jar lib/
cp $GHIDRA_HOME/Ghidra/Framework/Docking/lib/Docking.jar lib/
cp $GHIDRA_HOME/Ghidra/Framework/Generic/lib/Generic.jar lib/
cp $GHIDRA_HOME/Ghidra/Framework/Project/lib/Project.jar lib/
cp $GHIDRA_HOME/Ghidra/Framework/SoftwareModeling/lib/SoftwareModeling.jar lib/
cp $GHIDRA_HOME/Ghidra/Framework/Utility/lib/Utility.jar lib/
cp $GHIDRA_HOME/Ghidra/Framework/Gui/lib/Gui.jar lib/
```

2. Build:
```bash
mvn clean package assembly:single
```

Output: `target/GhidraMCP-1.0-SNAPSHOT.zip`

## License

Apache License 2.0
