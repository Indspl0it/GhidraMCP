# /// script
# requires-python = ">=3.10"
# dependencies = [
#     "requests>=2,<3",
#     "mcp>=1.2.0,<2",
# ]
# ///

import sys
import requests
import argparse
import logging
from urllib.parse import urljoin

from mcp.server.fastmcp import FastMCP

DEFAULT_GHIDRA_SERVER = "http://127.0.0.1:8080/"

logger = logging.getLogger(__name__)

mcp = FastMCP("ghidra-mcp")

# Initialize ghidra_server_url with default value
ghidra_server_url = DEFAULT_GHIDRA_SERVER

def safe_get(endpoint: str, params: dict = None) -> list:
    """
    Perform a GET request with optional query parameters.
    """
    if params is None:
        params = {}

    url = urljoin(ghidra_server_url, endpoint)

    try:
        response = requests.get(url, params=params, timeout=5)
        response.encoding = 'utf-8'
        if response.ok:
            return response.text.splitlines()
        else:
            return [f"Error {response.status_code}: {response.text.strip()}"]
    except Exception as e:
        return [f"Request failed: {str(e)}"]

def safe_post(endpoint: str, data: dict | str) -> str:
    try:
        url = urljoin(ghidra_server_url, endpoint)
        if isinstance(data, dict):
            response = requests.post(url, data=data, timeout=5)
        else:
            response = requests.post(url, data=data.encode("utf-8"), timeout=5)
        response.encoding = 'utf-8'
        if response.ok:
            return response.text.strip()
        else:
            return f"Error {response.status_code}: {response.text.strip()}"
    except Exception as e:
        return f"Request failed: {str(e)}"

def safe_get_long(endpoint: str, params: dict = None, timeout: int = 300) -> list:
    """Perform a GET request with a longer timeout for async operations."""
    if params is None:
        params = {}
    url = urljoin(ghidra_server_url, endpoint)
    try:
        response = requests.get(url, params=params, timeout=timeout)
        response.encoding = 'utf-8'
        if response.ok:
            return response.text.splitlines()
        else:
            return [f"Error {response.status_code}: {response.text.strip()}"]
    except Exception as e:
        return [f"Request failed: {str(e)}"]

@mcp.tool()
def list_methods(offset: int = 0, limit: int = 100) -> list:
    """
    List all function names in the program with pagination.
    """
    return safe_get("methods", {"offset": offset, "limit": limit})

@mcp.tool()
def list_classes(offset: int = 0, limit: int = 100) -> list:
    """
    List all namespace/class names in the program with pagination.
    """
    return safe_get("classes", {"offset": offset, "limit": limit})

@mcp.tool()
def decompile_function(name: str) -> str:
    """
    Decompile a specific function by name and return the decompiled C code.
    """
    return safe_post("decompile", name)

@mcp.tool()
def rename_function(old_name: str, new_name: str) -> str:
    """
    Rename a function by its current name to a new user-defined name.
    """
    return safe_post("renameFunction", {"oldName": old_name, "newName": new_name})

@mcp.tool()
def rename_data(address: str, new_name: str) -> str:
    """
    Rename a data label at the specified address.
    """
    return safe_post("renameData", {"address": address, "newName": new_name})

@mcp.tool()
def list_segments(offset: int = 0, limit: int = 100) -> list:
    """
    List all memory segments in the program with pagination.
    """
    return safe_get("segments", {"offset": offset, "limit": limit})

@mcp.tool()
def list_imports(offset: int = 0, limit: int = 100) -> list:
    """
    List imported symbols in the program with pagination.
    """
    return safe_get("imports", {"offset": offset, "limit": limit})

@mcp.tool()
def list_exports(offset: int = 0, limit: int = 100) -> list:
    """
    List exported functions/symbols with pagination.
    """
    return safe_get("exports", {"offset": offset, "limit": limit})

@mcp.tool()
def list_namespaces(offset: int = 0, limit: int = 100) -> list:
    """
    List all non-global namespaces in the program with pagination.
    """
    return safe_get("namespaces", {"offset": offset, "limit": limit})

@mcp.tool()
def list_data_items(offset: int = 0, limit: int = 100) -> list:
    """
    List defined data labels and their values with pagination.
    """
    return safe_get("data", {"offset": offset, "limit": limit})

@mcp.tool()
def search_functions_by_name(query: str, offset: int = 0, limit: int = 100) -> list:
    """
    Search for functions whose name contains the given substring.
    """
    if not query:
        return ["Error: query string is required"]
    return safe_get("searchFunctions", {"query": query, "offset": offset, "limit": limit})

@mcp.tool()
def rename_variable(function_name: str, old_name: str, new_name: str) -> str:
    """
    Rename a local variable within a function.
    """
    return safe_post("renameVariable", {
        "functionName": function_name,
        "oldName": old_name,
        "newName": new_name
    })

@mcp.tool()
def get_function_by_address(address: str) -> str:
    """
    Get a function by its address.
    """
    return "\n".join(safe_get("get_function_by_address", {"address": address}))

@mcp.tool()
def get_current_address() -> str:
    """
    Get the address currently selected by the user.
    """
    return "\n".join(safe_get("get_current_address"))

@mcp.tool()
def get_current_function() -> str:
    """
    Get the function currently selected by the user.
    """
    return "\n".join(safe_get("get_current_function"))

@mcp.tool()
def list_functions() -> list:
    """
    List all functions in the database.
    """
    return safe_get("list_functions")

@mcp.tool()
def decompile_function_by_address(address: str) -> str:
    """
    Decompile a function at the given address.
    """
    return "\n".join(safe_get("decompile_function", {"address": address}))

@mcp.tool()
def disassemble_function(address: str) -> list:
    """
    Get assembly code (address: instruction; comment) for a function.
    """
    return safe_get("disassemble_function", {"address": address})

@mcp.tool()
def set_decompiler_comment(address: str, comment: str) -> str:
    """
    Set a comment for a given address in the function pseudocode.
    """
    return safe_post("set_decompiler_comment", {"address": address, "comment": comment})

@mcp.tool()
def set_disassembly_comment(address: str, comment: str) -> str:
    """
    Set a comment for a given address in the function disassembly.
    """
    return safe_post("set_disassembly_comment", {"address": address, "comment": comment})

@mcp.tool()
def rename_function_by_address(function_address: str, new_name: str) -> str:
    """
    Rename a function by its address.
    """
    return safe_post("rename_function_by_address", {"function_address": function_address, "new_name": new_name})

@mcp.tool()
def set_function_prototype(function_address: str, prototype: str) -> str:
    """
    Set a function's prototype.
    """
    return safe_post("set_function_prototype", {"function_address": function_address, "prototype": prototype})

@mcp.tool()
def set_local_variable_type(function_address: str, variable_name: str, new_type: str) -> str:
    """
    Set a local variable's type.
    """
    return safe_post("set_local_variable_type", {"function_address": function_address, "variable_name": variable_name, "new_type": new_type})

@mcp.tool()
def get_xrefs_to(address: str, offset: int = 0, limit: int = 100) -> list:
    """
    Get all references to the specified address (xref to).
    
    Args:
        address: Target address in hex format (e.g. "0x1400010a0")
        offset: Pagination offset (default: 0)
        limit: Maximum number of references to return (default: 100)
        
    Returns:
        List of references to the specified address
    """
    return safe_get("xrefs_to", {"address": address, "offset": offset, "limit": limit})

@mcp.tool()
def get_xrefs_from(address: str, offset: int = 0, limit: int = 100) -> list:
    """
    Get all references from the specified address (xref from).
    
    Args:
        address: Source address in hex format (e.g. "0x1400010a0")
        offset: Pagination offset (default: 0)
        limit: Maximum number of references to return (default: 100)
        
    Returns:
        List of references from the specified address
    """
    return safe_get("xrefs_from", {"address": address, "offset": offset, "limit": limit})

@mcp.tool()
def get_function_xrefs(name: str, offset: int = 0, limit: int = 100) -> list:
    """
    Get all references to the specified function by name.
    
    Args:
        name: Function name to search for
        offset: Pagination offset (default: 0)
        limit: Maximum number of references to return (default: 100)
        
    Returns:
        List of references to the specified function
    """
    return safe_get("function_xrefs", {"name": name, "offset": offset, "limit": limit})

@mcp.tool()
def list_strings(offset: int = 0, limit: int = 2000, filter: str = None) -> list:
    """
    List all defined strings in the program with their addresses.
    
    Args:
        offset: Pagination offset (default: 0)
        limit: Maximum number of strings to return (default: 2000)
        filter: Optional filter to match within string content
        
    Returns:
        List of strings with their addresses
    """
    params = {"offset": offset, "limit": limit}
    if filter:
        params["filter"] = filter
    return safe_get("strings", params)

@mcp.tool()
def get_program_info() -> str:
    """
    Get program metadata: architecture, language, compiler, base address, format, SHA256,
    function count, and memory block layout. Call this first to understand what you're analyzing.
    """
    return "\n".join(safe_get("program_info"))

@mcp.tool()
def get_callees(address: str) -> list:
    """
    Get all functions called by the function at the given address.
    Useful for understanding code flow and dependencies.
    """
    return safe_get("get_callees", {"address": address})

@mcp.tool()
def get_callers(address: str) -> list:
    """
    Get all functions that call the function at the given address.
    Useful for impact analysis and understanding usage.
    """
    return safe_get("get_callers", {"address": address})

@mcp.tool()
def list_data_types(filter: str = None, offset: int = 0, limit: int = 100) -> list:
    """
    List available data types in the program's data type manager.

    Args:
        filter: Optional substring filter on type names
        offset: Pagination offset (default: 0)
        limit: Maximum results (default: 100)
    """
    params = {"offset": offset, "limit": limit}
    if filter:
        params["filter"] = filter
    return safe_get("list_data_types", params)

@mcp.tool()
def search_memory(pattern: str, max_results: int = 20) -> list:
    """
    Search program memory for a hex byte pattern.

    Args:
        pattern: Hex bytes to search for (e.g., "48 8b 05" or "488b05")
        max_results: Maximum number of matches to return (default: 20)
    """
    return safe_get("search_memory", {"pattern": pattern, "max_results": max_results})

@mcp.tool()
def set_plate_comment(address: str, comment: str) -> str:
    """
    Set a plate comment for a given address. Plate comments appear as banners above code blocks.
    """
    return safe_post("set_plate_comment", {"address": address, "comment": comment})

# --- Async decompilation tools ---

@mcp.tool()
def decompile_function_async(address: str) -> str:
    """
    Start an async decompilation of a function at the given address.
    Returns a task_id that can be polled with get_task_status/get_task_result.
    Useful for large functions that take a long time to decompile.
    """
    return "\n".join(safe_get("decompile_async", {"address": address}))

@mcp.tool()
def get_task_status(task_id: str) -> str:
    """
    Get the status of an async decompilation task.
    Returns state (running/completed/error) and elapsed time.
    """
    return "\n".join(safe_get("task_status", {"task_id": task_id}))

@mcp.tool()
def get_task_result(task_id: str) -> str:
    """
    Get the result of a completed async decompilation task.
    Returns the decompiled code if the task is complete.
    """
    return "\n".join(safe_get_long("task_result", {"task_id": task_id}))

# --- Data manipulation tools ---

@mcp.tool()
def clear_data(address: str, length: int = None) -> str:
    """
    Clear defined data at an address, reverting it to undefined bytes.
    If length is not specified, clears the data item at that address.
    """
    params = {"address": address}
    if length is not None:
        params["length"] = str(length)
    return safe_post("clear_data", params)

@mcp.tool()
def define_data(address: str, data_type: str) -> str:
    """
    Define a data type at an address (e.g., int, short, float, double, char, pointer).
    """
    return safe_post("define_data", {"address": address, "data_type": data_type})

@mcp.tool()
def read_bytes(address: str, length: int = 16) -> str:
    """
    Read raw bytes at an address. Returns hex-encoded bytes.

    Args:
        address: Memory address in hex format (e.g. "0x1400010a0")
        length: Number of bytes to read (1-4096, default: 16)
    """
    return "\n".join(safe_get("read_bytes", {"address": address, "length": length}))

@mcp.tool()
def get_data_at(address: str) -> str:
    """
    Get defined data information at an address, including type, label, length and value.
    """
    return "\n".join(safe_get("get_data_at", {"address": address}))

@mcp.tool()
def create_label(address: str, name: str) -> str:
    """
    Create a label/symbol at the specified address.
    """
    return safe_post("create_label", {"address": address, "name": name})

@mcp.tool()
def create_enum(name: str, members: str, size: int = 4) -> str:
    """
    Create an enum data type.

    Args:
        name: Enum type name
        members: Semicolon-separated name:value pairs (e.g. "VAL_A:0;VAL_B:1;VAL_C:2")
        size: Enum size in bytes (default: 4)
    """
    return safe_post("create_enum", {"name": name, "size": str(size), "members": members})

@mcp.tool()
def create_struct(name: str, fields: str) -> str:
    """
    Create a struct data type.

    Args:
        name: Struct type name
        fields: Semicolon-separated name:type pairs (e.g. "field1:int;field2:char;ptr:pointer")
    """
    return safe_post("create_struct", {"name": name, "fields": fields})

@mcp.tool()
def apply_struct(address: str, struct_name: str) -> str:
    """
    Apply a struct data type at an address.
    """
    return safe_post("apply_struct", {"address": address, "struct_name": struct_name})


def main():
    parser = argparse.ArgumentParser(description="MCP server for Ghidra")
    parser.add_argument("--ghidra-server", type=str, default=DEFAULT_GHIDRA_SERVER,
                        help=f"Ghidra server URL, default: {DEFAULT_GHIDRA_SERVER}")
    parser.add_argument("--mcp-host", type=str, default="127.0.0.1",
                        help="Host to run MCP server on (only used for sse), default: 127.0.0.1")
    parser.add_argument("--mcp-port", type=int,
                        help="Port to run MCP server on (only used for sse), default: 8081")
    parser.add_argument("--transport", type=str, default="stdio", choices=["stdio", "sse"],
                        help="Transport protocol for MCP, default: stdio")
    args = parser.parse_args()
    
    # Use the global variable to ensure it's properly updated
    global ghidra_server_url
    if args.ghidra_server:
        ghidra_server_url = args.ghidra_server
    
    if args.transport == "sse":
        try:
            # Set up logging
            log_level = logging.INFO
            logging.basicConfig(level=log_level)
            logging.getLogger().setLevel(log_level)

            # Configure MCP settings
            mcp.settings.log_level = "INFO"
            if args.mcp_host:
                mcp.settings.host = args.mcp_host
            else:
                mcp.settings.host = "127.0.0.1"

            if args.mcp_port:
                mcp.settings.port = args.mcp_port
            else:
                mcp.settings.port = 8081

            logger.info(f"Connecting to Ghidra server at {ghidra_server_url}")
            logger.info(f"Starting MCP server on http://{mcp.settings.host}:{mcp.settings.port}/sse")
            logger.info(f"Using transport: {args.transport}")

            mcp.run(transport="sse")
        except KeyboardInterrupt:
            logger.info("Server stopped by user")
    else:
        mcp.run()
        
if __name__ == "__main__":
    main()

