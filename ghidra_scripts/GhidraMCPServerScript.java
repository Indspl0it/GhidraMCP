// GhidraMCPServerScript.java
// Headless GhidraScript that starts an HTTP server providing the same API as the GUI plugin.
// Usage: analyzeHeadless <project_dir> <project_name> -import <binary> -postScript GhidraMCPServerScript.java [port]

import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.GlobalNamespace;
import ghidra.program.model.listing.*;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.*;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.LocalSymbolMap;
import ghidra.program.model.pcode.HighFunctionDBUtil;
import ghidra.program.model.pcode.HighFunctionDBUtil.ReturnCommitOption;
import ghidra.program.model.pcode.HighVariable;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.PointerDataType;
import ghidra.util.task.ConsoleTaskMonitor;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicLong;

public class GhidraMCPServerScript extends GhidraScript {

    // Async decompilation support
    private static final int MAX_ASYNC_TASKS = 50;
    private static final long TASK_TTL_MS = 30 * 60 * 1000; // 30 minutes
    private final ConcurrentHashMap<String, AsyncTask> asyncTasks = new ConcurrentHashMap<>();
    private final ExecutorService asyncExecutor = Executors.newFixedThreadPool(4);
    private final AtomicLong taskCounter = new AtomicLong(0);
    private final ScheduledExecutorService taskCleaner = Executors.newSingleThreadScheduledExecutor();

    private static class AsyncTask {
        final String id;
        final long createdAt;
        volatile String state; // "running", "completed", "error"
        volatile String result;
        volatile long completedAt;

        AsyncTask(String id) {
            this.id = id;
            this.createdAt = System.currentTimeMillis();
            this.state = "running";
        }

        void complete(String result) {
            this.result = result;
            this.state = "completed";
            this.completedAt = System.currentTimeMillis();
        }

        void fail(String error) {
            this.result = error;
            this.state = "error";
            this.completedAt = System.currentTimeMillis();
        }

        boolean isExpired() {
            return System.currentTimeMillis() - createdAt > TASK_TTL_MS;
        }
    }

    @Override
    public void run() throws Exception {
        // Parse port from script args
        String[] args = getScriptArgs();
        int port = args.length > 0 ? Integer.parseInt(args[0]) : 8080;

        if (currentProgram == null) {
            println("ERROR: No program loaded. Cannot start GhidraMCP server.");
            return;
        }

        // Schedule periodic cleanup of expired async tasks
        taskCleaner.scheduleAtFixedRate(() -> {
            asyncTasks.entrySet().removeIf(e -> e.getValue().isExpired());
        }, 5, 5, TimeUnit.MINUTES);

        HttpServer server = HttpServer.create(new InetSocketAddress(port), 0);

        // ---- Listing endpoints ----

        server.createContext("/methods", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = parseIntOrDefault(qparams.get("limit"),  100);
            sendResponse(exchange, getAllFunctionNames(offset, limit));
        });

        server.createContext("/classes", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = parseIntOrDefault(qparams.get("limit"),  100);
            sendResponse(exchange, getAllClassNames(offset, limit));
        });

        server.createContext("/decompile", exchange -> {
            String name = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
            sendResponse(exchange, decompileFunctionByName(name));
        });

        server.createContext("/renameFunction", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String response = renameFunction(params.get("oldName"), params.get("newName"))
                    ? "Renamed successfully" : "Rename failed";
            sendResponse(exchange, response);
        });

        server.createContext("/renameData", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            renameDataAtAddress(params.get("address"), params.get("newName"));
            sendResponse(exchange, "Rename data attempted");
        });

        server.createContext("/renameVariable", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String functionName = params.get("functionName");
            String oldName = params.get("oldName");
            String newName = params.get("newName");
            String result = renameVariableInFunction(functionName, oldName, newName);
            sendResponse(exchange, result);
        });

        server.createContext("/segments", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = parseIntOrDefault(qparams.get("limit"),  100);
            sendResponse(exchange, listSegments(offset, limit));
        });

        server.createContext("/imports", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = parseIntOrDefault(qparams.get("limit"),  100);
            sendResponse(exchange, listImports(offset, limit));
        });

        server.createContext("/exports", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = parseIntOrDefault(qparams.get("limit"),  100);
            sendResponse(exchange, listExports(offset, limit));
        });

        server.createContext("/namespaces", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = parseIntOrDefault(qparams.get("limit"),  100);
            sendResponse(exchange, listNamespaces(offset, limit));
        });

        server.createContext("/data", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = parseIntOrDefault(qparams.get("limit"),  100);
            sendResponse(exchange, listDefinedData(offset, limit));
        });

        server.createContext("/searchFunctions", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String searchTerm = qparams.get("query");
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = parseIntOrDefault(qparams.get("limit"),  100);
            sendResponse(exchange, searchFunctionsByName(searchTerm, offset, limit));
        });

        // ---- New API endpoints ----

        server.createContext("/get_function_by_address", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String address = qparams.get("address");
            sendResponse(exchange, getFunctionByAddress(address));
        });

        server.createContext("/get_current_address", exchange -> {
            sendResponse(exchange, "Not available in headless mode. Use /get_function_by_address?address=<addr> instead.");
        });

        server.createContext("/get_current_function", exchange -> {
            sendResponse(exchange, "Not available in headless mode. Use /get_function_by_address?address=<addr> or /searchFunctions?query=<name> instead.");
        });

        server.createContext("/list_functions", exchange -> {
            sendResponse(exchange, listFunctions());
        });

        server.createContext("/decompile_function", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String address = qparams.get("address");
            sendResponse(exchange, decompileFunctionByAddress(address));
        });

        server.createContext("/disassemble_function", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String address = qparams.get("address");
            sendResponse(exchange, disassembleFunction(address));
        });

        server.createContext("/set_decompiler_comment", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String address = params.get("address");
            String comment = params.get("comment");
            boolean success = setDecompilerComment(address, comment);
            sendResponse(exchange, success ? "Comment set successfully" : "Failed to set comment");
        });

        server.createContext("/set_disassembly_comment", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String address = params.get("address");
            String comment = params.get("comment");
            boolean success = setDisassemblyComment(address, comment);
            sendResponse(exchange, success ? "Comment set successfully" : "Failed to set comment");
        });

        server.createContext("/set_plate_comment", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String address = params.get("address");
            String comment = params.get("comment");
            boolean success = setPlateComment(address, comment);
            sendResponse(exchange, success ? "Plate comment set successfully" : "Failed to set plate comment");
        });

        server.createContext("/rename_function_by_address", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String functionAddress = params.get("function_address");
            String newName = params.get("new_name");
            boolean success = renameFunctionByAddress(functionAddress, newName);
            sendResponse(exchange, success ? "Function renamed successfully" : "Failed to rename function");
        });

        server.createContext("/set_function_prototype", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String functionAddress = params.get("function_address");
            String prototype = params.get("prototype");
            String result = setFunctionPrototype(functionAddress, prototype);
            sendResponse(exchange, result);
        });

        server.createContext("/set_local_variable_type", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String functionAddress = params.get("function_address");
            String variableName = params.get("variable_name");
            String newType = params.get("new_type");

            StringBuilder responseMsg = new StringBuilder();
            responseMsg.append("Setting variable type: ").append(variableName)
                      .append(" to ").append(newType)
                      .append(" in function at ").append(functionAddress).append("\n\n");

            DataTypeManager dtm = currentProgram.getDataTypeManager();
            DataType directType = findDataTypeByNameInAllCategories(dtm, newType);
            if (directType != null) {
                responseMsg.append("Found type: ").append(directType.getPathName()).append("\n");
            } else if (newType != null && newType.startsWith("P") && newType.length() > 1) {
                String baseTypeName = newType.substring(1);
                DataType baseType = findDataTypeByNameInAllCategories(dtm, baseTypeName);
                if (baseType != null) {
                    responseMsg.append("Found base type for pointer: ").append(baseType.getPathName()).append("\n");
                } else {
                    responseMsg.append("Base type not found for pointer: ").append(baseTypeName).append("\n");
                }
            } else {
                responseMsg.append("Type not found directly: ").append(newType).append("\n");
            }

            boolean success = setLocalVariableType(functionAddress, variableName, newType);
            String successMsg = success ? "Variable type set successfully" : "Failed to set variable type";
            responseMsg.append("\nResult: ").append(successMsg);

            sendResponse(exchange, responseMsg.toString());
        });

        server.createContext("/xrefs_to", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String address = qparams.get("address");
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = parseIntOrDefault(qparams.get("limit"),  100);
            sendResponse(exchange, getXrefsTo(address, offset, limit));
        });

        server.createContext("/xrefs_from", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String address = qparams.get("address");
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = parseIntOrDefault(qparams.get("limit"),  100);
            sendResponse(exchange, getXrefsFrom(address, offset, limit));
        });

        server.createContext("/function_xrefs", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String name = qparams.get("name");
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = parseIntOrDefault(qparams.get("limit"),  100);
            sendResponse(exchange, getFunctionXrefs(name, offset, limit));
        });

        // ---- Async decompilation endpoints ----

        server.createContext("/decompile_async", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String address = qparams.get("address");
            sendResponse(exchange, startAsyncDecompile(address));
        });

        server.createContext("/task_status", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String taskId = qparams.get("task_id");
            sendResponse(exchange, getTaskStatus(taskId));
        });

        server.createContext("/task_result", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String taskId = qparams.get("task_id");
            sendResponse(exchange, getTaskResult(taskId));
        });

        // ---- Additional endpoints ----

        server.createContext("/get_callers", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String address = qparams.get("address");
            sendResponse(exchange, getCallers(address));
        });

        server.createContext("/list_data_types", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String filter = qparams.get("filter");
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = parseIntOrDefault(qparams.get("limit"),  100);
            sendResponse(exchange, listDataTypes(filter, offset, limit));
        });

        server.createContext("/search_memory", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String pattern = qparams.get("pattern");
            int maxResults = parseIntOrDefault(qparams.get("max_results"), 20);
            sendResponse(exchange, searchMemory(pattern, maxResults));
        });

        // ---- Data manipulation endpoints ----

        server.createContext("/clear_data", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String address = params.get("address");
            String lengthStr = params.get("length");
            sendResponse(exchange, clearData(address, lengthStr));
        });

        server.createContext("/define_data", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String address = params.get("address");
            String dataType = params.get("data_type");
            sendResponse(exchange, defineData(address, dataType));
        });

        server.createContext("/read_bytes", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String address = qparams.get("address");
            int length = parseIntOrDefault(qparams.get("length"), 16);
            sendResponse(exchange, readBytes(address, length));
        });

        server.createContext("/get_data_at", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String address = qparams.get("address");
            sendResponse(exchange, getDataAt(address));
        });

        server.createContext("/create_label", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String address = params.get("address");
            String name = params.get("name");
            sendResponse(exchange, createLabel(address, name));
        });

        server.createContext("/create_enum", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String name = params.get("name");
            int size = parseIntOrDefault(params.get("size"), 4);
            String members = params.get("members");
            sendResponse(exchange, createEnum(name, size, members));
        });

        server.createContext("/create_struct", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String name = params.get("name");
            String fields = params.get("fields");
            sendResponse(exchange, createStruct(name, fields));
        });

        server.createContext("/apply_struct", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String address = params.get("address");
            String structName = params.get("struct_name");
            sendResponse(exchange, applyStruct(address, structName));
        });

        server.createContext("/strings", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = parseIntOrDefault(qparams.get("limit"),  100);
            String filter = qparams.get("filter");
            sendResponse(exchange, listDefinedStrings(offset, limit, filter));
        });

        server.setExecutor(Executors.newFixedThreadPool(4));
        server.start();

        println("GhidraMCP headless server started on port " + port);
        println("Program: " + currentProgram.getName());
        println("Press Ctrl+C to stop");

        // Block until interrupted
        try {
            while (!monitor.isCancelled()) {
                Thread.sleep(1000);
            }
        } finally {
            server.stop(0);
            asyncExecutor.shutdownNow();
            taskCleaner.shutdownNow();
            asyncTasks.clear();
            println("GhidraMCP headless server stopped.");
        }
    }

    // ----------------------------------------------------------------------------------
    // Pagination-aware listing methods
    // ----------------------------------------------------------------------------------

    private String getAllFunctionNames(int offset, int limit) {
        List<String> names = new ArrayList<>();
        for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
            names.add(f.getName());
        }
        return paginateList(names, offset, limit);
    }

    private String getAllClassNames(int offset, int limit) {
        Set<String> classNames = new HashSet<>();
        for (Symbol symbol : currentProgram.getSymbolTable().getAllSymbols(true)) {
            Namespace ns = symbol.getParentNamespace();
            if (ns != null && !ns.isGlobal()) {
                classNames.add(ns.getName());
            }
        }
        List<String> sorted = new ArrayList<>(classNames);
        Collections.sort(sorted);
        return paginateList(sorted, offset, limit);
    }

    private String listSegments(int offset, int limit) {
        List<String> lines = new ArrayList<>();
        for (MemoryBlock block : currentProgram.getMemory().getBlocks()) {
            lines.add(String.format("%s: %s - %s", block.getName(), block.getStart(), block.getEnd()));
        }
        return paginateList(lines, offset, limit);
    }

    private String listImports(int offset, int limit) {
        List<String> lines = new ArrayList<>();
        for (Symbol symbol : currentProgram.getSymbolTable().getExternalSymbols()) {
            lines.add(symbol.getName() + " -> " + symbol.getAddress());
        }
        return paginateList(lines, offset, limit);
    }

    private String listExports(int offset, int limit) {
        SymbolTable table = currentProgram.getSymbolTable();
        SymbolIterator it = table.getAllSymbols(true);
        List<String> lines = new ArrayList<>();
        while (it.hasNext()) {
            Symbol s = it.next();
            if (s.isExternalEntryPoint()) {
                lines.add(s.getName() + " -> " + s.getAddress());
            }
        }
        return paginateList(lines, offset, limit);
    }

    private String listNamespaces(int offset, int limit) {
        Set<String> namespaces = new HashSet<>();
        for (Symbol symbol : currentProgram.getSymbolTable().getAllSymbols(true)) {
            Namespace ns = symbol.getParentNamespace();
            if (ns != null && !(ns instanceof GlobalNamespace)) {
                namespaces.add(ns.getName());
            }
        }
        List<String> sorted = new ArrayList<>(namespaces);
        Collections.sort(sorted);
        return paginateList(sorted, offset, limit);
    }

    private String listDefinedData(int offset, int limit) {
        List<String> lines = new ArrayList<>();
        for (MemoryBlock block : currentProgram.getMemory().getBlocks()) {
            DataIterator it = currentProgram.getListing().getDefinedData(block.getStart(), true);
            while (it.hasNext()) {
                Data data = it.next();
                if (block.contains(data.getAddress())) {
                    String label   = data.getLabel() != null ? data.getLabel() : "(unnamed)";
                    String valRepr = data.getDefaultValueRepresentation();
                    lines.add(String.format("%s: %s = %s",
                        data.getAddress(),
                        escapeNonAscii(label),
                        escapeNonAscii(valRepr)
                    ));
                }
            }
        }
        return paginateList(lines, offset, limit);
    }

    private String searchFunctionsByName(String searchTerm, int offset, int limit) {
        if (searchTerm == null || searchTerm.isEmpty()) return "Search term is required";

        List<String> matches = new ArrayList<>();
        for (Function func : currentProgram.getFunctionManager().getFunctions(true)) {
            String name = func.getName();
            if (name.toLowerCase().contains(searchTerm.toLowerCase())) {
                matches.add(String.format("%s @ %s", name, func.getEntryPoint()));
            }
        }

        Collections.sort(matches);

        if (matches.isEmpty()) {
            return "No functions matching '" + searchTerm + "'";
        }
        return paginateList(matches, offset, limit);
    }

    // ----------------------------------------------------------------------------------
    // Logic for rename, decompile, etc.
    // ----------------------------------------------------------------------------------

    private String decompileFunctionByName(String name) {
        DecompInterface decomp = new DecompInterface();
        try {
            decomp.openProgram(currentProgram);
            for (Function func : currentProgram.getFunctionManager().getFunctions(true)) {
                if (func.getName().equals(name)) {
                    DecompileResults result =
                        decomp.decompileFunction(func, 30, monitor);
                    if (result != null && result.decompileCompleted()) {
                        return result.getDecompiledFunction().getC();
                    } else {
                        return "Decompilation failed";
                    }
                }
            }
            return "Function not found";
        } finally {
            decomp.dispose();
        }
    }

    private boolean renameFunction(String oldName, String newName) {
        int tx = currentProgram.startTransaction("Rename function via HTTP");
        boolean success = false;
        try {
            for (Function func : currentProgram.getFunctionManager().getFunctions(true)) {
                if (func.getName().equals(oldName)) {
                    func.setName(newName, SourceType.USER_DEFINED);
                    success = true;
                    break;
                }
            }
        } catch (Exception e) {
            println("Error renaming function: " + e.getMessage());
        } finally {
            currentProgram.endTransaction(tx, success);
        }
        return success;
    }

    private void renameDataAtAddress(String addressStr, String newName) {
        int tx = currentProgram.startTransaction("Rename data");
        try {
            Address addr = currentProgram.getAddressFactory().getAddress(addressStr);
            Listing listing = currentProgram.getListing();
            Data data = listing.getDefinedDataAt(addr);
            if (data != null) {
                SymbolTable symTable = currentProgram.getSymbolTable();
                Symbol symbol = symTable.getPrimarySymbol(addr);
                if (symbol != null) {
                    symbol.setName(newName, SourceType.USER_DEFINED);
                } else {
                    symTable.createLabel(addr, newName, SourceType.USER_DEFINED);
                }
            }
        } catch (Exception e) {
            println("Rename data error: " + e.getMessage());
        } finally {
            currentProgram.endTransaction(tx, true);
        }
    }

    private String renameVariableInFunction(String functionName, String oldVarName, String newVarName) {
        DecompInterface decomp = new DecompInterface();
        try {
        decomp.openProgram(currentProgram);

        Function func = null;
        for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
            if (f.getName().equals(functionName)) {
                func = f;
                break;
            }
        }

        if (func == null) {
            return "Function not found";
        }

        DecompileResults result = decomp.decompileFunction(func, 30, monitor);
        if (result == null || !result.decompileCompleted()) {
            return "Decompilation failed";
        }

        HighFunction highFunction = result.getHighFunction();
        if (highFunction == null) {
            return "Decompilation failed (no high function)";
        }

        LocalSymbolMap localSymbolMap = highFunction.getLocalSymbolMap();
        if (localSymbolMap == null) {
            return "Decompilation failed (no local symbol map)";
        }

        HighSymbol highSymbol = null;
        Iterator<HighSymbol> symbols = localSymbolMap.getSymbols();
        while (symbols.hasNext()) {
            HighSymbol symbol = symbols.next();
            String symbolName = symbol.getName();

            if (symbolName.equals(oldVarName)) {
                highSymbol = symbol;
            }
            if (symbolName.equals(newVarName)) {
                return "Error: A variable with name '" + newVarName + "' already exists in this function";
            }
        }

        if (highSymbol == null) {
            return "Variable not found";
        }

        boolean commitRequired = checkFullCommit(highSymbol, highFunction);

        int tx = currentProgram.startTransaction("Rename variable");
        boolean success = false;
        try {
            if (commitRequired) {
                HighFunctionDBUtil.commitParamsToDatabase(highFunction, false,
                    ReturnCommitOption.NO_COMMIT, func.getSignatureSource());
            }
            HighFunctionDBUtil.updateDBVariable(
                highSymbol,
                newVarName,
                null,
                SourceType.USER_DEFINED
            );
            success = true;
        } catch (Exception e) {
            println("Failed to rename variable: " + e.getMessage());
        } finally {
            currentProgram.endTransaction(tx, success);
        }
        return success ? "Variable renamed" : "Failed to rename variable";
        } finally {
            decomp.dispose();
        }
    }

    /**
     * Copied from AbstractDecompilerAction.checkFullCommit (it is protected).
     */
    private static boolean checkFullCommit(HighSymbol highSymbol, HighFunction hfunction) {
        if (highSymbol != null && !highSymbol.isParameter()) {
            return false;
        }
        Function function = hfunction.getFunction();
        Parameter[] parameters = function.getParameters();
        LocalSymbolMap localSymbolMap = hfunction.getLocalSymbolMap();
        int numParams = localSymbolMap.getNumParams();
        if (numParams != parameters.length) {
            return true;
        }

        for (int i = 0; i < numParams; i++) {
            HighSymbol param = localSymbolMap.getParamSymbol(i);
            if (param.getCategoryIndex() != i) {
                return true;
            }
            VariableStorage storage = param.getStorage();
            if (0 != storage.compareTo(parameters[i].getVariableStorage())) {
                return true;
            }
        }

        return false;
    }

    // ----------------------------------------------------------------------------------
    // New functionality methods
    // ----------------------------------------------------------------------------------

    private String getFunctionByAddress(String addressStr) {
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";

        try {
            Address addr = currentProgram.getAddressFactory().getAddress(addressStr);
            Function func = currentProgram.getFunctionManager().getFunctionAt(addr);

            if (func == null) return "No function found at address " + addressStr;

            return String.format("Function: %s at %s\nSignature: %s\nEntry: %s\nBody: %s - %s",
                func.getName(),
                func.getEntryPoint(),
                func.getSignature(),
                func.getEntryPoint(),
                func.getBody().getMinAddress(),
                func.getBody().getMaxAddress());
        } catch (Exception e) {
            return "Error getting function: " + e.getMessage();
        }
    }

    private String listFunctions() {
        StringBuilder result = new StringBuilder();
        for (Function func : currentProgram.getFunctionManager().getFunctions(true)) {
            result.append(String.format("%s at %s\n",
                func.getName(),
                func.getEntryPoint()));
        }
        return result.toString();
    }

    private Function getFunctionForAddress(Address addr) {
        Function func = currentProgram.getFunctionManager().getFunctionAt(addr);
        if (func == null) {
            func = currentProgram.getFunctionManager().getFunctionContaining(addr);
        }
        return func;
    }

    private String decompileFunctionByAddress(String addressStr) {
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";

        try {
            Address addr = currentProgram.getAddressFactory().getAddress(addressStr);
            Function func = getFunctionForAddress(addr);
            if (func == null) return "No function found at or containing address " + addressStr;

            DecompInterface decomp = new DecompInterface();
            try {
                decomp.openProgram(currentProgram);
                DecompileResults result = decomp.decompileFunction(func, 30, monitor);

                return (result != null && result.decompileCompleted())
                    ? result.getDecompiledFunction().getC()
                    : "Decompilation failed";
            } finally {
                decomp.dispose();
            }
        } catch (Exception e) {
            return "Error decompiling function: " + e.getMessage();
        }
    }

    private String disassembleFunction(String addressStr) {
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";

        try {
            Address addr = currentProgram.getAddressFactory().getAddress(addressStr);
            Function func = getFunctionForAddress(addr);
            if (func == null) return "No function found at or containing address " + addressStr;

            StringBuilder result = new StringBuilder();
            Listing listing = currentProgram.getListing();
            Address start = func.getEntryPoint();
            Address end = func.getBody().getMaxAddress();

            InstructionIterator instructions = listing.getInstructions(start, true);
            while (instructions.hasNext()) {
                Instruction instr = instructions.next();
                if (instr.getAddress().compareTo(end) > 0) {
                    break;
                }
                String comment = listing.getComment(CommentType.EOL, instr.getAddress());
                comment = (comment != null) ? "; " + comment : "";

                result.append(String.format("%s: %s %s\n",
                    instr.getAddress(),
                    instr.toString(),
                    comment));
            }

            return result.toString();
        } catch (Exception e) {
            return "Error disassembling function: " + e.getMessage();
        }
    }

    private boolean setCommentAtAddress(String addressStr, String comment, CommentType commentType, String transactionName) {
        if (addressStr == null || addressStr.isEmpty() || comment == null) return false;

        int tx = currentProgram.startTransaction(transactionName);
        boolean success = false;
        try {
            Address addr = currentProgram.getAddressFactory().getAddress(addressStr);
            currentProgram.getListing().setComment(addr, commentType, comment);
            success = true;
        } catch (Exception e) {
            println("Error setting " + transactionName.toLowerCase() + ": " + e.getMessage());
        } finally {
            currentProgram.endTransaction(tx, success);
        }
        return success;
    }

    private boolean setDecompilerComment(String addressStr, String comment) {
        return setCommentAtAddress(addressStr, comment, CommentType.PRE, "Set decompiler comment");
    }

    private boolean setDisassemblyComment(String addressStr, String comment) {
        return setCommentAtAddress(addressStr, comment, CommentType.EOL, "Set disassembly comment");
    }

    private boolean setPlateComment(String addressStr, String comment) {
        return setCommentAtAddress(addressStr, comment, CommentType.PLATE, "Set plate comment");
    }

    private boolean renameFunctionByAddress(String functionAddrStr, String newName) {
        if (functionAddrStr == null || functionAddrStr.isEmpty() ||
            newName == null || newName.isEmpty()) {
            return false;
        }

        int tx = currentProgram.startTransaction("Rename function by address");
        boolean success = false;
        try {
            Address addr = currentProgram.getAddressFactory().getAddress(functionAddrStr);
            Function func = getFunctionForAddress(addr);

            if (func == null) {
                println("Could not find function at address: " + functionAddrStr);
                return false;
            }

            func.setName(newName, SourceType.USER_DEFINED);
            success = true;
        } catch (Exception e) {
            println("Error renaming function by address: " + e.getMessage());
        } finally {
            currentProgram.endTransaction(tx, success);
        }
        return success;
    }

    private String setFunctionPrototype(String functionAddrStr, String prototype) {
        if (functionAddrStr == null || functionAddrStr.isEmpty()) {
            return "Function address is required";
        }
        if (prototype == null || prototype.isEmpty()) {
            return "Function prototype is required";
        }

        try {
            Address addr = currentProgram.getAddressFactory().getAddress(functionAddrStr);
            Function func = getFunctionForAddress(addr);

            if (func == null) {
                return "Could not find function at address: " + functionAddrStr;
            }

            // Add a plate comment showing the prototype being set
            int txComment = currentProgram.startTransaction("Add prototype comment");
            try {
                currentProgram.getListing().setComment(
                    func.getEntryPoint(),
                    CommentType.PLATE,
                    "Setting prototype: " + prototype
                );
            } finally {
                currentProgram.endTransaction(txComment, true);
            }

            // Parse and apply the function signature
            DataTypeManager dtm = currentProgram.getDataTypeManager();

            // In headless mode, DataTypeManagerService is not available, so pass null
            ghidra.app.util.parser.FunctionSignatureParser parser =
                new ghidra.app.util.parser.FunctionSignatureParser(dtm, null);

            ghidra.program.model.data.FunctionDefinitionDataType sig = parser.parse(null, prototype);

            if (sig == null) {
                return "Failed to parse function prototype";
            }

            int txProto = currentProgram.startTransaction("Set function prototype");
            boolean success = false;
            try {
                ghidra.app.cmd.function.ApplyFunctionSignatureCmd cmd =
                    new ghidra.app.cmd.function.ApplyFunctionSignatureCmd(
                        addr, sig, SourceType.USER_DEFINED);

                boolean cmdResult = cmd.applyTo(currentProgram, monitor);

                if (cmdResult) {
                    success = true;
                    return "Function prototype set successfully";
                } else {
                    return "Failed to set function prototype: " + cmd.getStatusMsg();
                }
            } finally {
                currentProgram.endTransaction(txProto, success);
            }
        } catch (Exception e) {
            return "Error setting function prototype: " + e.getMessage();
        }
    }

    private boolean setLocalVariableType(String functionAddrStr, String variableName, String newType) {
        if (functionAddrStr == null || functionAddrStr.isEmpty() ||
            variableName == null || variableName.isEmpty() ||
            newType == null || newType.isEmpty()) {
            return false;
        }

        try {
            Address addr = currentProgram.getAddressFactory().getAddress(functionAddrStr);
            Function func = getFunctionForAddress(addr);

            if (func == null) {
                println("Could not find function at address: " + functionAddrStr);
                return false;
            }

            DecompInterface decomp = new DecompInterface();
            try {
                decomp.openProgram(currentProgram);
                decomp.setSimplificationStyle("decompile");
                DecompileResults results = decomp.decompileFunction(func, 60, monitor);

                if (results == null || !results.decompileCompleted()) {
                    println("Could not decompile function: " + (results != null ? results.getErrorMessage() : "null"));
                    return false;
                }

                HighFunction highFunction = results.getHighFunction();
                if (highFunction == null) {
                    println("No high function available");
                    return false;
                }

                HighSymbol symbol = null;
                Iterator<HighSymbol> symbols = highFunction.getLocalSymbolMap().getSymbols();
                while (symbols.hasNext()) {
                    HighSymbol s = symbols.next();
                    if (s.getName().equals(variableName)) {
                        symbol = s;
                        break;
                    }
                }

                if (symbol == null) {
                    println("Could not find variable '" + variableName + "' in decompiled function");
                    return false;
                }

                HighVariable highVar = symbol.getHighVariable();
                if (highVar == null) {
                    println("No HighVariable found for symbol: " + variableName);
                    return false;
                }

                DataTypeManager dtm = currentProgram.getDataTypeManager();
                DataType dataType = resolveDataType(dtm, newType);

                if (dataType == null) {
                    println("Could not resolve data type: " + newType);
                    return false;
                }

                int tx = currentProgram.startTransaction("Set variable type");
                boolean success = false;
                try {
                    HighFunctionDBUtil.updateDBVariable(
                        symbol,
                        symbol.getName(),
                        dataType,
                        SourceType.USER_DEFINED
                    );
                    success = true;
                } catch (Exception e) {
                    println("Error setting variable type: " + e.getMessage());
                } finally {
                    currentProgram.endTransaction(tx, success);
                }
                return success;
            } finally {
                decomp.dispose();
            }
        } catch (Exception e) {
            println("Error setting variable type: " + e.getMessage());
            return false;
        }
    }

    // ----------------------------------------------------------------------------------
    // Cross-references
    // ----------------------------------------------------------------------------------

    private String getXrefsTo(String addressStr, int offset, int limit) {
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";

        try {
            Address addr = currentProgram.getAddressFactory().getAddress(addressStr);
            ReferenceManager refManager = currentProgram.getReferenceManager();

            ReferenceIterator refIter = refManager.getReferencesTo(addr);

            List<String> refs = new ArrayList<>();
            while (refIter.hasNext()) {
                Reference ref = refIter.next();
                Address fromAddr = ref.getFromAddress();
                RefType refType = ref.getReferenceType();

                Function fromFunc = currentProgram.getFunctionManager().getFunctionContaining(fromAddr);
                String funcInfo = (fromFunc != null) ? " in " + fromFunc.getName() : "";

                refs.add(String.format("From %s%s [%s]", fromAddr, funcInfo, refType.getName()));
            }

            return paginateList(refs, offset, limit);
        } catch (Exception e) {
            return "Error getting references to address: " + e.getMessage();
        }
    }

    private String getXrefsFrom(String addressStr, int offset, int limit) {
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";

        try {
            Address addr = currentProgram.getAddressFactory().getAddress(addressStr);
            ReferenceManager refManager = currentProgram.getReferenceManager();

            Reference[] references = refManager.getReferencesFrom(addr);

            List<String> refs = new ArrayList<>();
            for (Reference ref : references) {
                Address toAddr = ref.getToAddress();
                RefType refType = ref.getReferenceType();

                String targetInfo = "";
                Function toFunc = currentProgram.getFunctionManager().getFunctionAt(toAddr);
                if (toFunc != null) {
                    targetInfo = " to function " + toFunc.getName();
                } else {
                    Data data = currentProgram.getListing().getDataAt(toAddr);
                    if (data != null) {
                        targetInfo = " to data " + (data.getLabel() != null ? data.getLabel() : data.getPathName());
                    }
                }

                refs.add(String.format("To %s%s [%s]", toAddr, targetInfo, refType.getName()));
            }

            return paginateList(refs, offset, limit);
        } catch (Exception e) {
            return "Error getting references from address: " + e.getMessage();
        }
    }

    private String getFunctionXrefs(String functionName, int offset, int limit) {
        if (functionName == null || functionName.isEmpty()) return "Function name is required";

        try {
            List<String> refs = new ArrayList<>();
            FunctionManager funcManager = currentProgram.getFunctionManager();
            for (Function function : funcManager.getFunctions(true)) {
                if (function.getName().equals(functionName)) {
                    Address entryPoint = function.getEntryPoint();
                    ReferenceIterator refIter = currentProgram.getReferenceManager().getReferencesTo(entryPoint);

                    while (refIter.hasNext()) {
                        Reference ref = refIter.next();
                        Address fromAddr = ref.getFromAddress();
                        RefType refType = ref.getReferenceType();

                        Function fromFunc = funcManager.getFunctionContaining(fromAddr);
                        String funcInfo = (fromFunc != null) ? " in " + fromFunc.getName() : "";

                        refs.add(String.format("From %s%s [%s]", fromAddr, funcInfo, refType.getName()));
                    }
                }
            }

            if (refs.isEmpty()) {
                return "No references found to function: " + functionName;
            }

            return paginateList(refs, offset, limit);
        } catch (Exception e) {
            return "Error getting function references: " + e.getMessage();
        }
    }

    // ----------------------------------------------------------------------------------
    // Strings
    // ----------------------------------------------------------------------------------

    private String listDefinedStrings(int offset, int limit, String filter) {
        List<String> lines = new ArrayList<>();
        DataIterator dataIt = currentProgram.getListing().getDefinedData(true);

        while (dataIt.hasNext()) {
            Data data = dataIt.next();

            if (data != null && isStringData(data)) {
                String value = data.getValue() != null ? data.getValue().toString() : "";

                if (filter == null || value.toLowerCase().contains(filter.toLowerCase())) {
                    String escapedValue = escapeString(value);
                    lines.add(String.format("%s: \"%s\"", data.getAddress(), escapedValue));
                }
            }
        }

        return paginateList(lines, offset, limit);
    }

    private boolean isStringData(Data data) {
        if (data == null) return false;
        DataType dt = data.getDataType();
        String typeName = dt.getName().toLowerCase();
        return typeName.contains("string") || typeName.contains("char") || typeName.equals("unicode");
    }

    private String escapeString(String input) {
        if (input == null) return "";
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < input.length(); i++) {
            char c = input.charAt(i);
            if (c >= 32 && c < 127) {
                sb.append(c);
            } else if (c == '\n') {
                sb.append("\\n");
            } else if (c == '\r') {
                sb.append("\\r");
            } else if (c == '\t') {
                sb.append("\\t");
            } else {
                sb.append(String.format("\\x%02x", (int)c & 0xFF));
            }
        }
        return sb.toString();
    }

    // ----------------------------------------------------------------------------------
    // Additional endpoints: callers, data types, memory search
    // ----------------------------------------------------------------------------------

    private String getCallers(String addressStr) {
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";

        try {
            Address addr = currentProgram.getAddressFactory().getAddress(addressStr);
            Function func = getFunctionForAddress(addr);
            if (func == null) return "No function found at " + addressStr;

            Set<Function> callingFunctions = func.getCallingFunctions(monitor);
            List<String> results = new ArrayList<>();
            for (Function caller : callingFunctions) {
                results.add(String.format("%s @ %s", caller.getName(), caller.getEntryPoint()));
            }

            if (results.isEmpty()) return "No callers found for " + func.getName();
            Collections.sort(results);
            return String.join("\n", results);
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    private String listDataTypes(String filter, int offset, int limit) {
        DataTypeManager dtm = currentProgram.getDataTypeManager();
        List<String> types = new ArrayList<>();
        Iterator<DataType> allTypes = dtm.getAllDataTypes();
        while (allTypes.hasNext()) {
            DataType dt = allTypes.next();
            String entry = String.format("%s (%d bytes)", dt.getPathName(), dt.getLength());
            if (filter == null || dt.getName().toLowerCase().contains(filter.toLowerCase())) {
                types.add(entry);
            }
        }
        Collections.sort(types);
        return paginateList(types, offset, limit);
    }

    private String searchMemory(String patternHex, int maxResults) {
        if (patternHex == null || patternHex.isEmpty()) return "Hex pattern is required (e.g., '48 8b 05' or '488b05')";

        try {
            String clean = patternHex.replaceAll("\\s+", "");
            if (clean.length() % 2 != 0) return "Invalid hex pattern: odd number of characters";

            byte[] pattern = new byte[clean.length() / 2];
            for (int i = 0; i < pattern.length; i++) {
                pattern[i] = (byte) Integer.parseInt(clean.substring(i * 2, i * 2 + 2), 16);
            }

            List<String> results = new ArrayList<>();
            ghidra.program.model.mem.Memory memory = currentProgram.getMemory();
            Address start = memory.getMinAddress();
            int found = 0;

            while (start != null && found < maxResults) {
                Address addr = memory.findBytes(start, pattern, null, true, monitor);
                if (addr == null) break;

                Function func = currentProgram.getFunctionManager().getFunctionContaining(addr);
                String funcInfo = (func != null) ? " in " + func.getName() : "";
                results.add(String.format("%s%s", addr, funcInfo));
                found++;

                start = addr.add(1);
            }

            if (results.isEmpty()) return "Pattern not found";
            return String.join("\n", results);
        } catch (Exception e) {
            return "Error searching memory: " + e.getMessage();
        }
    }

    // ----------------------------------------------------------------------------------
    // Async decompilation
    // ----------------------------------------------------------------------------------

    private String startAsyncDecompile(String addressStr) {
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";
        if (asyncTasks.size() >= MAX_ASYNC_TASKS) {
            asyncTasks.entrySet().removeIf(e -> e.getValue().isExpired());
            if (asyncTasks.size() >= MAX_ASYNC_TASKS) {
                return "Too many pending tasks. Please wait for existing tasks to complete.";
            }
        }

        String taskId = "task-" + taskCounter.incrementAndGet();
        AsyncTask task = new AsyncTask(taskId);
        asyncTasks.put(taskId, task);

        asyncExecutor.submit(() -> {
            try {
                Address addr = currentProgram.getAddressFactory().getAddress(addressStr);
                Function func = getFunctionForAddress(addr);
                if (func == null) {
                    task.fail("No function found at or containing address " + addressStr);
                    return;
                }

                DecompInterface decomp = new DecompInterface();
                try {
                    decomp.openProgram(currentProgram);
                    DecompileResults result = decomp.decompileFunction(func, 300, new ConsoleTaskMonitor());

                    if (result != null && result.decompileCompleted()) {
                        task.complete(result.getDecompiledFunction().getC());
                    } else {
                        task.fail("Decompilation failed");
                    }
                } finally {
                    decomp.dispose();
                }
            } catch (Exception e) {
                task.fail("Error: " + e.getMessage());
            }
        });

        return "task_id=" + taskId;
    }

    private String getTaskStatus(String taskId) {
        if (taskId == null || taskId.isEmpty()) return "task_id is required";
        AsyncTask task = asyncTasks.get(taskId);
        if (task == null) return "Task not found: " + taskId;

        long elapsed = System.currentTimeMillis() - task.createdAt;
        return String.format("task_id=%s\nstate=%s\nelapsed_ms=%d", task.id, task.state, elapsed);
    }

    private String getTaskResult(String taskId) {
        if (taskId == null || taskId.isEmpty()) return "task_id is required";
        AsyncTask task = asyncTasks.get(taskId);
        if (task == null) return "Task not found: " + taskId;
        if ("running".equals(task.state)) return "Task still running";
        return task.result;
    }

    // ----------------------------------------------------------------------------------
    // Data manipulation methods
    // ----------------------------------------------------------------------------------

    private String clearData(String addressStr, String lengthStr) {
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";

        int tx = currentProgram.startTransaction("Clear data");
        boolean success = false;
        StringBuilder result = new StringBuilder();
        try {
            Address addr = currentProgram.getAddressFactory().getAddress(addressStr);
            int length = 1;
            if (lengthStr != null && !lengthStr.isEmpty()) {
                length = Integer.parseInt(lengthStr);
            } else {
                Data data = currentProgram.getListing().getDataAt(addr);
                if (data != null) {
                    length = data.getLength();
                }
            }
            currentProgram.getListing().clearCodeUnits(addr, addr.add(length - 1), false);
            success = true;
            result.append("Cleared ").append(length).append(" bytes at ").append(addressStr);
        } catch (Exception e) {
            result.append("Error: ").append(e.getMessage());
        } finally {
            currentProgram.endTransaction(tx, success);
        }
        return result.toString();
    }

    private String defineData(String addressStr, String dataTypeName) {
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";
        if (dataTypeName == null || dataTypeName.isEmpty()) return "Data type is required";

        int tx = currentProgram.startTransaction("Define data");
        boolean success = false;
        StringBuilder result = new StringBuilder();
        try {
            Address addr = currentProgram.getAddressFactory().getAddress(addressStr);
            DataTypeManager dtm = currentProgram.getDataTypeManager();
            DataType dt = resolveDataType(dtm, dataTypeName);
            if (dt == null) {
                result.append("Unknown data type: ").append(dataTypeName);
                return result.toString();
            }
            currentProgram.getListing().clearCodeUnits(addr, addr.add(dt.getLength() - 1), false);
            currentProgram.getListing().createData(addr, dt);
            success = true;
            result.append("Defined ").append(dataTypeName).append(" at ").append(addressStr);
        } catch (Exception e) {
            result.append("Error: ").append(e.getMessage());
        } finally {
            currentProgram.endTransaction(tx, success);
        }
        return result.toString();
    }

    private String readBytes(String addressStr, int length) {
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";
        if (length <= 0 || length > 4096) return "Length must be between 1 and 4096";

        try {
            Address addr = currentProgram.getAddressFactory().getAddress(addressStr);
            byte[] bytes = new byte[length];
            int bytesRead = currentProgram.getMemory().getBytes(addr, bytes);

            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < bytesRead; i++) {
                if (i > 0) sb.append(" ");
                sb.append(String.format("%02x", bytes[i] & 0xFF));
            }
            return sb.toString();
        } catch (Exception e) {
            return "Error reading bytes: " + e.getMessage();
        }
    }

    private String getDataAt(String addressStr) {
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";

        try {
            Address addr = currentProgram.getAddressFactory().getAddress(addressStr);
            Data data = currentProgram.getListing().getDataAt(addr);
            if (data == null) {
                data = currentProgram.getListing().getDataContaining(addr);
            }
            if (data == null) return "No data defined at " + addressStr;

            String label = data.getLabel() != null ? data.getLabel() : "(unnamed)";
            return String.format("Address: %s\nLabel: %s\nType: %s\nLength: %d\nValue: %s",
                data.getAddress(), label, data.getDataType().getName(),
                data.getLength(), data.getDefaultValueRepresentation());
        } catch (Exception e) {
            return "Error getting data: " + e.getMessage();
        }
    }

    private String createLabel(String addressStr, String name) {
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";
        if (name == null || name.isEmpty()) return "Label name is required";

        int tx = currentProgram.startTransaction("Create label");
        boolean success = false;
        try {
            Address addr = currentProgram.getAddressFactory().getAddress(addressStr);
            currentProgram.getSymbolTable().createLabel(addr, name, SourceType.USER_DEFINED);
            success = true;
        } catch (Exception e) {
            println("Error creating label: " + e.getMessage());
        } finally {
            currentProgram.endTransaction(tx, success);
        }
        return success ? "Label '" + name + "' created at " + addressStr : "Failed to create label";
    }

    private String createEnum(String name, int size, String membersStr) {
        if (name == null || name.isEmpty()) return "Enum name is required";
        if (membersStr == null || membersStr.isEmpty()) return "Members are required (format: NAME1:0;NAME2:1)";

        int tx = currentProgram.startTransaction("Create enum");
        boolean success = false;
        StringBuilder result = new StringBuilder();
        try {
            DataTypeManager dtm = currentProgram.getDataTypeManager();
            ghidra.program.model.data.EnumDataType enumDt =
                new ghidra.program.model.data.EnumDataType(name, size);

            int count = 0;
            for (String member : membersStr.split(";")) {
                String[] parts = member.trim().split(":", 2);
                if (parts.length == 2) {
                    enumDt.add(parts[0].trim(), Long.parseLong(parts[1].trim()));
                    count++;
                }
            }

            dtm.addDataType(enumDt, ghidra.program.model.data.DataTypeConflictHandler.REPLACE_HANDLER);
            success = true;
            result.append("Created enum '").append(name).append("' with ").append(count).append(" members");
        } catch (Exception e) {
            result.append("Error: ").append(e.getMessage());
        } finally {
            currentProgram.endTransaction(tx, success);
        }
        return result.toString();
    }

    private String createStruct(String name, String fieldsStr) {
        if (name == null || name.isEmpty()) return "Struct name is required";
        if (fieldsStr == null || fieldsStr.isEmpty()) return "Fields are required (format: name1:type1;name2:type2)";

        int tx = currentProgram.startTransaction("Create struct");
        boolean success = false;
        StringBuilder result = new StringBuilder();
        try {
            DataTypeManager dtm = currentProgram.getDataTypeManager();
            ghidra.program.model.data.StructureDataType structDt =
                new ghidra.program.model.data.StructureDataType(name, 0);

            int count = 0;
            for (String field : fieldsStr.split(";")) {
                String[] parts = field.trim().split(":", 2);
                if (parts.length == 2) {
                    String fieldName = parts[0].trim();
                    String fieldType = parts[1].trim();
                    DataType dt = resolveDataType(dtm, fieldType);
                    if (dt != null) {
                        structDt.add(dt, fieldName, null);
                        count++;
                    }
                }
            }

            dtm.addDataType(structDt, ghidra.program.model.data.DataTypeConflictHandler.REPLACE_HANDLER);
            success = true;
            result.append("Created struct '").append(name).append("' with ").append(count).append(" fields");
        } catch (Exception e) {
            result.append("Error: ").append(e.getMessage());
        } finally {
            currentProgram.endTransaction(tx, success);
        }
        return result.toString();
    }

    private String applyStruct(String addressStr, String structName) {
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";
        if (structName == null || structName.isEmpty()) return "Struct name is required";

        int tx = currentProgram.startTransaction("Apply struct");
        boolean success = false;
        StringBuilder result = new StringBuilder();
        try {
            Address addr = currentProgram.getAddressFactory().getAddress(addressStr);
            DataTypeManager dtm = currentProgram.getDataTypeManager();
            DataType dt = findDataTypeByNameInAllCategories(dtm, structName);
            if (dt == null) {
                result.append("Struct not found: ").append(structName);
                return result.toString();
            }
            currentProgram.getListing().clearCodeUnits(addr, addr.add(dt.getLength() - 1), false);
            currentProgram.getListing().createData(addr, dt);
            success = true;
            result.append("Applied struct '").append(structName).append("' at ").append(addressStr);
        } catch (Exception e) {
            result.append("Error: ").append(e.getMessage());
        } finally {
            currentProgram.endTransaction(tx, success);
        }
        return result.toString();
    }

    // ----------------------------------------------------------------------------------
    // Data type resolution helpers
    // ----------------------------------------------------------------------------------

    private DataType resolveDataType(DataTypeManager dtm, String typeName) {
        DataType dataType = findDataTypeByNameInAllCategories(dtm, typeName);
        if (dataType != null) {
            return dataType;
        }

        // Check for Windows-style pointer types (PXXX)
        if (typeName.startsWith("P") && typeName.length() > 1) {
            String baseTypeName = typeName.substring(1);

            if (baseTypeName.equals("VOID")) {
                return new PointerDataType(dtm.getDataType("/void"));
            }

            DataType baseType = findDataTypeByNameInAllCategories(dtm, baseTypeName);
            if (baseType != null) {
                return new PointerDataType(baseType);
            }

            return new PointerDataType(dtm.getDataType("/void"));
        }

        // Handle common built-in types
        switch (typeName.toLowerCase()) {
            case "int":
            case "long":
                return dtm.getDataType("/int");
            case "uint":
            case "unsigned int":
            case "unsigned long":
            case "dword":
                return dtm.getDataType("/uint");
            case "short":
                return dtm.getDataType("/short");
            case "ushort":
            case "unsigned short":
            case "word":
                return dtm.getDataType("/ushort");
            case "char":
            case "byte":
                return dtm.getDataType("/char");
            case "uchar":
            case "unsigned char":
                return dtm.getDataType("/uchar");
            case "float":
                return dtm.getDataType("/float");
            case "double":
                return dtm.getDataType("/double");
            case "qword":
            case "longlong":
            case "__int64":
                return dtm.getDataType("/longlong");
            case "uqword":
            case "ulonglong":
            case "unsigned __int64":
                return dtm.getDataType("/ulonglong");
            case "pointer":
            case "addr":
                return new PointerDataType();
            case "bool":
            case "boolean":
                return dtm.getDataType("/bool");
            case "void":
                return dtm.getDataType("/void");
            default:
                DataType directType = dtm.getDataType("/" + typeName);
                if (directType != null) {
                    return directType;
                }
                println("Unknown type: " + typeName + ", defaulting to int");
                return dtm.getDataType("/int");
        }
    }

    private DataType findDataTypeByNameInAllCategories(DataTypeManager dtm, String typeName) {
        DataType result = searchByNameInAllCategories(dtm, typeName);
        if (result != null) {
            return result;
        }
        return searchByNameInAllCategories(dtm, typeName.toLowerCase());
    }

    private DataType searchByNameInAllCategories(DataTypeManager dtm, String name) {
        Iterator<DataType> allTypes = dtm.getAllDataTypes();
        while (allTypes.hasNext()) {
            DataType dt = allTypes.next();
            if (dt.getName().equals(name)) {
                return dt;
            }
            if (dt.getName().equalsIgnoreCase(name)) {
                return dt;
            }
        }
        return null;
    }

    // ----------------------------------------------------------------------------------
    // Utility methods
    // ----------------------------------------------------------------------------------

    private Map<String, String> parseQueryParams(HttpExchange exchange) {
        Map<String, String> result = new HashMap<>();
        String query = exchange.getRequestURI().getQuery();
        if (query != null) {
            String[] pairs = query.split("&");
            for (String p : pairs) {
                String[] kv = p.split("=", 2);
                if (kv.length == 2) {
                    try {
                        String key = URLDecoder.decode(kv[0], StandardCharsets.UTF_8);
                        String value = URLDecoder.decode(kv[1], StandardCharsets.UTF_8);
                        result.put(key, value);
                    } catch (Exception e) {
                        println("Error decoding URL parameter: " + e.getMessage());
                    }
                }
            }
        }
        return result;
    }

    private Map<String, String> parsePostParams(HttpExchange exchange) throws IOException {
        byte[] body = exchange.getRequestBody().readAllBytes();
        String bodyStr = new String(body, StandardCharsets.UTF_8);
        Map<String, String> params = new HashMap<>();
        for (String pair : bodyStr.split("&")) {
            String[] kv = pair.split("=", 2);
            if (kv.length == 2) {
                try {
                    String key = URLDecoder.decode(kv[0], StandardCharsets.UTF_8);
                    String value = URLDecoder.decode(kv[1], StandardCharsets.UTF_8);
                    params.put(key, value);
                } catch (Exception e) {
                    println("Error decoding URL parameter: " + e.getMessage());
                }
            }
        }
        return params;
    }

    private String paginateList(List<String> items, int offset, int limit) {
        int start = Math.max(0, offset);
        int end   = Math.min(items.size(), offset + limit);

        if (start >= items.size()) {
            return "";
        }
        List<String> sub = items.subList(start, end);
        return String.join("\n", sub);
    }

    private int parseIntOrDefault(String val, int defaultValue) {
        if (val == null) return defaultValue;
        try {
            return Integer.parseInt(val);
        } catch (NumberFormatException e) {
            return defaultValue;
        }
    }

    private String escapeNonAscii(String input) {
        if (input == null) return "";
        StringBuilder sb = new StringBuilder();
        for (char c : input.toCharArray()) {
            if (c >= 32 && c < 127) {
                sb.append(c);
            } else if (c > 0xFF) {
                sb.append(String.format("\\u%04x", (int) c));
            } else {
                sb.append(String.format("\\x%02x", (int) c & 0xFF));
            }
        }
        return sb.toString();
    }

    private void sendResponse(HttpExchange exchange, String response) throws IOException {
        byte[] bytes = response.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "text/plain; charset=utf-8");
        exchange.sendResponseHeaders(200, bytes.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(bytes);
        }
    }
}
