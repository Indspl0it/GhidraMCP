# Changelog

## v2.0.0 (2026-04-05)

Major release with new features, Ghidra 12.x support, headless mode, and bug fixes. Incorporates community contributions from upstream PRs.

### Breaking Changes
- Upgraded to Ghidra 12.0.4 (Java 21 required)
- Replaced deprecated `CodeUnit` comment constants with `CommentType` enums (Ghidra 12.x API)

### New Features

#### Headless Mode
- Added `GhidraMCPServerScript.java` for running without Ghidra GUI
- Added `run_headless.sh` helper script for quick setup
- Full API parity with GUI plugin (except cursor-dependent endpoints)
- Ideal for servers and remote access

#### Program Analysis
- `GET /program_info` - Architecture, language, compiler, base address, format, SHA256, memory layout
- `GET /get_callees` - Functions called by a function
- `GET /get_callers` - Functions calling a function
- `GET /list_data_types` - Browse available data types with filter and pagination
- `GET /search_memory` - Search for hex byte patterns in memory

#### Data Manipulation (from upstream PR #139)
- `POST /clear_data` - Clear defined data at an address
- `POST /define_data` - Define a data type at an address
- `GET /read_bytes` - Read raw bytes from memory
- `GET /get_data_at` - Get data info at an address
- `POST /create_label` - Create a symbol/label
- `POST /create_enum` - Create enum data type
- `POST /create_struct` - Create struct data type
- `POST /apply_struct` - Apply struct at an address
- Extended `resolveDataType` with float, double, qword, pointer types

#### Async Decompilation (from upstream PR #124)
- `GET /decompile_async` - Non-blocking decompilation returning task_id
- `GET /task_status` - Poll task state (running/completed/error)
- `GET /task_result` - Retrieve completed result
- Bounded task pool (max 50 concurrent), 30-minute TTL with automatic cleanup

#### Comments (from upstream PR #128)
- `POST /set_plate_comment` - Set plate comments (banner-style)

### Bug Fixes
- Fixed `parsePostParams` to use `split("=", 2)` allowing `=` in parameter values (from upstream PR #128)

### Python Bridge
- Added MCP tool functions for all new endpoints
- Added `safe_get_long()` for long-timeout async operations

### Credits
Incorporates work from upstream PRs by:
- @0pendev (PR #126 - localhost binding)
- @jethac (PR #124 - async decompilation)
- @dj0nes (PR #139 - data manipulation)
- @dyingc (PR #128 - plate comment, split fix)
- @kariemoorman (PR #118 - CommentType deprecation fix)
- @ozymand-AI-s (PR #132 - Ghidra 12.x support)
