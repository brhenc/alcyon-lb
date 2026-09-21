# HAProxy Runtime API (CLI) Command Inventory & Output Specifications

**Oracle:** HAProxy C source codebase `/home/bhenc/reference/haproxy` @ commit `e6f616af97c93c1d8945cf8cfd77a1c8e36a2640` (3.5-dev7).

---

## 1. Overview & Extraction Methodology

CLI commands in HAProxy are registered at startup via `INITCALL1(STG_REGISTER, cli_register_kw, &cli_kws)`. Each module declares a `struct cli_kw_list` containing an array of `struct cli_kw` definitions terminated by `{ { NULL }, NULL, ... }`.

Each `struct cli_kw` specifies:
- `str_kw`: An array of up to 5 keyword components (e.g. `{"show", "stat", NULL}`).
- `usage`: The verbatim help/usage text string (or `NULL` if internal/unlisted).
- `parse`: Function pointer `int (*parse)(char **args, char *payload, struct appctx *appctx, void *private)`.
- `io_handler`: Function pointer `int (*io_handler)(struct appctx *appctx)`.
- `io_release`: Function pointer `void (*io_release)(struct appctx *appctx)`.
- `private`: Private pointer passed to the parser / IO handler.
- `level`: Access level flags (`ACCESS_LVL_*`, `ACCESS_MASTER`, `ACCESS_MASTER_ONLY`, `ACCESS_EXPERT`, `ACCESS_EXPERIMENTAL`).

Across all 26 source files containing CLI keyword registrations, exactly **172 CLI commands** are defined.

---

## 2. Detailed Output Format Specifications

The following sections document the **exact output format** implemented by the respective `io_handler` and `parse` functions in the C source code.

---

### 2.1 `show info`

- **Source Citation:** [`src/stats.c:1380`](file:///home/bhenc/reference/haproxy/src/stats.c#L1380)
- **Handler Functions:** Parse: `cli_parse_show_info` ([`src/stats.c:937`](file:///home/bhenc/reference/haproxy/src/stats.c#L937)), IO Handler: `cli_io_handler_dump_info` ([`src/stats.c:1037`](file:///home/bhenc/reference/haproxy/src/stats.c#L1037)), Output Generator: `stats_dump_info_to_buffer` ([`src/stats.c:860`](file:///home/bhenc/reference/haproxy/src/stats.c#L860)), `stats_dump_info_fields` ([`src/stats.c:654`](file:///home/bhenc/reference/haproxy/src/stats.c#L654)).
- **Required Access Level:** `ACCESS_LVL_NONE` (accessible at all CLI access levels).

#### Output Formats & Variants

1. **Default Format (`show info`):**
   - Emits key-value pairs formatted as `<Name>: <Value>
`.
   - Field separator: `: ` (colon followed by space).
   - Record separator / Line terminator: `
` (newline).
   - Empty result: Not possible in a running process; all standard process statistics fields are populated.

2. **Description Variant (`show info desc`):**
   - Appends field descriptions: `<Name>: <Value>:"<Description>"
`.

3. **Typed Variant (`show info typed`):**
   - Format: `<Index>.<Name>.<ProcessNum>:<Tags>:<Type>:<Value>
`
   - Colon-separated tagged metric format for machine parsing.

4. **JSON Variant (`show info json`):**
   - Generates a valid JSON object structure mapping info metric names to typed value objects.

#### Field Order (`stat_cols_info[ST_I_INF_MAX]` defined in [`src/stats.c:95-180`](file:///home/bhenc/reference/haproxy/src/stats.c#L95-L180)):
1. `Name` (Product name: "HAProxy")
2. `Version` (Product version, e.g. "3.5-dev7-e6f616-55")
3. `Release_date` (Source update date, e.g. "2026/09/21")
4. `Nbthread` (Number of started threads)
5. `Nbproc` (Historical worker process count, always 1)
6. `Process_num` (Relative worker process number, e.g. 1)
7. `Pid` (Worker process PID)
8. `Uptime` (Human readable uptime: days, hours, mins, secs)
9. `Uptime_sec` (Uptime in seconds)
10. `Start_time_sec` (Start timestamp in seconds)
11. `Memmax_MB` (Memory limit in MB)
12. `Memmax_bytes` (Memory limit in bytes)
13. `PoolAlloc_MB` (Allocated pool memory in MB)
14. `PoolAlloc_bytes` (Allocated pool memory in bytes)
15. `PoolUsed_MB` (Used pool memory in MB)
16. `PoolUsed_bytes` (Used pool memory in bytes)
17. `PoolFailed` (Failed pool allocations)
18. `Ulimit-n` (Hard file descriptor limit)
19. `Maxsock` (Max open sockets limit)
20. `Maxconn` (Process max connection limit)
21. `Hard_maxconn` (Hard max connections limit)
22. `CurrConns` (Current connection count)
23. `CumConns` (Cumulative connection count)
24. `CumReq` (Cumulative request count)
25. `MaxSslConns` (Max SSL endpoints limit)
26. `CurrSslConns` (Current SSL endpoints)
27. `CumSslConns` (Cumulative SSL endpoints)
28. `Maxpipes` (Max splice pipes)
29. `PipesUsed` (Pipes in use)
30. `PipesFree` (Pipes free)
31. `ConnRate` (Current connection rate per second)
32. `ConnRateLimit` (Configured connection rate limit)
33. `MaxConnRate` (Peak connection rate)
34. `SessRate` (Current session rate per second)
35. `SessRateLimit` (Configured session rate limit)
36. `MaxSessRate` (Peak session rate)
37. `SslRate` (Current SSL rate)
38. `SslRateLimit` (Configured SSL rate limit)
39. `MaxSslRate` (Peak SSL rate)
40. `SslFrontendKeyRate` (Frontend SSL key generation rate)
41. `SslFrontendMaxKeyRate` (Frontend SSL peak key rate)
42. `SslFrontendSessionReuse_pct` (Frontend SSL session reuse percentage)
43. `SslBackendKeyRate` (Backend SSL key generation rate)
44. `SslBackendMaxKeyRate` (Backend SSL peak key rate)
45. `SslCacheLookups` (SSL session cache lookups)
46. `SslCacheMisses` (SSL session cache misses)
47. `CompressBpsIn` (HTTP compression bytes in/s)
48. `CompressBpsOut` (HTTP compression bytes out/s)
49. `CompressBpsRateLim` (HTTP compression rate limit)
50. `ZlibMemUsage` (Zlib compression memory usage)
51. `MaxZlibMemUsage` (Max Zlib memory limit)
52. `Tasks` (Active and sleeping tasks)
53. `Run_queue` (Run queue tasks + tasklets)
54. `Idle_pct` (Idle percentage over last second)
55. `node` (Node name)
56. `description` (Node description)
57. `Stopping` (Worker stopping status: 0 or 1)
58. `Jobs` (Active jobs: frontend/master/listeners)
59. `Unstoppable Jobs` (Unstoppable jobs: master conns)
60. `Listeners` (Active listeners)
61. `ActivePeers` (Active peers count)
62. `ConnectedPeers` (Connected peers count)
63. `DroppedLogs` (Dropped log count)
64. `BusyPolling` (Busy polling state: 0 or 1)
65. `FailedResolutions` (Failed DNS resolutions)
66. `TotalBytesOut` (Total bytes sent)
67. `TotalSplicedBytesOut` (Total bytes sent via splice)
68. `BytesOutRate` (Bytes out per second)
69. `DebugCommandsIssued` (Debug commands count)
70. `CumRecvLogs` (Cumulative logs received)
71. `Build info` (Build compile information)
72. `Tainted` (Tainted flags integer)
73. `TotalWarnings` (Total warnings emitted)
74. `MaxconnReached` (Maxconn reached count)
75. `BootTime_ms` (Config parse & startup time in ms)
76. `Niced_tasks` (Niced tasks count)
77. `CurrStreams` (Current active streams)
78. `CumStreams` (Cumulative streams count)
79. `BlockedTrafficWarnings` (Blocked traffic warnings)
80. `PatternsAdded` (ACL/map patterns added)
81. `PatternsFreed` (ACL/map patterns freed)
82. `NbThreadGroups` (Thread groups count)
83. `Master_id` (Master ID, if present)
84. `Worker_id` (Worker ID, if present)

---

### 2.2 `show stat`

- **Source Citation:** [`src/stats.c:1381`](file:///home/bhenc/reference/haproxy/src/stats.c#L1381)
- **Handler Functions:** Parse: `cli_parse_show_stat` ([`src/stats.c:962`](file:///home/bhenc/reference/haproxy/src/stats.c#L962)), IO Handler: `cli_io_handler_dump_stat` ([`src/stats.c:1047`](file:///home/bhenc/reference/haproxy/src/stats.c#L1047)), Release: `cli_io_handler_release_stat` ([`src/stats.c:1054`](file:///home/bhenc/reference/haproxy/src/stats.c#L1054)), Engine: `stats_dump_stat_to_buffer` ([`src/stats.c:553`](file:///home/bhenc/reference/haproxy/src/stats.c#L553)), Header: `stats_dump_csv_header` ([`src/stats.c:332`](file:///home/bhenc/reference/haproxy/src/stats.c#L332)).
- **Required Access Level:** `ACCESS_LVL_NONE` (accessible to all; operators/admins see additional fields like `addr`, `cookie`, `algo` when `STAT_F_SHLGNDS` is enabled).

#### Output Formats & Variants

1. **Default Format (`show stat`):**
   - Format: CSV (Comma-Separated Values).
   - Header Line: `# ` followed by comma-separated column names, ending with `,` and a newline `
`.
     - Special delimiter `-,` is output after static proxy fields (`ST_I_PX_MAX`).
   - Data Lines: One line per object (Frontend, Listener, Backend, Server) formatted as `<val1>,<val2>,...,<valN>,
`.
   - Field Separator: `,` (comma).
   - Line Terminator: `
` (newline).
   - Every line (header and data) ends with a trailing comma `,` followed immediately by `
`.
   - Empty values: Rendered as empty strings between delimiters (e.g. `,,`).
   - Empty result: If no proxies or servers are configured, the command outputs solely the header row `# pxname,svname,...,-,
`.

2. **Field Order (`stat_cols_px` defined in [`src/stats-proxy.c:79-170`](file:///home/bhenc/reference/haproxy/src/stats-proxy.c#L79-L170)):**
   1. `pxname`: Proxy name
   2. `svname`: Server / component name (`FRONTEND`, `BACKEND`, or server name)
   3. `qcur`: Current queue
   4. `qmax`: Max queue
   5. `scur`: Current sessions
   6. `smax`: Max sessions
   7. `slim`: Session limit
   8. `stot`: Cumulative sessions
   9. `bin`: Bytes in
   10. `bout`: Bytes out
   11. `dreq`: Denied requests
   12. `dresp`: Denied responses
   13. `ereq`: Request errors
   14. `econ`: Connection errors
   15. `eresp`: Response errors
   16. `wretr`: Retry warnings
   17. `wredis`: Redispatch warnings
   18. `status`: Status (`OPEN`, `UP`, `DOWN`, `MAINT`, `DRAIN`, `NOLB`, etc.)
   19. `weight`: Server weight / backend active weight
   20. `act`: Active UP servers count
   21. `bck`: Backup UP servers count
   22. `chkfail`: Check failures
   23. `chkdown`: Transitions to DOWN
   24. `lastchg`: Time since last state change (seconds)
   25. `downtime`: Total downtime (seconds)
   26. `qlimit`: Queue limit
   27. `pid`: Process number (1)
   28. `iid`: Proxy numeric ID
   29. `sid`: Server numeric ID
   30. `throttle`: Slowstart throttle ratio
   31. `lbtot`: Total loadbalanced connections
   32. `tracked`: Tracked server name
   33. `type`: Component type (0=frontend, 1=backend, 2=server, 3=listener)
   34. `rate`: Current session / request rate
   35. `rate_lim`: Rate limit
   36. `rate_max`: Max observed rate
   37. `check_status`: Health check status
   38. `check_code`: Health check HTTP/TCP response code
   39. `check_duration`: Check duration (ms)
   40. `hrsp_1xx`: HTTP 1xx responses
   41. `hrsp_2xx`: HTTP 2xx responses
   42. `hrsp_3xx`: HTTP 3xx responses
   43. `hrsp_4xx`: HTTP 4xx responses
   44. `hrsp_5xx`: HTTP 5xx responses
   45. `hrsp_other`: HTTP other responses
   46. `hanafail`: Failed health analysis checks
   47. `req_rate`: Frontend HTTP request rate
   48. `req_rate_max`: Frontend peak request rate
   49. `req_tot`: Cumulative HTTP requests
   50. `cli_abrt`: Client connection aborts
   51. `srv_abrt`: Server connection aborts
   52. `comp_in`: Compressor bytes in
   53. `comp_out`: Compressor bytes out
   54. `comp_byp`: Compressor bytes bypassed
   55. `comp_rsp`: Compressed responses count
   56. `lastsess`: Seconds since last session
   57. `last_chk`: Short health check description
   58. `last_agt`: Short agent check description
   59. `qtime`: Average queue time (ms)
   60. `ctime`: Average connect time (ms)
   61. `rtime`: Average response time (ms)
   62. `ttime`: Average total session time (ms)
   63. `agent_status`: Agent check status
   64. `agent_code`: Agent check return code
   65. `agent_duration`: Agent check duration (ms)
   66. `check_desc`: Health check text description
   67. `agent_desc`: Agent check text description
   68. `check_rise`: Check rise threshold
   69. `check_fall`: Check fall threshold
   70. `check_health`: Check health level
   71. `agent_rise`: Agent rise threshold
   72. `agent_fall`: Agent fall threshold
   73. `agent_health`: Agent health level
   74. `addr`: Server address:port (if oper/admin)
   75. `cookie`: Cookie name / value (if oper/admin)
   76. `mode`: Proxy mode (`tcp`, `http`, etc.)
   77. `algo`: Load balancing algorithm
   78. `conn_rate`: Frontend connection rate
   79. `conn_rate_max`: Frontend peak connection rate
   80. `conn_tot`: Frontend cumulative connections
   81. `intercepted`: Intercepted requests
   82. `dcon`: Denied connections
   83. `dses`: Denied sessions
   84. `wrew`: Failed header rewrites
   85. `connect`: Outgoing connection attempts
   86. `reuse`: Reused server connections
   87. `cache_lookups`: HTTP cache lookups
   88. `cache_hits`: HTTP cache hits
   89. `srv_icur`: Idle connections current
   90. `src_ilim`: Idle connections limit
   91. `srv_smax`: Safe idle connections max
   92. `uweight`: User configured weight
   93. `agg_server_check_status`: Aggregated check status
   94. `bck_act`: Active backup servers
   95. `bck_bck`: Backup backup servers
   96. `failed_secu`: Security failed requests
   97. `-`: Delimiter marking end of static fields

---

### 2.3 `show table` and `show table <name>`

- **Source Citation:** [`src/stick_table.c:6031`](file:///home/bhenc/reference/haproxy/src/stick_table.c#L6031)
- **Handler Functions:** Parse: `cli_parse_table_req` ([`src/stick_table.c:5714`](file:///home/bhenc/reference/haproxy/src/stick_table.c#L5714)), IO Handler: `cli_io_handler_table` ([`src/stick_table.c:5769`](file:///home/bhenc/reference/haproxy/src/stick_table.c#L5769)), Release: `cli_release_show_table` ([`src/stick_table.c:5761`](file:///home/bhenc/reference/haproxy/src/stick_table.c#L5761)), Header Dump: `table_dump_head_to_buffer` ([`src/stick_table.c:5276`](file:///home/bhenc/reference/haproxy/src/stick_table.c#L5276)), Entry Dump: `table_dump_entry_to_buffer` ([`src/stick_table.c:5297`](file:///home/bhenc/reference/haproxy/src/stick_table.c#L5297)).
- **Required Access Level:** `ACCESS_LVL_NONE` for summary/header; `ACCESS_LVL_OPER` required to dump individual table entries.

#### Output Formats & Variants

1. **Global Summary (`show table` without argument):**
   - Loops across all stick tables in memory and emits one header line per table:
     `# table: <table_id>, type: <type_kw>, size:<size>, used:<current>
`
   - Key types: `ip` (IPv4), `ipv6`, `integer`, `string`, `binary`.
   - Field format: `# table: %s, type: %s, size:%d, used:%d
`.
   - Empty result: If no stick tables exist, output is empty (0 bytes).

2. **Specific Table Dump (`show table <name>`):**
   - Header Line: `# table: <table_id>, type: <type_kw>, size:<size>, used:<current>
`
   - Access Level Check:
     - If socket permission < `ACCESS_LVL_OPER`:
       `# contents not dumped due to insufficient privileges
`
     - If socket permission >= `ACCESS_LVL_OPER`:
       Emits one line per stick session entry:
       `<entry_ptr>: key=<key_repr> use=<use_cnt> exp=<expire_ms> [data_col=value ...]
`
   - Entry Field Structure:
     - `%p:` Memory pointer representation of `struct stksess`.
     - ` key=%s`: Formatted key (IP address, integer, or quoted/escaped string/binary).
     - ` use=%d`: Reference count.
     - ` exp=%d`: Expiration timer remaining in milliseconds.
     - Followed by space-separated stored data types configured on the table, e.g.:
       ` server_id=%d`, ` gpc0=%u`, ` gpc1=%u`, ` conn_cnt=%u`, ` conn_rate(%d)=%u`, ` conn_cur=%u`, ` sess_cnt=%u`, ` sess_rate(%d)=%u`, ` http_req_cnt=%u`, ` http_req_rate(%d)=%u`, ` http_err_cnt=%u`, ` http_err_rate(%d)=%u`, ` bytes_in_cnt=%llu`, ` bytes_in_rate(%d)=%u`, ` bytes_out_cnt=%llu`, ` bytes_out_rate(%d)=%u`.
   - Record Terminator: `
` per entry.
   - Empty table result (`used:0`): Only the header line `# table: ...
` is output.
   - Non-existent table: If `<name>` is not found, `cli_parse_table_req` returns:
     `No such table
`

---

### 2.4 `show sess` and `show sess <id>`

- **Source Citation:** [`src/stream.c:4549`](file:///home/bhenc/reference/haproxy/src/stream.c#L4549)
- **Handler Functions:** Parse: `cli_parse_show_sess` ([`src/stream.c:3958`](file:///home/bhenc/reference/haproxy/src/stream.c#L3958)), IO Handler: `cli_io_handler_dump_sess` ([`src/stream.c:4214`](file:///home/bhenc/reference/haproxy/src/stream.c#L4214)), Release: `cli_release_show_sess` ([`src/stream.c:4204`](file:///home/bhenc/reference/haproxy/src/stream.c#L4204)), Full Stream Dump: `stats_dump_full_strm_to_buffer` ([`src/stream.c:4077`](file:///home/bhenc/reference/haproxy/src/stream.c#L4077)).
- **Required Access Level:** `ACCESS_LVL_OPER` (checked in `cli_parse_show_sess`).

#### Output Formats & Variants

1. **Short Summary Format (`show sess`):**
   - Scans all threads and emits one line per active stream:
     `%p: proto=%s src=%s fe=%s be=%s srv=%s ts=%02x epoch=%#x age=%s calls=%u rate=%u cpu=%llu lat=%llu rq[f=%06xh,i=%u,an=%02xh,ax=%s] rp[f=%06xh,i=%u,an=%02xh,ax=%s] scf=[%d,%1xh,fd=%u/%d,rex=%s,wex=%s] scb=[%d,%1xh,fd=%u/%d,rex=%s,wex=%s] exp=%s rc=%d c_exp=%s [run(nice=%d)] [uri=%s]
`
   - Fields:
     - `%p`: Stream memory pointer.
     - `proto=%s`: Protocol name (e.g. `tcp`, `http`, `uxst`).
     - `src=%s`: Source address:port or unix socket ID (anonymized if anon mode is active).
     - `fe=%s`: Frontend proxy name.
     - `be=%s`: Backend proxy name or `<NONE>`.
     - `srv=%s`: Server name or `<none>`.
     - `ts=%02x`: Task state hex.
     - `epoch=%#x`: Stream epoch identifier.
     - `age=%s`: Human readable age string (e.g. `12s`, `5m30s`).
     - `calls=%u`: Task scheduler call count.
     - `rate=%u`: Stream call rate.
     - `cpu=%llu`: CPU time consumed in microseconds.
     - `lat=%llu`: Scheduler latency time.
     - `rq[...]`: Request channel state flags, buffer data length `i`, active analysers hex `an`, analysis expiry `ax`.
     - `rp[...]`: Response channel state flags, buffer data length `i`, active analysers hex `an`, analysis expiry `ax`.
     - `scf=[...]`: Stream connector frontend state, flags, thread group ID / FD, read expiry, write expiry.
     - `scb=[...]`: Stream connector backend state, flags, thread group ID / FD, read expiry, write expiry.
     - `exp=%s`: Task expiration timer.
     - `rc=%d`: Connection retry count.
     - `c_exp=%s`: Connection timeout expiry.
     - `run(nice=%d)`: Included if stream task is currently in run queue.
     - `uri=%s`: Included if `show-uri` option was supplied and HTTP transaction exists.
   - Separator: Space ` ` between fields. Line terminator: `
`.
   - Empty result: If no active streams match filters, output is empty (0 bytes).

2. **Detailed Multi-Section Dump (`show sess <id>` or `show sess all`):**
   - Multi-line structured dump with sections:
     - `Stream <ptr> (epoch ...)`
     - `Flags: ...`
     - `Frontend: ...`, `Backend: ...`, `Server: ...`
     - `Task: ...`, `Channel req: ...`, `Channel res: ...`
     - `Stream Connector Frontend: ...`, `Stream Connector Backend: ...`
     - `Filters: ...`, `HTTP Transaction: ...`
   - Empty result / non-existent ID: Produces 0 bytes of stream dump.

3. **Help Output (`show sess help`):**
   - Returns usage guidance terminated with `
`.

---

### 2.5 `show servers state`

- **Source Citation:** [`src/proxy.c:5610`](file:///home/bhenc/reference/haproxy/src/proxy.c#L5610)
- **Handler Functions:** Parse: `cli_parse_show_servers` ([`src/proxy.c:4577`](file:///home/bhenc/reference/haproxy/src/proxy.c#L4577)), IO Handler: `cli_io_handler_servers_state` ([`src/proxy.c:4691`](file:///home/bhenc/reference/haproxy/src/proxy.c#L4691)), Release: `cli_io_release_show_servers` ([`src/proxy.c:4731`](file:///home/bhenc/reference/haproxy/src/proxy.c#L4731)), Server Dumper: `dump_servers_state` ([`src/proxy.c:4607`](file:///home/bhenc/reference/haproxy/src/proxy.c#L4607)).
- **Required Access Level:** `ACCESS_LVL_NONE` (accessible to all CLI levels).

#### Output Format

- **Header Lines:**
  - Line 1: Server state file format version: `1
` (`SRV_STATE_FILE_VERSION`).
  - Line 2: Header comment line starting with `# `:
    `# be_id be_name srv_id srv_name srv_addr srv_op_state srv_admin_state srv_uweight srv_iweight srv_time_since_last_change srv_check_status srv_check_result srv_check_health srv_check_state srv_agent_state bk_f_forced_id srv_f_forced_id srv_fqdn srv_port srvrecord srv_use_ssl srv_check_port srv_check_addr srv_agent_addr srv_agent_port
`
- **Data Lines:**
  - One space-separated line per server across all backends:
    `%d %s %d %s %s %d %d %d %d %ld %d %d %d %d %d %d %d %s %u %s %d %d %s %s %d
`
- **Field Order & Meanings (25 columns):**
  1. `be_id`: Backend proxy unique ID (`px->uuid`)
  2. `be_name`: Backend name (`px->id`)
  3. `srv_id`: Server unique ID (`srv->puid`)
  4. `srv_name`: Server name (`srv->id`)
  5. `srv_addr`: Server IP address (anonymized if anon mode active)
  6. `srv_op_state`: Operational state (0=STOPPED, 1=STARTING, 2=RUNNING, 3=STOPPING)
  7. `srv_admin_state`: Administrative state bitmask (F_MAINT, F_DRAIN, etc.)
  8. `srv_uweight`: User configured weight (`srv->uweight`)
  9. `srv_iweight`: Initial weight (`srv->iweight`)
  10. `srv_time_since_last_change`: Seconds elapsed since last state change
  11. `srv_check_status`: Check status code
  12. `srv_check_result`: Check result (0=FAILED, 1=PASSED, 2=UNCHECKED)
  13. `srv_check_health`: Health counter
  14. `srv_check_state`: Check state bitmask
  15. `srv_agent_state`: Agent check state bitmask
  16. `bk_f_forced_id`: Backend forced ID flag (1 or 0)
  17. `srv_f_forced_id`: Server forced ID flag (1 or 0)
  18. `srv_fqdn`: Server FQDN hostname or `-`
  19. `srv_port`: Service port number
  20. `srvrecord`: SRV record name or `-`
  21. `srv_use_ssl`: SSL enabled flag (1 or 0)
  22. `srv_check_port`: Health check port number
  23. `srv_check_addr`: Health check IP address
  24. `srv_agent_addr`: Agent check IP address
  25. `srv_agent_port`: Agent check port number
- **Separator:** Single space ` ` between fields.
- **Line Terminator:** `
` (newline).
- **Empty result:** If no backends or servers are present, outputs only the two header lines:
  ```
  1
  # be_id be_name srv_id srv_name srv_addr srv_op_state srv_admin_state srv_uweight srv_iweight srv_time_since_last_change srv_check_status srv_check_result srv_check_health srv_check_state srv_agent_state bk_f_forced_id srv_f_forced_id srv_fqdn srv_port srvrecord srv_use_ssl srv_check_port srv_check_addr srv_agent_addr srv_agent_port
  ```

---

### 2.6 `set server <b>/<s> state`

- **Source Citation:** [`src/server.c:7095`](file:///home/bhenc/reference/haproxy/src/server.c#L7095)
- **Handler Function:** Parse: `cli_parse_set_server` ([`src/server.c:5891`](file:///home/bhenc/reference/haproxy/src/server.c#L5891)), Server Resolver: `cli_find_server` ([`src/server.c:5860`](file:///home/bhenc/reference/haproxy/src/server.c#L5860)).
- **Required Access Level:** `ACCESS_LVL_ADMIN` (enforced via `cli_has_level(appctx, ACCESS_LVL_ADMIN)`).

#### Behavior & Output Format

- **Syntax:** `set server <backend>/<server> state <ready|drain|maint>`
- **Execution:** Synchronously updates server administrative state (`srv_adm_set_ready`, `srv_adm_set_drain`, `srv_adm_set_maint`) while holding `SERVER_LOCK`.
- **Success Output:** Completely empty (0 bytes). HAProxy CLI conventions return no message on successful state mutations.
- **Error Responses (terminated with `
`):**
  - Insufficient permission: `Permission denied
`
  - Missing server argument: `Require 'backend/server'.
`
  - Backend not found: `No such backend.
`
  - Server not found: `No such server.
`
  - Disabled backend: `Proxy is disabled.
`
  - Invalid state keyword: `'set server <srv> state' expects 'ready', 'drain' and 'maint'.
`

---

### 2.7 `set weight`

- **Source Citation:** [`src/server.c:7097`](file:///home/bhenc/reference/haproxy/src/server.c#L7097)
- **Handler Function:** Parse: `cli_parse_set_weight` ([`src/server.c:6166`](file:///home/bhenc/reference/haproxy/src/server.c#L6166)), Weight Parser: `server_parse_weight_change_request` ([`src/server.c:2564`](file:///home/bhenc/reference/haproxy/src/server.c#L2564)).
- **Required Access Level:** `ACCESS_LVL_ADMIN` (enforced via `cli_has_level(appctx, ACCESS_LVL_ADMIN)`).

#### Behavior & Output Format

- **Syntax:** `set weight <backend>/<server> <weight|weight%>` (DEPRECATED: modern syntax is `set server <bk>/<srv> weight <val>`).
- **Supported Value Formats:**
  - Absolute integer: `0` to `256` inclusive.
  - Relative percentage: `<positive_integer>%` (relative to initial weight `sv->iweight`).
- **Success Output:** Completely empty (0 bytes).
- **Error Responses (terminated with `
`):**
  - Insufficient permission: `Permission denied
`
  - Missing parameter: `Require <weight> or <weight%>.
`
  - Invalid / empty input: `Empty weight string empty or preceded by garbage
`
  - Negative relative percentage: `Relative weight must be positive.
`
  - Out of range absolute weight: `Absolute weight can only be between 0 and 256 inclusive.
`
  - Trailing garbage: `Trailing garbage in weight string
`
  - Static LB algorithm rejecting non-zero/non-100 weights: `Backend is using a static LB algorithm and only accepts weights '0%' and '100%'.
`
  - Server / Backend lookup errors: `Require 'backend/server'.
`, `No such backend.
`, `No such server.
`, `Proxy is disabled.
`.

---

### 2.8 `disable server` and `enable server`

- **Source Citations:**
  - `disable server`: [`src/server.c:7090`](file:///home/bhenc/reference/haproxy/src/server.c#L7090)
  - `enable server`: [`src/server.c:7093`](file:///home/bhenc/reference/haproxy/src/server.c#L7093)
- **Handler Functions:**
  - `disable server`: `cli_parse_disable_server` ([`src/server.c:6262`](file:///home/bhenc/reference/haproxy/src/server.c#L6262))
  - `enable server`: `cli_parse_enable_server` ([`src/server.c:6332`](file:///home/bhenc/reference/haproxy/src/server.c#L6332))
- **Required Access Level:** `ACCESS_LVL_ADMIN` (enforced via `cli_has_level(appctx, ACCESS_LVL_ADMIN)`).

#### Behavior & Output Format

- **Syntax:**
  - `disable server <backend>/<server>` (DEPRECATED: alias for `set server <bk>/<srv> state maint`)
  - `enable server <backend>/<server>` (DEPRECATED: alias for `set server <bk>/<srv> state ready`)
- **Execution:**
  - `disable server`: Calls `srv_adm_set_maint(sv)` under `SERVER_LOCK`.
  - `enable server`: Calls `srv_adm_set_ready(sv)` under `SERVER_LOCK` and triggers dynamic cookie deduplication check if applicable.
- **Success Output:** Completely empty (0 bytes).
- **Error Responses (terminated with `
`):**
  - Insufficient permission: `Permission denied
`
  - Missing parameter / invalid target: `Require 'backend/server'.
`, `No such backend.
`, `No such server.
`, `Proxy is disabled.
`.

---

## 3. Complete CLI Command Inventory Table

The table below lists all **172 CLI commands** registered in HAProxy 3.5-dev7 (`e6f616af`), extracted directly from the C sources.

| # | Keywords | Usage | Parse Function | IO Handler | Release Function | Access Level | Citation |
|---|---|---|---|---|---|---|---|
| 1 | `acme renew` | `acme renew <certfile>                   : renew a certificate using the ACME protocol` | `cli_acme_renew_parse` | - | - | `ACCESS_LVL_ADMIN` | [`src/acme.c:3751`](file:///home/bhenc/reference/haproxy/src/acme.c#L3751) |
| 2 | `acme status` | `acme status                             : show status of certificates configured with ACME` | `cli_acme_parse_status` | `cli_acme_status_io_handler` | - | `ACCESS_LVL_ADMIN` | [`src/acme.c:3752`](file:///home/bhenc/reference/haproxy/src/acme.c#L3752) |
| 3 | `acme challenge_ready` | `acme challenge_ready <certfile> domain <domain> : notify HAProxy that the ACME challenge is ready` | `cli_acme_chall_ready_parse` | - | - | `ACCESS_LVL_ADMIN` | [`src/acme.c:3753`](file:///home/bhenc/reference/haproxy/src/acme.c#L3753) |
| 4 | `set profiling` | `set profiling <what> {auto\|on\|off}      : enable/disable resource profiling (tasks,memory)` | `cli_parse_set_profiling` | - | - | `ACCESS_LVL_ADMIN` | [`src/activity.c:1871`](file:///home/bhenc/reference/haproxy/src/activity.c#L1871) |
| 5 | `show activity` | `show activity [-1\|0\|thread_num]         : show per-thread activity stats (for support/developers)` | `cli_parse_show_activity` | `cli_io_handler_show_activity` | - | `ACCESS_LVL_OPER` | [`src/activity.c:1872`](file:///home/bhenc/reference/haproxy/src/activity.c#L1872) |
| 6 | `show profiling` | `show profiling [<what>\|<#lines>\|<opts>]*: show profiling state (all,status,tasks,memory)` | `cli_parse_show_profiling` | `cli_io_handler_show_profiling` | `cli_release_show_profiling` | `ACCESS_LVL_ADMIN` | [`src/activity.c:1873`](file:///home/bhenc/reference/haproxy/src/activity.c#L1873) |
| 7 | `show tasks` | `show tasks                              : show running tasks` | - | `cli_io_handler_show_tasks` | - | `ACCESS_LVL_NONE` | [`src/activity.c:1874`](file:///home/bhenc/reference/haproxy/src/activity.c#L1874) |
| 8 | `show cache` | `show cache                              : show cache status` | `cli_parse_show_cache` | `cli_io_handler_show_cache` | - | `ACCESS_LVL_ADMIN` | [`src/cache.c:3760`](file:///home/bhenc/reference/haproxy/src/cache.c#L3760) |
| 9 | `help` | *none (internal)* | `cli_parse_simple` | - | - | `ACCESS_MASTER` | [`src/cli.c:4460`](file:///home/bhenc/reference/haproxy/src/cli.c#L4460) |
| 10 | `echo` | `echo <text>                             : print text to the output` | `cli_parse_echo` | - | - | `ACCESS_MASTER` | [`src/cli.c:4461`](file:///home/bhenc/reference/haproxy/src/cli.c#L4461) |
| 11 | `prompt` | *none (internal)* | `cli_parse_simple` | - | - | `ACCESS_MASTER` | [`src/cli.c:4462`](file:///home/bhenc/reference/haproxy/src/cli.c#L4462) |
| 12 | `quit` | *none (internal)* | `cli_parse_simple` | - | - | `ACCESS_MASTER` | [`src/cli.c:4463`](file:///home/bhenc/reference/haproxy/src/cli.c#L4463) |
| 13 | `_getsocks` | *none (internal)* | `_getsocks` | - | - | `ACCESS_LVL_NONE` | [`src/cli.c:4464`](file:///home/bhenc/reference/haproxy/src/cli.c#L4464) |
| 14 | `expert-mode` | *none (internal)* | `cli_parse_expert_experimental_mode` | - | - | `ACCESS_LVL_ADMIN \| ACCESS_MASTER` | [`src/cli.c:4465`](file:///home/bhenc/reference/haproxy/src/cli.c#L4465) |
| 15 | `experimental-mode` | *none (internal)* | `cli_parse_expert_experimental_mode` | - | - | `ACCESS_LVL_ADMIN \| ACCESS_MASTER` | [`src/cli.c:4466`](file:///home/bhenc/reference/haproxy/src/cli.c#L4466) |
| 16 | `mcli-debug-mode` | *none (internal)* | `cli_parse_expert_experimental_mode` | - | - | `ACCESS_LVL_ADMIN \| ACCESS_MASTER_ONLY` | [`src/cli.c:4467`](file:///home/bhenc/reference/haproxy/src/cli.c#L4467) |
| 17 | `set anon on` | `set anon on [value]                     : activate the anonymized mode` | `cli_parse_set_anon` | - | - | `ACCESS_LVL_NONE` | [`src/cli.c:4468`](file:///home/bhenc/reference/haproxy/src/cli.c#L4468) |
| 18 | `set anon off` | `set anon off                            : deactivate the anonymized mode` | `cli_parse_set_anon` | - | - | `ACCESS_LVL_NONE` | [`src/cli.c:4469`](file:///home/bhenc/reference/haproxy/src/cli.c#L4469) |
| 19 | `set anon global-key` | `set anon global-key <value>             : change the global anonymizing key` | `cli_parse_set_global_key` | - | - | `ACCESS_LVL_ADMIN` | [`src/cli.c:4470`](file:///home/bhenc/reference/haproxy/src/cli.c#L4470) |
| 20 | `set maxconn global` | `set maxconn global <value>              : change the per-process maxconn setting` | `cli_parse_set_maxconn_global` | - | - | `ACCESS_LVL_ADMIN` | [`src/cli.c:4471`](file:///home/bhenc/reference/haproxy/src/cli.c#L4471) |
| 21 | `set rate-limit` | `set rate-limit <setting> <value>        : change a rate limiting value` | `cli_parse_set_ratelimit` | - | - | `ACCESS_LVL_ADMIN` | [`src/cli.c:4472`](file:///home/bhenc/reference/haproxy/src/cli.c#L4472) |
| 22 | `set severity-output` | `set severity-output [none\|number\|string]: set presence of severity level in feedback information` | `cli_parse_set_severity_output` | - | - | `ACCESS_LVL_NONE` | [`src/cli.c:4473`](file:///home/bhenc/reference/haproxy/src/cli.c#L4473) |
| 23 | `set timeout` | `set timeout [cli] <delay>               : change a timeout setting` | `cli_parse_set_timeout` | - | - | `ACCESS_LVL_NONE` | [`src/cli.c:4474`](file:///home/bhenc/reference/haproxy/src/cli.c#L4474) |
| 24 | `show anon` | `show anon                               : display the current state of anonymized mode` | `cli_parse_show_anon` | - | - | `ACCESS_LVL_OPER` | [`src/cli.c:4475`](file:///home/bhenc/reference/haproxy/src/cli.c#L4475) |
| 25 | `show env` | `show env [var]                          : dump environment variables known to the process` | `cli_parse_show_env` | `cli_io_handler_show_env` | - | `ACCESS_LVL_OPER \| ACCESS_MASTER` | [`src/cli.c:4476`](file:///home/bhenc/reference/haproxy/src/cli.c#L4476) |
| 26 | `show cli sockets` | `show cli sockets                        : dump list of cli sockets` | `cli_parse_default` | `cli_io_handler_show_cli_sock` | - | `ACCESS_LVL_ADMIN \| ACCESS_MASTER` | [`src/cli.c:4477`](file:///home/bhenc/reference/haproxy/src/cli.c#L4477) |
| 27 | `show cli level` | `show cli level                          : display the level of the current CLI session` | `cli_parse_show_lvl` | - | - | `ACCESS_LVL_ADMIN \| ACCESS_MASTER` | [`src/cli.c:4478`](file:///home/bhenc/reference/haproxy/src/cli.c#L4478) |
| 28 | `show fd` | `show fd [-!plcfbs]* [num]               : dump list of file descriptors in use or a specific one` | `cli_parse_show_fd` | `cli_io_handler_show_fd` | `cli_release_show_fd` | `ACCESS_LVL_OPER` | [`src/cli.c:4479`](file:///home/bhenc/reference/haproxy/src/cli.c#L4479) |
| 29 | `show version` | `show version                            : show version of the current process` | `cli_parse_show_version` | - | - | `ACCESS_MASTER` | [`src/cli.c:4480`](file:///home/bhenc/reference/haproxy/src/cli.c#L4480) |
| 30 | `operator` | `operator                                : lower the level of the current CLI session to operator` | `cli_parse_set_lvl` | - | - | `ACCESS_LVL_OPER \| ACCESS_MASTER` | [`src/cli.c:4481`](file:///home/bhenc/reference/haproxy/src/cli.c#L4481) |
| 31 | `user` | `user                                    : lower the level of the current CLI session to user` | `cli_parse_set_lvl` | - | - | `ACCESS_LVL_OPER \| ACCESS_MASTER` | [`src/cli.c:4482`](file:///home/bhenc/reference/haproxy/src/cli.c#L4482) |
| 32 | `wait` | `wait {-h\|<delay_ms>} cond [args...]     : wait the specified delay or condition (-h to see list)` | `cli_parse_wait` | `cli_io_handler_wait` | `cli_release_wait` | `ACCESS_LVL_ADMIN` | [`src/cli.c:4483`](file:///home/bhenc/reference/haproxy/src/cli.c#L4483) |
| 33 | `_send_status` | *none (internal)* | `_send_status` | - | - | `ACCESS_MASTER_ONLY` | [`src/cli.c:4484`](file:///home/bhenc/reference/haproxy/src/cli.c#L4484) |
| 34 | `debug counters` | `debug counters [?\|all\|bug\|cnt\|chk\|glt]* : dump/reset rare event counters` | `debug_parse_cli_counters` | `debug_iohandler_counters` | - | `ACCESS_LVL_ADMIN` | [`src/debug.c:3261`](file:///home/bhenc/reference/haproxy/src/debug.c#L3261) |
| 35 | `debug dev abort` | `debug dev abort                         : call ABORT_NOW() and possibly crash` | `debug_parse_cli_abort` | - | - | `ACCESS_LVL_ADMIN \| ACCESS_EXPERT` | [`src/debug.c:3263`](file:///home/bhenc/reference/haproxy/src/debug.c#L3263) |
| 36 | `debug dev bug` | `debug dev bug                           : call BUG_ON() and crash` | `debug_parse_cli_bug` | - | - | `ACCESS_LVL_ADMIN \| ACCESS_EXPERT` | [`src/debug.c:3264`](file:///home/bhenc/reference/haproxy/src/debug.c#L3264) |
| 37 | `debug dev check` | `debug dev check                         : call CHECK_IF() and possibly crash` | `debug_parse_cli_check` | - | - | `ACCESS_LVL_ADMIN \| ACCESS_EXPERT` | [`src/debug.c:3265`](file:///home/bhenc/reference/haproxy/src/debug.c#L3265) |
| 38 | `debug dev close` | `debug dev close  <fd> [hard]            : close this file descriptor` | `debug_parse_cli_close` | - | - | `ACCESS_LVL_ADMIN \| ACCESS_EXPERT` | [`src/debug.c:3266`](file:///home/bhenc/reference/haproxy/src/debug.c#L3266) |
| 39 | `debug dev deadlock` | `debug dev deadlock [nbtask]             : deadlock between this number of tasks` | `debug_parse_cli_deadlock` | - | - | `ACCESS_LVL_ADMIN \| ACCESS_EXPERT` | [`src/debug.c:3267`](file:///home/bhenc/reference/haproxy/src/debug.c#L3267) |
| 40 | `debug dev delay` | `debug dev delay  [ms]                   : sleep this long` | `debug_parse_cli_delay` | - | - | `ACCESS_LVL_ADMIN \| ACCESS_EXPERT` | [`src/debug.c:3268`](file:///home/bhenc/reference/haproxy/src/debug.c#L3268) |
| 41 | `debug dev delay-inj` | `debug dev delay-inj <inter> <count>     : inject random delays into threads` | `debug_parse_delay_inj` | - | - | `ACCESS_LVL_ADMIN \| ACCESS_EXPERT` | [`src/debug.c:3270`](file:///home/bhenc/reference/haproxy/src/debug.c#L3270) |
| 42 | `debug dev exec` | `debug dev exec   [cmd] ...              : show this command's output` | `debug_parse_cli_exec` | - | - | `ACCESS_LVL_ADMIN \| ACCESS_EXPERT` | [`src/debug.c:3271`](file:///home/bhenc/reference/haproxy/src/debug.c#L3271) |
| 43 | `debug dev fd` | `debug dev fd                            : scan for rogue/unhandled FDs` | `debug_parse_cli_fd` | `debug_iohandler_fd` | - | `ACCESS_LVL_OPER \| ACCESS_EXPERT` | [`src/debug.c:3273`](file:///home/bhenc/reference/haproxy/src/debug.c#L3273) |
| 44 | `debug dev exit` | `debug dev exit   [code]                 : immediately exit the process` | `debug_parse_cli_exit` | - | - | `ACCESS_LVL_ADMIN \| ACCESS_EXPERT` | [`src/debug.c:3274`](file:///home/bhenc/reference/haproxy/src/debug.c#L3274) |
| 45 | `debug dev hash` | `debug dev hash   [msg]                  : return msg hashed if anon is set` | `debug_parse_cli_hash` | - | - | `ACCESS_LVL_NONE` | [`src/debug.c:3275`](file:///home/bhenc/reference/haproxy/src/debug.c#L3275) |
| 46 | `debug dev hex` | `debug dev hex    <addr> [len]           : dump a memory area` | `debug_parse_cli_hex` | - | - | `ACCESS_LVL_ADMIN \| ACCESS_EXPERT` | [`src/debug.c:3276`](file:///home/bhenc/reference/haproxy/src/debug.c#L3276) |
| 47 | `debug dev log` | `debug dev log    [msg] ...              : send this msg to global logs` | `debug_parse_cli_log` | - | - | `ACCESS_LVL_ADMIN \| ACCESS_EXPERT` | [`src/debug.c:3277`](file:///home/bhenc/reference/haproxy/src/debug.c#L3277) |
| 48 | `debug dev loop` | `debug dev loop   <ms> [isolated\|warn]   : loop this long, possibly isolated` | `debug_parse_cli_loop` | - | - | `ACCESS_LVL_ADMIN \| ACCESS_EXPERT` | [`src/debug.c:3278`](file:///home/bhenc/reference/haproxy/src/debug.c#L3278) |
| 49 | `debug dev memstats` | `debug dev memstats [reset\|all\|match ...]: dump/reset memory statistics` | `debug_parse_cli_memstats` | `debug_iohandler_memstats` | `debug_release_memstats` | `ACCESS_LVL_ADMIN` | [`src/debug.c:3280`](file:///home/bhenc/reference/haproxy/src/debug.c#L3280) |
| 50 | `debug dev panic` | `debug dev panic                         : immediately trigger a panic` | `debug_parse_cli_panic` | - | - | `ACCESS_LVL_ADMIN \| ACCESS_EXPERT` | [`src/debug.c:3282`](file:///home/bhenc/reference/haproxy/src/debug.c#L3282) |
| 51 | `debug dev sched` | `debug dev sched  {task\|tasklet} [k=v]*  : stress the scheduler` | `debug_parse_cli_sched` | - | - | `ACCESS_LVL_ADMIN \| ACCESS_EXPERT` | [`src/debug.c:3283`](file:///home/bhenc/reference/haproxy/src/debug.c#L3283) |
| 52 | `debug dev stream` | `debug dev stream [k=v]*                 : show/manipulate stream flags` | `debug_parse_cli_stream` | - | - | `ACCESS_LVL_ADMIN \| ACCESS_EXPERT` | [`src/debug.c:3284`](file:///home/bhenc/reference/haproxy/src/debug.c#L3284) |
| 53 | `debug dev sym` | `debug dev sym    <addr>                 : resolve symbol address` | `debug_parse_cli_sym` | - | - | `ACCESS_LVL_ADMIN \| ACCESS_EXPERT` | [`src/debug.c:3285`](file:///home/bhenc/reference/haproxy/src/debug.c#L3285) |
| 54 | `debug dev task` | `debug dev task <ptr> [wake\|expire\|kill] : show/wake/expire/kill task/tasklet` | `debug_parse_cli_task` | - | - | `ACCESS_LVL_ADMIN \| ACCESS_EXPERT` | [`src/debug.c:3286`](file:///home/bhenc/reference/haproxy/src/debug.c#L3286) |
| 55 | `debug dev tkill` | `debug dev tkill  [thr] [sig]            : send signal to thread` | `debug_parse_cli_tkill` | - | - | `ACCESS_LVL_ADMIN \| ACCESS_EXPERT` | [`src/debug.c:3287`](file:///home/bhenc/reference/haproxy/src/debug.c#L3287) |
| 56 | `debug dev trace` | `debug dev trace [nbthr]                 : flood traces from that many threads` | `debug_parse_cli_trace` | - | - | `ACCESS_LVL_ADMIN \| ACCESS_EXPERT` | [`src/debug.c:3289`](file:///home/bhenc/reference/haproxy/src/debug.c#L3289) |
| 57 | `debug dev warn` | `debug dev warn                          : call WARN_ON() and possibly crash` | `debug_parse_cli_warn` | - | - | `ACCESS_LVL_ADMIN \| ACCESS_EXPERT` | [`src/debug.c:3291`](file:///home/bhenc/reference/haproxy/src/debug.c#L3291) |
| 58 | `debug dev write` | `debug dev write  [size]                 : write that many bytes in return` | `debug_parse_cli_write` | - | - | `ACCESS_EXPERT` | [`src/debug.c:3292`](file:///home/bhenc/reference/haproxy/src/debug.c#L3292) |
| 59 | `show dev` | `show dev                                : show debug info for developers` | `debug_parse_cli_show_dev` | - | - | `ACCESS_LVL_NONE` | [`src/debug.c:3294`](file:///home/bhenc/reference/haproxy/src/debug.c#L3294) |
| 60 | `show libs` | `show libs                               : show loaded object files and libraries` | `debug_parse_cli_show_libs` | - | - | `ACCESS_LVL_OPER` | [`src/debug.c:3296`](file:///home/bhenc/reference/haproxy/src/debug.c#L3296) |
| 61 | `show threads` | `show threads                            : show some threads debugging information` | - | `cli_io_handler_show_threads` | - | `ACCESS_LVL_NONE` | [`src/debug.c:3298`](file:///home/bhenc/reference/haproxy/src/debug.c#L3298) |
| 62 | `show ssl ech` | `show ssl ech [<name>]                   : display a named ECH configuration or all` | `cli_parse_show_ech` | `cli_io_handler_ech_details` | `cli_release_ech` | `ACCESS_LVL_ADMIN \| ACCESS_EXPERIMENTAL` | [`src/ech.c:628`](file:///home/bhenc/reference/haproxy/src/ech.c#L628) |
| 63 | `add ssl ech` | `add ssl ech <name> <payload>            : add a new PEM-formatted ECH config and key ` | `cli_parse_add_ech` | - | - | `ACCESS_LVL_ADMIN \| ACCESS_EXPERIMENTAL` | [`src/ech.c:629`](file:///home/bhenc/reference/haproxy/src/ech.c#L629) |
| 64 | `set ssl ech` | `set ssl ech <name> <payload>            : replace all ECH configs with that provided` | `cli_parse_set_ech` | - | - | `ACCESS_LVL_ADMIN \| ACCESS_EXPERIMENTAL` | [`src/ech.c:630`](file:///home/bhenc/reference/haproxy/src/ech.c#L630) |
| 65 | `del ssl ech` | `del ssl ech <name> [<age-in-secs>]      : delete ECH configs` | `cli_parse_del_ech` | - | - | `ACCESS_LVL_ADMIN \| ACCESS_EXPERIMENTAL` | [`src/ech.c:631`](file:///home/bhenc/reference/haproxy/src/ech.c#L631) |
| 66 | `show startup-logs` | `show startup-logs                       : report logs emitted during HAProxy startup` | `cli_parse_show_startup_logs` | - | - | `ACCESS_LVL_OPER \| ACCESS_MASTER` | [`src/errors.c:449`](file:///home/bhenc/reference/haproxy/src/errors.c#L449) |
| 67 | `httpclient` | `httpclient <method> <URI>               : launch an HTTP request` | `hc_cli_parse` | `hc_cli_io_handler` | `hc_cli_release` | `ACCESS_LVL_ADMIN \| ACCESS_EXPERT` | [`src/httpclient_cli.c:269`](file:///home/bhenc/reference/haproxy/src/httpclient_cli.c#L269) |
| 68 | `add acl` | `add acl [@<ver>] <acl> <pattern>        : add an acl entry` | `cli_parse_add_map` | - | - | `ACCESS_LVL_ADMIN` | [`src/map.c:1207`](file:///home/bhenc/reference/haproxy/src/map.c#L1207) |
| 69 | `clear acl` | `clear acl [@<ver>] <acl>                : clear the contents of this acl` | `cli_parse_clear_map` | `cli_io_handler_clear_map` | - | `ACCESS_LVL_ADMIN` | [`src/map.c:1208`](file:///home/bhenc/reference/haproxy/src/map.c#L1208) |
| 70 | `commit acl` | `commit acl @<ver> <acl>                 : commit the ACL at this version` | `cli_parse_commit_map` | `cli_io_handler_clear_map` | - | `ACCESS_LVL_ADMIN` | [`src/map.c:1209`](file:///home/bhenc/reference/haproxy/src/map.c#L1209) |
| 71 | `del acl` | `del acl <acl> [<key>\|#<ref>]            : delete acl entries matching <key>` | `cli_parse_del_map` | - | - | `ACCESS_LVL_ADMIN` | [`src/map.c:1210`](file:///home/bhenc/reference/haproxy/src/map.c#L1210) |
| 72 | `get acl` | `get acl <acl> <value>                   : report the patterns matching a sample for an ACL` | `cli_parse_get_map` | `cli_io_handler_map_lookup` | `cli_release_mlook` | `ACCESS_LVL_ADMIN` | [`src/map.c:1211`](file:///home/bhenc/reference/haproxy/src/map.c#L1211) |
| 73 | `prepare acl` | `prepare acl <acl>                       : prepare a new version for atomic ACL replacement` | `cli_parse_prepare_map` | - | - | `ACCESS_LVL_ADMIN` | [`src/map.c:1212`](file:///home/bhenc/reference/haproxy/src/map.c#L1212) |
| 74 | `show acl` | `show acl [@<ver>] <acl>                 : report available acls or dump an acl's contents` | `cli_parse_show_map` | - | - | `ACCESS_LVL_ADMIN` | [`src/map.c:1213`](file:///home/bhenc/reference/haproxy/src/map.c#L1213) |
| 75 | `add map` | `add map [@<ver>] <map> <key> <val>      : add a map entry (payload supported instead of key/val)` | `cli_parse_add_map` | - | - | `ACCESS_LVL_ADMIN` | [`src/map.c:1214`](file:///home/bhenc/reference/haproxy/src/map.c#L1214) |
| 76 | `clear map` | `clear map [@<ver>] <map>                : clear the contents of this map` | `cli_parse_clear_map` | `cli_io_handler_clear_map` | - | `ACCESS_LVL_ADMIN` | [`src/map.c:1215`](file:///home/bhenc/reference/haproxy/src/map.c#L1215) |
| 77 | `commit map` | `commit map @<ver> <map>                 : commit the map at this version` | `cli_parse_commit_map` | `cli_io_handler_clear_map` | - | `ACCESS_LVL_ADMIN` | [`src/map.c:1216`](file:///home/bhenc/reference/haproxy/src/map.c#L1216) |
| 78 | `del map` | `del map <map> [<key>\|#<ref>]            : delete map entries matching <key>` | `cli_parse_del_map` | - | - | `ACCESS_LVL_ADMIN` | [`src/map.c:1217`](file:///home/bhenc/reference/haproxy/src/map.c#L1217) |
| 79 | `get map` | `get map <map> <value>                   : report the keys and values matching a sample for a map` | `cli_parse_get_map` | `cli_io_handler_map_lookup` | `cli_release_mlook` | `ACCESS_LVL_ADMIN` | [`src/map.c:1218`](file:///home/bhenc/reference/haproxy/src/map.c#L1218) |
| 80 | `prepare map` | `prepare map <map>                       : prepare a new version for atomic map replacement` | `cli_parse_prepare_map` | - | - | `ACCESS_LVL_ADMIN` | [`src/map.c:1219`](file:///home/bhenc/reference/haproxy/src/map.c#L1219) |
| 81 | `set map` | `set map <map> [<key>\|#<ref>] <value>    : modify a map entry` | `cli_parse_set_map` | - | - | `ACCESS_LVL_ADMIN` | [`src/map.c:1220`](file:///home/bhenc/reference/haproxy/src/map.c#L1220) |
| 82 | `show map` | `show map [@<ver>] [map]                 : report available maps or dump a map's contents` | `cli_parse_show_map` | - | - | `ACCESS_LVL_ADMIN` | [`src/map.c:1221`](file:///home/bhenc/reference/haproxy/src/map.c#L1221) |
| 83 | `@<relative pid>` | `@<relative pid>                         : send a command to the <relative pid> process` | - | `cli_io_handler_show_proc` | - | `ACCESS_MASTER_ONLY` | [`src/mworker.c:1428`](file:///home/bhenc/reference/haproxy/src/mworker.c#L1428) |
| 84 | `@!<pid>` | `@!<pid>                                 : send a command to the <pid> process` | `cli_parse_default` | - | - | `ACCESS_MASTER_ONLY` | [`src/mworker.c:1429`](file:///home/bhenc/reference/haproxy/src/mworker.c#L1429) |
| 85 | `@master` | `@master                                 : send a command to the master process` | `cli_parse_default` | - | - | `ACCESS_MASTER_ONLY` | [`src/mworker.c:1430`](file:///home/bhenc/reference/haproxy/src/mworker.c#L1430) |
| 86 | `show proc` | `show proc                               : show processes status` | `cli_parse_show_proc` | `cli_io_handler_show_proc` | - | `ACCESS_LVL_OPER \| ACCESS_MASTER_ONLY` | [`src/mworker.c:1431`](file:///home/bhenc/reference/haproxy/src/mworker.c#L1431) |
| 87 | `reload` | `reload                                  : achieve a soft-reload (-sf) of haproxy` | `cli_parse_reload` | - | - | `ACCESS_LVL_OPER \| ACCESS_MASTER_ONLY` | [`src/mworker.c:1432`](file:///home/bhenc/reference/haproxy/src/mworker.c#L1432) |
| 88 | `hard-reload` | `hard-reload                             : achieve a hard-reload (-st) of haproxy` | `cli_parse_reload` | - | - | `ACCESS_LVL_OPER \| ACCESS_MASTER_ONLY` | [`src/mworker.c:1433`](file:///home/bhenc/reference/haproxy/src/mworker.c#L1433) |
| 89 | `_loadstatus` | *none (internal)* | `cli_parse_default` | `cli_io_handler_show_loadstatus` | - | `ACCESS_LVL_OPER \| ACCESS_MASTER_ONLY` | [`src/mworker.c:1434`](file:///home/bhenc/reference/haproxy/src/mworker.c#L1434) |
| 90 | `show peers` | `show peers [dict\|-] [section]           : dump some information about all the peers or this peers section` | `cli_parse_show_peers` | `cli_io_handler_show_peers` | - | `ACCESS_LVL_NONE` | [`src/peers.c:4502`](file:///home/bhenc/reference/haproxy/src/peers.c#L4502) |
| 91 | `show pools` | `show pools [by*] [match <pfx>] [nb]     : report information about the memory pools usage` | `cli_parse_show_pools` | `cli_io_handler_dump_pools` | `cli_release_show_pools` | `ACCESS_LVL_NONE` | [`src/pool.c:1710`](file:///home/bhenc/reference/haproxy/src/pool.c#L1710) |
| 92 | `add backend` | `add backend <backend>                   : add a new backend` | `cli_parse_add_backend` | - | - | `ACCESS_LVL_ADMIN` | [`src/proxy.c:5601`](file:///home/bhenc/reference/haproxy/src/proxy.c#L5601) |
| 93 | `del backend` | `del backend <backend>                   : delete a backend` | `cli_parse_delete_backend` | - | - | `ACCESS_LVL_ADMIN` | [`src/proxy.c:5602`](file:///home/bhenc/reference/haproxy/src/proxy.c#L5602) |
| 94 | `disable frontend` | `disable frontend <frontend>             : temporarily disable specific frontend` | `cli_parse_disable_frontend` | - | - | `ACCESS_LVL_ADMIN` | [`src/proxy.c:5603`](file:///home/bhenc/reference/haproxy/src/proxy.c#L5603) |
| 95 | `enable frontend` | `enable frontend <frontend>              : re-enable specific frontend` | `cli_parse_enable_frontend` | - | - | `ACCESS_LVL_ADMIN` | [`src/proxy.c:5604`](file:///home/bhenc/reference/haproxy/src/proxy.c#L5604) |
| 96 | `publish backend` | `publish backend <backend>               : mark backend as ready for traffic` | `cli_parse_publish_backend` | - | - | `ACCESS_LVL_ADMIN` | [`src/proxy.c:5605`](file:///home/bhenc/reference/haproxy/src/proxy.c#L5605) |
| 97 | `set maxconn frontend` | `set maxconn frontend <frontend> <value> : change a frontend's maxconn setting` | `cli_parse_set_maxconn_frontend` | - | - | `ACCESS_LVL_ADMIN` | [`src/proxy.c:5606`](file:///home/bhenc/reference/haproxy/src/proxy.c#L5606) |
| 98 | `show default-server` | `show default-server [<backend>]         : list default-server instances in all or a single backend` | `cli_parse_show_default_server` | `cli_io_handler_show_default_server` | `cli_io_release_show_default_server` | `ACCESS_LVL_NONE` | [`src/proxy.c:5607`](file:///home/bhenc/reference/haproxy/src/proxy.c#L5607) |
| 99 | `show defaults` | `show defaults                           : list all proxies defaults sections` | - | `cli_io_handler_show_defaults` | - | `ACCESS_LVL_NONE` | [`src/proxy.c:5608`](file:///home/bhenc/reference/haproxy/src/proxy.c#L5608) |
| 100 | `show servers conn` | `show servers conn [<backend>]           : dump server connections status (all or for a single backend)` | `cli_parse_show_servers` | `cli_io_handler_servers_state` | `cli_io_release_show_servers` | `ACCESS_LVL_NONE` | [`src/proxy.c:5609`](file:///home/bhenc/reference/haproxy/src/proxy.c#L5609) |
| 101 | `show servers state` | `show servers state [<backend>]          : dump volatile server information (all or for a single backend)` | `cli_parse_show_servers` | `cli_io_handler_servers_state` | `cli_io_release_show_servers` | `ACCESS_LVL_NONE` | [`src/proxy.c:5610`](file:///home/bhenc/reference/haproxy/src/proxy.c#L5610) |
| 102 | `show backend` | `show backend                            : list backends in the current running config` | - | `cli_io_handler_show_backend` | `cli_io_release_show_backend` | `ACCESS_LVL_NONE` | [`src/proxy.c:5611`](file:///home/bhenc/reference/haproxy/src/proxy.c#L5611) |
| 103 | `shutdown frontend` | `shutdown frontend <frontend>            : stop a specific frontend` | `cli_parse_shutdown_frontend` | - | - | `ACCESS_LVL_ADMIN` | [`src/proxy.c:5612`](file:///home/bhenc/reference/haproxy/src/proxy.c#L5612) |
| 104 | `set dynamic-cookie-key backend` | `set dynamic-cookie-key backend <bk> <k> : change a backend secret key for dynamic cookies` | `cli_parse_set_dyncookie_key_backend` | - | - | `ACCESS_LVL_ADMIN` | [`src/proxy.c:5613`](file:///home/bhenc/reference/haproxy/src/proxy.c#L5613) |
| 105 | `unpublish backend` | `unpublish backend <backend>             : remove backend for traffic processing` | `cli_parse_unpublish_backend` | - | - | `ACCESS_LVL_ADMIN` | [`src/proxy.c:5614`](file:///home/bhenc/reference/haproxy/src/proxy.c#L5614) |
| 106 | `enable dynamic-cookie backend` | `enable dynamic-cookie backend <bk>      : enable dynamic cookies on a specific backend` | `cli_parse_enable_dyncookie_backend` | - | - | `ACCESS_LVL_ADMIN` | [`src/proxy.c:5615`](file:///home/bhenc/reference/haproxy/src/proxy.c#L5615) |
| 107 | `disable dynamic-cookie backend` | `disable dynamic-cookie backend <bk>     : disable dynamic cookies on a specific backend` | `cli_parse_disable_dyncookie_backend` | - | - | `ACCESS_LVL_ADMIN` | [`src/proxy.c:5616`](file:///home/bhenc/reference/haproxy/src/proxy.c#L5616) |
| 108 | `show errors` | `show errors [<px>] [request\|response]   : report last request and/or response errors for each proxy` | `cli_parse_show_errors` | `cli_io_handler_show_errors` | `cli_io_release_show_errors` | `ACCESS_LVL_OPER` | [`src/proxy.c:5617`](file:///home/bhenc/reference/haproxy/src/proxy.c#L5617) |
| 109 | `show quic` | `show quic [help\|<format>] [<filter>]    : display quic connections status` | `cli_parse_show_quic` | `cli_io_handler_dump_quic` | `cli_release_show_quic` | `ACCESS_LVL_OPER` | [`src/quic_cli.c:594`](file:///home/bhenc/reference/haproxy/src/quic_cli.c#L594) |
| 110 | `show resolvers` | `show resolvers [id]                     : dumps counters from all resolvers section and associated name servers` | `cli_parse_stat_resolvers` | `cli_io_handler_dump_resolvers_to_buffer` | - | `ACCESS_LVL_NONE` | [`src/resolvers.c:3211`](file:///home/bhenc/reference/haproxy/src/resolvers.c#L3211) |
| 111 | `disable agent` | `disable agent                           : disable agent checks` | `cli_parse_disable_agent` | - | - | `ACCESS_LVL_ADMIN` | [`src/server.c:7088`](file:///home/bhenc/reference/haproxy/src/server.c#L7088) |
| 112 | `disable health` | `disable health                          : disable health checks` | `cli_parse_disable_health` | - | - | `ACCESS_LVL_ADMIN` | [`src/server.c:7089`](file:///home/bhenc/reference/haproxy/src/server.c#L7089) |
| 113 | `disable server` | `disable server (DEPRECATED)             : disable a server for maintenance (use 'set server' instead)` | `cli_parse_disable_server` | - | - | `ACCESS_LVL_ADMIN` | [`src/server.c:7090`](file:///home/bhenc/reference/haproxy/src/server.c#L7090) |
| 114 | `enable agent` | `enable agent                            : enable agent checks` | `cli_parse_enable_agent` | - | - | `ACCESS_LVL_ADMIN` | [`src/server.c:7091`](file:///home/bhenc/reference/haproxy/src/server.c#L7091) |
| 115 | `enable health` | `enable health                           : enable health checks` | `cli_parse_enable_health` | - | - | `ACCESS_LVL_ADMIN` | [`src/server.c:7092`](file:///home/bhenc/reference/haproxy/src/server.c#L7092) |
| 116 | `enable server` | `enable server  (DEPRECATED)             : enable a disabled server (use 'set server' instead)` | `cli_parse_enable_server` | - | - | `ACCESS_LVL_ADMIN` | [`src/server.c:7093`](file:///home/bhenc/reference/haproxy/src/server.c#L7093) |
| 117 | `set maxconn server` | `set maxconn server <bk>/<srv>           : change a server's maxconn setting` | `cli_parse_set_maxconn_server` | - | - | `ACCESS_LVL_ADMIN` | [`src/server.c:7094`](file:///home/bhenc/reference/haproxy/src/server.c#L7094) |
| 118 | `set server` | `set server <bk>/<srv> [opts]            : change a server's state, weight, address, name or ssl` | `cli_parse_set_server` | - | - | `ACCESS_LVL_ADMIN` | [`src/server.c:7095`](file:///home/bhenc/reference/haproxy/src/server.c#L7095) |
| 119 | `get weight` | `get weight <bk>/<srv>                   : report a server's current weight` | `cli_parse_get_weight` | - | - | `ACCESS_LVL_NONE` | [`src/server.c:7096`](file:///home/bhenc/reference/haproxy/src/server.c#L7096) |
| 120 | `set weight` | `set weight <bk>/<srv>  (DEPRECATED)     : change a server's weight (use 'set server' instead)` | `cli_parse_set_weight` | - | - | `ACCESS_LVL_ADMIN` | [`src/server.c:7097`](file:///home/bhenc/reference/haproxy/src/server.c#L7097) |
| 121 | `add server` | `add server <bk>/<srv>                   : create a new server` | `cli_parse_add_server` | `cli_io_handler_add_server` | - | `ACCESS_LVL_ADMIN` | [`src/server.c:7098`](file:///home/bhenc/reference/haproxy/src/server.c#L7098) |
| 122 | `del server` | `del server <bk>/<srv>                   : remove a dynamically added server` | `cli_parse_delete_server` | - | - | `ACCESS_LVL_ADMIN` | [`src/server.c:7099`](file:///home/bhenc/reference/haproxy/src/server.c#L7099) |
| 123 | `show events` | `show events [-0hnrsw]* [<sink>]         : show event sink state` | `cli_parse_show_events` | - | - | `ACCESS_LVL_OPER` | [`src/sink.c:1508`](file:///home/bhenc/reference/haproxy/src/sink.c#L1508) |
| 124 | `show ssl sni` | `show ssl sni [-f <frontend>] [-A]       : display the list of SNI and their corresponding filename` | `cli_parse_show_sni` | `cli_io_handler_show_sni` | `cli_release_show_sni` | `ACCESS_LVL_NONE` | [`src/ssl_ckch.c:4891`](file:///home/bhenc/reference/haproxy/src/ssl_ckch.c#L4891) |
| 125 | `new ssl cert` | `new ssl cert <certfile>                 : create a new certificate file to be used in a crt-list or a directory` | `cli_parse_new_cert` | - | - | `ACCESS_LVL_ADMIN` | [`src/ssl_ckch.c:4893`](file:///home/bhenc/reference/haproxy/src/ssl_ckch.c#L4893) |
| 126 | `set ssl cert` | `set ssl cert <certfile> <payload>       : replace a certificate file` | `cli_parse_set_cert` | - | - | `ACCESS_LVL_ADMIN` | [`src/ssl_ckch.c:4894`](file:///home/bhenc/reference/haproxy/src/ssl_ckch.c#L4894) |
| 127 | `commit ssl cert` | `commit ssl cert <certfile>              : commit a certificate file` | `cli_parse_commit_cert` | `cli_io_handler_commit_cert` | `cli_release_commit_cert` | `ACCESS_LVL_ADMIN` | [`src/ssl_ckch.c:4895`](file:///home/bhenc/reference/haproxy/src/ssl_ckch.c#L4895) |
| 128 | `abort ssl cert` | `abort ssl cert <certfile>               : abort a transaction for a certificate file` | `cli_parse_abort_cert` | - | - | `ACCESS_LVL_ADMIN` | [`src/ssl_ckch.c:4896`](file:///home/bhenc/reference/haproxy/src/ssl_ckch.c#L4896) |
| 129 | `del ssl cert` | `del ssl cert <certfile>                 : delete an unused certificate file` | `cli_parse_del_cert` | - | - | `ACCESS_LVL_ADMIN` | [`src/ssl_ckch.c:4897`](file:///home/bhenc/reference/haproxy/src/ssl_ckch.c#L4897) |
| 130 | `show ssl cert` | `show ssl cert [<certfile>]              : display the SSL certificates used in memory, or the details of a file` | `cli_parse_show_cert` | `cli_io_handler_show_cert` | `cli_release_show_cert` | `ACCESS_LVL_OPER` | [`src/ssl_ckch.c:4898`](file:///home/bhenc/reference/haproxy/src/ssl_ckch.c#L4898) |
| 131 | `dump ssl cert` | `dump ssl cert <certfile>                : dump the SSL certificates in PEM format` | `cli_parse_dump_cert` | `cli_io_handler_dump_cert` | `cli_release_dump_cert` | `ACCESS_LVL_ADMIN` | [`src/ssl_ckch.c:4899`](file:///home/bhenc/reference/haproxy/src/ssl_ckch.c#L4899) |
| 132 | `add ssl jwt` | `add ssl jwt <certfile>                  : add certificate to list of certificates used for JWT validation` | `cli_parse_add_jwt` | - | - | `ACCESS_LVL_ADMIN` | [`src/ssl_ckch.c:4901`](file:///home/bhenc/reference/haproxy/src/ssl_ckch.c#L4901) |
| 133 | `del ssl jwt` | `del ssl jwt <certfile>                  : remove certificate from list of certificates used for JWT validation` | `cli_parse_del_jwt` | - | - | `ACCESS_LVL_ADMIN` | [`src/ssl_ckch.c:4902`](file:///home/bhenc/reference/haproxy/src/ssl_ckch.c#L4902) |
| 134 | `show ssl jwt` | `show ssl jwt                            : show list of certificates used for JWT validation` | `cli_parse_show_jwt` | `cli_io_handler_show_jwt` | `cli_release_show_jwt` | `ACCESS_LVL_OPER` | [`src/ssl_ckch.c:4903`](file:///home/bhenc/reference/haproxy/src/ssl_ckch.c#L4903) |
| 135 | `new ssl ca-file` | `new ssl ca-file <cafile>                : create a new CA file to be used in a crt-list` | `cli_parse_new_cafile` | - | - | `ACCESS_LVL_ADMIN` | [`src/ssl_ckch.c:4906`](file:///home/bhenc/reference/haproxy/src/ssl_ckch.c#L4906) |
| 136 | `add ssl ca-file` | `add ssl ca-file <cafile> <payload>      : add a certificate into the CA file` | `cli_parse_set_cafile` | - | - | `ACCESS_LVL_ADMIN` | [`src/ssl_ckch.c:4907`](file:///home/bhenc/reference/haproxy/src/ssl_ckch.c#L4907) |
| 137 | `set ssl ca-file` | `set ssl ca-file <cafile> <payload>      : replace a CA file` | `cli_parse_set_cafile` | - | - | `ACCESS_LVL_ADMIN` | [`src/ssl_ckch.c:4908`](file:///home/bhenc/reference/haproxy/src/ssl_ckch.c#L4908) |
| 138 | `commit ssl ca-file` | `commit ssl ca-file <cafile>             : commit a CA file` | `cli_parse_commit_cafile` | `cli_io_handler_commit_cafile_crlfile` | `cli_release_commit_cafile` | `ACCESS_LVL_ADMIN` | [`src/ssl_ckch.c:4909`](file:///home/bhenc/reference/haproxy/src/ssl_ckch.c#L4909) |
| 139 | `abort ssl ca-file` | `abort ssl ca-file <cafile>              : abort a transaction for a CA file` | `cli_parse_abort_cafile` | - | - | `ACCESS_LVL_ADMIN` | [`src/ssl_ckch.c:4910`](file:///home/bhenc/reference/haproxy/src/ssl_ckch.c#L4910) |
| 140 | `del ssl ca-file` | `del ssl ca-file <cafile>                : delete an unused CA file` | `cli_parse_del_cafile` | - | - | `ACCESS_LVL_ADMIN` | [`src/ssl_ckch.c:4911`](file:///home/bhenc/reference/haproxy/src/ssl_ckch.c#L4911) |
| 141 | `show ssl ca-file` | `show ssl ca-file [<cafile>[:<index>]]   : display the SSL CA files used in memory, or the details of a <cafile>, or a single certificate of index <index> of a CA file <cafile>` | `cli_parse_show_cafile` | `cli_io_handler_show_cafile` | `cli_release_show_cafile` | `ACCESS_LVL_OPER` | [`src/ssl_ckch.c:4912`](file:///home/bhenc/reference/haproxy/src/ssl_ckch.c#L4912) |
| 142 | `new ssl crl-file` | `new ssl crl-file <crlfile>               : create a new CRL file to be used in a crt-list` | `cli_parse_new_crlfile` | - | - | `ACCESS_LVL_ADMIN` | [`src/ssl_ckch.c:4914`](file:///home/bhenc/reference/haproxy/src/ssl_ckch.c#L4914) |
| 143 | `set ssl crl-file` | `set ssl crl-file <crlfile> <payload>    : replace a CRL file` | `cli_parse_set_crlfile` | - | - | `ACCESS_LVL_ADMIN` | [`src/ssl_ckch.c:4915`](file:///home/bhenc/reference/haproxy/src/ssl_ckch.c#L4915) |
| 144 | `commit ssl crl-file` | `commit ssl crl-file <crlfile>           : commit a CRL file` | `cli_parse_commit_crlfile` | `cli_io_handler_commit_cafile_crlfile` | `cli_release_commit_crlfile` | `ACCESS_LVL_ADMIN` | [`src/ssl_ckch.c:4916`](file:///home/bhenc/reference/haproxy/src/ssl_ckch.c#L4916) |
| 145 | `abort ssl crl-file` | `abort ssl crl-file <crlfile>            : abort a transaction for a CRL file` | `cli_parse_abort_crlfile` | - | - | `ACCESS_LVL_ADMIN` | [`src/ssl_ckch.c:4917`](file:///home/bhenc/reference/haproxy/src/ssl_ckch.c#L4917) |
| 146 | `del ssl crl-file` | `del ssl crl-file <crlfile>              : delete an unused CRL file` | `cli_parse_del_crlfile` | - | - | `ACCESS_LVL_ADMIN` | [`src/ssl_ckch.c:4918`](file:///home/bhenc/reference/haproxy/src/ssl_ckch.c#L4918) |
| 147 | `show ssl crl-file` | `show ssl crl-file [<crlfile[:<index>>]] : display the SSL CRL files used in memory, or the details of a <crlfile>, or a single CRL of index <index> of CRL file <crlfile>` | `cli_parse_show_crlfile` | `cli_io_handler_show_crlfile` | `cli_release_show_crlfile` | `ACCESS_LVL_OPER` | [`src/ssl_ckch.c:4919`](file:///home/bhenc/reference/haproxy/src/ssl_ckch.c#L4919) |
| 148 | `add ssl crt-list` | `add ssl crt-list <list> <cert> [opts]*  : add to crt-list file <list> a line <cert> or a payload` | `cli_parse_add_crtlist` | `cli_io_handler_add_crtlist` | `cli_release_add_crtlist` | `ACCESS_LVL_ADMIN` | [`src/ssl_crtlist.c:1634`](file:///home/bhenc/reference/haproxy/src/ssl_crtlist.c#L1634) |
| 149 | `del ssl crt-list` | `del ssl crt-list <list> <cert[:line]>   : delete a line <cert> from crt-list file <list>` | `cli_parse_del_crtlist` | - | - | `ACCESS_LVL_ADMIN` | [`src/ssl_crtlist.c:1635`](file:///home/bhenc/reference/haproxy/src/ssl_crtlist.c#L1635) |
| 150 | `show ssl crt-list` | `show ssl crt-list [-n] [<list>]         : show the list of crt-lists or the content of a crt-list file <list>` | `cli_parse_dump_crtlist` | `cli_io_handler_dump_crtlist` | - | `ACCESS_LVL_ADMIN` | [`src/ssl_crtlist.c:1636`](file:///home/bhenc/reference/haproxy/src/ssl_crtlist.c#L1636) |
| 151 | `set ssl ocsp-response` | `set ssl ocsp-response <resp\|payload>       : update a certificate's OCSP Response from a base64-encode DER` | `cli_parse_set_ocspresponse` | - | - | `ACCESS_LVL_ADMIN` | [`src/ssl_ocsp.c:2197`](file:///home/bhenc/reference/haproxy/src/ssl_ocsp.c#L2197) |
| 152 | `show ssl ocsp-response` | `show ssl ocsp-response [[text\|base64] id]  : display the IDs of the OCSP responses used in memory, or the details of a single OCSP response (in text or base64 format)` | `cli_parse_show_ocspresponse` | `cli_io_handler_show_ocspresponse` | `cli_release_show_ocspresponse` | `ACCESS_LVL_ADMIN` | [`src/ssl_ocsp.c:2199`](file:///home/bhenc/reference/haproxy/src/ssl_ocsp.c#L2199) |
| 153 | `show ssl ocsp-updates` | `show ssl ocsp-updates                      : display information about the next 'nb' ocsp responses that will be updated automatically` | `cli_parse_show_ocsp_updates` | `cli_io_handler_show_ocsp_updates` | `cli_release_show_ocsp_updates` | `ACCESS_LVL_ADMIN` | [`src/ssl_ocsp.c:2200`](file:///home/bhenc/reference/haproxy/src/ssl_ocsp.c#L2200) |
| 154 | `update ssl ocsp-response` | `update ssl ocsp-response <certfile>     : send ocsp request and update stored ocsp response` | `cli_parse_update_ocsp_response` | - | - | `ACCESS_LVL_ADMIN` | [`src/ssl_ocsp.c:2202`](file:///home/bhenc/reference/haproxy/src/ssl_ocsp.c#L2202) |
| 155 | `show tls-keys` | `show tls-keys [id\|*]                    : show tls keys references or dump tls ticket keys when id specified` | `cli_parse_show_tlskeys` | `cli_io_handler_tlskeys_files` | - | `ACCESS_LVL_ADMIN` | [`src/ssl_sock.c:8740`](file:///home/bhenc/reference/haproxy/src/ssl_sock.c#L8740) |
| 156 | `set ssl tls-key` | `set ssl tls-key [id\|file] <key>         : set the next TLS key for the <id> or <file> listener to <key>` | `cli_parse_set_tlskeys` | - | - | `ACCESS_LVL_ADMIN` | [`src/ssl_sock.c:8741`](file:///home/bhenc/reference/haproxy/src/ssl_sock.c#L8741) |
| 157 | `show ssl providers` | `show ssl providers                      : show loaded SSL providers` | - | `cli_io_handler_show_providers` | - | `ACCESS_LVL_NONE` | [`src/ssl_sock.c:8744`](file:///home/bhenc/reference/haproxy/src/ssl_sock.c#L8744) |
| 158 | `clear counters` | `clear counters [all\|server <bk>/<srv> [force]] : clear max statistics counters (or all, or one server's)` | `cli_parse_clear_counters` | - | - | `ACCESS_LVL_ADMIN` | [`src/stats.c:1379`](file:///home/bhenc/reference/haproxy/src/stats.c#L1379) |
| 159 | `show info` | `show info [desc\|json\|typed\|float]*      : report information about the running process` | `cli_parse_show_info` | `cli_io_handler_dump_info` | - | `ACCESS_LVL_NONE` | [`src/stats.c:1380`](file:///home/bhenc/reference/haproxy/src/stats.c#L1380) |
| 160 | `show stat` | `show stat [desc\|json\|no-maint\|typed\|up]*: report counters for each proxy and server` | `cli_parse_show_stat` | `cli_io_handler_dump_stat` | `cli_io_handler_release_stat` | `ACCESS_LVL_OPER` | [`src/stats.c:1381`](file:///home/bhenc/reference/haproxy/src/stats.c#L1381) |
| 161 | `show schema json` | `show schema json                        : report schema used for stats` | `cli_parse_show_schema_json` | `cli_io_handler_dump_json_schema` | - | `ACCESS_LVL_NONE` | [`src/stats.c:1382`](file:///home/bhenc/reference/haproxy/src/stats.c#L1382) |
| 162 | `dump stats-file` | `dump stats-file                         : dump stats for restore` | `cli_parse_dump_stat_file` | `cli_io_handler_dump_stat_file` | `cli_io_handler_release_dump_stat_file` | `ACCESS_LVL_NONE` | [`src/stats.c:1383`](file:///home/bhenc/reference/haproxy/src/stats.c#L1383) |
| 163 | `clear table` | `clear table <table> [<filter>]*         : remove an entry from a table (filter: data/key)` | `cli_parse_table_req` | `cli_io_handler_table` | `cli_release_show_table` | `ACCESS_LVL_OPER` | [`src/stick_table.c:6029`](file:///home/bhenc/reference/haproxy/src/stick_table.c#L6029) |
| 164 | `set table` | `set table <table> key <k> [data.* <v>]* : update or create a table entry's data` | `cli_parse_table_req` | `cli_io_handler_table` | - | `ACCESS_LVL_OPER` | [`src/stick_table.c:6030`](file:///home/bhenc/reference/haproxy/src/stick_table.c#L6030) |
| 165 | `show table` | `show table [<table> [<filter>]*]        : report table usage stats or dump this table's contents (filter: data/key)` | `cli_parse_table_req` | `cli_io_handler_table` | `cli_release_show_table` | `ACCESS_LVL_OPER` | [`src/stick_table.c:6031`](file:///home/bhenc/reference/haproxy/src/stick_table.c#L6031) |
| 166 | `show sess` | `show sess [help\|<id>\|all] [opts...]     : report the list of current streams or dump this exact stream` | `cli_parse_show_sess` | `cli_io_handler_dump_sess` | `cli_release_show_sess` | `ACCESS_LVL_OPER` | [`src/stream.c:4549`](file:///home/bhenc/reference/haproxy/src/stream.c#L4549) |
| 167 | `shutdown session` | `shutdown session [id]                   : kill a specific session` | `cli_parse_shutdown_session` | - | - | `ACCESS_LVL_ADMIN` | [`src/stream.c:4550`](file:///home/bhenc/reference/haproxy/src/stream.c#L4550) |
| 168 | `shutdown sessions server` | `shutdown sessions server <bk>/<srv>     : kill sessions on a server` | `cli_parse_shutdown_sessions_server` | - | - | `ACCESS_LVL_ADMIN` | [`src/stream.c:4551`](file:///home/bhenc/reference/haproxy/src/stream.c#L4551) |
| 169 | `trace` | `trace [<module>\|0] [cmd [args...]]      : manage live tracing (empty to list, 0 to stop all)` | `cli_parse_trace` | - | - | `ACCESS_LVL_OPER` | [`src/trace.c:1352`](file:///home/bhenc/reference/haproxy/src/trace.c#L1352) |
| 170 | `show trace` | `show trace [<module>]                   : show live tracing state` | `cli_parse_show_trace` | - | - | `ACCESS_LVL_OPER` | [`src/trace.c:1353`](file:///home/bhenc/reference/haproxy/src/trace.c#L1353) |
| 171 | `get var` | `get var <name>                          : retrieve contents of a process-wide variable` | `vars_parse_cli_get_var` | - | - | `ACCESS_LVL_OPER` | [`src/vars.c:1767`](file:///home/bhenc/reference/haproxy/src/vars.c#L1767) |
| 172 | `set var` | `set var <name> [fmt\|expr] {<fmt>\|<expr>}: set variable from an expression or a format` | `vars_parse_cli_set_var` | - | - | `ACCESS_LVL_OPER \| ACCESS_EXPERIMENTAL` | [`src/vars.c:1768`](file:///home/bhenc/reference/haproxy/src/vars.c#L1768) |
