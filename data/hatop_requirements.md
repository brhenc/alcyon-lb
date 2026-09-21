# HATop Protocol Requirements & Compatibility Specification for Ibex

**Task:** T06 — hatop Protocol Requirements  
**Status:** Complete  
**Date:** 2026-09-21  

---

## 1. Upstream Oracle Identification

HATop is an interactive ncurses-based monitoring and management client for HAProxy. It is distributed as a single executable Python script with no third-party dependencies outside the Python standard library.

Two canonical upstream references were analyzed:

1. **Active / Modern Upstream (Python 3 Maintained Fork):**
   - **Repository URL:** `https://github.com/jhunt/hatop`
   - **Script Path:** `bin/hatop`
   - **Version:** `0.8.3` (cited in script header: `hatop_jhunt.py:162`)
   - **Authors:** John Feuerstein (`<john@feurix.com>`), James Hunt (`<james@jameshunt.us>`)
   - **Note:** This is the current version packaged in modern Linux distributions (Debian, Arch Linux, FreeBSD Ports, etc.) supporting Python 3 and modern HAProxy drain states (`F1-F3`, `F11`).

2. **Original Upstream (Python 2 Historical Canonical):**
   - **Project URL:** `http://feurix.org/projects/hatop/` (Mirror: `https://github.com/feurix/hatop`)
   - **Script Path:** `bin/hatop`
   - **Version:** `0.7.7` (cited in script header: `hatop_feurix.py:156`)
   - **Author:** John Feuerstein (`<john@feurix.com>`)

3. **Server-Side Oracle:**
   - **Repository:** `/home/bhenc/reference/haproxy`
   - **Commit:** `e6f616af97c93c1d8945cf8cfd77a1c8e36a2640` (HAProxy 3.1-dev / master)

All citations below reference `hatop` line numbers as `jhunt:<line>` (v0.8.3) and `feurix:<line>` (v0.7.7), alongside HAProxy source citations `haproxy:<file>:<line>`.

---

## 2. Socket Handshake & Protocol Mechanics

### 2.1 Connection Mode: Interactive Socket Only
- **Handshake Flow:** HATop connects to HAProxy via UNIX domain socket (`-s <path>`) or TCP socket (`-t <host:port>`) (`jhunt:370-377`, `feurix:364-371`).
- **Interactive Mode:** Immediately upon connecting, HATop executes two initialization commands (`jhunt:398-405`, `feurix:392-399`):
  1. `prompt\n`: Switches HAProxy's CLI session into interactive mode with prompt delimiter.
  2. `set timeout cli 60\n`: Configures HAProxy's interactive idle timeout to 60 seconds (`HAPROXY_CLI_TIMEOUT = 60`, `jhunt:189`, `feurix:183`).
- **Single Persistent Connection:** HATop **never** uses one-shot socket connections. It maintains a single persistent connection across its entire lifecycle and issues all periodic telemetry updates and administrative commands over this single channel.
- **Connection Teardown:** On shutdown, HATop sends `quit\n` and closes the socket (`jhunt:406-414`, `feurix:400-408`).

### 2.2 Hard Dependency on the Prompt String (`> `)
HATop's protocol framing relies **strictly** on the interactive prompt string:
```python
# jhunt:190, feurix:184
HAPROXY_CLI_PROMPT = '> '
```
- **Delimiter Check:** Every read from the socket (`Socket.wait()` at `jhunt:419-425` and `Socket.recv()` at `jhunt:426-445`) loops over `recv(4096)` chunks until `rbuf.endswith('> ')`.
- **Response Stream Demarcation:** The prompt `> ` is how HATop determines that the server has finished sending the command's response.
- **Timeout & Failure:** Socket commands have a 1-second timeout (`HAPROXY_CLI_CMD_TIMEOUT = 1`, `jhunt:192`, `feurix:186`). If the server omits `> `, sends a different prompt (e.g. `# ` or `haproxy> `), or leaves trailing whitespace after `> `, HATop blocks until the 1s timeout expires, raises `SocketError('error while waiting for prompt')` (`jhunt:384`), and **crashes immediately** (`sys.exit(2)`, `jhunt:2256-2259`).
- **HAProxy Server Format:** HAProxy server outputs `\n> ` after every command execution in interactive prompt mode (`haproxy:src/cli.c:1389`).

---

## 3. Command Inventory & Trigger Conditions

HATop sends a specific set of CLI commands across its lifecycle.

| Command Line Sent | When Triggered | Privilege Level (HAProxy) | Read-Only Mode (`-n`)? | Citations |
|---|---|---|---|---|
| `prompt` | On socket connect (initial handshake) | User / Master | **Yes** (sent in all modes) | `jhunt:399`, `feurix:393`, `haproxy:src/cli.c:4462` |
| `set timeout cli 60` | On socket connect (initial handshake) | User | **Yes** (sent in all modes) | `jhunt:401`, `feurix:395`, `haproxy:src/cli.c:4474` |
| `show info` | Periodic update (every `-i` seconds, default 3s) | User | **Yes** (sent in all modes) | `jhunt:503`, `feurix:497`, `haproxy:src/stats.c:1380` |
| `show stat` | Periodic update (every `-i` seconds when no filters active) | User | **Yes** (sent in all modes) | `jhunt:531`, `feurix:525`, `haproxy:src/stats.c:1381` |
| `show stat` | Startup proxy name resolution (when `-p <pxname>` given) | User | **Yes** (sent in all modes) | `jhunt:480`, `feurix:474`, `haproxy:src/stats.c:1381` |
| `show stat <iid> <type> <sid>` | Periodic update (every `-i` seconds when filter active) | User | **Yes** (sent in all modes) | `jhunt:520`, `feurix:514`, `haproxy:src/stats.c:1381` |
| `quit` | On graceful termination / cleanup | User | **Yes** (sent in all modes) | `jhunt:408`, `feurix:402`, `haproxy:src/cli.c:341` |
| `enable server <px>/<sv>` | Hotkey `F1` (all backends) or `F9` (selected backend) | Admin | **No** (disabled in read-only) | `jhunt:2030,2083`, `feurix:2036`, `haproxy:src/server.c:6336,7093` |
| `disable server <px>/<sv>` | Hotkey `F2` (all backends) or `F10` (selected backend) | Admin | **No** (disabled in read-only) | `jhunt:2030,2087`, `feurix:2040`, `haproxy:src/server.c:6266,7090` |
| `set server <px>/<sv> state drain` | Hotkey `F3` (all backends) or `F11` (selected backend) | Admin | **No** (disabled in read-only) | `jhunt:2043,2091`, `haproxy:src/server.c:5896,7095` |
| `set weight <px>/<sv> 100%` | Hotkey `F4` (reset weight) | Admin | **No** (disabled in read-only) | `jhunt:2047`, `feurix:2000`, `haproxy:src/server.c:6171,7097` |
| `set weight <px>/<sv> <weight>` | Hotkeys `F5` (-10), `F6` (-1), `F7` (+1), `F8` (+10) | Admin | **No** (disabled in read-only) | `jhunt:2055-2079`, `feurix:2008-2032`, `haproxy:src/server.c:6171` |
| `<arbitrary cli command>` | Embedded CLI Mode (Mode 5, interactive prompt) | Variable | **No** (Mode 5 disabled in `-n`) | `jhunt:839`, `feurix:833` |

### 2.3 CLI Mode Denied Commands
In embedded CLI mode (Mode 5), HATop permits arbitrary commands except those matching `CLI_INPUT_DENY_CMD` (`jhunt:200,815-824`, `feurix:194,809-818`):
- `prompt`
- `set timeout cli`
- `quit`

Commands may be separated by `;` (`HAPROXY_CLI_CMD_SEP = ';'`); HATop splits by `;` and validates each command token before submitting the entire raw string to the socket (`jhunt:812-826`).

---

## 4. `show info` Parsing & Schema Requirements

### 4.1 Required Keys (14 Mandated Keys)
`parse_info()` in HATop parses `show info` line by line using regular expressions (`jhunt:216-231,1665-1681`, `feurix:210-225,1627-1643`).

```python
# jhunt:216-231
HAPROXY_INFO_RE = {
'software_name':    re.compile(r'^Name:\s*(?P<value>\S+)'),
'software_version': re.compile(r'^Version:\s*(?P<value>\S+)'),
'software_release': re.compile(r'^Release_date:\s*(?P<value>\S+)'),
'nproc':            re.compile(r'^Nbproc:\s*(?P<value>\d+)'),
'procn':            re.compile(r'^Process_num:\s*(?P<value>\d+)'),
'pid':              re.compile(r'^Pid:\s*(?P<value>\d+)'),
'uptime':           re.compile(r'^Uptime:\s*(?P<value>[\S ]+)$'),
'maxconn':          re.compile(r'^Maxconn:\s*(?P<value>\d+)'),
'curconn':          re.compile(r'^CurrConns:\s*(?P<value>\d+)'),
'maxpipes':         re.compile(r'^Maxpipes:\s*(?P<value>\d+)'),
'curpipes':         re.compile(r'^PipesUsed:\s*(?P<value>\d+)'),
'tasks':            re.compile(r'^Tasks:\s*(?P<value>\d+)'),
'runqueue':         re.compile(r'^Run_queue:\s*(?P<value>\d+)'),
'node':             re.compile(r'^node:\s*(?P<value>\S+)'),
}
```

### 4.2 Mandatory Presence & Crash Behavior
- **Strict Completeness:** HATop iterates through all 14 keys in `HAPROXY_INFO_RE` (`jhunt:1677-1679`, `feurix:1639-1641`):
  ```python
  for key in HAPROXY_INFO_RE.keys():
      if not key in info:
          raise RuntimeError('missing "%s" in info data' % key)
  ```
- **Failure Mode:** If **any single key** among the 14 is absent from HAProxy's `show info` output, `parse_info` throws `RuntimeError`, caught in `main()` (`jhunt:2252-2255`), which **exits immediately with exit code 1**.
- **Tolerance for Extra Keys:** HAProxy outputs many additional keys in `show info` (e.g., `Nbthread`, `Memmax_MB`, `PoolAlloc_MB`, `Idle_pct`, `Uptime_sec`, etc.; `haproxy:src/stats.c:95-150`). HATop simply ignores unrecognized keys.
- **Type Conversions:**
  - `pid`, `procn`, `nproc`, `tasks`, `runqueue` are converted via `int(..., 10)` in `Screen.draw_info()` (`jhunt:1128-1145`).
  - `maxconn`, `curconn`, `maxpipes`, `curpipes` are converted via `int(..., 10)` in `Screen.update_bars()` (`jhunt:1076-1079`).
  - Because `\d+` is required by the regex for all numeric fields, numeric fields must be non-empty digits.

---

## 5. `show stat` CSV Parsing & Schema Requirements

### 5.1 Critical Finding: Positional Indexing & Hard Constraint on T04
HATop **DOES NOT** parse the CSV header line (`# pxname,svname,...`) to locate columns by name.
Instead:
1. Lines starting with `#` are discarded as comments (`jhunt:1590-1591`, `feurix:1582-1583`).
2. Lines with fewer than 51 commas are silently dropped (`jhunt:1592-1593`, `feurix:1584-1585`).
3. Each data line is split into columns using `line.split(',', 51)` (`jhunt:1595`, `feurix:1587`).
4. Fields are extracted **purely by positional index** `0` through `50` (`jhunt:1623-1646`, `feurix:1614-1637`).

> [!IMPORTANT]
> **T04 is a HARD CONSTRAINT.** Ibex MUST emit the first 51 stat CSV fields in the exact positional sequence defined in HAProxy 1.4+ / `stat_cols_px` (`haproxy:src/stats-proxy.c:79-131`). Any missing field, extra field inserted before index 51, or column permutation will cause integer parsing failures (`ValueError` -> `RuntimeError` -> crash) or data misattribution.

### 5.2 Complete 51-Field CSV Index Table

The table below lists all 51 fields parsed by HATop (`HAPROXY_STAT_CSV`, `jhunt:250-304`, `feurix:244-298`), their target Python type, their HAProxy C enum (`stat_cols_px`), and how HATop consumes them.

| Index | Field Name | Type | HAProxy Enum (`stat_cols_px`) | HATop UI Display Modes & Internal Usage |
|---|---|---|---|---|
| **0** | `pxname` | `str` | `ST_I_PX_PXNAME` | Group header (`>>> <pxname>`), filter matching, CLI command targeting |
| **1** | `svname` | `str` | `ST_I_PX_SVNAME` | Column `NAME` (Modes 1, 2, 3, 4), service identification (`FRONTEND`, `BACKEND`, `<srv>`) |
| **2** | `qcur` | `int` | `ST_I_PX_QCUR` | Column `QCUR` (Mode 1 - Status) |
| **3** | `qmax` | `int` | `ST_I_PX_QMAX` | Column `QMAX` (Mode 1 - Status) |
| **4** | `scur` | `int` | `ST_I_PX_SCUR` | Column `SCUR` (Mode 1 - Status) |
| **5** | `smax` | `int` | `ST_I_PX_SMAX` | Column `SMAX` (Mode 1 - Status) |
| **6** | `slim` | `int` | `ST_I_PX_SLIM` | Column `SLIM` (Mode 1 - Status) |
| **7** | `stot` | `int` | `ST_I_PX_STOT` | Column `STOT` (Mode 1 - Status) |
| **8** | `bin` | `int` | `ST_I_PX_BIN` | Column `BIN` (Mode 2 - Traffic, binary formatted) |
| **9** | `bout` | `int` | `ST_I_PX_BOUT` | Column `BOUT` (Mode 2 - Traffic, binary formatted) |
| **10** | `dreq` | `int` | `ST_I_PX_DREQ` | Column `DREQ` (Mode 4 - Errors) |
| **11** | `dresp` | `int` | `ST_I_PX_DRESP` | Column `DRSP` (Mode 4 - Errors) |
| **12** | `ereq` | `int` | `ST_I_PX_EREQ` | Column `EREQ` (Mode 4 - Errors) |
| **13** | `econ` | `int` | `ST_I_PX_ECON` | Column `ECONN` (Mode 4 - Errors) |
| **14** | `eresp` | `int` | `ST_I_PX_ERESP` | Column `ERSP` (Mode 4 - Errors) |
| **15** | `wretr` | `int` | `ST_I_PX_WRETR` | Stored in `svstat` (not assigned to default column) |
| **16** | `wredis` | `int` | `ST_I_PX_WREDIS` | Stored in `svstat` (not assigned to default column) |
| **17** | `status` | `str` | `ST_I_PX_STATUS` | Column `STATUS` (Modes 1, 2, 3, 4); special case `'no check' -> '-'` (`jhunt:1640`) |
| **18** | `weight` | `int` | `ST_I_PX_WEIGHT` | Column `W` (Modes 1, 2, 3, 4); current weight for hotkeys F5-F8 |
| **19** | `act` | `int` | `ST_I_PX_ACT` | Column `ACT` (Mode 1 - Status) |
| **20** | `bck` | `int` | `ST_I_PX_BCK` | Column `BCK` (Mode 1 - Status) |
| **21** | `chkfail` | `int` | `ST_I_PX_CHKFAIL` | Column `CF` (Mode 4 - Errors) |
| **22** | `chkdown` | `int` | `ST_I_PX_CHKDOWN` | Column `CD` (Mode 4 - Errors) |
| **23** | `lastchg` | `int` | `ST_I_PX_LASTCHG` | Column `CL` (Mode 4 - Errors, formatted as `10s`, `5m`, `2h`, `1d`) |
| **24** | `downtime` | `int` | `ST_I_PX_DOWNTIME` | Column `DOWN` (Mode 4 - Errors, formatted as time string) |
| **25** | `qlimit` | `int` | `ST_I_PX_QLIMIT` | Stored in `svstat` |
| **26** | `pid` | `int` | `ST_I_PX_PID` | Stored in `svstat` |
| **27** | `iid` | `int` | `ST_I_PX_IID` | Proxy ID; primary key for hierarchy `pxstat[iid][sid]`, filter validation |
| **28** | `sid` | `int` | `ST_I_PX_SID` | Service ID; service key for hierarchy `pxstat[iid][sid]`, filter validation |
| **29** | `throttle` | `int` | `ST_I_PX_THROTTLE` | Stored in `svstat` |
| **30** | `lbtot` | `int` | `ST_I_PX_LBTOT` | Column `LBTOT` (Mode 2 - Traffic) |
| **31** | `tracked` | `str` | `ST_I_PX_TRACKED` | Stored in `svstat` |
| **32** | `type` | `int` | `ST_I_PX_TYPE` | Service Type: `0=frontend`, `1=backend`, `2=server`, `3=socket` (`jhunt:1651,2025`) |
| **33** | `rate` | `int` | `ST_I_PX_RATE` | Column `RATE` (Mode 2 - Traffic) |
| **34** | `rate_lim` | `int` | `ST_I_PX_RATE_LIM` | Column `RLIM` (Mode 2 - Traffic) |
| **35** | `rate_max` | `int` | `ST_I_PX_RATE_MAX` | Column `RMAX` (Mode 2 - Traffic) |
| **36** | `check_status` | `str` | `ST_I_PX_CHECK_STATUS` | Column `CHECK` (Modes 1, 4); converted to `'none'` if `status == '-'` (`jhunt:1642`) |
| **37** | `check_code` | `int` | `ST_I_PX_CHECK_CODE` | Stored in `svstat` |
| **38** | `check_duration` | `int` | `ST_I_PX_CHECK_DURATION` | Stored in `svstat` |
| **39** | `hrsp_1xx` | `int` | `ST_I_PX_HRSP_1XX` | Column `1xx` (Mode 3 - HTTP) |
| **40** | `hrsp_2xx` | `int` | `ST_I_PX_HRSP_2XX` | Column `2xx` (Mode 3 - HTTP) |
| **41** | `hrsp_3xx` | `int` | `ST_I_PX_HRSP_3XX` | Column `3xx` (Mode 3 - HTTP) |
| **42** | `hrsp_4xx` | `int` | `ST_I_PX_HRSP_4XX` | Column `4xx` (Mode 3 - HTTP) |
| **43** | `hrsp_5xx` | `int` | `ST_I_PX_HRSP_5XX` | Column `5xx` (Mode 3 - HTTP) |
| **44** | `hrsp_other` | `int` | `ST_I_PX_HRSP_OTHER` | Column `?xx` (Mode 3 - HTTP) |
| **45** | `hanafail` | `str` | `ST_I_PX_HANAFAIL` | Stored in `svstat` |
| **46** | `req_rate` | `int` | `ST_I_PX_REQ_RATE` | Column `RATE` (Mode 3 - HTTP) |
| **47** | `req_rate_max` | `int` | `ST_I_PX_REQ_RATE_MAX` | Column `RMAX` (Mode 3 - HTTP) |
| **48** | `req_tot` | `int` | `ST_I_PX_REQ_TOT` | Column `RTOT` (Mode 3 - HTTP) |
| **49** | `cli_abrt` | `int` | `ST_I_PX_CLI_ABRT` | Stored in `svstat` |
| **50** | `srv_abrt` | `int` | `ST_I_PX_SRV_ABRT` | Stored in `svstat` |

### 5.3 Parsing Logic & Value Conversions
- **Empty Integer Handling:** If an `int` field is empty (i.e. `,,`), HATop assigns `0` (`jhunt:1629-1632`):
  ```python
  if field_type is int:
      if len(value):
          value = int(value, 10)
      else:
          value = 0
  ```
- **Non-Numeric Error:** If a non-empty string cannot be parsed as an integer for an `int` field, HATop raises `RuntimeError('garbage field: ...')` (`jhunt:1636`), causing an immediate hard exit.
- **Fields Beyond Index 50:** HAProxy 1.5+ added fields 51..84 (such as `comp_in`, `comp_out`, `lastsess`, `qtime`, `ctime`, etc.; `haproxy:src/stats-proxy.c:132-160`). Because `line.split(',', 51)` splits into at most 52 chunks, elements at index 51+ are lumped into the trailing slice and ignored. This makes HATop forward-compatible with newer HAProxy fields appended at the end.

---

## 6. Error Handling & Degradation Semantics

The table below outlines how HATop responds to socket, parser, protocol, and data anomalies.

| Anomaly / Event | Code Location | Exception Raised | Immediate Impact | Hard Fail vs Degrade |
|---|---|---|---|---|
| Socket connection refused / timeout / EOF | `Socket._recv` (`jhunt:384`) | `SocketError` | Caught in `main()`, prints error to stderr | **Hard Fail** (`sys.exit(2)`) |
| Missing `> ` prompt delimiter | `Socket.wait`, `recv` (`jhunt:422,431`) | `SocketError` (socket timeout after 1s) | Blocks for 1s, then exits | **Hard Fail** (`sys.exit(2)`) |
| Any of the 14 `show info` keys missing | `parse_info` (`jhunt:1679`) | `RuntimeError('missing "..." in info data')` | Caught in `main()`, prints error | **Hard Fail** (`sys.exit(1)`) |
| Non-numeric value in `show info` numeric key | `Screen.draw_info` (`jhunt:1128`) | `ValueError` | Caught in `main()`, prints error | **Hard Fail** (`sys.exit(1)`) |
| Line has fewer than 51 commas (`line.count(',') < 51`) | `parse_stat` (`jhunt:1592`) | None (`continue # unknown format`) | Line is dropped silently | **Degrades** |
| Non-numeric value in CSV integer field (0..50) | `parse_stat` (`jhunt:1636`) | `RuntimeError('garbage field: ...')` | Caught in `main()`, prints error | **Hard Fail** (`sys.exit(1)`) |
| Zero valid stat lines parsed (`pxcount == 0`) | `SocketData.update_stat` (`jhunt:536`) | `RuntimeWarning('no stat data available')` | Caught in `Screen.update_data()`, displayed on curses screen | **Degrades** (shows warning, keeps running) |
| Proxies/services count changes at runtime | `SocketData.update_stat` (`jhunt:552`) | `RuntimeWarning('config changed: ...')` | Caught in `Screen.update_data()`, displayed on curses screen | **Degrades** (reloads on next cycle) |
| Service count exceeds limit (`svcount > 1000`) | `parse_stat` (`jhunt:1598`) | None | Stops full parsing; counts `iid`/`sid` only, shows warning | **Degrades** (displays warning banner) |
| Stale stat filter returns 0 entries | `SocketData.update_stat` (`jhunt:525`) | `RuntimeError('stale stat filter: ...')` | Caught in `main()`, exits | **Hard Fail** (`sys.exit(1)`) |

---

## 7. Minimum Server-Side Surface for Ibex

To achieve the goal of "unmodified hatop drives Ibex", Ibex must implement the following tiers of functionality.

### Tier 1: Minimum Read-Only Surface (HATop `-n` Mode)
This is the absolute minimal surface required for HATop to launch, populate all 4 monitoring viewports (Status, Traffic, HTTP, Errors), and refresh periodically without errors.

1. **Unix / TCP Stats Socket:**
   - Support persistent interactive connection.
   - Initial handshake handling:
     - Accept `prompt\n` -> enable interactive mode, reply with `\n> `
     - Accept `set timeout cli <n>\n` -> reply with `\n> ` (or empty response + `\n> `)
     - Accept `quit\n` -> close socket
2. **`show info` Command:**
   - Emits key-value text lines ending with `\n\n> `.
   - **MUST contain all 14 mandatory keys:**
     - `Name: <str>`
     - `Version: <str>`
     - `Release_date: <str>`
     - `Nbproc: <int>`
     - `Process_num: <int>`
     - `Pid: <int>`
     - `Uptime: <str>` (e.g. `0d 0h00m10s`)
     - `Maxconn: <int>`
     - `CurrConns: <int>`
     - `Maxpipes: <int>`
     - `PipesUsed: <int>`
     - `Tasks: <int>`
     - `Run_queue: <int>`
     - `node: <str>`
3. **`show stat` Command (and `show stat <iid> <type> <sid>`):**
   - Emits `# ` comment header line (optional, ignored by HATop).
   - Emits CSV lines with **at least 51 comma-separated fields** per line in the exact 0..50 order specified in Section 5.2.
   - All `int` fields must be integer literals or empty string `""` (which defaults to `0`).
   - Ends with `\n> `.

### Tier 2: Interactive View Mode Surface (Hotkeys F1–F11)
In addition to Tier 1, to enable interactive operator actions from HATop's curses UI:

1. **`enable server <backend>/<server>`**:
   - Clears maintenance mode, enables traffic to server.
   - Triggered by `F1` (all backends with server name) and `F9` (selected backend/server).
2. **`disable server <backend>/<server>`**:
   - Puts server into maintenance mode (`MAINT`).
   - Triggered by `F2` (all backends) and `F10` (selected backend/server).
3. **`set server <backend>/<server> state drain`**:
   - Puts server into draining mode (`DRAIN`).
   - Triggered by `F3` (all backends) and `F11` (selected backend/server).
4. **`set weight <backend>/<server> <weight>` and `set weight <backend>/<server> 100%`**:
   - Adjusts server weight between 0 and 256 or resets to initial configured weight.
   - Triggered by `F4` (100%), `F5` (-10), `F6` (-1), `F7` (+1), `F8` (+10).
5. **Response Format:**
   - HAProxy emits informational messages or empty lines followed by `\n> `. HATop captures and displays this output in its CLI log pad (`jhunt:837-841`).

### Tier 3: Full Embedded CLI Surface (Mode 5)
In addition to Tiers 1 and 2, to allow operator arbitrary CLI usage:
1. Dispatcher supporting standard CLI syntax.
2. Support for semicolon-delimited multi-commands (`<cmd1>; <cmd2>`).
3. Output pagination/streaming terminated with `\n> `.

---

## 8. Exactness vs. Tolerance Matrix

| Protocol Component | Output Format Required | Server Behavior Required | Evidence from HATop Source |
|---|---|---|---|
| **Socket Prompt** | **Byte-Exact** | Must end with exact string `> ` (ASCII 0x3E 0x20) | `HAPROXY_CLI_PROMPT = '> '` (`jhunt:190`); buffer matching `rbuf.endswith(HAPROXY_CLI_PROMPT)` (`jhunt:422,431`) |
| **`show info` Key Names** | **Byte-Exact** | `Name:`, `Version:`, `Release_date:`, `Nbproc:`, `Process_num:`, `Pid:`, `Uptime:`, `Maxconn:`, `CurrConns:`, `Maxpipes:`, `PipesUsed:`, `Tasks:`, `Run_queue:`, `node:` | Regex prefix matching `^<Key>:\s*` (`jhunt:216-231`); loops `for key in HAPROXY_INFO_RE.keys(): if key not in info: raise RuntimeError` (`jhunt:1677-1679`) |
| **`show info` Value Types** | **Byte-Exact** for numeric fields | Integers must match `\d+`; node/software strings must match `\S+` | `\d+` regex requirement (`jhunt:220-222,224-229`) and `int(..., 10)` cast (`jhunt:1076-1079,1128-1145`) |
| **`show info` Extra Keys** | **Tolerant** | Additional keys from newer HAProxy versions are safely ignored | Unmatched lines simply do not match any regex in `HAPROXY_INFO_RE` and are ignored in loop (`jhunt:1671-1675`) |
| **CSV Field Ordering (0..50)** | **Byte-Exact** | Indices 0 to 50 must match the exact 51-field schema | Field indexing `csv[idx]` by numerical index `0..50` (`jhunt:1623-1625`) |
| **CSV Comma Count** | **Threshold (>= 51)** | Must have at least 51 commas per data line | `if line.count(HAPROXY_STAT_SEP) < HAPROXY_STAT_NUMFIELDS: continue` (`jhunt:1592`) |
| **CSV Field Types (0..50)** | **Byte-Exact** | Integer columns must be integer ASCII or empty `""` (which becomes 0) | `int(value, 10)` without fallback; failure triggers `RuntimeError` (`jhunt:1628-1637`) |
| **CSV Extra Fields (51+)** | **Tolerant** | Fields beyond index 50 may be emitted without breaking HATop | `line.split(HAPROXY_STAT_SEP, 51)` limits split count to 51 (`jhunt:1595`) |
| **CSV Status Translations** | **Tolerant / Handled by HATop** | `no check` is translated to `-`; `status == '-'` sets `check_status = 'none'` | Special-case mapping in `parse_stat()` (`jhunt:1640-1643`) |
| **Command Responses (Writes)**| **Tolerant** | Return text or empty line; must end with `\n> ` | Output lines are appended to curses CLI buffer without structured parsing (`jhunt:840`) |
