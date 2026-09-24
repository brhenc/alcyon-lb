# VTC Action Plan

## Unlocked VTCs
- `stats/clear_counters_server.vtc`: Aligned CLI error strings (`No such backend.` and `No such server.`) in `applet.rs` for server commands, unblocking `clear counters` and `set server` state modification tests.
- VTCs involving `show info` monitoring: Fixed to accept trailing arguments in the command line instead of throwing `Unknown command.`, correctly dumping system info matching HAProxy behavior.
- VTCs testing `show servers state`: Handled the error path by returning `Can't find backend.\n` when the target backend does not exist.
- VTCs validating stick table dumps: Corrected `show table` and `show table <name>` output formatting to perfectly mirror HAProxy (`# table: <name>, type: <type>, size:<size>, used:<used>` and `0x0: key=<key> use=0 exp=0 [data_fields...]`), and implemented exact-match/inequality field filtering logic (e.g. `data.conn_rate > 5`).

## Next Targets
- Implement remaining runtime data path configuration actions (`capture`, `log-format`, `http-check`, `tcp-check`).
- Fix `vtc_runner.py`'s block parser which extracts an empty configuration for `haproxy h1 -conf-BAD {} {` rather than the intended syntax error, which falsely prevents `startup/default_rules.vtc` from passing.
