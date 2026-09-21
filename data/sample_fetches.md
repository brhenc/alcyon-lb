# HAProxy Sample Fetch Inventory

**Reference Source:** HAProxy commit `e6f616af` (3.5-dev7)
**Extraction Target:** `struct sample_fetch_kw_list` registration tables across the codebase
**Total Sample Fetches Extracted:** 570
**Total Registered Tables Identified:** 26 static tables (24 active tables with keyword entries, 2 empty placeholder tables)

---

## 1. Frequency Table of `out_type`

| Output Type (`out_type`) | Count | Percentage | Description |
|---|---|---|---|
| `SMP_T_SINT` | 325 | 57.0% | Signed 64-bit integer |
| `SMP_T_STR` | 141 | 24.7% | Character string |
| `SMP_T_BIN` | 47 | 8.2% | Binary buffer |
| `SMP_T_BOOL` | 37 | 6.5% | Boolean (0 or 1) |
| `SMP_T_ADDR` | 10 | 1.8% | IP Address (IPv4 or IPv6 pseudo-type) |
| `SMP_T_ANY` | 5 | 0.9% | Any type (generic pseudo-type) |
| `SMP_T_METH` | 2 | 0.4% | HTTP request method |
| `SMP_T_IPV4` | 2 | 0.4% | IPv4 Address |
| `SMP_T_IPV6` | 1 | 0.2% | IPv6 Address |
| **Total** | **570** | **100.0%** | |

## 2. Distinct `SMP_T_*` Types and Definitions

All sample output types are defined in `include/haproxy/sample-t.h` lines 36–48:

| Enum Symbol | Value | Defined at | Status in Fetches |
|---|---|---|---|
| `SMP_T_ANY` | `0` | `include/haproxy/sample-t.h:37` | Present (5 fetches) |
| `SMP_T_SAME` | `1` | `include/haproxy/sample-t.h:38` | Not used in fetches (converter-only type hint) |
| `SMP_T_BOOL` | `2` | `include/haproxy/sample-t.h:39` | Present (37 fetches) |
| `SMP_T_SINT` | `3` | `include/haproxy/sample-t.h:40` | Present (325 fetches) |
| `SMP_T_ADDR` | `4` | `include/haproxy/sample-t.h:41` | Present (10 fetches) |
| `SMP_T_IPV4` | `5` | `include/haproxy/sample-t.h:42` | Present (2 fetches) |
| `SMP_T_IPV6` | `6` | `include/haproxy/sample-t.h:43` | Present (1 fetch) |
| `SMP_T_STR` | `7` | `include/haproxy/sample-t.h:44` | Present (141 fetches) |
| `SMP_T_BIN` | `8` | `include/haproxy/sample-t.h:45` | Present (47 fetches) |
| `SMP_T_METH` | `9` | `include/haproxy/sample-t.h:46` | Present (2 fetches) |
| `SMP_TYPES` | `10` | `include/haproxy/sample-t.h:47` | Internal sentinel / count |

## 3. Distinct `SMP_VAL_*` Validity Bitmasks and Definitions

Sample validity bitmasks (`SMP_VAL_*`) define the checkpoint rules where samples can be fetched.
They are defined in `include/haproxy/sample-t.h` lines 152–187 based on the `SMP_CKP_*` checkpoints enum (lines 84–108).
At fetch registration (`sample_register_fetches` in `src/sample.c:445`), each fetch's `use` field (composed of `SMP_USE_*` source flags) is mapped to its `val` bitmask via the `fetch_cap[]` lookup table (`src/sample.c:97-304`).

| `SMP_VAL_*` Flag | Definition / Checkpoint | Defined at |
|---|---|---|
| `SMP_VAL___________` | 0 (Visual marker / empty mask) | `include/haproxy/sample-t.h:153` |
| `SMP_VAL_FE_CON_ACC` | 1 << SMP_CKP_FE_CON_ACC (FE connection accept rules: tcp-request connection) | `include/haproxy/sample-t.h:154` |
| `SMP_VAL_FE_SES_ACC` | 1 << SMP_CKP_FE_SES_ACC (FE stream accept rules: tcp-request session) | `include/haproxy/sample-t.h:155` |
| `SMP_VAL_FE_REQ_CNT` | 1 << SMP_CKP_FE_REQ_CNT (FE request content rules: tcp-request content) | `include/haproxy/sample-t.h:156` |
| `SMP_VAL_FE_HRQ_HDR` | 1 << SMP_CKP_FE_HRQ_HDR (FE HTTP request headers: rules, headers, monitor, stats, redirect) | `include/haproxy/sample-t.h:157` |
| `SMP_VAL_FE_HRQ_BDY` | 1 << SMP_CKP_FE_HRQ_BDY (FE HTTP request body) | `include/haproxy/sample-t.h:158` |
| `SMP_VAL_FE_SET_BCK` | 1 << SMP_CKP_FE_SET_BCK (FE backend switching rules: use_backend) | `include/haproxy/sample-t.h:159` |
| `SMP_VAL_BE_REQ_CNT` | 1 << SMP_CKP_BE_REQ_CNT (BE request content rules: tcp-request content) | `include/haproxy/sample-t.h:160` |
| `SMP_VAL_BE_HRQ_HDR` | 1 << SMP_CKP_BE_HRQ_HDR (BE HTTP request headers: rules, headers, monitor, stats, redirect) | `include/haproxy/sample-t.h:161` |
| `SMP_VAL_BE_HRQ_BDY` | 1 << SMP_CKP_BE_HRQ_BDY (BE HTTP request body) | `include/haproxy/sample-t.h:162` |
| `SMP_VAL_BE_SET_SRV` | 1 << SMP_CKP_BE_SET_SRV (BE server switching rules: use_server, balance, force-persist, stick) | `include/haproxy/sample-t.h:163` |
| `SMP_VAL_BE_SRV_CON` | 1 << SMP_CKP_BE_SRV_CON (BE server connect: source) | `include/haproxy/sample-t.h:164` |
| `SMP_VAL_BE_RES_CNT` | 1 << SMP_CKP_BE_RES_CNT (BE response content rules: tcp-response content) | `include/haproxy/sample-t.h:165` |
| `SMP_VAL_BE_HRS_HDR` | 1 << SMP_CKP_BE_HRS_HDR (BE HTTP response headers: rules, headers) | `include/haproxy/sample-t.h:166` |
| `SMP_VAL_BE_HRS_BDY` | 1 << SMP_CKP_BE_HRS_BDY (BE HTTP response body: stick-store rules) | `include/haproxy/sample-t.h:167` |
| `SMP_VAL_BE_STO_RUL` | 1 << SMP_CKP_BE_STO_RUL (BE stick-store rules) | `include/haproxy/sample-t.h:168` |
| `SMP_VAL_FE_RES_CNT` | 1 << SMP_CKP_FE_RES_CNT (FE response content rules: tcp-response content) | `include/haproxy/sample-t.h:169` |
| `SMP_VAL_FE_HRS_HDR` | 1 << SMP_CKP_FE_HRS_HDR (FE HTTP response headers: rules, headers) | `include/haproxy/sample-t.h:170` |
| `SMP_VAL_FE_HRS_BDY` | 1 << SMP_CKP_FE_HRS_BDY (FE HTTP response body) | `include/haproxy/sample-t.h:171` |
| `SMP_VAL_FE_LOG_END` | 1 << SMP_CKP_FE_LOG_END (FE log at end of txn/stream) | `include/haproxy/sample-t.h:172` |
| `SMP_VAL_BE_CHK_RUL` | 1 << SMP_CKP_BE_CHK_RUL (BE tcp-check rule) | `include/haproxy/sample-t.h:173` |
| `SMP_VAL_CFG_PARSER` | 1 << SMP_CKP_CFG_PARSER (Within config parser) | `include/haproxy/sample-t.h:174` |
| `SMP_VAL_CLI_PARSER` | 1 << SMP_CKP_CLI_PARSER (Within command line parser) | `include/haproxy/sample-t.h:175` |
| `SMP_VAL_REQUEST` | Composite: FE/BE request checkpoints (FE_CON_ACC|FE_SES_ACC|FE_REQ_CNT|FE_HRQ_HDR|FE_HRQ_BDY|FE_SET_BCK|BE_REQ_CNT|BE_HRQ_HDR|BE_HRQ_BDY|BE_SET_SRV|BE_CHK_RUL) | `include/haproxy/sample-t.h:178` |
| `SMP_VAL_RESPONSE` | Composite: FE/BE response checkpoints (BE_SRV_CON|BE_RES_CNT|BE_HRS_HDR|BE_HRS_BDY|BE_STO_RUL|FE_RES_CNT|FE_HRS_HDR|FE_HRS_BDY|FE_LOG_END|BE_CHK_RUL) | `include/haproxy/sample-t.h:183` |

## 4. Unparsed Entries and Structural Notes

- **Unparsed entries:** 0. All 570 entries across all 26 static registration tables were parsed completely without errors.
- **Empty registration tables (2 tables):**
  - `src/check.c:2094` (`smp_kws`): Registered at line 2098, contains only `{ /* END */ }` (0 keyword entries).
  - `src/flt_decomp.c:1357` (`sample_fetch_keywords`): Registered at line 1362, contains only `{ /* END */ }` (0 keyword entries).
- **Runtime dynamic registration:**
  - `src/hlua.c:10352` (`sample_register_fetches(sfk)`): Allocates and registers dynamic sample fetch keywords registered via Lua scripts (`core.register_fetches`) at runtime; no static C keyword entries.
- **Global list head:**
  - `src/sample.c:88` (`sample_fetches`): List head anchor (`LIST_HEAD_INIT`), not a keyword provider table.
- **7-field struct initializers (2 entries):**
  - `src/cache.c:3803` (`res.cache_hit`): Explicitly specifies both `SMP_USE_HRSHP` (field 6) and `SMP_VAL_RESPONSE` (field 7).
  - `src/cache.c:3804` (`res.cache_name`): Explicitly specifies both `SMP_USE_HRSHP` (field 6) and `SMP_VAL_RESPONSE` (field 7).

## 5. Table-by-Table Registration Summary

| # | Source File | Table Variable Name | Registered At | Keyword Count |
|---|---|---|---|---|
| 1 | `addons/51degrees/51d.c` | `sample_fetch_keywords` | `addons/51degrees/51d.c:1176` | 1 |
| 2 | `addons/deviceatlas/da.c` | `fetch_kws` | `addons/deviceatlas/da.c:563` | 1 |
| 3 | `addons/wurfl/wurfl.c` | `fetch_kws` | `addons/wurfl/wurfl.c:638` | 2 |
| 4 | `src/acl.c` | `smp_kws` | `src/acl.c:1415` | 1 |
| 5 | `src/backend.c` | `smp_kws` | `src/backend.c:3984` | 25 |
| 6 | `src/cache.c` | `sample_fetch_keywords` | `src/cache.c:3809` | 2 |
| 7 | `src/check.c` | `smp_kws` | `src/check.c:2098` | 0 |
| 8 | `src/connection.c` | `sample_fetch_keywords` | `src/connection.c:2922` | 18 |
| 9 | `src/fcgi-app.c` | `sample_fetch_keywords` | `src/fcgi-app.c:1099` | 2 |
| 10 | `src/flt_decomp.c` | `sample_fetch_keywords` | `src/flt_decomp.c:1362` | 0 |
| 11 | `src/flt_http_comp.c` | `sample_fetch_keywords` | `src/flt_http_comp.c:1274` | 2 |
| 12 | `src/flt_spoe.c` | `smp_kws` | `src/flt_spoe.c:2955` | 1 |
| 13 | `src/frontend.c` | `smp_kws` | `src/frontend.c:355` | 8 |
| 14 | `src/http_fetch.c` | `sample_fetch_keywords` | `src/http_fetch.c:2467` | 87 |
| 15 | `src/http_htx.c` | `sample_fetch_keywords` | `src/http_htx.c:3191` | 14 |
| 16 | `src/listener.c` | `smp_kws` | `src/listener.c:3038` | 3 |
| 17 | `src/payload.c` | `smp_kws` | `src/payload.c:1490` | 31 |
| 18 | `src/queue.c` | `smp_kws` | `src/queue.c:902` | 2 |
| 19 | `src/sample.c (logs)` | `smp_logs_kws` | `src/sample.c:5940` | 19 |
| 20 | `src/sample.c (base)` | `smp_kws` | `src/sample.c:5988` | 34 |
| 21 | `src/ssl_sample.c` | `sample_fetch_keywords` | `src/ssl_sample.c:2949` | 105 |
| 22 | `src/stconn.c` | `sample_fetch_keywords` | `src/stconn.c:2392` | 8 |
| 23 | `src/stick_table.c` | `smp_fetch_keywords` | `src/stick_table.c:6284` | 156 |
| 24 | `src/stream.c` | `smp_kws` | `src/stream.c:4898` | 16 |
| 25 | `src/tcp_sample.c` | `sample_fetch_keywords` | `src/tcp_sample.c:637` | 30 |
| 26 | `src/vars.c` | `sample_fetch_keywords` | `src/vars.c:1668` | 2 |
| | **Total Across All Tables** | | | **570** |

## 6. Complete Sample Fetch Inventory (570 entries)

| Keyword | Process Function | Argument Mask | Output Type | Valid Where / Use | Citation |
|---|---|---|---|---|---|
| `51d.all` | `_51d_fetch` | `ARG5(1,STR,STR,STR,STR,STR)` | `SMP_T_STR` | `SMP_USE_HRQHV` | `addons/51degrees/51d.c:1172` |
| `da-csv-fetch` | `da_haproxy_fetch` | `ARG12(1,STR,STR,STR,STR,STR,STR,STR,STR,STR,STR,STR,STR)` | `SMP_T_STR` | `SMP_USE_HRQHV` | `addons/deviceatlas/da.c:559` |
| `wurfl-get-all` | `ha_wurfl_get_all` | `0` | `SMP_T_STR` | `SMP_USE_HRQHV` | `addons/wurfl/wurfl.c:632` |
| `wurfl-get` | `ha_wurfl_get` | `ARG12(1,STR,STR,STR,STR,STR,STR,STR,STR,STR,STR,STR,STR)` | `SMP_T_STR` | `SMP_USE_HRQHV` | `addons/wurfl/wurfl.c:633` |
| `acl` | `smp_fetch_acl` | `ARG12(1,STR,STR,STR,STR,STR,STR,STR,STR,STR,STR,STR,STR)` | `SMP_T_BOOL` | `SMP_USE_CONST` | `src/acl.c:1411` |
| `avg_queue` | `smp_fetch_avg_queue_size` | `ARG1(1,BE)` | `SMP_T_SINT` | `SMP_USE_INTRN` | `src/backend.c:3956` |
| `be_conn` | `smp_fetch_be_conn` | `ARG1(1,BE)` | `SMP_T_SINT` | `SMP_USE_INTRN` | `src/backend.c:3957` |
| `be_conn_free` | `smp_fetch_be_conn_free` | `ARG1(1,BE)` | `SMP_T_SINT` | `SMP_USE_INTRN` | `src/backend.c:3958` |
| `be_id` | `smp_fetch_be_id` | `0` | `SMP_T_SINT` | `SMP_USE_BKEND` | `src/backend.c:3959` |
| `be_name` | `smp_fetch_be_name` | `0` | `SMP_T_STR` | `SMP_USE_BKEND` | `src/backend.c:3960` |
| `be_connect_timeout` | `smp_fetch_be_connect_timeout` | `0` | `SMP_T_SINT` | `SMP_USE_BKEND` | `src/backend.c:3961` |
| `be_max_retries` | `smp_fetch_be_max_retries` | `0` | `SMP_T_SINT` | `SMP_USE_BKEND` | `src/backend.c:3962` |
| `be_queue_timeout` | `smp_fetch_be_queue_timeout` | `0` | `SMP_T_SINT` | `SMP_USE_BKEND` | `src/backend.c:3963` |
| `be_server_timeout` | `smp_fetch_be_server_timeout` | `0` | `SMP_T_SINT` | `SMP_USE_BKEND` | `src/backend.c:3964` |
| `be_sess_rate` | `smp_fetch_be_sess_rate` | `ARG1(1,BE)` | `SMP_T_SINT` | `SMP_USE_INTRN` | `src/backend.c:3965` |
| `be_tarpit_timeout` | `smp_fetch_be_tarpit_timeout` | `0` | `SMP_T_SINT` | `SMP_USE_BKEND` | `src/backend.c:3966` |
| `be_tunnel_timeout` | `smp_fetch_be_tunnel_timeout` | `0` | `SMP_T_SINT` | `SMP_USE_BKEND` | `src/backend.c:3967` |
| `connslots` | `smp_fetch_connslots` | `ARG1(1,BE)` | `SMP_T_SINT` | `SMP_USE_INTRN` | `src/backend.c:3968` |
| `nbsrv` | `smp_fetch_nbsrv` | `ARG1(1,BE)` | `SMP_T_SINT` | `SMP_USE_INTRN` | `src/backend.c:3969` |
| `queue` | `smp_fetch_queue_size` | `ARG1(1,BE)` | `SMP_T_SINT` | `SMP_USE_INTRN` | `src/backend.c:3970` |
| `srv_conn` | `smp_fetch_srv_conn` | `ARG1(1,SRV)` | `SMP_T_SINT` | `SMP_USE_INTRN` | `src/backend.c:3971` |
| `srv_conn_free` | `smp_fetch_srv_conn_free` | `ARG1(1,SRV)` | `SMP_T_SINT` | `SMP_USE_INTRN` | `src/backend.c:3972` |
| `srv_id` | `smp_fetch_srv_id` | `0` | `SMP_T_SINT` | `SMP_USE_SERVR` | `src/backend.c:3973` |
| `srv_is_up` | `smp_fetch_srv_is_up` | `ARG1(1,SRV)` | `SMP_T_BOOL` | `SMP_USE_INTRN` | `src/backend.c:3974` |
| `srv_name` | `smp_fetch_srv_name` | `0` | `SMP_T_STR` | `SMP_USE_SERVR` | `src/backend.c:3975` |
| `srv_queue` | `smp_fetch_srv_queue` | `ARG1(1,SRV)` | `SMP_T_SINT` | `SMP_USE_INTRN` | `src/backend.c:3976` |
| `srv_sess_rate` | `smp_fetch_srv_sess_rate` | `ARG1(1,SRV)` | `SMP_T_SINT` | `SMP_USE_INTRN` | `src/backend.c:3977` |
| `srv_weight` | `smp_fetch_srv_weight` | `ARG1(1,SRV)` | `SMP_T_SINT` | `SMP_USE_INTRN` | `src/backend.c:3978` |
| `srv_iweight` | `smp_fetch_srv_iweight` | `ARG1(1,SRV)` | `SMP_T_SINT` | `SMP_USE_INTRN` | `src/backend.c:3979` |
| `srv_uweight` | `smp_fetch_srv_uweight` | `ARG1(1,SRV)` | `SMP_T_SINT` | `SMP_USE_INTRN` | `src/backend.c:3980` |
| `res.cache_hit` | `smp_fetch_res_cache_hit` | `0` | `SMP_T_BOOL` | `SMP_USE_HRSHP, SMP_VAL_RESPONSE` | `src/cache.c:3803` |
| `res.cache_name` | `smp_fetch_res_cache_name` | `0` | `SMP_T_STR` | `SMP_USE_HRSHP, SMP_VAL_RESPONSE` | `src/cache.c:3804` |
| `bc_err` | `smp_fetch_fc_err` | `0` | `SMP_T_SINT` | `SMP_USE_L4SRV` | `src/connection.c:2901` |
| `bc_err_name` | `smp_fetch_fc_err_str` | `0` | `SMP_T_STR` | `SMP_USE_L4SRV` | `src/connection.c:2902` |
| `bc_err_str` | `smp_fetch_fc_err_str` | `0` | `SMP_T_STR` | `SMP_USE_L4SRV` | `src/connection.c:2903` |
| `bc_glitches` | `smp_fetch_fc_glitches` | `0` | `SMP_T_SINT` | `SMP_USE_L4SRV` | `src/connection.c:2904` |
| `bc_http_major` | `smp_fetch_fc_http_major` | `0` | `SMP_T_SINT` | `SMP_USE_L4SRV` | `src/connection.c:2905` |
| `bc_nb_streams` | `smp_fetch_fc_nb_streams` | `0` | `SMP_T_SINT` | `SMP_USE_L5SRV` | `src/connection.c:2906` |
| `bc_settings_streams_limit` | `smp_fetch_fc_streams_limit` | `0` | `SMP_T_SINT` | `SMP_USE_L5SRV` | `src/connection.c:2907` |
| `fc_err` | `smp_fetch_fc_err` | `0` | `SMP_T_SINT` | `SMP_USE_L4CLI` | `src/connection.c:2908` |
| `fc_err_name` | `smp_fetch_fc_err_str` | `0` | `SMP_T_STR` | `SMP_USE_L4CLI` | `src/connection.c:2909` |
| `fc_err_str` | `smp_fetch_fc_err_str` | `0` | `SMP_T_STR` | `SMP_USE_L4CLI` | `src/connection.c:2910` |
| `fc_glitches` | `smp_fetch_fc_glitches` | `0` | `SMP_T_SINT` | `SMP_USE_L4CLI` | `src/connection.c:2911` |
| `fc_http_major` | `smp_fetch_fc_http_major` | `0` | `SMP_T_SINT` | `SMP_USE_L4CLI` | `src/connection.c:2912` |
| `fc_rcvd_proxy` | `smp_fetch_fc_rcvd_proxy` | `0` | `SMP_T_BOOL` | `SMP_USE_L4CLI` | `src/connection.c:2913` |
| `fc_nb_streams` | `smp_fetch_fc_nb_streams` | `0` | `SMP_T_SINT` | `SMP_USE_L4CLI` | `src/connection.c:2914` |
| `fc_pp_authority` | `smp_fetch_fc_pp_authority` | `0` | `SMP_T_STR` | `SMP_USE_L4CLI` | `src/connection.c:2915` |
| `fc_pp_unique_id` | `smp_fetch_fc_pp_unique_id` | `0` | `SMP_T_STR` | `SMP_USE_L4CLI` | `src/connection.c:2916` |
| `fc_pp_tlv` | `smp_fetch_fc_pp_tlv` | `ARG1(1, STR)` | `SMP_T_STR` | `SMP_USE_L5CLI` | `src/connection.c:2917` |
| `fc_settings_streams_limit` | `smp_fetch_fc_streams_limit` | `0` | `SMP_T_SINT` | `SMP_USE_L5CLI` | `src/connection.c:2918` |
| `fcgi.docroot` | `smp_fetch_fcgi_docroot` | `0` | `SMP_T_STR` | `SMP_USE_HRQHV` | `src/fcgi-app.c:1094` |
| `fcgi.index` | `smp_fetch_fcgi_index` | `0` | `SMP_T_STR` | `SMP_USE_HRQHV` | `src/fcgi-app.c:1095` |
| `res.comp` | `smp_fetch_res_comp` | `0` | `SMP_T_BOOL` | `SMP_USE_HRSHP` | `src/flt_http_comp.c:1268` |
| `res.comp_algo` | `smp_fetch_res_comp_algo` | `0` | `SMP_T_STR` | `SMP_USE_HRSHP` | `src/flt_http_comp.c:1269` |
| `spoe.engine-id` | `smp_fetch_spoe_engine_id` | `0` | `SMP_T_STR` | `SMP_USE_INTRN` | `src/flt_spoe.c:2951` |
| `fe_client_timeout` | `smp_fetch_fe_client_timeout` | `0` | `SMP_T_SINT` | `SMP_USE_FTEND` | `src/frontend.c:344` |
| `fe_tarpit_timeout` | `smp_fetch_fe_tarpit_timeout` | `0` | `SMP_T_SINT` | `SMP_USE_FTEND` | `src/frontend.c:345` |
| `fe_conn` | `smp_fetch_fe_conn` | `ARG1(1,FE)` | `SMP_T_SINT` | `SMP_USE_INTRN` | `src/frontend.c:346` |
| `fe_defbe` | `smp_fetch_fe_defbe` | `0` | `SMP_T_STR` | `SMP_USE_FTEND` | `src/frontend.c:347` |
| `fe_id` | `smp_fetch_fe_id` | `0` | `SMP_T_SINT` | `SMP_USE_FTEND` | `src/frontend.c:348` |
| `fe_name` | `smp_fetch_fe_name` | `0` | `SMP_T_STR` | `SMP_USE_FTEND` | `src/frontend.c:349` |
| `fe_req_rate` | `smp_fetch_fe_req_rate` | `ARG1(1,FE)` | `SMP_T_SINT` | `SMP_USE_INTRN` | `src/frontend.c:350` |
| `fe_sess_rate` | `smp_fetch_fe_sess_rate` | `ARG1(1,FE)` | `SMP_T_SINT` | `SMP_USE_INTRN` | `src/frontend.c:351` |
| `base` | `smp_fetch_base` | `0` | `SMP_T_STR` | `SMP_USE_HRQHV` | `src/http_fetch.c:2338` |
| `base32` | `smp_fetch_base32` | `0` | `SMP_T_SINT` | `SMP_USE_HRQHV` | `src/http_fetch.c:2339` |
| `base32+src` | `smp_fetch_base32_src` | `0` | `SMP_T_BIN` | `SMP_USE_HRQHV` | `src/http_fetch.c:2340` |
| `baseq` | `smp_fetch_base` | `0` | `SMP_T_STR` | `SMP_USE_HRQHV` | `src/http_fetch.c:2341` |
| `capture.req.hdr` | `smp_fetch_capture_req_hdr` | `ARG1(1,SINT)` | `SMP_T_STR` | `SMP_USE_HRQHP` | `src/http_fetch.c:2344` |
| `capture.req.method` | `smp_fetch_capture_req_method` | `0` | `SMP_T_STR` | `SMP_USE_HRQHP` | `src/http_fetch.c:2347` |
| `capture.req.uri` | `smp_fetch_capture_req_uri` | `0` | `SMP_T_STR` | `SMP_USE_HRQHP` | `src/http_fetch.c:2348` |
| `capture.req.ver` | `smp_fetch_capture_req_ver` | `0` | `SMP_T_STR` | `SMP_USE_HRQHP` | `src/http_fetch.c:2349` |
| `capture.res.hdr` | `smp_fetch_capture_res_hdr` | `ARG1(1,SINT)` | `SMP_T_STR` | `SMP_USE_HRSHP` | `src/http_fetch.c:2351` |
| `capture.res.ver` | `smp_fetch_capture_res_ver` | `0` | `SMP_T_STR` | `SMP_USE_HRQHP` | `src/http_fetch.c:2352` |
| `cook` | `smp_fetch_cookie` | `ARG1(0,STR)` | `SMP_T_STR` | `SMP_USE_HRQHV` | `src/http_fetch.c:2358` |
| `cookie` | `smp_fetch_chn_cookie` | `ARG1(0,STR)` | `SMP_T_STR` | `SMP_USE_HRQHV|SMP_USE_HRSHV` | `src/http_fetch.c:2359` |
| `cook_cnt` | `smp_fetch_cookie_cnt` | `ARG1(0,STR)` | `SMP_T_SINT` | `SMP_USE_HRQHV` | `src/http_fetch.c:2360` |
| `cook_val` | `smp_fetch_cookie_val` | `ARG1(0,STR)` | `SMP_T_SINT` | `SMP_USE_HRQHV` | `src/http_fetch.c:2361` |
| `hdr` | `smp_fetch_chn_hdr` | `ARG2(0,STR,SINT)` | `SMP_T_STR` | `SMP_USE_HRQHV|SMP_USE_HRSHV` | `src/http_fetch.c:2367` |
| `hdr_cnt` | `smp_fetch_hdr_cnt` | `ARG1(0,STR)` | `SMP_T_SINT` | `SMP_USE_HRQHV` | `src/http_fetch.c:2368` |
| `hdr_ip` | `smp_fetch_hdr_ip` | `ARG2(0,STR,SINT)` | `SMP_T_ADDR` | `SMP_USE_HRQHV` | `src/http_fetch.c:2369` |
| `hdr_val` | `smp_fetch_hdr_val` | `ARG2(0,STR,SINT)` | `SMP_T_SINT` | `SMP_USE_HRQHV` | `src/http_fetch.c:2370` |
| `http_auth_type` | `smp_fetch_http_auth_type` | `0` | `SMP_T_STR` | `SMP_USE_HRQHV` | `src/http_fetch.c:2372` |
| `http_auth_user` | `smp_fetch_http_auth_user` | `0` | `SMP_T_STR` | `SMP_USE_HRQHV` | `src/http_fetch.c:2373` |
| `http_auth_pass` | `smp_fetch_http_auth_pass` | `0` | `SMP_T_STR` | `SMP_USE_HRQHV` | `src/http_fetch.c:2374` |
| `http_auth_bearer` | `smp_fetch_http_auth_bearer` | `ARG1(0,STR)` | `SMP_T_STR` | `SMP_USE_HRQHV` | `src/http_fetch.c:2375` |
| `http_auth` | `smp_fetch_http_auth` | `ARG1(1,USR)` | `SMP_T_BOOL` | `SMP_USE_HRQHV` | `src/http_fetch.c:2376` |
| `http_auth_group` | `smp_fetch_http_auth_grp` | `ARG1(1,USR)` | `SMP_T_STR` | `SMP_USE_HRQHV` | `src/http_fetch.c:2377` |
| `http_first_req` | `smp_fetch_http_first_req` | `0` | `SMP_T_BOOL` | `SMP_USE_HRQHP` | `src/http_fetch.c:2378` |
| `method` | `smp_fetch_meth` | `0` | `SMP_T_METH` | `SMP_USE_HRQHP` | `src/http_fetch.c:2379` |
| `path` | `smp_fetch_path` | `0` | `SMP_T_STR` | `SMP_USE_HRQHV` | `src/http_fetch.c:2380` |
| `pathq` | `smp_fetch_path` | `0` | `SMP_T_STR` | `SMP_USE_HRQHV` | `src/http_fetch.c:2381` |
| `query` | `smp_fetch_query` | `ARG1(0,STR)` | `SMP_T_STR` | `SMP_USE_HRQHV` | `src/http_fetch.c:2382` |
| `req.proto_http` | `smp_fetch_proto_http` | `0` | `SMP_T_BOOL` | `SMP_USE_HRQHP` | `src/http_fetch.c:2385` |
| `req_proto_http` | `smp_fetch_proto_http` | `0` | `SMP_T_BOOL` | `SMP_USE_HRQHP` | `src/http_fetch.c:2386` |
| `req.ver` | `smp_fetch_rqver` | `0` | `SMP_T_STR` | `SMP_USE_HRQHP` | `src/http_fetch.c:2389` |
| `req_ver` | `smp_fetch_rqver` | `0` | `SMP_T_STR` | `SMP_USE_HRQHP` | `src/http_fetch.c:2390` |
| `req.body` | `smp_fetch_body` | `0` | `SMP_T_BIN` | `SMP_USE_HRQHV` | `src/http_fetch.c:2392` |
| `req.body_len` | `smp_fetch_body_len` | `0` | `SMP_T_SINT` | `SMP_USE_HRQHV` | `src/http_fetch.c:2393` |
| `req.body_size` | `smp_fetch_body_size` | `0` | `SMP_T_SINT` | `SMP_USE_HRQHV` | `src/http_fetch.c:2394` |
| `req.body_param` | `smp_fetch_body_param` | `ARG2(0,STR,STR)` | `SMP_T_BIN` | `SMP_USE_HRQHV` | `src/http_fetch.c:2395` |
| `req.hdrs` | `smp_fetch_hdrs` | `0` | `SMP_T_BIN` | `SMP_USE_HRQHV` | `src/http_fetch.c:2397` |
| `req.hdrs_bin` | `smp_fetch_hdrs_bin` | `0` | `SMP_T_BIN` | `SMP_USE_HRQHV` | `src/http_fetch.c:2398` |
| `res.ver` | `smp_fetch_stver` | `0` | `SMP_T_STR` | `SMP_USE_HRSHP` | `src/http_fetch.c:2401` |
| `resp_ver` | `smp_fetch_stver` | `0` | `SMP_T_STR` | `SMP_USE_HRSHP` | `src/http_fetch.c:2402` |
| `res.body` | `smp_fetch_body` | `0` | `SMP_T_BIN` | `SMP_USE_HRSHV` | `src/http_fetch.c:2404` |
| `res.body_len` | `smp_fetch_body_len` | `0` | `SMP_T_SINT` | `SMP_USE_HRSHV` | `src/http_fetch.c:2405` |
| `res.body_size` | `smp_fetch_body_size` | `0` | `SMP_T_SINT` | `SMP_USE_HRSHV` | `src/http_fetch.c:2406` |
| `res.hdrs` | `smp_fetch_hdrs` | `0` | `SMP_T_BIN` | `SMP_USE_HRSHV` | `src/http_fetch.c:2408` |
| `res.hdrs_bin` | `smp_fetch_hdrs_bin` | `0` | `SMP_T_BIN` | `SMP_USE_HRSHV` | `src/http_fetch.c:2409` |
| `req.cook` | `smp_fetch_cookie` | `ARG1(0,STR)` | `SMP_T_STR` | `SMP_USE_HRQHV` | `src/http_fetch.c:2412` |
| `req.cook_cnt` | `smp_fetch_cookie_cnt` | `ARG1(0,STR)` | `SMP_T_SINT` | `SMP_USE_HRQHV` | `src/http_fetch.c:2413` |
| `req.cook_val` | `smp_fetch_cookie_val` | `ARG1(0,STR)` | `SMP_T_SINT` | `SMP_USE_HRQHV` | `src/http_fetch.c:2414` |
| `req.cook_names` | `smp_fetch_cookie_names` | `ARG1(0,STR)` | `SMP_T_STR` | `SMP_USE_HRQHV` | `src/http_fetch.c:2415` |
| `req.fhdr` | `smp_fetch_fhdr` | `ARG2(0,STR,SINT)` | `SMP_T_STR` | `SMP_USE_HRQHV` | `src/http_fetch.c:2417` |
| `req.fhdr_cnt` | `smp_fetch_fhdr_cnt` | `ARG1(0,STR)` | `SMP_T_SINT` | `SMP_USE_HRQHV` | `src/http_fetch.c:2418` |
| `req.hdr` | `smp_fetch_hdr` | `ARG2(0,STR,SINT)` | `SMP_T_STR` | `SMP_USE_HRQHV` | `src/http_fetch.c:2419` |
| `req.hdr_cnt` | `smp_fetch_hdr_cnt` | `ARG1(0,STR)` | `SMP_T_SINT` | `SMP_USE_HRQHV` | `src/http_fetch.c:2420` |
| `req.hdr_ip` | `smp_fetch_hdr_ip` | `ARG2(0,STR,SINT)` | `SMP_T_ADDR` | `SMP_USE_HRQHV` | `src/http_fetch.c:2421` |
| `req.hdr_names` | `smp_fetch_hdr_names` | `ARG1(0,STR)` | `SMP_T_STR` | `SMP_USE_HRQHV` | `src/http_fetch.c:2422` |
| `req.hdr_val` | `smp_fetch_hdr_val` | `ARG2(0,STR,SINT)` | `SMP_T_SINT` | `SMP_USE_HRQHV` | `src/http_fetch.c:2423` |
| `res.cook` | `smp_fetch_cookie` | `ARG1(0,STR)` | `SMP_T_STR` | `SMP_USE_HRSHV` | `src/http_fetch.c:2426` |
| `res.cook_cnt` | `smp_fetch_cookie_cnt` | `ARG1(0,STR)` | `SMP_T_SINT` | `SMP_USE_HRSHV` | `src/http_fetch.c:2427` |
| `res.cook_val` | `smp_fetch_cookie_val` | `ARG1(0,STR)` | `SMP_T_SINT` | `SMP_USE_HRSHV` | `src/http_fetch.c:2428` |
| `res.cook_names` | `smp_fetch_cookie_names` | `ARG1(0,STR)` | `SMP_T_STR` | `SMP_USE_HRSHV` | `src/http_fetch.c:2429` |
| `res.fhdr` | `smp_fetch_fhdr` | `ARG2(0,STR,SINT)` | `SMP_T_STR` | `SMP_USE_HRSHV` | `src/http_fetch.c:2431` |
| `res.fhdr_cnt` | `smp_fetch_fhdr_cnt` | `ARG1(0,STR)` | `SMP_T_SINT` | `SMP_USE_HRSHV` | `src/http_fetch.c:2432` |
| `res.hdr` | `smp_fetch_hdr` | `ARG2(0,STR,SINT)` | `SMP_T_STR` | `SMP_USE_HRSHV` | `src/http_fetch.c:2433` |
| `res.hdr_cnt` | `smp_fetch_hdr_cnt` | `ARG1(0,STR)` | `SMP_T_SINT` | `SMP_USE_HRSHV` | `src/http_fetch.c:2434` |
| `res.hdr_ip` | `smp_fetch_hdr_ip` | `ARG2(0,STR,SINT)` | `SMP_T_ADDR` | `SMP_USE_HRSHV` | `src/http_fetch.c:2435` |
| `res.hdr_names` | `smp_fetch_hdr_names` | `ARG1(0,STR)` | `SMP_T_STR` | `SMP_USE_HRSHV` | `src/http_fetch.c:2436` |
| `res.hdr_val` | `smp_fetch_hdr_val` | `ARG2(0,STR,SINT)` | `SMP_T_SINT` | `SMP_USE_HRSHV` | `src/http_fetch.c:2437` |
| `server_status` | `smp_fetch_srv_status` | `0` | `SMP_T_SINT` | `SMP_USE_HRSHP` | `src/http_fetch.c:2439` |
| `scook` | `smp_fetch_cookie` | `ARG1(0,STR)` | `SMP_T_STR` | `SMP_USE_HRSHV` | `src/http_fetch.c:2442` |
| `scook_cnt` | `smp_fetch_cookie_cnt` | `ARG1(0,STR)` | `SMP_T_SINT` | `SMP_USE_HRSHV` | `src/http_fetch.c:2443` |
| `scook_val` | `smp_fetch_cookie_val` | `ARG1(0,STR)` | `SMP_T_SINT` | `SMP_USE_HRSHV` | `src/http_fetch.c:2444` |
| `shdr` | `smp_fetch_hdr` | `ARG2(0,STR,SINT)` | `SMP_T_STR` | `SMP_USE_HRSHV` | `src/http_fetch.c:2447` |
| `shdr_cnt` | `smp_fetch_hdr_cnt` | `ARG1(0,STR)` | `SMP_T_SINT` | `SMP_USE_HRSHV` | `src/http_fetch.c:2448` |
| `shdr_ip` | `smp_fetch_hdr_ip` | `ARG2(0,STR,SINT)` | `SMP_T_ADDR` | `SMP_USE_HRSHV` | `src/http_fetch.c:2449` |
| `shdr_val` | `smp_fetch_hdr_val` | `ARG2(0,STR,SINT)` | `SMP_T_SINT` | `SMP_USE_HRSHV` | `src/http_fetch.c:2450` |
| `status` | `smp_fetch_stcode` | `0` | `SMP_T_SINT` | `SMP_USE_HRSHP` | `src/http_fetch.c:2452` |
| `txn.status` | `smp_fetch_srv_status` | `0` | `SMP_T_SINT` | `SMP_USE_HRSHP` | `src/http_fetch.c:2453` |
| `unique-id` | `smp_fetch_uniqueid` | `0` | `SMP_T_STR` | `SMP_SRC_L4SRV` | `src/http_fetch.c:2454` |
| `url` | `smp_fetch_url` | `0` | `SMP_T_STR` | `SMP_USE_HRQHV` | `src/http_fetch.c:2455` |
| `url32` | `smp_fetch_url32` | `0` | `SMP_T_SINT` | `SMP_USE_HRQHV` | `src/http_fetch.c:2456` |
| `url32+src` | `smp_fetch_url32_src` | `0` | `SMP_T_BIN` | `SMP_USE_HRQHV` | `src/http_fetch.c:2457` |
| `url_ip` | `smp_fetch_url_ip` | `0` | `SMP_T_IPV4` | `SMP_USE_HRQHV` | `src/http_fetch.c:2458` |
| `url_port` | `smp_fetch_url_port` | `0` | `SMP_T_SINT` | `SMP_USE_HRQHV` | `src/http_fetch.c:2459` |
| `url_param` | `smp_fetch_url_param` | `ARG3(0,STR,STR,STR)` | `SMP_T_STR` | `SMP_USE_HRQHV` | `src/http_fetch.c:2460` |
| `urlp` | `smp_fetch_url_param` | `ARG3(0,STR,STR,STR)` | `SMP_T_STR` | `SMP_USE_HRQHV` | `src/http_fetch.c:2461` |
| `urlp_val` | `smp_fetch_url_param_val` | `ARG3(0,STR,STR,STR)` | `SMP_T_SINT` | `SMP_USE_HRQHV` | `src/http_fetch.c:2462` |
| `internal.strm.is_htx` | `smp_fetch_is_htx` | `0` | `SMP_T_BOOL` | `SMP_USE_INTRN` | `src/http_htx.c:3171` |
| `internal.htx.nbblks` | `smp_fetch_htx_nbblks` | `0` | `SMP_T_SINT` | `SMP_USE_HRQHV|SMP_USE_HRSHV` | `src/http_htx.c:3173` |
| `internal.htx.size` | `smp_fetch_htx_size` | `0` | `SMP_T_SINT` | `SMP_USE_HRQHV|SMP_USE_HRSHV` | `src/http_htx.c:3174` |
| `internal.htx.data` | `smp_fetch_htx_data` | `0` | `SMP_T_SINT` | `SMP_USE_HRQHV|SMP_USE_HRSHV` | `src/http_htx.c:3175` |
| `internal.htx.used` | `smp_fetch_htx_used` | `0` | `SMP_T_SINT` | `SMP_USE_HRQHV|SMP_USE_HRSHV` | `src/http_htx.c:3176` |
| `internal.htx.free` | `smp_fetch_htx_free` | `0` | `SMP_T_SINT` | `SMP_USE_HRQHV|SMP_USE_HRSHV` | `src/http_htx.c:3177` |
| `internal.htx.free_data` | `smp_fetch_htx_free_data` | `0` | `SMP_T_SINT` | `SMP_USE_HRQHV|SMP_USE_HRSHV` | `src/http_htx.c:3178` |
| `internal.htx.has_eom` | `smp_fetch_htx_has_eom` | `0` | `SMP_T_BOOL` | `SMP_USE_HRQHV|SMP_USE_HRSHV` | `src/http_htx.c:3179` |
| `internal.htx_blk.type` | `smp_fetch_htx_blk_type` | `ARG1(1,STR)` | `SMP_T_STR` | `SMP_USE_HRQHV|SMP_USE_HRSHV` | `src/http_htx.c:3181` |
| `internal.htx_blk.size` | `smp_fetch_htx_blk_size` | `ARG1(1,STR)` | `SMP_T_SINT` | `SMP_USE_HRQHV|SMP_USE_HRSHV` | `src/http_htx.c:3182` |
| `internal.htx_blk.start_line` | `smp_fetch_htx_blk_stline` | `ARG1(1,STR)` | `SMP_T_STR` | `SMP_USE_HRQHV|SMP_USE_HRSHV` | `src/http_htx.c:3183` |
| `internal.htx_blk.hdrname` | `smp_fetch_htx_blk_hdrname` | `ARG1(1,STR)` | `SMP_T_STR` | `SMP_USE_HRQHV|SMP_USE_HRSHV` | `src/http_htx.c:3184` |
| `internal.htx_blk.hdrval` | `smp_fetch_htx_blk_hdrval` | `ARG1(1,STR)` | `SMP_T_STR` | `SMP_USE_HRQHV|SMP_USE_HRSHV` | `src/http_htx.c:3185` |
| `internal.htx_blk.data` | `smp_fetch_htx_blk_data` | `ARG1(1,STR)` | `SMP_T_BIN` | `SMP_USE_HRQHV|SMP_USE_HRSHV` | `src/http_htx.c:3186` |
| `dst_conn` | `smp_fetch_dconn` | `0` | `SMP_T_SINT` | `SMP_USE_FTEND` | `src/listener.c:3032` |
| `so_id` | `smp_fetch_so_id` | `0` | `SMP_T_SINT` | `SMP_USE_FTEND` | `src/listener.c:3033` |
| `so_name` | `smp_fetch_so_name` | `0` | `SMP_T_STR` | `SMP_USE_FTEND` | `src/listener.c:3034` |
| `distcc_body` | `smp_fetch_distcc_body` | `ARG2(1,STR,SINT)` | `SMP_T_BIN` | `SMP_USE_L6REQ|SMP_USE_L6RES` | `src/payload.c:1455` |
| `distcc_param` | `smp_fetch_distcc_param` | `ARG2(1,STR,SINT)` | `SMP_T_SINT` | `SMP_USE_L6REQ|SMP_USE_L6RES` | `src/payload.c:1456` |
| `payload` | `smp_fetch_payload` | `ARG2(2,SINT,SINT)` | `SMP_T_BIN` | `SMP_USE_L6REQ|SMP_USE_L6RES` | `src/payload.c:1457` |
| `payload_lv` | `smp_fetch_payload_lv` | `ARG3(2,SINT,SINT,STR)` | `SMP_T_BIN` | `SMP_USE_L6REQ|SMP_USE_L6RES` | `src/payload.c:1458` |
| `rdp_cookie` | `smp_fetch_rdp_cookie` | `ARG1(0,STR)` | `SMP_T_STR` | `SMP_USE_L6REQ` | `src/payload.c:1459` |
| `rdp_cookie_cnt` | `smp_fetch_rdp_cookie_cnt` | `ARG1(0,STR)` | `SMP_T_SINT` | `SMP_USE_L6REQ` | `src/payload.c:1460` |
| `rep_ssl_hello_type` | `smp_fetch_ssl_hello_type` | `0` | `SMP_T_SINT` | `SMP_USE_L6RES` | `src/payload.c:1461` |
| `req_len` | `smp_fetch_len` | `0` | `SMP_T_SINT` | `SMP_USE_L6REQ` | `src/payload.c:1462` |
| `req_ssl_hello_type` | `smp_fetch_ssl_hello_type` | `0` | `SMP_T_SINT` | `SMP_USE_L6REQ` | `src/payload.c:1463` |
| `req_ssl_sni` | `smp_fetch_ssl_hello_sni` | `0` | `SMP_T_STR` | `SMP_USE_L6REQ` | `src/payload.c:1464` |
| `req_ssl_ver` | `smp_fetch_req_ssl_ver` | `0` | `SMP_T_SINT` | `SMP_USE_L6REQ` | `src/payload.c:1465` |
| `req.len` | `smp_fetch_len` | `0` | `SMP_T_SINT` | `SMP_USE_L6REQ` | `src/payload.c:1467` |
| `req.payload` | `smp_fetch_payload` | `ARG2(2,SINT,SINT)` | `SMP_T_BIN` | `SMP_USE_L6REQ` | `src/payload.c:1468` |
| `req.payload_lv` | `smp_fetch_payload_lv` | `ARG3(2,SINT,SINT,STR)` | `SMP_T_BIN` | `SMP_USE_L6REQ` | `src/payload.c:1469` |
| `req.rdp_cookie` | `smp_fetch_rdp_cookie` | `ARG1(0,STR)` | `SMP_T_STR` | `SMP_USE_L6REQ` | `src/payload.c:1470` |
| `req.rdp_cookie_cnt` | `smp_fetch_rdp_cookie_cnt` | `ARG1(0,STR)` | `SMP_T_SINT` | `SMP_USE_L6REQ` | `src/payload.c:1471` |
| `req.ssl_ec_ext` | `smp_fetch_req_ssl_ec_ext` | `0` | `SMP_T_BOOL` | `SMP_USE_L6REQ` | `src/payload.c:1472` |
| `req.ssl_st_ext` | `smp_fetch_req_ssl_st_ext` | `0` | `SMP_T_SINT` | `SMP_USE_L6REQ` | `src/payload.c:1473` |
| `req.ssl_hello_type` | `smp_fetch_ssl_hello_type` | `0` | `SMP_T_SINT` | `SMP_USE_L6REQ` | `src/payload.c:1474` |
| `req.ssl_sni` | `smp_fetch_ssl_hello_sni` | `0` | `SMP_T_STR` | `SMP_USE_L6REQ` | `src/payload.c:1475` |
| `req.ssl_cipherlist` | `smp_fetch_ssl_cipherlist` | `0` | `SMP_T_BIN` | `SMP_USE_L6REQ|SMP_USE_L4CLI|SMP_USE_L5CLI|SMP_USE_FTEND` | `src/payload.c:1476` |
| `req.ssl_supported_groups` | `smp_fetch_ssl_supported_groups` | `0` | `SMP_T_BIN` | `SMP_USE_L6REQ|SMP_USE_L4CLI|SMP_USE_L5CLI|SMP_USE_FTEND` | `src/payload.c:1477` |
| `req.ssl_sigalgs` | `smp_fetch_ssl_sigalgs` | `0` | `SMP_T_BIN` | `SMP_USE_L6REQ|SMP_USE_L4CLI|SMP_USE_L5CLI|SMP_USE_FTEND` | `src/payload.c:1478` |
| `req.ssl_keyshare_groups` | `smp_fetch_ssl_keyshare_groups` | `0` | `SMP_T_BIN` | `SMP_USE_L6REQ|SMP_USE_L4CLI|SMP_USE_L5CLI|SMP_USE_FTEND` | `src/payload.c:1479` |
| `req.ssl_alpn` | `smp_fetch_ssl_hello_alpn` | `0` | `SMP_T_STR` | `SMP_USE_L6REQ` | `src/payload.c:1480` |
| `req.ssl_ver` | `smp_fetch_req_ssl_ver` | `0` | `SMP_T_SINT` | `SMP_USE_L6REQ` | `src/payload.c:1481` |
| `res.len` | `smp_fetch_len` | `0` | `SMP_T_SINT` | `SMP_USE_L6RES` | `src/payload.c:1482` |
| `res.payload` | `smp_fetch_payload` | `ARG2(2,SINT,SINT)` | `SMP_T_BIN` | `SMP_USE_L6RES` | `src/payload.c:1483` |
| `res.payload_lv` | `smp_fetch_payload_lv` | `ARG3(2,SINT,SINT,STR)` | `SMP_T_BIN` | `SMP_USE_L6RES` | `src/payload.c:1484` |
| `res.ssl_hello_type` | `smp_fetch_ssl_hello_type` | `0` | `SMP_T_SINT` | `SMP_USE_L6RES` | `src/payload.c:1485` |
| `wait_end` | `smp_fetch_wait_end` | `0` | `SMP_T_BOOL` | `SMP_USE_INTRN` | `src/payload.c:1486` |
| `prio_class` | `smp_fetch_priority_class` | `0` | `SMP_T_SINT` | `SMP_USE_INTRN` | `src/queue.c:897` |
| `prio_offset` | `smp_fetch_priority_offset` | `0` | `SMP_T_SINT` | `SMP_USE_INTRN` | `src/queue.c:898` |
| `bytes_in` | `smp_fetch_bytes` | `0` | `SMP_T_SINT` | `SMP_USE_RQFIN` | `src/sample.c:5914` |
| `bytes_out` | `smp_fetch_bytes` | `0` | `SMP_T_SINT` | `SMP_USE_RSFIN` | `src/sample.c:5915` |
| `txn.timer.total` | `smp_fetch_txn_timers` | `0` | `SMP_T_SINT` | `SMP_USE_TXFIN` | `src/sample.c:5917` |
| `txn.timer.user` | `smp_fetch_txn_timers` | `0` | `SMP_T_SINT` | `SMP_USE_TXFIN` | `src/sample.c:5918` |
| `bc.timer.connect` | `smp_fetch_conn_timers` | `0` | `SMP_T_SINT` | `SMP_USE_L4SRV` | `src/sample.c:5920` |
| `bc_be_queue` | `smp_fetch_conn_queues` | `0` | `SMP_T_SINT` | `SMP_USE_L4SRV` | `src/sample.c:5921` |
| `bc_srv_queue` | `smp_fetch_conn_queues` | `0` | `SMP_T_SINT` | `SMP_USE_L4SRV` | `src/sample.c:5922` |
| `fc.timer.handshake` | `smp_fetch_conn_timers` | `0` | `SMP_T_SINT` | `SMP_USE_L4CLI` | `src/sample.c:5924` |
| `fc.timer.total` | `smp_fetch_conn_timers` | `0` | `SMP_T_SINT` | `SMP_USE_SSFIN` | `src/sample.c:5925` |
| `req.bytes_in` | `smp_fetch_bytes` | `0` | `SMP_T_SINT` | `SMP_USE_RQFIN` | `src/sample.c:5927` |
| `req.bytes_out` | `smp_fetch_bytes` | `0` | `SMP_T_SINT` | `SMP_USE_RQFIN` | `src/sample.c:5928` |
| `req.timer.idle` | `smp_fetch_reX_timers` | `0` | `SMP_T_SINT` | `SMP_USE_HRQHV` | `src/sample.c:5929` |
| `req.timer.tq` | `smp_fetch_reX_timers` | `0` | `SMP_T_SINT` | `SMP_USE_HRQHV` | `src/sample.c:5930` |
| `req.timer.hdr` | `smp_fetch_reX_timers` | `0` | `SMP_T_SINT` | `SMP_USE_HRQHV` | `src/sample.c:5931` |
| `req.timer.queue` | `smp_fetch_reX_timers` | `0` | `SMP_T_SINT` | `SMP_USE_L4SRV` | `src/sample.c:5932` |
| `res.bytes_in` | `smp_fetch_bytes` | `0` | `SMP_T_SINT` | `SMP_USE_RSFIN` | `src/sample.c:5933` |
| `res.bytes_out` | `smp_fetch_bytes` | `0` | `SMP_T_SINT` | `SMP_USE_RSFIN` | `src/sample.c:5934` |
| `res.timer.data` | `smp_fetch_reX_timers` | `0` | `SMP_T_SINT` | `SMP_USE_RSFIN` | `src/sample.c:5935` |
| `res.timer.hdr` | `smp_fetch_reX_timers` | `0` | `SMP_T_SINT` | `SMP_USE_HRSHV` | `src/sample.c:5936` |
| `act_conn` | `smp_fetch_actconn` | `0` | `SMP_T_SINT` | `SMP_USE_CONST` | `src/sample.c:5948` |
| `always_false` | `smp_fetch_false` | `0` | `SMP_T_BOOL` | `SMP_USE_CONST` | `src/sample.c:5949` |
| `always_true` | `smp_fetch_true` | `0` | `SMP_T_BOOL` | `SMP_USE_CONST` | `src/sample.c:5950` |
| `env` | `smp_fetch_env` | `ARG1(1,STR)` | `SMP_T_STR` | `SMP_USE_CONST` | `src/sample.c:5951` |
| `date` | `smp_fetch_date` | `ARG2(0,SINT,STR)` | `SMP_T_SINT` | `SMP_USE_CONST` | `src/sample.c:5952` |
| `date_us` | `smp_fetch_date_us` | `0` | `SMP_T_SINT` | `SMP_USE_CONST` | `src/sample.c:5953` |
| `hostname` | `smp_fetch_hostname` | `0` | `SMP_T_STR` | `SMP_USE_CONST` | `src/sample.c:5954` |
| `master_id` | `smp_fetch_master_id` | `0` | `SMP_T_STR` | `SMP_USE_CONST` | `src/sample.c:5955` |
| `nbproc` | `smp_fetch_nbproc` | `0` | `SMP_T_SINT` | `SMP_USE_CONST` | `src/sample.c:5956` |
| `pid` | `smp_fetch_pid` | `0` | `SMP_T_SINT` | `SMP_USE_CONST` | `src/sample.c:5957` |
| `proc` | `smp_fetch_proc` | `0` | `SMP_T_SINT` | `SMP_USE_CONST` | `src/sample.c:5958` |
| `quic_enabled` | `smp_fetch_quic_enabled` | `0` | `SMP_T_BOOL` | `SMP_USE_CONST` | `src/sample.c:5959` |
| `thread` | `smp_fetch_thread` | `0` | `SMP_T_SINT` | `SMP_USE_CONST` | `src/sample.c:5960` |
| `tgroup` | `smp_fetch_tgroup` | `0` | `SMP_T_SINT` | `SMP_USE_CONST` | `src/sample.c:5961` |
| `rand` | `smp_fetch_rand` | `ARG1(0,SINT)` | `SMP_T_SINT` | `SMP_USE_CONST` | `src/sample.c:5962` |
| `stopping` | `smp_fetch_stopping` | `0` | `SMP_T_BOOL` | `SMP_USE_INTRN` | `src/sample.c:5963` |
| `uptime` | `smp_fetch_uptime` | `0` | `SMP_T_SINT` | `SMP_USE_CONST` | `src/sample.c:5964` |
| `uuid` | `smp_fetch_uuid` | `ARG1(0, SINT)` | `SMP_T_STR` | `SMP_USE_CONST` | `src/sample.c:5965` |
| `worker_id` | `smp_fetch_worker_id` | `0` | `SMP_T_STR` | `SMP_USE_CONST` | `src/sample.c:5966` |
| `cpu_calls` | `smp_fetch_cpu_calls` | `0` | `SMP_T_SINT` | `SMP_USE_INTRN` | `src/sample.c:5968` |
| `cpu_ns_avg` | `smp_fetch_cpu_ns_avg` | `0` | `SMP_T_SINT` | `SMP_USE_INTRN` | `src/sample.c:5969` |
| `cpu_ns_tot` | `smp_fetch_cpu_ns_tot` | `0` | `SMP_T_SINT` | `SMP_USE_INTRN` | `src/sample.c:5970` |
| `cpu_usage_grp` | `smp_fetch_cpu_usage_grp` | `0` | `SMP_T_SINT` | `SMP_USE_INTRN` | `src/sample.c:5971` |
| `cpu_usage_proc` | `smp_fetch_cpu_usage_proc` | `0` | `SMP_T_SINT` | `SMP_USE_INTRN` | `src/sample.c:5972` |
| `cpu_usage_thr` | `smp_fetch_cpu_usage_thr` | `0` | `SMP_T_SINT` | `SMP_USE_INTRN` | `src/sample.c:5973` |
| `lat_ns_avg` | `smp_fetch_lat_ns_avg` | `0` | `SMP_T_SINT` | `SMP_USE_INTRN` | `src/sample.c:5974` |
| `lat_ns_tot` | `smp_fetch_lat_ns_tot` | `0` | `SMP_T_SINT` | `SMP_USE_INTRN` | `src/sample.c:5975` |
| `str` | `smp_fetch_const_str` | `ARG1(1,STR)` | `SMP_T_STR` | `SMP_USE_CONST` | `src/sample.c:5977` |
| `bool` | `smp_fetch_const_bool` | `ARG1(1,STR)` | `SMP_T_BOOL` | `SMP_USE_CONST` | `src/sample.c:5978` |
| `int` | `smp_fetch_const_int` | `ARG1(1,SINT)` | `SMP_T_SINT` | `SMP_USE_CONST` | `src/sample.c:5979` |
| `ipv4` | `smp_fetch_const_ipv4` | `ARG1(1,IPV4)` | `SMP_T_IPV4` | `SMP_USE_CONST` | `src/sample.c:5980` |
| `ipv6` | `smp_fetch_const_ipv6` | `ARG1(1,IPV6)` | `SMP_T_IPV6` | `SMP_USE_CONST` | `src/sample.c:5981` |
| `bin` | `smp_fetch_const_bin` | `ARG1(1,STR)` | `SMP_T_BIN` | `SMP_USE_CONST` | `src/sample.c:5982` |
| `meth` | `smp_fetch_const_meth` | `ARG1(1,STR)` | `SMP_T_METH` | `SMP_USE_CONST` | `src/sample.c:5983` |
| `ssl_bc` | `smp_fetch_ssl_fc` | `0` | `SMP_T_BOOL` | `SMP_USE_L5SRV` | `src/ssl_sample.c:2805` |
| `ssl_bc_alg_keysize` | `smp_fetch_ssl_fc_alg_keysize` | `0` | `SMP_T_SINT` | `SMP_USE_L5SRV` | `src/ssl_sample.c:2806` |
| `ssl_bc_alpn` | `smp_fetch_ssl_fc_alpn` | `0` | `SMP_T_STR` | `SMP_USE_L5SRV` | `src/ssl_sample.c:2808` |
| `ssl_bc_cipher` | `smp_fetch_ssl_fc_cipher` | `0` | `SMP_T_STR` | `SMP_USE_L5SRV` | `src/ssl_sample.c:2810` |
| `ssl_bc_curve` | `smp_fetch_ssl_fc_ec` | `0` | `SMP_T_STR` | `SMP_USE_L5SRV` | `src/ssl_sample.c:2812` |
| `ssl_bc_npn` | `smp_fetch_ssl_fc_npn` | `0` | `SMP_T_STR` | `SMP_USE_L5SRV` | `src/ssl_sample.c:2815` |
| `ssl_bc_is_resumed` | `smp_fetch_ssl_fc_is_resumed` | `0` | `SMP_T_BOOL` | `SMP_USE_L5SRV` | `src/ssl_sample.c:2817` |
| `ssl_bc_protocol` | `smp_fetch_ssl_fc_protocol` | `0` | `SMP_T_STR` | `SMP_USE_L5SRV` | `src/ssl_sample.c:2818` |
| `ssl_bc_unique_id` | `smp_fetch_ssl_fc_unique_id` | `0` | `SMP_T_BIN` | `SMP_USE_L5SRV` | `src/ssl_sample.c:2819` |
| `ssl_bc_use_keysize` | `smp_fetch_ssl_fc_use_keysize` | `0` | `SMP_T_SINT` | `SMP_USE_L5SRV` | `src/ssl_sample.c:2820` |
| `ssl_bc_session_id` | `smp_fetch_ssl_fc_session_id` | `0` | `SMP_T_BIN` | `SMP_USE_L5SRV` | `src/ssl_sample.c:2822` |
| `ssl_bc_client_random` | `smp_fetch_ssl_fc_random` | `0` | `SMP_T_BIN` | `SMP_USE_L5SRV` | `src/ssl_sample.c:2825` |
| `ssl_bc_server_random` | `smp_fetch_ssl_fc_random` | `0` | `SMP_T_BIN` | `SMP_USE_L5SRV` | `src/ssl_sample.c:2826` |
| `ssl_bc_session_key` | `smp_fetch_ssl_fc_session_key` | `0` | `SMP_T_BIN` | `SMP_USE_L5SRV` | `src/ssl_sample.c:2827` |
| `ssl_bc_client_early_traffic_secret` | `smp_fetch_ssl_x_keylog` | `0` | `SMP_T_STR` | `SMP_USE_L5CLI` | `src/ssl_sample.c:2830` |
| `ssl_bc_client_handshake_traffic_secret` | `smp_fetch_ssl_x_keylog` | `0` | `SMP_T_STR` | `SMP_USE_L5CLI` | `src/ssl_sample.c:2831` |
| `ssl_bc_server_handshake_traffic_secret` | `smp_fetch_ssl_x_keylog` | `0` | `SMP_T_STR` | `SMP_USE_L5CLI` | `src/ssl_sample.c:2832` |
| `ssl_bc_client_traffic_secret_0` | `smp_fetch_ssl_x_keylog` | `0` | `SMP_T_STR` | `SMP_USE_L5CLI` | `src/ssl_sample.c:2833` |
| `ssl_bc_server_traffic_secret_0` | `smp_fetch_ssl_x_keylog` | `0` | `SMP_T_STR` | `SMP_USE_L5CLI` | `src/ssl_sample.c:2834` |
| `ssl_bc_exporter_secret` | `smp_fetch_ssl_x_keylog` | `0` | `SMP_T_STR` | `SMP_USE_L5CLI` | `src/ssl_sample.c:2835` |
| `ssl_bc_early_exporter_secret` | `smp_fetch_ssl_x_keylog` | `0` | `SMP_T_STR` | `SMP_USE_L5CLI` | `src/ssl_sample.c:2836` |
| `ssl_bc_err` | `smp_fetch_ssl_fc_err` | `0` | `SMP_T_SINT` | `SMP_USE_L5SRV` | `src/ssl_sample.c:2838` |
| `ssl_bc_err_str` | `smp_fetch_ssl_fc_err_str` | `0` | `SMP_T_STR` | `SMP_USE_L5SRV` | `src/ssl_sample.c:2839` |
| `ssl_bc_sni` | `smp_fetch_ssl_fc_sni` | `0` | `SMP_T_STR` | `SMP_USE_L5SRV` | `src/ssl_sample.c:2840` |
| `ssl_c_ca_err` | `smp_fetch_ssl_c_ca_err` | `0` | `SMP_T_SINT` | `SMP_USE_L5CLI` | `src/ssl_sample.c:2841` |
| `ssl_c_ca_err_depth` | `smp_fetch_ssl_c_ca_err_depth` | `0` | `SMP_T_SINT` | `SMP_USE_L5CLI` | `src/ssl_sample.c:2842` |
| `ssl_c_der` | `smp_fetch_ssl_x_der` | `0` | `SMP_T_BIN` | `SMP_USE_L5CLI` | `src/ssl_sample.c:2843` |
| `ssl_c_chain_der` | `smp_fetch_ssl_x_chain_der` | `0` | `SMP_T_BIN` | `SMP_USE_L5CLI` | `src/ssl_sample.c:2844` |
| `ssl_c_err` | `smp_fetch_ssl_c_err` | `0` | `SMP_T_SINT` | `SMP_USE_L5CLI` | `src/ssl_sample.c:2845` |
| `ssl_c_i_dn` | `smp_fetch_ssl_x_i_dn` | `ARG3(0,STR,SINT,STR)` | `SMP_T_STR` | `SMP_USE_L5CLI` | `src/ssl_sample.c:2846` |
| `ssl_c_key_alg` | `smp_fetch_ssl_x_key_alg` | `0` | `SMP_T_STR` | `SMP_USE_L5CLI` | `src/ssl_sample.c:2847` |
| `ssl_c_notafter` | `smp_fetch_ssl_x_notafter` | `0` | `SMP_T_STR` | `SMP_USE_L5CLI` | `src/ssl_sample.c:2848` |
| `ssl_c_notbefore` | `smp_fetch_ssl_x_notbefore` | `0` | `SMP_T_STR` | `SMP_USE_L5CLI` | `src/ssl_sample.c:2849` |
| `ssl_c_policies` | `smp_fetch_ssl_c_policies` | `ARG1(0,STR)` | `SMP_T_STR` | `SMP_USE_L5CLI` | `src/ssl_sample.c:2851` |
| `ssl_c_r_dn` | `smp_fetch_ssl_r_dn` | `ARG3(0,STR,SINT,STR)` | `SMP_T_STR` | `SMP_USE_L5CLI` | `src/ssl_sample.c:2854` |
| `ssl_c_sig_alg` | `smp_fetch_ssl_x_sig_alg` | `0` | `SMP_T_STR` | `SMP_USE_L5CLI` | `src/ssl_sample.c:2856` |
| `ssl_c_san` | `smp_fetch_ssl_x_san` | `0` | `SMP_T_STR` | `SMP_USE_L5CLI` | `src/ssl_sample.c:2857` |
| `ssl_c_s_dn` | `smp_fetch_ssl_x_s_dn` | `ARG3(0,STR,SINT,STR)` | `SMP_T_STR` | `SMP_USE_L5CLI` | `src/ssl_sample.c:2858` |
| `ssl_c_serial` | `smp_fetch_ssl_x_serial` | `0` | `SMP_T_BIN` | `SMP_USE_L5CLI` | `src/ssl_sample.c:2859` |
| `ssl_c_sha1` | `smp_fetch_ssl_x_sha1` | `0` | `SMP_T_BIN` | `SMP_USE_L5CLI` | `src/ssl_sample.c:2860` |
| `ssl_c_used` | `smp_fetch_ssl_c_used` | `0` | `SMP_T_BOOL` | `SMP_USE_L5CLI` | `src/ssl_sample.c:2861` |
| `ssl_c_verify` | `smp_fetch_ssl_c_verify` | `0` | `SMP_T_SINT` | `SMP_USE_L5CLI` | `src/ssl_sample.c:2862` |
| `ssl_c_version` | `smp_fetch_ssl_x_version` | `0` | `SMP_T_SINT` | `SMP_USE_L5CLI` | `src/ssl_sample.c:2863` |
| `ssl_f_der` | `smp_fetch_ssl_x_der` | `0` | `SMP_T_BIN` | `SMP_USE_L5CLI` | `src/ssl_sample.c:2864` |
| `ssl_f_i_dn` | `smp_fetch_ssl_x_i_dn` | `ARG3(0,STR,SINT,STR)` | `SMP_T_STR` | `SMP_USE_L5CLI` | `src/ssl_sample.c:2865` |
| `ssl_f_key_alg` | `smp_fetch_ssl_x_key_alg` | `0` | `SMP_T_STR` | `SMP_USE_L5CLI` | `src/ssl_sample.c:2866` |
| `ssl_f_notafter` | `smp_fetch_ssl_x_notafter` | `0` | `SMP_T_STR` | `SMP_USE_L5CLI` | `src/ssl_sample.c:2867` |
| `ssl_f_notbefore` | `smp_fetch_ssl_x_notbefore` | `0` | `SMP_T_STR` | `SMP_USE_L5CLI` | `src/ssl_sample.c:2868` |
| `ssl_f_sig_alg` | `smp_fetch_ssl_x_sig_alg` | `0` | `SMP_T_STR` | `SMP_USE_L5CLI` | `src/ssl_sample.c:2869` |
| `ssl_f_s_dn` | `smp_fetch_ssl_x_s_dn` | `ARG3(0,STR,SINT,STR)` | `SMP_T_STR` | `SMP_USE_L5CLI` | `src/ssl_sample.c:2870` |
| `ssl_f_serial` | `smp_fetch_ssl_x_serial` | `0` | `SMP_T_BIN` | `SMP_USE_L5CLI` | `src/ssl_sample.c:2871` |
| `ssl_f_sha1` | `smp_fetch_ssl_x_sha1` | `0` | `SMP_T_BIN` | `SMP_USE_L5CLI` | `src/ssl_sample.c:2872` |
| `ssl_f_version` | `smp_fetch_ssl_x_version` | `0` | `SMP_T_SINT` | `SMP_USE_L5CLI` | `src/ssl_sample.c:2873` |
| `ssl_fc` | `smp_fetch_ssl_fc` | `0` | `SMP_T_BOOL` | `SMP_USE_L5CLI` | `src/ssl_sample.c:2874` |
| `ssl_fc_alg_keysize` | `smp_fetch_ssl_fc_alg_keysize` | `0` | `SMP_T_SINT` | `SMP_USE_L5CLI` | `src/ssl_sample.c:2875` |
| `ssl_fc_cipher` | `smp_fetch_ssl_fc_cipher` | `0` | `SMP_T_STR` | `SMP_USE_L5CLI` | `src/ssl_sample.c:2876` |
| `ssl_fc_curve` | `smp_fetch_ssl_fc_ec` | `0` | `SMP_T_STR` | `SMP_USE_L5CLI` | `src/ssl_sample.c:2878` |
| `ssl_fc_early_rcvd` | `smp_fetch_ssl_fc_early_rcvd` | `0` | `SMP_T_BOOL` | `SMP_USE_L5CLI` | `src/ssl_sample.c:2880` |
| `ssl_fc_has_crt` | `smp_fetch_ssl_fc_has_crt` | `0` | `SMP_T_BOOL` | `SMP_USE_L5CLI` | `src/ssl_sample.c:2881` |
| `ssl_fc_has_early` | `smp_fetch_ssl_fc_has_early` | `0` | `SMP_T_BOOL` | `SMP_USE_L5CLI` | `src/ssl_sample.c:2882` |
| `ssl_fc_has_sni` | `smp_fetch_ssl_fc_has_sni` | `0` | `SMP_T_BOOL` | `SMP_USE_L5CLI` | `src/ssl_sample.c:2883` |
| `ssl_fc_is_resumed` | `smp_fetch_ssl_fc_is_resumed` | `0` | `SMP_T_BOOL` | `SMP_USE_L5CLI` | `src/ssl_sample.c:2884` |
| `ssl_fc_npn` | `smp_fetch_ssl_fc_npn` | `0` | `SMP_T_STR` | `SMP_USE_L5CLI` | `src/ssl_sample.c:2886` |
| `ssl_fc_alpn` | `smp_fetch_ssl_fc_alpn` | `0` | `SMP_T_STR` | `SMP_USE_L5CLI` | `src/ssl_sample.c:2889` |
| `ssl_fc_protocol` | `smp_fetch_ssl_fc_protocol` | `0` | `SMP_T_STR` | `SMP_USE_L5CLI` | `src/ssl_sample.c:2891` |
| `ssl_fc_unique_id` | `smp_fetch_ssl_fc_unique_id` | `0` | `SMP_T_BIN` | `SMP_USE_L5CLI` | `src/ssl_sample.c:2893` |
| `ssl_fc_use_keysize` | `smp_fetch_ssl_fc_use_keysize` | `0` | `SMP_T_SINT` | `SMP_USE_L5CLI` | `src/ssl_sample.c:2895` |
| `ssl_fc_session_id` | `smp_fetch_ssl_fc_session_id` | `0` | `SMP_T_BIN` | `SMP_USE_L5CLI` | `src/ssl_sample.c:2897` |
| `ssl_fc_client_random` | `smp_fetch_ssl_fc_random` | `0` | `SMP_T_BIN` | `SMP_USE_L5CLI` | `src/ssl_sample.c:2900` |
| `ssl_fc_server_random` | `smp_fetch_ssl_fc_random` | `0` | `SMP_T_BIN` | `SMP_USE_L5CLI` | `src/ssl_sample.c:2901` |
| `ssl_fc_session_key` | `smp_fetch_ssl_fc_session_key` | `0` | `SMP_T_BIN` | `SMP_USE_L5CLI` | `src/ssl_sample.c:2902` |
| `ssl_fc_client_early_traffic_secret` | `smp_fetch_ssl_x_keylog` | `0` | `SMP_T_STR` | `SMP_USE_L5CLI` | `src/ssl_sample.c:2906` |
| `ssl_fc_client_handshake_traffic_secret` | `smp_fetch_ssl_x_keylog` | `0` | `SMP_T_STR` | `SMP_USE_L5CLI` | `src/ssl_sample.c:2907` |
| `ssl_fc_server_handshake_traffic_secret` | `smp_fetch_ssl_x_keylog` | `0` | `SMP_T_STR` | `SMP_USE_L5CLI` | `src/ssl_sample.c:2908` |
| `ssl_fc_client_traffic_secret_0` | `smp_fetch_ssl_x_keylog` | `0` | `SMP_T_STR` | `SMP_USE_L5CLI` | `src/ssl_sample.c:2909` |
| `ssl_fc_server_traffic_secret_0` | `smp_fetch_ssl_x_keylog` | `0` | `SMP_T_STR` | `SMP_USE_L5CLI` | `src/ssl_sample.c:2910` |
| `ssl_fc_exporter_secret` | `smp_fetch_ssl_x_keylog` | `0` | `SMP_T_STR` | `SMP_USE_L5CLI` | `src/ssl_sample.c:2911` |
| `ssl_fc_early_exporter_secret` | `smp_fetch_ssl_x_keylog` | `0` | `SMP_T_STR` | `SMP_USE_L5CLI` | `src/ssl_sample.c:2912` |
| `ssl_fc_sni` | `smp_fetch_ssl_fc_sni` | `0` | `SMP_T_STR` | `SMP_USE_L5CLI` | `src/ssl_sample.c:2915` |
| `ssl_fc_crtname` | `smp_fetch_ssl_fc_crtname` | `0` | `SMP_T_STR` | `SMP_USE_L5CLI` | `src/ssl_sample.c:2916` |
| `ssl_fc_ech_status` | `smp_fetch_ssl_fc_ech_status` | `0` | `SMP_T_STR` | `SMP_USE_L5CLI` | `src/ssl_sample.c:2918` |
| `ssl_fc_ech_outer_sni` | `smp_fetch_ssl_fc_ech_outer_sni` | `0` | `SMP_T_STR` | `SMP_USE_L5CLI` | `src/ssl_sample.c:2919` |
| `ssl_fc_cipherlist_bin` | `smp_fetch_ssl_fc_cl_bin` | `ARG1(0,SINT)` | `SMP_T_STR` | `SMP_USE_L5CLI` | `src/ssl_sample.c:2921` |
| `ssl_fc_cipherlist_hex` | `smp_fetch_ssl_fc_cl_hex` | `ARG1(0,SINT)` | `SMP_T_BIN` | `SMP_USE_L5CLI` | `src/ssl_sample.c:2922` |
| `ssl_fc_cipherlist_str` | `smp_fetch_ssl_fc_cl_str` | `ARG1(0,SINT)` | `SMP_T_STR` | `SMP_USE_L5CLI` | `src/ssl_sample.c:2923` |
| `ssl_fc_cipherlist_xxh` | `smp_fetch_ssl_fc_cl_xxh64` | `0` | `SMP_T_SINT` | `SMP_USE_L5CLI` | `src/ssl_sample.c:2924` |
| `ssl_fc_err` | `smp_fetch_ssl_fc_err` | `0` | `SMP_T_SINT` | `SMP_USE_L5CLI` | `src/ssl_sample.c:2925` |
| `ssl_fc_err_str` | `smp_fetch_ssl_fc_err_str` | `0` | `SMP_T_STR` | `SMP_USE_L5CLI` | `src/ssl_sample.c:2926` |
| `ssl_fc_protocol_hello_id` | `smp_fetch_ssl_fc_protocol_hello_id` | `0` | `SMP_T_SINT` | `SMP_USE_L5CLI` | `src/ssl_sample.c:2927` |
| `ssl_fc_extlist_bin` | `smp_fetch_ssl_fc_ext_bin` | `ARG1(0,SINT)` | `SMP_T_STR` | `SMP_USE_L5CLI` | `src/ssl_sample.c:2928` |
| `ssl_fc_eclist_bin` | `smp_fetch_ssl_fc_ecl_bin` | `ARG1(0,SINT)` | `SMP_T_STR` | `SMP_USE_L5CLI` | `src/ssl_sample.c:2929` |
| `ssl_fc_ecformats_bin` | `smp_fetch_ssl_fc_ecf_bin` | `0` | `SMP_T_STR` | `SMP_USE_L5CLI` | `src/ssl_sample.c:2930` |
| `ssl_fc_supported_versions_bin` | `smp_fetch_ssl_fc_supver_bin` | `ARG1(0,SINT)` | `SMP_T_BIN` | `SMP_USE_L5CLI` | `src/ssl_sample.c:2931` |
| `ssl_fc_sigalgs_bin` | `smp_fetch_ssl_fc_sigalgs_bin` | `ARG1(0,SINT)` | `SMP_T_BIN` | `SMP_USE_L5CLI` | `src/ssl_sample.c:2932` |
| `ssl_s_der` | `smp_fetch_ssl_x_der` | `0` | `SMP_T_BIN` | `SMP_USE_L5CLI` | `src/ssl_sample.c:2935` |
| `ssl_s_chain_der` | `smp_fetch_ssl_x_chain_der` | `0` | `SMP_T_BIN` | `SMP_USE_L5CLI` | `src/ssl_sample.c:2936` |
| `ssl_s_key_alg` | `smp_fetch_ssl_x_key_alg` | `0` | `SMP_T_STR` | `SMP_USE_L5CLI` | `src/ssl_sample.c:2937` |
| `ssl_s_notafter` | `smp_fetch_ssl_x_notafter` | `0` | `SMP_T_STR` | `SMP_USE_L5CLI` | `src/ssl_sample.c:2938` |
| `ssl_s_notbefore` | `smp_fetch_ssl_x_notbefore` | `0` | `SMP_T_STR` | `SMP_USE_L5CLI` | `src/ssl_sample.c:2939` |
| `ssl_s_sig_alg` | `smp_fetch_ssl_x_sig_alg` | `0` | `SMP_T_STR` | `SMP_USE_L5CLI` | `src/ssl_sample.c:2940` |
| `ssl_s_s_dn` | `smp_fetch_ssl_x_s_dn` | `ARG3(0,STR,SINT,STR)` | `SMP_T_STR` | `SMP_USE_L5CLI` | `src/ssl_sample.c:2941` |
| `ssl_s_i_dn` | `smp_fetch_ssl_x_i_dn` | `ARG3(0,STR,SINT,STR)` | `SMP_T_STR` | `SMP_USE_L5CLI` | `src/ssl_sample.c:2942` |
| `ssl_s_serial` | `smp_fetch_ssl_x_serial` | `0` | `SMP_T_BIN` | `SMP_USE_L5CLI` | `src/ssl_sample.c:2943` |
| `ssl_s_sha1` | `smp_fetch_ssl_x_sha1` | `0` | `SMP_T_BIN` | `SMP_USE_L5CLI` | `src/ssl_sample.c:2944` |
| `ssl_s_version` | `smp_fetch_ssl_x_version` | `0` | `SMP_T_SINT` | `SMP_USE_L5CLI` | `src/ssl_sample.c:2945` |
| `bs.debug_str` | `smp_fetch_debug_str` | `ARG1(0,SINT)` | `SMP_T_STR` | `SMP_USE_L5SRV` | `src/stconn.c:2381` |
| `bs.id` | `smp_fetch_sid` | `0` | `SMP_T_SINT` | `SMP_USE_L5SRV` | `src/stconn.c:2382` |
| `bs.aborted` | `smp_fetch_strm_aborted` | `0` | `SMP_T_SINT` | `SMP_USE_L5SRV` | `src/stconn.c:2383` |
| `bs.rst_code` | `smp_fetch_strm_rst_code` | `0` | `SMP_T_SINT` | `SMP_USE_L5SRV` | `src/stconn.c:2384` |
| `fs.debug_str` | `smp_fetch_debug_str` | `ARG1(0,SINT)` | `SMP_T_STR` | `SMP_USE_L5CLI` | `src/stconn.c:2385` |
| `fs.id` | `smp_fetch_sid` | `0` | `SMP_T_STR` | `SMP_USE_L5CLI` | `src/stconn.c:2386` |
| `fs.aborted` | `smp_fetch_strm_aborted` | `0` | `SMP_T_SINT` | `SMP_USE_L5CLI` | `src/stconn.c:2387` |
| `fs.rst_code` | `smp_fetch_strm_rst_code` | `0` | `SMP_T_SINT` | `SMP_USE_L5CLI` | `src/stconn.c:2388` |
| `sc_bytes_in_rate` | `smp_fetch_sc_bytes_in_rate` | `ARG2(1,SINT,TAB)` | `SMP_T_SINT` | `SMP_USE_INTRN` | `src/stick_table.c:6125` |
| `sc_bytes_out_rate` | `smp_fetch_sc_bytes_out_rate` | `ARG2(1,SINT,TAB)` | `SMP_T_SINT` | `SMP_USE_INTRN` | `src/stick_table.c:6126` |
| `sc_clr_gpc` | `smp_fetch_sc_clr_gpc` | `ARG3(2,SINT,SINT,TAB)` | `SMP_T_SINT` | `SMP_USE_INTRN` | `src/stick_table.c:6127` |
| `sc_clr_gpc0` | `smp_fetch_sc_clr_gpc0` | `ARG2(1,SINT,TAB)` | `SMP_T_SINT` | `SMP_USE_INTRN` | `src/stick_table.c:6128` |
| `sc_clr_gpc1` | `smp_fetch_sc_clr_gpc1` | `ARG2(1,SINT,TAB)` | `SMP_T_SINT` | `SMP_USE_INTRN` | `src/stick_table.c:6129` |
| `sc_conn_cnt` | `smp_fetch_sc_conn_cnt` | `ARG2(1,SINT,TAB)` | `SMP_T_SINT` | `SMP_USE_INTRN` | `src/stick_table.c:6130` |
| `sc_conn_cur` | `smp_fetch_sc_conn_cur` | `ARG2(1,SINT,TAB)` | `SMP_T_SINT` | `SMP_USE_INTRN` | `src/stick_table.c:6131` |
| `sc_conn_rate` | `smp_fetch_sc_conn_rate` | `ARG2(1,SINT,TAB)` | `SMP_T_SINT` | `SMP_USE_INTRN` | `src/stick_table.c:6132` |
| `sc_get_gpt` | `smp_fetch_sc_get_gpt` | `ARG3(2,SINT,SINT,TAB)` | `SMP_T_SINT` | `SMP_USE_INTRN` | `src/stick_table.c:6133` |
| `sc_get_gpt0` | `smp_fetch_sc_get_gpt0` | `ARG2(1,SINT,TAB)` | `SMP_T_SINT` | `SMP_USE_INTRN` | `src/stick_table.c:6134` |
| `sc_get_gpc` | `smp_fetch_sc_get_gpc` | `ARG3(2,SINT,SINT,TAB)` | `SMP_T_SINT` | `SMP_USE_INTRN` | `src/stick_table.c:6135` |
| `sc_get_gpc0` | `smp_fetch_sc_get_gpc0` | `ARG2(1,SINT,TAB)` | `SMP_T_SINT` | `SMP_USE_INTRN` | `src/stick_table.c:6136` |
| `sc_get_gpc1` | `smp_fetch_sc_get_gpc1` | `ARG2(1,SINT,TAB)` | `SMP_T_SINT` | `SMP_USE_INTRN` | `src/stick_table.c:6137` |
| `sc_glitch_cnt` | `smp_fetch_sc_glitch_cnt` | `ARG2(1,SINT,TAB)` | `SMP_T_SINT` | `SMP_USE_INTRN` | `src/stick_table.c:6138` |
| `sc_glitch_rate` | `smp_fetch_sc_glitch_rate` | `ARG2(1,SINT,TAB)` | `SMP_T_SINT` | `SMP_USE_INTRN` | `src/stick_table.c:6139` |
| `sc_gpc_rate` | `smp_fetch_sc_gpc_rate` | `ARG3(2,SINT,SINT,TAB)` | `SMP_T_SINT` | `SMP_USE_INTRN` | `src/stick_table.c:6140` |
| `sc_gpc0_rate` | `smp_fetch_sc_gpc0_rate` | `ARG2(1,SINT,TAB)` | `SMP_T_SINT` | `SMP_USE_INTRN` | `src/stick_table.c:6141` |
| `sc_gpc1_rate` | `smp_fetch_sc_gpc1_rate` | `ARG2(1,SINT,TAB)` | `SMP_T_SINT` | `SMP_USE_INTRN` | `src/stick_table.c:6142` |
| `sc_http_err_cnt` | `smp_fetch_sc_http_err_cnt` | `ARG2(1,SINT,TAB)` | `SMP_T_SINT` | `SMP_USE_INTRN` | `src/stick_table.c:6143` |
| `sc_http_err_rate` | `smp_fetch_sc_http_err_rate` | `ARG2(1,SINT,TAB)` | `SMP_T_SINT` | `SMP_USE_INTRN` | `src/stick_table.c:6144` |
| `sc_http_fail_cnt` | `smp_fetch_sc_http_fail_cnt` | `ARG2(1,SINT,TAB)` | `SMP_T_SINT` | `SMP_USE_INTRN` | `src/stick_table.c:6145` |
| `sc_http_fail_rate` | `smp_fetch_sc_http_fail_rate` | `ARG2(1,SINT,TAB)` | `SMP_T_SINT` | `SMP_USE_INTRN` | `src/stick_table.c:6146` |
| `sc_http_req_cnt` | `smp_fetch_sc_http_req_cnt` | `ARG2(1,SINT,TAB)` | `SMP_T_SINT` | `SMP_USE_INTRN` | `src/stick_table.c:6147` |
| `sc_http_req_rate` | `smp_fetch_sc_http_req_rate` | `ARG2(1,SINT,TAB)` | `SMP_T_SINT` | `SMP_USE_INTRN` | `src/stick_table.c:6148` |
| `sc_inc_gpc` | `smp_fetch_sc_inc_gpc` | `ARG3(2,SINT,SINT,TAB)` | `SMP_T_SINT` | `SMP_USE_INTRN` | `src/stick_table.c:6149` |
| `sc_inc_gpc0` | `smp_fetch_sc_inc_gpc0` | `ARG2(1,SINT,TAB)` | `SMP_T_SINT` | `SMP_USE_INTRN` | `src/stick_table.c:6150` |
| `sc_inc_gpc1` | `smp_fetch_sc_inc_gpc1` | `ARG2(1,SINT,TAB)` | `SMP_T_SINT` | `SMP_USE_INTRN` | `src/stick_table.c:6151` |
| `sc_kbytes_in` | `smp_fetch_sc_kbytes_in` | `ARG2(1,SINT,TAB)` | `SMP_T_SINT` | `SMP_USE_L4CLI` | `src/stick_table.c:6152` |
| `sc_kbytes_out` | `smp_fetch_sc_kbytes_out` | `ARG2(1,SINT,TAB)` | `SMP_T_SINT` | `SMP_USE_L4CLI` | `src/stick_table.c:6153` |
| `sc_key` | `smp_fetch_sc_key` | `ARG1(1,SINT)` | `SMP_T_ANY` | `SMP_USE_INTRN` | `src/stick_table.c:6154` |
| `sc_sess_cnt` | `smp_fetch_sc_sess_cnt` | `ARG2(1,SINT,TAB)` | `SMP_T_SINT` | `SMP_USE_INTRN` | `src/stick_table.c:6155` |
| `sc_sess_rate` | `smp_fetch_sc_sess_rate` | `ARG2(1,SINT,TAB)` | `SMP_T_SINT` | `SMP_USE_INTRN` | `src/stick_table.c:6156` |
| `sc_tracked` | `smp_fetch_sc_tracked` | `ARG2(1,SINT,TAB)` | `SMP_T_BOOL` | `SMP_USE_INTRN` | `src/stick_table.c:6157` |
| `sc_trackers` | `smp_fetch_sc_trackers` | `ARG2(1,SINT,TAB)` | `SMP_T_SINT` | `SMP_USE_INTRN` | `src/stick_table.c:6158` |
| `sc0_bytes_in_rate` | `smp_fetch_sc_bytes_in_rate` | `ARG1(0,TAB)` | `SMP_T_SINT` | `SMP_USE_INTRN` | `src/stick_table.c:6159` |
| `sc0_bytes_out_rate` | `smp_fetch_sc_bytes_out_rate` | `ARG1(0,TAB)` | `SMP_T_SINT` | `SMP_USE_INTRN` | `src/stick_table.c:6160` |
| `sc0_clr_gpc0` | `smp_fetch_sc_clr_gpc0` | `ARG1(0,TAB)` | `SMP_T_SINT` | `SMP_USE_INTRN` | `src/stick_table.c:6161` |
| `sc0_clr_gpc1` | `smp_fetch_sc_clr_gpc1` | `ARG1(0,TAB)` | `SMP_T_SINT` | `SMP_USE_INTRN` | `src/stick_table.c:6162` |
| `sc0_conn_cnt` | `smp_fetch_sc_conn_cnt` | `ARG1(0,TAB)` | `SMP_T_SINT` | `SMP_USE_INTRN` | `src/stick_table.c:6163` |
| `sc0_conn_cur` | `smp_fetch_sc_conn_cur` | `ARG1(0,TAB)` | `SMP_T_SINT` | `SMP_USE_INTRN` | `src/stick_table.c:6164` |
| `sc0_conn_rate` | `smp_fetch_sc_conn_rate` | `ARG1(0,TAB)` | `SMP_T_SINT` | `SMP_USE_INTRN` | `src/stick_table.c:6165` |
| `sc0_get_gpt0` | `smp_fetch_sc_get_gpt0` | `ARG1(0,TAB)` | `SMP_T_SINT` | `SMP_USE_INTRN` | `src/stick_table.c:6166` |
| `sc0_get_gpc0` | `smp_fetch_sc_get_gpc0` | `ARG1(0,TAB)` | `SMP_T_SINT` | `SMP_USE_INTRN` | `src/stick_table.c:6167` |
| `sc0_get_gpc1` | `smp_fetch_sc_get_gpc1` | `ARG1(0,TAB)` | `SMP_T_SINT` | `SMP_USE_INTRN` | `src/stick_table.c:6168` |
| `sc0_glitch_cnt` | `smp_fetch_sc_glitch_cnt` | `ARG1(0,TAB)` | `SMP_T_SINT` | `SMP_USE_INTRN` | `src/stick_table.c:6169` |
| `sc0_glitch_rate` | `smp_fetch_sc_glitch_rate` | `ARG1(0,TAB)` | `SMP_T_SINT` | `SMP_USE_INTRN` | `src/stick_table.c:6170` |
| `sc0_gpc0_rate` | `smp_fetch_sc_gpc0_rate` | `ARG1(0,TAB)` | `SMP_T_SINT` | `SMP_USE_INTRN` | `src/stick_table.c:6171` |
| `sc0_gpc1_rate` | `smp_fetch_sc_gpc1_rate` | `ARG1(0,TAB)` | `SMP_T_SINT` | `SMP_USE_INTRN` | `src/stick_table.c:6172` |
| `sc0_http_err_cnt` | `smp_fetch_sc_http_err_cnt` | `ARG1(0,TAB)` | `SMP_T_SINT` | `SMP_USE_INTRN` | `src/stick_table.c:6173` |
| `sc0_http_err_rate` | `smp_fetch_sc_http_err_rate` | `ARG1(0,TAB)` | `SMP_T_SINT` | `SMP_USE_INTRN` | `src/stick_table.c:6174` |
| `sc0_http_fail_cnt` | `smp_fetch_sc_http_fail_cnt` | `ARG1(0,TAB)` | `SMP_T_SINT` | `SMP_USE_INTRN` | `src/stick_table.c:6175` |
| `sc0_http_fail_rate` | `smp_fetch_sc_http_fail_rate` | `ARG1(0,TAB)` | `SMP_T_SINT` | `SMP_USE_INTRN` | `src/stick_table.c:6176` |
| `sc0_http_req_cnt` | `smp_fetch_sc_http_req_cnt` | `ARG1(0,TAB)` | `SMP_T_SINT` | `SMP_USE_INTRN` | `src/stick_table.c:6177` |
| `sc0_http_req_rate` | `smp_fetch_sc_http_req_rate` | `ARG1(0,TAB)` | `SMP_T_SINT` | `SMP_USE_INTRN` | `src/stick_table.c:6178` |
| `sc0_inc_gpc0` | `smp_fetch_sc_inc_gpc0` | `ARG1(0,TAB)` | `SMP_T_SINT` | `SMP_USE_INTRN` | `src/stick_table.c:6179` |
| `sc0_inc_gpc1` | `smp_fetch_sc_inc_gpc1` | `ARG1(0,TAB)` | `SMP_T_SINT` | `SMP_USE_INTRN` | `src/stick_table.c:6180` |
| `sc0_kbytes_in` | `smp_fetch_sc_kbytes_in` | `ARG1(0,TAB)` | `SMP_T_SINT` | `SMP_USE_L4CLI` | `src/stick_table.c:6181` |
| `sc0_kbytes_out` | `smp_fetch_sc_kbytes_out` | `ARG1(0,TAB)` | `SMP_T_SINT` | `SMP_USE_L4CLI` | `src/stick_table.c:6182` |
| `sc0_key` | `smp_fetch_sc_key` | `0` | `SMP_T_ANY` | `SMP_USE_INTRN` | `src/stick_table.c:6183` |
| `sc0_sess_cnt` | `smp_fetch_sc_sess_cnt` | `ARG1(0,TAB)` | `SMP_T_SINT` | `SMP_USE_INTRN` | `src/stick_table.c:6184` |
| `sc0_sess_rate` | `smp_fetch_sc_sess_rate` | `ARG1(0,TAB)` | `SMP_T_SINT` | `SMP_USE_INTRN` | `src/stick_table.c:6185` |
| `sc0_tracked` | `smp_fetch_sc_tracked` | `ARG1(0,TAB)` | `SMP_T_BOOL` | `SMP_USE_INTRN` | `src/stick_table.c:6186` |
| `sc0_trackers` | `smp_fetch_sc_trackers` | `ARG1(0,TAB)` | `SMP_T_SINT` | `SMP_USE_INTRN` | `src/stick_table.c:6187` |
| `sc1_bytes_in_rate` | `smp_fetch_sc_bytes_in_rate` | `ARG1(0,TAB)` | `SMP_T_SINT` | `SMP_USE_INTRN` | `src/stick_table.c:6188` |
| `sc1_bytes_out_rate` | `smp_fetch_sc_bytes_out_rate` | `ARG1(0,TAB)` | `SMP_T_SINT` | `SMP_USE_INTRN` | `src/stick_table.c:6189` |
| `sc1_clr_gpc` | `smp_fetch_sc_clr_gpc` | `ARG2(1,SINT,TAB)` | `SMP_T_SINT` | `SMP_USE_INTRN` | `src/stick_table.c:6190` |
| `sc1_clr_gpc0` | `smp_fetch_sc_clr_gpc0` | `ARG1(0,TAB)` | `SMP_T_SINT` | `SMP_USE_INTRN` | `src/stick_table.c:6191` |
| `sc1_clr_gpc1` | `smp_fetch_sc_clr_gpc1` | `ARG1(0,TAB)` | `SMP_T_SINT` | `SMP_USE_INTRN` | `src/stick_table.c:6192` |
| `sc1_conn_cnt` | `smp_fetch_sc_conn_cnt` | `ARG1(0,TAB)` | `SMP_T_SINT` | `SMP_USE_INTRN` | `src/stick_table.c:6193` |
| `sc1_conn_cur` | `smp_fetch_sc_conn_cur` | `ARG1(0,TAB)` | `SMP_T_SINT` | `SMP_USE_INTRN` | `src/stick_table.c:6194` |
| `sc1_conn_rate` | `smp_fetch_sc_conn_rate` | `ARG1(0,TAB)` | `SMP_T_SINT` | `SMP_USE_INTRN` | `src/stick_table.c:6195` |
| `sc1_get_gpt0` | `smp_fetch_sc_get_gpt0` | `ARG1(0,TAB)` | `SMP_T_SINT` | `SMP_USE_INTRN` | `src/stick_table.c:6196` |
| `sc1_get_gpc0` | `smp_fetch_sc_get_gpc0` | `ARG1(0,TAB)` | `SMP_T_SINT` | `SMP_USE_INTRN` | `src/stick_table.c:6197` |
| `sc1_get_gpc1` | `smp_fetch_sc_get_gpc1` | `ARG1(0,TAB)` | `SMP_T_SINT` | `SMP_USE_INTRN` | `src/stick_table.c:6198` |
| `sc1_glitch_cnt` | `smp_fetch_sc_glitch_cnt` | `ARG1(0,TAB)` | `SMP_T_SINT` | `SMP_USE_INTRN` | `src/stick_table.c:6199` |
| `sc1_glitch_rate` | `smp_fetch_sc_glitch_rate` | `ARG1(0,TAB)` | `SMP_T_SINT` | `SMP_USE_INTRN` | `src/stick_table.c:6200` |
| `sc1_gpc0_rate` | `smp_fetch_sc_gpc0_rate` | `ARG1(0,TAB)` | `SMP_T_SINT` | `SMP_USE_INTRN` | `src/stick_table.c:6201` |
| `sc1_gpc1_rate` | `smp_fetch_sc_gpc1_rate` | `ARG1(0,TAB)` | `SMP_T_SINT` | `SMP_USE_INTRN` | `src/stick_table.c:6202` |
| `sc1_http_err_cnt` | `smp_fetch_sc_http_err_cnt` | `ARG1(0,TAB)` | `SMP_T_SINT` | `SMP_USE_INTRN` | `src/stick_table.c:6203` |
| `sc1_http_err_rate` | `smp_fetch_sc_http_err_rate` | `ARG1(0,TAB)` | `SMP_T_SINT` | `SMP_USE_INTRN` | `src/stick_table.c:6204` |
| `sc1_http_fail_cnt` | `smp_fetch_sc_http_fail_cnt` | `ARG1(0,TAB)` | `SMP_T_SINT` | `SMP_USE_INTRN` | `src/stick_table.c:6205` |
| `sc1_http_fail_rate` | `smp_fetch_sc_http_fail_rate` | `ARG1(0,TAB)` | `SMP_T_SINT` | `SMP_USE_INTRN` | `src/stick_table.c:6206` |
| `sc1_http_req_cnt` | `smp_fetch_sc_http_req_cnt` | `ARG1(0,TAB)` | `SMP_T_SINT` | `SMP_USE_INTRN` | `src/stick_table.c:6207` |
| `sc1_http_req_rate` | `smp_fetch_sc_http_req_rate` | `ARG1(0,TAB)` | `SMP_T_SINT` | `SMP_USE_INTRN` | `src/stick_table.c:6208` |
| `sc1_inc_gpc0` | `smp_fetch_sc_inc_gpc0` | `ARG1(0,TAB)` | `SMP_T_SINT` | `SMP_USE_INTRN` | `src/stick_table.c:6209` |
| `sc1_inc_gpc1` | `smp_fetch_sc_inc_gpc1` | `ARG1(0,TAB)` | `SMP_T_SINT` | `SMP_USE_INTRN` | `src/stick_table.c:6210` |
| `sc1_kbytes_in` | `smp_fetch_sc_kbytes_in` | `ARG1(0,TAB)` | `SMP_T_SINT` | `SMP_USE_L4CLI` | `src/stick_table.c:6211` |
| `sc1_kbytes_out` | `smp_fetch_sc_kbytes_out` | `ARG1(0,TAB)` | `SMP_T_SINT` | `SMP_USE_L4CLI` | `src/stick_table.c:6212` |
| `sc1_key` | `smp_fetch_sc_key` | `0` | `SMP_T_ANY` | `SMP_USE_INTRN` | `src/stick_table.c:6213` |
| `sc1_sess_cnt` | `smp_fetch_sc_sess_cnt` | `ARG1(0,TAB)` | `SMP_T_SINT` | `SMP_USE_INTRN` | `src/stick_table.c:6214` |
| `sc1_sess_rate` | `smp_fetch_sc_sess_rate` | `ARG1(0,TAB)` | `SMP_T_SINT` | `SMP_USE_INTRN` | `src/stick_table.c:6215` |
| `sc1_tracked` | `smp_fetch_sc_tracked` | `ARG1(0,TAB)` | `SMP_T_BOOL` | `SMP_USE_INTRN` | `src/stick_table.c:6216` |
| `sc1_trackers` | `smp_fetch_sc_trackers` | `ARG1(0,TAB)` | `SMP_T_SINT` | `SMP_USE_INTRN` | `src/stick_table.c:6217` |
| `sc2_bytes_in_rate` | `smp_fetch_sc_bytes_in_rate` | `ARG1(0,TAB)` | `SMP_T_SINT` | `SMP_USE_INTRN` | `src/stick_table.c:6218` |
| `sc2_bytes_out_rate` | `smp_fetch_sc_bytes_out_rate` | `ARG1(0,TAB)` | `SMP_T_SINT` | `SMP_USE_INTRN` | `src/stick_table.c:6219` |
| `sc2_clr_gpc0` | `smp_fetch_sc_clr_gpc0` | `ARG1(0,TAB)` | `SMP_T_SINT` | `SMP_USE_INTRN` | `src/stick_table.c:6220` |
| `sc2_clr_gpc1` | `smp_fetch_sc_clr_gpc1` | `ARG1(0,TAB)` | `SMP_T_SINT` | `SMP_USE_INTRN` | `src/stick_table.c:6221` |
| `sc2_conn_cnt` | `smp_fetch_sc_conn_cnt` | `ARG1(0,TAB)` | `SMP_T_SINT` | `SMP_USE_INTRN` | `src/stick_table.c:6222` |
| `sc2_conn_cur` | `smp_fetch_sc_conn_cur` | `ARG1(0,TAB)` | `SMP_T_SINT` | `SMP_USE_INTRN` | `src/stick_table.c:6223` |
| `sc2_conn_rate` | `smp_fetch_sc_conn_rate` | `ARG1(0,TAB)` | `SMP_T_SINT` | `SMP_USE_INTRN` | `src/stick_table.c:6224` |
| `sc2_get_gpt0` | `smp_fetch_sc_get_gpt0` | `ARG1(0,TAB)` | `SMP_T_SINT` | `SMP_USE_INTRN` | `src/stick_table.c:6225` |
| `sc2_get_gpc0` | `smp_fetch_sc_get_gpc0` | `ARG1(0,TAB)` | `SMP_T_SINT` | `SMP_USE_INTRN` | `src/stick_table.c:6226` |
| `sc2_get_gpc1` | `smp_fetch_sc_get_gpc1` | `ARG1(0,TAB)` | `SMP_T_SINT` | `SMP_USE_INTRN` | `src/stick_table.c:6227` |
| `sc2_glitch_cnt` | `smp_fetch_sc_glitch_cnt` | `ARG1(0,TAB)` | `SMP_T_SINT` | `SMP_USE_INTRN` | `src/stick_table.c:6228` |
| `sc2_glitch_rate` | `smp_fetch_sc_glitch_rate` | `ARG1(0,TAB)` | `SMP_T_SINT` | `SMP_USE_INTRN` | `src/stick_table.c:6229` |
| `sc2_gpc0_rate` | `smp_fetch_sc_gpc0_rate` | `ARG1(0,TAB)` | `SMP_T_SINT` | `SMP_USE_INTRN` | `src/stick_table.c:6230` |
| `sc2_gpc1_rate` | `smp_fetch_sc_gpc1_rate` | `ARG1(0,TAB)` | `SMP_T_SINT` | `SMP_USE_INTRN` | `src/stick_table.c:6231` |
| `sc2_http_err_cnt` | `smp_fetch_sc_http_err_cnt` | `ARG1(0,TAB)` | `SMP_T_SINT` | `SMP_USE_INTRN` | `src/stick_table.c:6232` |
| `sc2_http_err_rate` | `smp_fetch_sc_http_err_rate` | `ARG1(0,TAB)` | `SMP_T_SINT` | `SMP_USE_INTRN` | `src/stick_table.c:6233` |
| `sc2_http_fail_cnt` | `smp_fetch_sc_http_fail_cnt` | `ARG1(0,TAB)` | `SMP_T_SINT` | `SMP_USE_INTRN` | `src/stick_table.c:6234` |
| `sc2_http_fail_rate` | `smp_fetch_sc_http_fail_rate` | `ARG1(0,TAB)` | `SMP_T_SINT` | `SMP_USE_INTRN` | `src/stick_table.c:6235` |
| `sc2_http_req_cnt` | `smp_fetch_sc_http_req_cnt` | `ARG1(0,TAB)` | `SMP_T_SINT` | `SMP_USE_INTRN` | `src/stick_table.c:6236` |
| `sc2_http_req_rate` | `smp_fetch_sc_http_req_rate` | `ARG1(0,TAB)` | `SMP_T_SINT` | `SMP_USE_INTRN` | `src/stick_table.c:6237` |
| `sc2_inc_gpc0` | `smp_fetch_sc_inc_gpc0` | `ARG1(0,TAB)` | `SMP_T_SINT` | `SMP_USE_INTRN` | `src/stick_table.c:6238` |
| `sc2_inc_gpc1` | `smp_fetch_sc_inc_gpc1` | `ARG1(0,TAB)` | `SMP_T_SINT` | `SMP_USE_INTRN` | `src/stick_table.c:6239` |
| `sc2_kbytes_in` | `smp_fetch_sc_kbytes_in` | `ARG1(0,TAB)` | `SMP_T_SINT` | `SMP_USE_L4CLI` | `src/stick_table.c:6240` |
| `sc2_kbytes_out` | `smp_fetch_sc_kbytes_out` | `ARG1(0,TAB)` | `SMP_T_SINT` | `SMP_USE_L4CLI` | `src/stick_table.c:6241` |
| `sc2_key` | `smp_fetch_sc_key` | `0` | `SMP_T_ANY` | `SMP_USE_INTRN` | `src/stick_table.c:6242` |
| `sc2_sess_cnt` | `smp_fetch_sc_sess_cnt` | `ARG1(0,TAB)` | `SMP_T_SINT` | `SMP_USE_INTRN` | `src/stick_table.c:6243` |
| `sc2_sess_rate` | `smp_fetch_sc_sess_rate` | `ARG1(0,TAB)` | `SMP_T_SINT` | `SMP_USE_INTRN` | `src/stick_table.c:6244` |
| `sc2_tracked` | `smp_fetch_sc_tracked` | `ARG1(0,TAB)` | `SMP_T_BOOL` | `SMP_USE_INTRN` | `src/stick_table.c:6245` |
| `sc2_trackers` | `smp_fetch_sc_trackers` | `ARG1(0,TAB)` | `SMP_T_SINT` | `SMP_USE_INTRN` | `src/stick_table.c:6246` |
| `src_bytes_in_rate` | `smp_fetch_sc_bytes_in_rate` | `ARG1(1,TAB)` | `SMP_T_SINT` | `SMP_USE_L4CLI` | `src/stick_table.c:6247` |
| `src_bytes_out_rate` | `smp_fetch_sc_bytes_out_rate` | `ARG1(1,TAB)` | `SMP_T_SINT` | `SMP_USE_L4CLI` | `src/stick_table.c:6248` |
| `src_clr_gpc` | `smp_fetch_sc_clr_gpc` | `ARG2(2,SINT,TAB)` | `SMP_T_SINT` | `SMP_USE_L4CLI` | `src/stick_table.c:6249` |
| `src_clr_gpc0` | `smp_fetch_sc_clr_gpc0` | `ARG1(1,TAB)` | `SMP_T_SINT` | `SMP_USE_L4CLI` | `src/stick_table.c:6250` |
| `src_clr_gpc1` | `smp_fetch_sc_clr_gpc1` | `ARG1(1,TAB)` | `SMP_T_SINT` | `SMP_USE_L4CLI` | `src/stick_table.c:6251` |
| `src_conn_cnt` | `smp_fetch_sc_conn_cnt` | `ARG1(1,TAB)` | `SMP_T_SINT` | `SMP_USE_L4CLI` | `src/stick_table.c:6252` |
| `src_conn_cur` | `smp_fetch_sc_conn_cur` | `ARG1(1,TAB)` | `SMP_T_SINT` | `SMP_USE_L4CLI` | `src/stick_table.c:6253` |
| `src_conn_rate` | `smp_fetch_sc_conn_rate` | `ARG1(1,TAB)` | `SMP_T_SINT` | `SMP_USE_L4CLI` | `src/stick_table.c:6254` |
| `src_get_gpt` | `smp_fetch_sc_get_gpt` | `ARG2(2,SINT,TAB)` | `SMP_T_SINT` | `SMP_USE_L4CLI` | `src/stick_table.c:6255` |
| `src_get_gpt0` | `smp_fetch_sc_get_gpt0` | `ARG1(1,TAB)` | `SMP_T_SINT` | `SMP_USE_L4CLI` | `src/stick_table.c:6256` |
| `src_get_gpc` | `smp_fetch_sc_get_gpc` | `ARG2(2,SINT,TAB)` | `SMP_T_SINT` | `SMP_USE_L4CLI` | `src/stick_table.c:6257` |
| `src_get_gpc0` | `smp_fetch_sc_get_gpc0` | `ARG1(1,TAB)` | `SMP_T_SINT` | `SMP_USE_L4CLI` | `src/stick_table.c:6258` |
| `src_get_gpc1` | `smp_fetch_sc_get_gpc1` | `ARG1(1,TAB)` | `SMP_T_SINT` | `SMP_USE_L4CLI` | `src/stick_table.c:6259` |
| `src_glitch_cnt` | `smp_fetch_sc_glitch_cnt` | `ARG1(1,TAB)` | `SMP_T_SINT` | `SMP_USE_L4CLI` | `src/stick_table.c:6260` |
| `src_glitch_rate` | `smp_fetch_sc_glitch_rate` | `ARG1(1,TAB)` | `SMP_T_SINT` | `SMP_USE_L4CLI` | `src/stick_table.c:6261` |
| `src_gpc_rate` | `smp_fetch_sc_gpc_rate` | `ARG2(2,SINT,TAB)` | `SMP_T_SINT` | `SMP_USE_L4CLI` | `src/stick_table.c:6262` |
| `src_gpc0_rate` | `smp_fetch_sc_gpc0_rate` | `ARG1(1,TAB)` | `SMP_T_SINT` | `SMP_USE_L4CLI` | `src/stick_table.c:6263` |
| `src_gpc1_rate` | `smp_fetch_sc_gpc1_rate` | `ARG1(1,TAB)` | `SMP_T_SINT` | `SMP_USE_L4CLI` | `src/stick_table.c:6264` |
| `src_http_err_cnt` | `smp_fetch_sc_http_err_cnt` | `ARG1(1,TAB)` | `SMP_T_SINT` | `SMP_USE_L4CLI` | `src/stick_table.c:6265` |
| `src_http_err_rate` | `smp_fetch_sc_http_err_rate` | `ARG1(1,TAB)` | `SMP_T_SINT` | `SMP_USE_L4CLI` | `src/stick_table.c:6266` |
| `src_http_fail_cnt` | `smp_fetch_sc_http_fail_cnt` | `ARG1(1,TAB)` | `SMP_T_SINT` | `SMP_USE_L4CLI` | `src/stick_table.c:6267` |
| `src_http_fail_rate` | `smp_fetch_sc_http_fail_rate` | `ARG1(1,TAB)` | `SMP_T_SINT` | `SMP_USE_L4CLI` | `src/stick_table.c:6268` |
| `src_http_req_cnt` | `smp_fetch_sc_http_req_cnt` | `ARG1(1,TAB)` | `SMP_T_SINT` | `SMP_USE_L4CLI` | `src/stick_table.c:6269` |
| `src_http_req_rate` | `smp_fetch_sc_http_req_rate` | `ARG1(1,TAB)` | `SMP_T_SINT` | `SMP_USE_L4CLI` | `src/stick_table.c:6270` |
| `src_inc_gpc` | `smp_fetch_sc_inc_gpc` | `ARG2(2,SINT,TAB)` | `SMP_T_SINT` | `SMP_USE_L4CLI` | `src/stick_table.c:6271` |
| `src_inc_gpc0` | `smp_fetch_sc_inc_gpc0` | `ARG1(1,TAB)` | `SMP_T_SINT` | `SMP_USE_L4CLI` | `src/stick_table.c:6272` |
| `src_inc_gpc1` | `smp_fetch_sc_inc_gpc1` | `ARG1(1,TAB)` | `SMP_T_SINT` | `SMP_USE_L4CLI` | `src/stick_table.c:6273` |
| `src_kbytes_in` | `smp_fetch_sc_kbytes_in` | `ARG1(1,TAB)` | `SMP_T_SINT` | `SMP_USE_L4CLI` | `src/stick_table.c:6274` |
| `src_kbytes_out` | `smp_fetch_sc_kbytes_out` | `ARG1(1,TAB)` | `SMP_T_SINT` | `SMP_USE_L4CLI` | `src/stick_table.c:6275` |
| `src_sess_cnt` | `smp_fetch_sc_sess_cnt` | `ARG1(1,TAB)` | `SMP_T_SINT` | `SMP_USE_L4CLI` | `src/stick_table.c:6276` |
| `src_sess_rate` | `smp_fetch_sc_sess_rate` | `ARG1(1,TAB)` | `SMP_T_SINT` | `SMP_USE_L4CLI` | `src/stick_table.c:6277` |
| `src_updt_conn_cnt` | `smp_fetch_src_updt_conn_cnt` | `ARG1(1,TAB)` | `SMP_T_SINT` | `SMP_USE_L4CLI` | `src/stick_table.c:6278` |
| `table_avl` | `smp_fetch_table_avl` | `ARG1(1,TAB)` | `SMP_T_SINT` | `SMP_USE_INTRN` | `src/stick_table.c:6279` |
| `table_cnt` | `smp_fetch_table_cnt` | `ARG1(1,TAB)` | `SMP_T_SINT` | `SMP_USE_INTRN` | `src/stick_table.c:6280` |
| `cur_connect_timeout` | `smp_fetch_cur_connect_timeout` | `0` | `SMP_T_SINT` | `SMP_USE_BKEND` | `src/stream.c:4879` |
| `cur_client_timeout` | `smp_fetch_cur_client_timeout` | `0` | `SMP_T_SINT` | `SMP_USE_FTEND` | `src/stream.c:4880` |
| `cur_max_retries` | `smp_fetch_cur_max_retries` | `0` | `SMP_T_SINT` | `SMP_USE_BKEND` | `src/stream.c:4881` |
| `cur_server_timeout` | `smp_fetch_cur_server_timeout` | `0` | `SMP_T_SINT` | `SMP_USE_BKEND` | `src/stream.c:4882` |
| `cur_queue_timeout` | `smp_fetch_cur_queue_timeout` | `0` | `SMP_T_SINT` | `SMP_USE_BKEND` | `src/stream.c:4883` |
| `cur_tarpit_timeout` | `smp_fetch_cur_tarpit_timeout` | `0` | `SMP_T_SINT` | `SMP_USE_FTEND | SMP_USE_BKEND` | `src/stream.c:4884` |
| `cur_tunnel_timeout` | `smp_fetch_cur_tunnel_timeout` | `0` | `SMP_T_SINT` | `SMP_USE_BKEND` | `src/stream.c:4885` |
| `last_entity` | `smp_fetch_last_entity` | `0` | `SMP_T_STR` | `SMP_USE_INTRN` | `src/stream.c:4886` |
| `last_rule_file` | `smp_fetch_last_rule_file` | `0` | `SMP_T_STR` | `SMP_USE_INTRN` | `src/stream.c:4887` |
| `last_rule_line` | `smp_fetch_last_rule_line` | `0` | `SMP_T_SINT` | `SMP_USE_INTRN` | `src/stream.c:4888` |
| `term_events` | `smp_fetch_tevts` | `0` | `SMP_T_STR` | `SMP_USE_INTRN` | `src/stream.c:4889` |
| `txn.conn_retries` | `smp_fetch_conn_retries` | `0` | `SMP_T_SINT` | `SMP_USE_L4SRV` | `src/stream.c:4890` |
| `txn.id32` | `smp_fetch_id32` | `0` | `SMP_T_SINT` | `SMP_USE_INTRN` | `src/stream.c:4891` |
| `txn.redispatched` | `smp_fetch_redispatched` | `0` | `SMP_T_BOOL` | `SMP_USE_L4SRV` | `src/stream.c:4892` |
| `txn.sess_term_state` | `smp_fetch_sess_term_state` | `0` | `SMP_T_STR` | `SMP_USE_INTRN` | `src/stream.c:4893` |
| `waiting_entity` | `smp_fetch_waiting_entity` | `0` | `SMP_T_STR` | `SMP_USE_INTRN` | `src/stream.c:4894` |
| `accept_date` | `smp_fetch_accept_date` | `ARG1(0,STR)` | `SMP_T_SINT` | `SMP_USE_L4CLI` | `src/tcp_sample.c:582` |
| `request_date` | `smp_fetch_accept_date` | `ARG1(0,STR)` | `SMP_T_SINT` | `SMP_USE_HRQHP` | `src/tcp_sample.c:583` |
| `bc_dst` | `smp_fetch_dst` | `0` | `SMP_T_ADDR` | `SMP_USE_L4SRV` | `src/tcp_sample.c:585` |
| `bc_dst_port` | `smp_fetch_dport` | `0` | `SMP_T_SINT` | `SMP_USE_L4SRV` | `src/tcp_sample.c:586` |
| `bc_src` | `smp_fetch_src` | `0` | `SMP_T_ADDR` | `SMP_USE_L4SRV` | `src/tcp_sample.c:587` |
| `bc_src_port` | `smp_fetch_sport` | `0` | `SMP_T_SINT` | `SMP_USE_L4SRV` | `src/tcp_sample.c:588` |
| `bc_reused` | `smp_fetch_reused` | `0` | `SMP_T_BOOL` | `SMP_USE_L4SRV` | `src/tcp_sample.c:589` |
| `dst` | `smp_fetch_dst` | `0` | `SMP_T_ADDR` | `SMP_USE_L4CLI` | `src/tcp_sample.c:591` |
| `dst_is_local` | `smp_fetch_dst_is_local` | `0` | `SMP_T_BOOL` | `SMP_USE_L4CLI` | `src/tcp_sample.c:592` |
| `dst_port` | `smp_fetch_dport` | `0` | `SMP_T_SINT` | `SMP_USE_L4CLI` | `src/tcp_sample.c:593` |
| `fc_dst` | `smp_fetch_dst` | `0` | `SMP_T_ADDR` | `SMP_USE_L4CLI` | `src/tcp_sample.c:595` |
| `fc_dst_is_local` | `smp_fetch_dst_is_local` | `0` | `SMP_T_BOOL` | `SMP_USE_L4CLI` | `src/tcp_sample.c:596` |
| `fc_dst_port` | `smp_fetch_dport` | `0` | `SMP_T_SINT` | `SMP_USE_L4CLI` | `src/tcp_sample.c:597` |
| `fc_src` | `smp_fetch_src` | `0` | `SMP_T_ADDR` | `SMP_USE_L4CLI` | `src/tcp_sample.c:599` |
| `fc_src_is_local` | `smp_fetch_src_is_local` | `0` | `SMP_T_BOOL` | `SMP_USE_L4CLI` | `src/tcp_sample.c:600` |
| `fc_src_port` | `smp_fetch_sport` | `0` | `SMP_T_SINT` | `SMP_USE_L4CLI` | `src/tcp_sample.c:601` |
| `src` | `smp_fetch_src` | `0` | `SMP_T_ADDR` | `SMP_USE_L4CLI` | `src/tcp_sample.c:603` |
| `src_is_local` | `smp_fetch_src_is_local` | `0` | `SMP_T_BOOL` | `SMP_USE_L4CLI` | `src/tcp_sample.c:604` |
| `src_port` | `smp_fetch_sport` | `0` | `SMP_T_SINT` | `SMP_USE_L4CLI` | `src/tcp_sample.c:605` |
| `fc_saved_syn` | `smp_fetch_fc_saved_syn` | `0` | `SMP_T_BIN` | `SMP_USE_L4CLI` | `src/tcp_sample.c:607` |
| `fc_rtt` | `smp_fetch_fc_rtt` | `ARG1(0,STR)` | `SMP_T_SINT` | `SMP_USE_L4CLI` | `src/tcp_sample.c:610` |
| `fc_rttvar` | `smp_fetch_fc_rttvar` | `ARG1(0,STR)` | `SMP_T_SINT` | `SMP_USE_L4CLI` | `src/tcp_sample.c:611` |
| `bc_rtt` | `smp_fetch_bc_rtt` | `ARG1(0,STR)` | `SMP_T_SINT` | `SMP_USE_L4CLI` | `src/tcp_sample.c:612` |
| `bc_rttvar` | `smp_fetch_bc_rttvar` | `ARG1(0,STR)` | `SMP_T_SINT` | `SMP_USE_L4CLI` | `src/tcp_sample.c:613` |
| `fc_unacked` | `smp_fetch_fc_unacked` | `ARG1(0,STR)` | `SMP_T_SINT` | `SMP_USE_L4CLI` | `src/tcp_sample.c:616` |
| `fc_sacked` | `smp_fetch_fc_sacked` | `ARG1(0,STR)` | `SMP_T_SINT` | `SMP_USE_L4CLI` | `src/tcp_sample.c:619` |
| `fc_retrans` | `smp_fetch_fc_retrans` | `ARG1(0,STR)` | `SMP_T_SINT` | `SMP_USE_L4CLI` | `src/tcp_sample.c:622` |
| `fc_fackets` | `smp_fetch_fc_fackets` | `ARG1(0,STR)` | `SMP_T_SINT` | `SMP_USE_L4CLI` | `src/tcp_sample.c:625` |
| `fc_lost` | `smp_fetch_fc_lost` | `ARG1(0,STR)` | `SMP_T_SINT` | `SMP_USE_L4CLI` | `src/tcp_sample.c:628` |
| `fc_reordering` | `smp_fetch_fc_reordering` | `ARG1(0,STR)` | `SMP_T_SINT` | `SMP_USE_L4CLI` | `src/tcp_sample.c:631` |
| `dump_all_vars` | `smp_fetch_dump_all_vars` | `ARG3(0,STR,STR,STR)` | `SMP_T_STR` | `SMP_USE_CONST` | `src/vars.c:1663` |
| `var` | `smp_fetch_var` | `ARG2(1,STR,STR)` | `SMP_T_ANY` | `SMP_USE_CONST` | `src/vars.c:1664` |
