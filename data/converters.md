# HAProxy Sample Converter Inventory & Type Lattice Reference

- **Reference source:** `/home/bhenc/reference/haproxy` @ commit `e6f616af` (3.5-dev7)
- **Total registered converters extracted:** 211

## 1. Complete Converter Inventory

| # | Keyword | Process Function | Argument Mask | Input Type | Output Type | Citation |
|---|---|---|---|---|---|---|
| 1 | `nbsrv` | `sample_conv_nbsrv` | `0` | `SMP_T_STR` | `SMP_T_SINT` | `src/backend.c:3988` |
| 2 | `srv_is_up` | `sample_conv_srv_is_up` | `0` | `SMP_T_STR` | `SMP_T_BOOL` | `src/backend.c:3989` |
| 3 | `srv_queue` | `sample_conv_srv_queue` | `0` | `SMP_T_STR` | `SMP_T_SINT` | `src/backend.c:3990` |
| 4 | `fe_exists` | `sample_conv_fe_exists` | `0` | `SMP_T_STR` | `SMP_T_BOOL` | `src/frontend.c:361` |
| 5 | `http_date` | `sample_conv_http_date` | `ARG2(0,SINT,STR)` | `SMP_T_SINT` | `SMP_T_STR` | `src/http_conv.c:468` |
| 6 | `date` | `sample_conv_http2epoch` | `0` | `SMP_T_STR` | `SMP_T_SINT` | `src/http_conv.c:469` |
| 7 | `language` | `sample_conv_q_preferred` | `ARG2(1,STR,STR)` | `SMP_T_STR` | `SMP_T_STR` | `src/http_conv.c:470` |
| 8 | `capture-req` | `smp_conv_req_capture` | `ARG1(1,SINT)` | `SMP_T_STR` | `SMP_T_STR` | `src/http_conv.c:471` |
| 9 | `capture-res` | `smp_conv_res_capture` | `ARG1(1,SINT)` | `SMP_T_STR` | `SMP_T_STR` | `src/http_conv.c:472` |
| 10 | `url_dec` | `sample_conv_url_dec` | `ARG1(0,SINT)` | `SMP_T_STR` | `SMP_T_STR` | `src/http_conv.c:473` |
| 11 | `url_enc` | `sample_conv_url_enc` | `ARG1(1,STR)` | `SMP_T_STR` | `SMP_T_STR` | `src/http_conv.c:474` |
| 12 | `rfc7239_is_valid` | `sample_conv_7239_valid` | `0` | `SMP_T_STR` | `SMP_T_BOOL` | `src/http_ext.c:1989` |
| 13 | `rfc7239_field` | `sample_conv_7239_field` | `ARG1(1,STR)` | `SMP_T_STR` | `SMP_T_STR` | `src/http_ext.c:1990` |
| 14 | `rfc7239_n2nn` | `sample_conv_7239_n2nn` | `0` | `SMP_T_STR` | `SMP_T_ANY` | `src/http_ext.c:1991` |
| 15 | `rfc7239_n2np` | `sample_conv_7239_n2np` | `0` | `SMP_T_STR` | `SMP_T_ANY` | `src/http_ext.c:1992` |
| 16 | `rfc7239_nn` | `sample_conv_7239_nn` | `0` | `SMP_T_ANY` | `SMP_T_STR` | `src/http_ext.c:1993` |
| 17 | `rfc7239_np` | `sample_conv_7239_np` | `0` | `SMP_T_ANY` | `SMP_T_STR` | `src/http_ext.c:1994` |
| 18 | `jwt_decrypt_secret` | `sample_conv_jwt_decrypt_secret` | `ARG1(1,STR)` | `SMP_T_BIN` | `SMP_T_BIN` | `src/jwe.c:2285` |
| 19 | `jwt_decrypt_cert` | `sample_conv_jwt_decrypt_cert` | `ARG1(1,STR)` | `SMP_T_BIN` | `SMP_T_BIN` | `src/jwe.c:2286` |
| 20 | `jwt_decrypt_jwk` | `sample_conv_jwt_decrypt_jwk` | `ARG1(1,STR)` | `SMP_T_BIN` | `SMP_T_BIN` | `src/jwe.c:2287` |
| 21 | `map` | `sample_conv_map` | `ARG2(1,STR,STR)` | `SMP_T_STR` | `SMP_T_STR` | `src/map.c:1244` |
| 22 | `map_str` | `sample_conv_map` | `ARG2(1,STR,STR)` | `SMP_T_STR` | `SMP_T_STR` | `src/map.c:1245` |
| 23 | `map_beg` | `sample_conv_map` | `ARG2(1,STR,STR)` | `SMP_T_STR` | `SMP_T_STR` | `src/map.c:1246` |
| 24 | `map_sub` | `sample_conv_map` | `ARG2(1,STR,STR)` | `SMP_T_STR` | `SMP_T_STR` | `src/map.c:1247` |
| 25 | `map_dir` | `sample_conv_map` | `ARG2(1,STR,STR)` | `SMP_T_STR` | `SMP_T_STR` | `src/map.c:1248` |
| 26 | `map_dom` | `sample_conv_map` | `ARG2(1,STR,STR)` | `SMP_T_STR` | `SMP_T_STR` | `src/map.c:1249` |
| 27 | `map_end` | `sample_conv_map` | `ARG2(1,STR,STR)` | `SMP_T_STR` | `SMP_T_STR` | `src/map.c:1250` |
| 28 | `map_reg` | `sample_conv_map` | `ARG2(1,STR,STR)` | `SMP_T_STR` | `SMP_T_STR` | `src/map.c:1251` |
| 29 | `map_regm` | `sample_conv_map` | `ARG2(1,STR,STR)` | `SMP_T_STR` | `SMP_T_STR` | `src/map.c:1252` |
| 30 | `map_int` | `sample_conv_map` | `ARG2(1,STR,STR)` | `SMP_T_SINT` | `SMP_T_STR` | `src/map.c:1253` |
| 31 | `map_ip` | `sample_conv_map` | `ARG2(1,STR,STR)` | `SMP_T_ADDR` | `SMP_T_STR` | `src/map.c:1254` |
| 32 | `map_str_int` | `sample_conv_map` | `ARG2(1,STR,SINT)` | `SMP_T_STR` | `SMP_T_SINT` | `src/map.c:1256` |
| 33 | `map_beg_int` | `sample_conv_map` | `ARG2(1,STR,SINT)` | `SMP_T_STR` | `SMP_T_SINT` | `src/map.c:1257` |
| 34 | `map_sub_int` | `sample_conv_map` | `ARG2(1,STR,SINT)` | `SMP_T_STR` | `SMP_T_SINT` | `src/map.c:1258` |
| 35 | `map_dir_int` | `sample_conv_map` | `ARG2(1,STR,SINT)` | `SMP_T_STR` | `SMP_T_SINT` | `src/map.c:1259` |
| 36 | `map_dom_int` | `sample_conv_map` | `ARG2(1,STR,SINT)` | `SMP_T_STR` | `SMP_T_SINT` | `src/map.c:1260` |
| 37 | `map_end_int` | `sample_conv_map` | `ARG2(1,STR,SINT)` | `SMP_T_STR` | `SMP_T_SINT` | `src/map.c:1261` |
| 38 | `map_reg_int` | `sample_conv_map` | `ARG2(1,STR,SINT)` | `SMP_T_STR` | `SMP_T_SINT` | `src/map.c:1262` |
| 39 | `map_int_int` | `sample_conv_map` | `ARG2(1,STR,SINT)` | `SMP_T_SINT` | `SMP_T_SINT` | `src/map.c:1263` |
| 40 | `map_ip_int` | `sample_conv_map` | `ARG2(1,STR,SINT)` | `SMP_T_ADDR` | `SMP_T_SINT` | `src/map.c:1264` |
| 41 | `map_str_ip` | `sample_conv_map` | `ARG2(1,STR,STR)` | `SMP_T_STR` | `SMP_T_ADDR` | `src/map.c:1266` |
| 42 | `map_beg_ip` | `sample_conv_map` | `ARG2(1,STR,STR)` | `SMP_T_STR` | `SMP_T_ADDR` | `src/map.c:1267` |
| 43 | `map_sub_ip` | `sample_conv_map` | `ARG2(1,STR,STR)` | `SMP_T_STR` | `SMP_T_ADDR` | `src/map.c:1268` |
| 44 | `map_dir_ip` | `sample_conv_map` | `ARG2(1,STR,STR)` | `SMP_T_STR` | `SMP_T_ADDR` | `src/map.c:1269` |
| 45 | `map_dom_ip` | `sample_conv_map` | `ARG2(1,STR,STR)` | `SMP_T_STR` | `SMP_T_ADDR` | `src/map.c:1270` |
| 46 | `map_end_ip` | `sample_conv_map` | `ARG2(1,STR,STR)` | `SMP_T_STR` | `SMP_T_ADDR` | `src/map.c:1271` |
| 47 | `map_reg_ip` | `sample_conv_map` | `ARG2(1,STR,STR)` | `SMP_T_STR` | `SMP_T_ADDR` | `src/map.c:1272` |
| 48 | `map_int_ip` | `sample_conv_map` | `ARG2(1,STR,STR)` | `SMP_T_SINT` | `SMP_T_ADDR` | `src/map.c:1273` |
| 49 | `map_ip_ip` | `sample_conv_map` | `ARG2(1,STR,STR)` | `SMP_T_ADDR` | `SMP_T_ADDR` | `src/map.c:1274` |
| 50 | `map_str_key` | `sample_conv_map_key` | `ARG1(1,STR)` | `SMP_T_STR` | `SMP_T_STR` | `src/map.c:1276` |
| 51 | `map_beg_key` | `sample_conv_map_key` | `ARG1(1,STR)` | `SMP_T_STR` | `SMP_T_STR` | `src/map.c:1277` |
| 52 | `map_sub_key` | `sample_conv_map_key` | `ARG1(1,STR)` | `SMP_T_STR` | `SMP_T_STR` | `src/map.c:1278` |
| 53 | `map_dir_key` | `sample_conv_map_key` | `ARG1(1,STR)` | `SMP_T_STR` | `SMP_T_STR` | `src/map.c:1279` |
| 54 | `map_dom_key` | `sample_conv_map_key` | `ARG1(1,STR)` | `SMP_T_STR` | `SMP_T_STR` | `src/map.c:1280` |
| 55 | `map_end_key` | `sample_conv_map_key` | `ARG1(1,STR)` | `SMP_T_STR` | `SMP_T_STR` | `src/map.c:1281` |
| 56 | `map_reg_key` | `sample_conv_map_key` | `ARG1(1,STR)` | `SMP_T_STR` | `SMP_T_STR` | `src/map.c:1282` |
| 57 | `map_int_key` | `sample_conv_map_key` | `ARG1(1,STR)` | `SMP_T_SINT` | `SMP_T_STR` | `src/map.c:1283` |
| 58 | `map_ip_key` | `sample_conv_map_key` | `ARG1(1,STR)` | `SMP_T_ADDR` | `SMP_T_STR` | `src/map.c:1284` |
| 59 | `eth.data` | `sample_conv_eth_data` | `0` | `SMP_T_BIN` | `SMP_T_BIN` | `src/net_helper.c:844` |
| 60 | `eth.dst` | `sample_conv_eth_dst` | `0` | `SMP_T_BIN` | `SMP_T_BIN` | `src/net_helper.c:845` |
| 61 | `eth.hdr` | `sample_conv_eth_hdr` | `0` | `SMP_T_BIN` | `SMP_T_BIN` | `src/net_helper.c:846` |
| 62 | `eth.proto` | `sample_conv_eth_proto` | `0` | `SMP_T_BIN` | `SMP_T_SINT` | `src/net_helper.c:847` |
| 63 | `eth.src` | `sample_conv_eth_src` | `0` | `SMP_T_BIN` | `SMP_T_BIN` | `src/net_helper.c:848` |
| 64 | `eth.vlan` | `sample_conv_eth_vlan` | `0` | `SMP_T_BIN` | `SMP_T_SINT` | `src/net_helper.c:849` |
| 65 | `ip.data` | `sample_conv_ip_data` | `0` | `SMP_T_BIN` | `SMP_T_BIN` | `src/net_helper.c:851` |
| 66 | `ip.df` | `sample_conv_ip_df` | `0` | `SMP_T_BIN` | `SMP_T_SINT` | `src/net_helper.c:852` |
| 67 | `ip.dst` | `sample_conv_ip_dst` | `0` | `SMP_T_BIN` | `SMP_T_ADDR` | `src/net_helper.c:853` |
| 68 | `ip.fp` | `sample_conv_ip_fp` | `ARG1(0,SINT)` | `SMP_T_BIN` | `SMP_T_BIN` | `src/net_helper.c:854` |
| 69 | `ip.hdr` | `sample_conv_ip_hdr` | `0` | `SMP_T_BIN` | `SMP_T_BIN` | `src/net_helper.c:855` |
| 70 | `ip.proto` | `sample_conv_ip_proto` | `0` | `SMP_T_BIN` | `SMP_T_SINT` | `src/net_helper.c:856` |
| 71 | `ip.src` | `sample_conv_ip_src` | `0` | `SMP_T_BIN` | `SMP_T_ADDR` | `src/net_helper.c:857` |
| 72 | `ip.tos` | `sample_conv_ip_tos` | `0` | `SMP_T_BIN` | `SMP_T_SINT` | `src/net_helper.c:858` |
| 73 | `ip.ttl` | `sample_conv_ip_ttl` | `0` | `SMP_T_BIN` | `SMP_T_SINT` | `src/net_helper.c:859` |
| 74 | `ip.ver` | `sample_conv_ip_ver` | `0` | `SMP_T_BIN` | `SMP_T_SINT` | `src/net_helper.c:860` |
| 75 | `tcp.dst` | `sample_conv_tcp_dst` | `0` | `SMP_T_BIN` | `SMP_T_SINT` | `src/net_helper.c:862` |
| 76 | `tcp.flags` | `sample_conv_tcp_flags` | `0` | `SMP_T_BIN` | `SMP_T_SINT` | `src/net_helper.c:863` |
| 77 | `tcp.options.mss` | `sample_conv_tcp_options_mss` | `0` | `SMP_T_BIN` | `SMP_T_SINT` | `src/net_helper.c:864` |
| 78 | `tcp.options.sack` | `sample_conv_tcp_options_sack` | `0` | `SMP_T_BIN` | `SMP_T_SINT` | `src/net_helper.c:865` |
| 79 | `tcp.options.tsopt` | `sample_conv_tcp_options_tsopt` | `0` | `SMP_T_BIN` | `SMP_T_SINT` | `src/net_helper.c:866` |
| 80 | `tcp.options.tsval` | `sample_conv_tcp_options_tsval` | `0` | `SMP_T_BIN` | `SMP_T_SINT` | `src/net_helper.c:867` |
| 81 | `tcp.options.wscale` | `sample_conv_tcp_options_wscale` | `0` | `SMP_T_BIN` | `SMP_T_SINT` | `src/net_helper.c:868` |
| 82 | `tcp.options.wsopt` | `sample_conv_tcp_options_wsopt` | `0` | `SMP_T_BIN` | `SMP_T_SINT` | `src/net_helper.c:869` |
| 83 | `tcp.options_list` | `sample_conv_tcp_options_list` | `0` | `SMP_T_BIN` | `SMP_T_BIN` | `src/net_helper.c:870` |
| 84 | `tcp.seq` | `sample_conv_tcp_seq` | `0` | `SMP_T_BIN` | `SMP_T_SINT` | `src/net_helper.c:871` |
| 85 | `tcp.src` | `sample_conv_tcp_src` | `0` | `SMP_T_BIN` | `SMP_T_SINT` | `src/net_helper.c:872` |
| 86 | `tcp.win` | `sample_conv_tcp_win` | `0` | `SMP_T_BIN` | `SMP_T_SINT` | `src/net_helper.c:873` |
| 87 | `add_item` | `sample_conv_add_item` | `ARG3(2,STR,STR,STR)` | `SMP_T_STR` | `SMP_T_STR` | `src/sample.c:5992` |
| 88 | `debug` | `sample_conv_debug` | `ARG2(0,STR,STR)` | `SMP_T_ANY` | `SMP_T_SAME` | `src/sample.c:5993` |
| 89 | `b64dec` | `sample_conv_base642bin` | `0` | `SMP_T_STR` | `SMP_T_BIN` | `src/sample.c:5994` |
| 90 | `base64` | `sample_conv_bin2base64` | `0` | `SMP_T_BIN` | `SMP_T_STR` | `src/sample.c:5995` |
| 91 | `concat` | `sample_conv_concat` | `ARG3(1,STR,STR,STR)` | `SMP_T_STR` | `SMP_T_STR` | `src/sample.c:5996` |
| 92 | `ub64enc` | `sample_conv_bin2base64url` | `0` | `SMP_T_BIN` | `SMP_T_STR` | `src/sample.c:5997` |
| 93 | `ub64dec` | `sample_conv_base64url2bin` | `0` | `SMP_T_STR` | `SMP_T_BIN` | `src/sample.c:5998` |
| 94 | `upper` | `sample_conv_str2upper` | `0` | `SMP_T_STR` | `SMP_T_STR` | `src/sample.c:5999` |
| 95 | `lower` | `sample_conv_str2lower` | `0` | `SMP_T_STR` | `SMP_T_STR` | `src/sample.c:6000` |
| 96 | `length` | `sample_conv_length` | `0` | `SMP_T_STR` | `SMP_T_SINT` | `src/sample.c:6001` |
| 97 | `base2` | `sample_conv_bin2base2` | `0` | `SMP_T_BIN` | `SMP_T_STR` | `src/sample.c:6002` |
| 98 | `be2dec` | `sample_conv_be2dec` | `ARG3(1,STR,SINT,SINT)` | `SMP_T_BIN` | `SMP_T_STR` | `src/sample.c:6003` |
| 99 | `le2dec` | `sample_conv_le2dec` | `ARG3(1,STR,SINT,SINT)` | `SMP_T_BIN` | `SMP_T_STR` | `src/sample.c:6004` |
| 100 | `be2hex` | `sample_conv_be2hex` | `ARG3(1,STR,SINT,SINT)` | `SMP_T_BIN` | `SMP_T_STR` | `src/sample.c:6005` |
| 101 | `be_sort` | `sample_conv_be_sort` | `ARG1(1,SINT)` | `SMP_T_BIN` | `SMP_T_BIN` | `src/sample.c:6006` |
| 102 | `has_ctl` | `sample_conv_hasctl` | `ARG1(0,STR)` | `SMP_T_BIN` | `SMP_T_BOOL` | `src/sample.c:6007` |
| 103 | `hex` | `sample_conv_bin2hex` | `0` | `SMP_T_BIN` | `SMP_T_STR` | `src/sample.c:6008` |
| 104 | `hex2i` | `sample_conv_hex2int` | `0` | `SMP_T_STR` | `SMP_T_SINT` | `src/sample.c:6009` |
| 105 | `ipmask` | `sample_conv_ipmask` | `ARG2(1,MSK4,MSK6)` | `SMP_T_ADDR` | `SMP_T_ADDR` | `src/sample.c:6010` |
| 106 | `ltime` | `sample_conv_ltime` | `ARG2(1,STR,SINT)` | `SMP_T_SINT` | `SMP_T_STR` | `src/sample.c:6011` |
| 107 | `ms_ltime` | `sample_conv_ms_ltime` | `ARG2(1,STR,SINT)` | `SMP_T_SINT` | `SMP_T_STR` | `src/sample.c:6012` |
| 108 | `us_ltime` | `sample_conv_us_ltime` | `ARG2(1,STR,SINT)` | `SMP_T_SINT` | `SMP_T_STR` | `src/sample.c:6013` |
| 109 | `utime` | `sample_conv_utime` | `ARG2(1,STR,SINT)` | `SMP_T_SINT` | `SMP_T_STR` | `src/sample.c:6014` |
| 110 | `ms_utime` | `sample_conv_ms_utime` | `ARG2(1,STR,SINT)` | `SMP_T_SINT` | `SMP_T_STR` | `src/sample.c:6015` |
| 111 | `us_utime` | `sample_conv_us_utime` | `ARG2(1,STR,SINT)` | `SMP_T_SINT` | `SMP_T_STR` | `src/sample.c:6016` |
| 112 | `crc32` | `sample_conv_crc32` | `ARG1(0,SINT)` | `SMP_T_BIN` | `SMP_T_SINT` | `src/sample.c:6017` |
| 113 | `crc32c` | `sample_conv_crc32c` | `ARG1(0,SINT)` | `SMP_T_BIN` | `SMP_T_SINT` | `src/sample.c:6018` |
| 114 | `djb2` | `sample_conv_djb2` | `ARG1(0,SINT)` | `SMP_T_BIN` | `SMP_T_SINT` | `src/sample.c:6019` |
| 115 | `sdbm` | `sample_conv_sdbm` | `ARG1(0,SINT)` | `SMP_T_BIN` | `SMP_T_SINT` | `src/sample.c:6020` |
| 116 | `wt6` | `sample_conv_wt6` | `ARG1(0,SINT)` | `SMP_T_BIN` | `SMP_T_SINT` | `src/sample.c:6021` |
| 117 | `xxh3` | `sample_conv_xxh3` | `ARG1(0,SINT)` | `SMP_T_BIN` | `SMP_T_SINT` | `src/sample.c:6022` |
| 118 | `xxh32` | `sample_conv_xxh32` | `ARG1(0,SINT)` | `SMP_T_BIN` | `SMP_T_SINT` | `src/sample.c:6023` |
| 119 | `xxh64` | `sample_conv_xxh64` | `ARG1(0,SINT)` | `SMP_T_BIN` | `SMP_T_SINT` | `src/sample.c:6024` |
| 120 | `json` | `sample_conv_json` | `ARG1(1,STR)` | `SMP_T_STR` | `SMP_T_STR` | `src/sample.c:6025` |
| 121 | `bytes` | `sample_conv_bytes` | `ARG2(1,STR,STR)` | `SMP_T_BIN` | `SMP_T_BIN` | `src/sample.c:6026` |
| 122 | `field` | `sample_conv_field` | `ARG3(2,SINT,STR,SINT)` | `SMP_T_STR` | `SMP_T_STR` | `src/sample.c:6027` |
| 123 | `word` | `sample_conv_word` | `ARG3(2,SINT,STR,SINT)` | `SMP_T_STR` | `SMP_T_STR` | `src/sample.c:6028` |
| 124 | `param` | `sample_conv_param` | `ARG2(1,STR,STR)` | `SMP_T_STR` | `SMP_T_STR` | `src/sample.c:6029` |
| 125 | `regsub` | `sample_conv_regsub` | `ARG3(2,REG,STR,STR)` | `SMP_T_STR` | `SMP_T_STR` | `src/sample.c:6030` |
| 126 | `sha1` | `sample_conv_sha1` | `0` | `SMP_T_BIN` | `SMP_T_BIN` | `src/sample.c:6031` |
| 127 | `strcmp` | `sample_conv_strcmp` | `ARG1(1,STR)` | `SMP_T_STR` | `SMP_T_SINT` | `src/sample.c:6032` |
| 128 | `host_only` | `sample_conv_host_only` | `0` | `SMP_T_STR` | `SMP_T_STR` | `src/sample.c:6033` |
| 129 | `port_only` | `sample_conv_port_only` | `0` | `SMP_T_STR` | `SMP_T_SINT` | `src/sample.c:6034` |
| 130 | `reverse` | `sample_conv_reverse` | `0` | `SMP_T_STR` | `SMP_T_STR` | `src/sample.c:6035` |
| 131 | `reverse_dom` | `sample_conv_reverse_dom` | `0` | `SMP_T_STR` | `SMP_T_STR` | `src/sample.c:6036` |
| 132 | `ungrpc` | `sample_conv_ungrpc` | `ARG2(1,PBUF_FNUM,STR)` | `SMP_T_BIN` | `SMP_T_BIN` | `src/sample.c:6039` |
| 133 | `protobuf` | `sample_conv_protobuf` | `ARG2(1,PBUF_FNUM,STR)` | `SMP_T_BIN` | `SMP_T_BIN` | `src/sample.c:6040` |
| 134 | `fix_is_valid` | `sample_conv_fix_is_valid` | `0` | `SMP_T_BIN` | `SMP_T_BOOL` | `src/sample.c:6043` |
| 135 | `fix_tag_value` | `sample_conv_fix_tag_value` | `ARG1(1,STR)` | `SMP_T_BIN` | `SMP_T_BIN` | `src/sample.c:6044` |
| 136 | `mqtt_is_valid` | `sample_conv_mqtt_is_valid` | `0` | `SMP_T_BIN` | `SMP_T_BOOL` | `src/sample.c:6047` |
| 137 | `mqtt_field_value` | `sample_conv_mqtt_field_value` | `ARG2(2,STR,STR)` | `SMP_T_BIN` | `SMP_T_STR` | `src/sample.c:6048` |
| 138 | `iif` | `sample_conv_iif` | `ARG2(2, STR, STR)` | `SMP_T_BOOL` | `SMP_T_STR` | `src/sample.c:6050` |
| 139 | `and` | `sample_conv_binary_and` | `ARG1(1,STR)` | `SMP_T_SINT` | `SMP_T_SINT` | `src/sample.c:6052` |
| 140 | `or` | `sample_conv_binary_or` | `ARG1(1,STR)` | `SMP_T_SINT` | `SMP_T_SINT` | `src/sample.c:6053` |
| 141 | `xor` | `sample_conv_binary_xor` | `ARG1(1,STR)` | `SMP_T_SINT` | `SMP_T_SINT` | `src/sample.c:6054` |
| 142 | `cpl` | `sample_conv_binary_cpl` | `0` | `SMP_T_SINT` | `SMP_T_SINT` | `src/sample.c:6055` |
| 143 | `bool` | `sample_conv_arith_bool` | `0` | `SMP_T_SINT` | `SMP_T_BOOL` | `src/sample.c:6056` |
| 144 | `not` | `sample_conv_arith_not` | `0` | `SMP_T_SINT` | `SMP_T_BOOL` | `src/sample.c:6057` |
| 145 | `odd` | `sample_conv_arith_odd` | `0` | `SMP_T_SINT` | `SMP_T_BOOL` | `src/sample.c:6058` |
| 146 | `even` | `sample_conv_arith_even` | `0` | `SMP_T_SINT` | `SMP_T_BOOL` | `src/sample.c:6059` |
| 147 | `add` | `sample_conv_arith_add` | `ARG1(1,STR)` | `SMP_T_SINT` | `SMP_T_SINT` | `src/sample.c:6060` |
| 148 | `sub` | `sample_conv_arith_sub` | `ARG1(1,STR)` | `SMP_T_SINT` | `SMP_T_SINT` | `src/sample.c:6061` |
| 149 | `mul` | `sample_conv_arith_mul` | `ARG1(1,STR)` | `SMP_T_SINT` | `SMP_T_SINT` | `src/sample.c:6062` |
| 150 | `div` | `sample_conv_arith_div` | `ARG1(1,STR)` | `SMP_T_SINT` | `SMP_T_SINT` | `src/sample.c:6063` |
| 151 | `mod` | `sample_conv_arith_mod` | `ARG1(1,STR)` | `SMP_T_SINT` | `SMP_T_SINT` | `src/sample.c:6064` |
| 152 | `neg` | `sample_conv_arith_neg` | `0` | `SMP_T_SINT` | `SMP_T_SINT` | `src/sample.c:6065` |
| 153 | `htonl` | `sample_conv_htonl` | `0` | `SMP_T_SINT` | `SMP_T_BIN` | `src/sample.c:6067` |
| 154 | `cut_crlf` | `sample_conv_cut_crlf` | `0` | `SMP_T_STR` | `SMP_T_STR` | `src/sample.c:6068` |
| 155 | `ltrim` | `sample_conv_ltrim` | `ARG1(1,STR)` | `SMP_T_STR` | `SMP_T_STR` | `src/sample.c:6069` |
| 156 | `rtrim` | `sample_conv_rtrim` | `ARG1(1,STR)` | `SMP_T_STR` | `SMP_T_STR` | `src/sample.c:6070` |
| 157 | `json_query` | `sample_conv_json_query` | `ARG2(1,STR,STR)` | `SMP_T_STR` | `SMP_T_ANY` | `src/sample.c:6071` |
| 158 | `jwt_header_query` | `sample_conv_jwt_header_query` | `ARG2(0,STR,STR)` | `SMP_T_BIN` | `SMP_T_ANY` | `src/sample.c:6075` |
| 159 | `jwt_payload_query` | `sample_conv_jwt_payload_query` | `ARG2(0,STR,STR)` | `SMP_T_BIN` | `SMP_T_ANY` | `src/sample.c:6076` |
| 160 | `jwt_verify` | `sample_conv_jwt_verify` | `ARG2(2,STR,STR)` | `SMP_T_BIN` | `SMP_T_SINT` | `src/sample.c:6077` |
| 161 | `jwt_verify_cert` | `sample_conv_jwt_verify_cert` | `ARG2(2,STR,STR)` | `SMP_T_BIN` | `SMP_T_SINT` | `src/sample.c:6078` |
| 162 | `when` | `sample_conv_when` | `ARG3(1,STR,STR,STR)` | `SMP_T_ANY` | `SMP_T_ANY` | `src/sample.c:6080` |
| 163 | `sha2` | `sample_conv_sha2` | `ARG1(0, SINT)` | `SMP_T_BIN` | `SMP_T_BIN` | `src/ssl_sample.c:2953` |
| 164 | `aes_gcm_enc` | `sample_conv_aes` | `ARG5(4,SINT,STR,STR,STR,STR)` | `SMP_T_BIN` | `SMP_T_BIN` | `src/ssl_sample.c:2955` |
| 165 | `aes_gcm_dec` | `sample_conv_aes` | `ARG5(4,SINT,STR,STR,STR,STR)` | `SMP_T_BIN` | `SMP_T_BIN` | `src/ssl_sample.c:2956` |
| 166 | `aes_cbc_enc` | `sample_conv_aes` | `ARG4(3,SINT,STR,STR,STR)` | `SMP_T_BIN` | `SMP_T_BIN` | `src/ssl_sample.c:2959` |
| 167 | `aes_cbc_dec` | `sample_conv_aes` | `ARG4(3,SINT,STR,STR,STR)` | `SMP_T_BIN` | `SMP_T_BIN` | `src/ssl_sample.c:2960` |
| 168 | `x509_v_err_str` | `sample_conv_x509_v_err` | `0` | `SMP_T_SINT` | `SMP_T_STR` | `src/ssl_sample.c:2962` |
| 169 | `digest` | `sample_conv_crypto_digest` | `ARG1(1,STR)` | `SMP_T_BIN` | `SMP_T_BIN` | `src/ssl_sample.c:2963` |
| 170 | `hmac` | `sample_conv_crypto_hmac` | `ARG2(2,STR,STR)` | `SMP_T_BIN` | `SMP_T_BIN` | `src/ssl_sample.c:2964` |
| 171 | `secure_memcmp` | `sample_conv_secure_memcmp` | `ARG1(1,STR)` | `SMP_T_BIN` | `SMP_T_BOOL` | `src/ssl_sample.c:2966` |
| 172 | `in_table` | `sample_conv_in_table` | `ARG1(1,TAB)` | `SMP_T_ANY` | `SMP_T_BOOL` | `src/stick_table.c:6288` |
| 173 | `table_bytes_in_rate` | `sample_conv_table_bytes_in_rate` | `ARG1(1,TAB)` | `SMP_T_ANY` | `SMP_T_SINT` | `src/stick_table.c:6289` |
| 174 | `table_bytes_out_rate` | `sample_conv_table_bytes_out_rate` | `ARG1(1,TAB)` | `SMP_T_ANY` | `SMP_T_SINT` | `src/stick_table.c:6290` |
| 175 | `table_clr_gpc` | `sample_conv_table_clr_gpc` | `ARG2(2,SINT,TAB)` | `SMP_T_ANY` | `SMP_T_SINT` | `src/stick_table.c:6291` |
| 176 | `table_clr_gpc0` | `sample_conv_table_clr_gpc0` | `ARG1(1,TAB)` | `SMP_T_ANY` | `SMP_T_SINT` | `src/stick_table.c:6292` |
| 177 | `table_clr_gpc1` | `sample_conv_table_clr_gpc1` | `ARG1(1,TAB)` | `SMP_T_ANY` | `SMP_T_SINT` | `src/stick_table.c:6293` |
| 178 | `table_conn_cnt` | `sample_conv_table_conn_cnt` | `ARG1(1,TAB)` | `SMP_T_ANY` | `SMP_T_SINT` | `src/stick_table.c:6294` |
| 179 | `table_conn_cur` | `sample_conv_table_conn_cur` | `ARG1(1,TAB)` | `SMP_T_ANY` | `SMP_T_SINT` | `src/stick_table.c:6295` |
| 180 | `table_conn_rate` | `sample_conv_table_conn_rate` | `ARG1(1,TAB)` | `SMP_T_ANY` | `SMP_T_SINT` | `src/stick_table.c:6296` |
| 181 | `table_expire` | `sample_conv_table_expire` | `ARG2(1,TAB,SINT)` | `SMP_T_ANY` | `SMP_T_SINT` | `src/stick_table.c:6297` |
| 182 | `table_gpt` | `sample_conv_table_gpt` | `ARG2(2,SINT,TAB)` | `SMP_T_ANY` | `SMP_T_SINT` | `src/stick_table.c:6298` |
| 183 | `table_gpt0` | `sample_conv_table_gpt0` | `ARG1(1,TAB)` | `SMP_T_ANY` | `SMP_T_SINT` | `src/stick_table.c:6299` |
| 184 | `table_gpc` | `sample_conv_table_gpc` | `ARG2(2,SINT,TAB)` | `SMP_T_ANY` | `SMP_T_SINT` | `src/stick_table.c:6300` |
| 185 | `table_gpc0` | `sample_conv_table_gpc0` | `ARG1(1,TAB)` | `SMP_T_ANY` | `SMP_T_SINT` | `src/stick_table.c:6301` |
| 186 | `table_gpc1` | `sample_conv_table_gpc1` | `ARG1(1,TAB)` | `SMP_T_ANY` | `SMP_T_SINT` | `src/stick_table.c:6302` |
| 187 | `table_gpc_rate` | `sample_conv_table_gpc_rate` | `ARG2(2,SINT,TAB)` | `SMP_T_ANY` | `SMP_T_SINT` | `src/stick_table.c:6303` |
| 188 | `table_gpc0_rate` | `sample_conv_table_gpc0_rate` | `ARG1(1,TAB)` | `SMP_T_ANY` | `SMP_T_SINT` | `src/stick_table.c:6304` |
| 189 | `table_gpc1_rate` | `sample_conv_table_gpc1_rate` | `ARG1(1,TAB)` | `SMP_T_ANY` | `SMP_T_SINT` | `src/stick_table.c:6305` |
| 190 | `table_glitch_cnt` | `sample_conv_table_glitch_cnt` | `ARG1(1,TAB)` | `SMP_T_ANY` | `SMP_T_SINT` | `src/stick_table.c:6306` |
| 191 | `table_glitch_rate` | `sample_conv_table_glitch_rate` | `ARG1(1,TAB)` | `SMP_T_ANY` | `SMP_T_SINT` | `src/stick_table.c:6307` |
| 192 | `table_http_err_cnt` | `sample_conv_table_http_err_cnt` | `ARG1(1,TAB)` | `SMP_T_ANY` | `SMP_T_SINT` | `src/stick_table.c:6308` |
| 193 | `table_http_err_rate` | `sample_conv_table_http_err_rate` | `ARG1(1,TAB)` | `SMP_T_ANY` | `SMP_T_SINT` | `src/stick_table.c:6309` |
| 194 | `table_http_fail_cnt` | `sample_conv_table_http_fail_cnt` | `ARG1(1,TAB)` | `SMP_T_ANY` | `SMP_T_SINT` | `src/stick_table.c:6310` |
| 195 | `table_http_fail_rate` | `sample_conv_table_http_fail_rate` | `ARG1(1,TAB)` | `SMP_T_ANY` | `SMP_T_SINT` | `src/stick_table.c:6311` |
| 196 | `table_http_req_cnt` | `sample_conv_table_http_req_cnt` | `ARG1(1,TAB)` | `SMP_T_ANY` | `SMP_T_SINT` | `src/stick_table.c:6312` |
| 197 | `table_http_req_rate` | `sample_conv_table_http_req_rate` | `ARG1(1,TAB)` | `SMP_T_ANY` | `SMP_T_SINT` | `src/stick_table.c:6313` |
| 198 | `table_idle` | `sample_conv_table_idle` | `ARG2(1,TAB,SINT)` | `SMP_T_ANY` | `SMP_T_SINT` | `src/stick_table.c:6314` |
| 199 | `table_inc_gpc` | `sample_conv_table_inc_gpc` | `ARG2(2,SINT,TAB)` | `SMP_T_ANY` | `SMP_T_SINT` | `src/stick_table.c:6315` |
| 200 | `table_inc_gpc0` | `sample_conv_table_inc_gpc0` | `ARG1(1,TAB)` | `SMP_T_ANY` | `SMP_T_SINT` | `src/stick_table.c:6316` |
| 201 | `table_inc_gpc1` | `sample_conv_table_inc_gpc1` | `ARG1(1,TAB)` | `SMP_T_ANY` | `SMP_T_SINT` | `src/stick_table.c:6317` |
| 202 | `table_kbytes_in` | `sample_conv_table_kbytes_in` | `ARG1(1,TAB)` | `SMP_T_ANY` | `SMP_T_SINT` | `src/stick_table.c:6318` |
| 203 | `table_kbytes_out` | `sample_conv_table_kbytes_out` | `ARG1(1,TAB)` | `SMP_T_ANY` | `SMP_T_SINT` | `src/stick_table.c:6319` |
| 204 | `table_server_id` | `sample_conv_table_server_id` | `ARG1(1,TAB)` | `SMP_T_ANY` | `SMP_T_SINT` | `src/stick_table.c:6320` |
| 205 | `table_sess_cnt` | `sample_conv_table_sess_cnt` | `ARG1(1,TAB)` | `SMP_T_ANY` | `SMP_T_SINT` | `src/stick_table.c:6321` |
| 206 | `table_sess_rate` | `sample_conv_table_sess_rate` | `ARG1(1,TAB)` | `SMP_T_ANY` | `SMP_T_SINT` | `src/stick_table.c:6322` |
| 207 | `table_trackers` | `sample_conv_table_trackers` | `ARG1(1,TAB)` | `SMP_T_ANY` | `SMP_T_SINT` | `src/stick_table.c:6323` |
| 208 | `set-var` | `smp_conv_store` | `ARG5(1,STR,STR,STR,STR,STR)` | `SMP_T_ANY` | `SMP_T_ANY` | `src/vars.c:1671` |
| 209 | `unset-var` | `smp_conv_clear` | `ARG1(1,STR)` | `SMP_T_ANY` | `SMP_T_ANY` | `src/vars.c:1672` |
| 210 | `51d.single` | `_51d_conv` | `ARG5(1,STR,STR,STR,STR,STR)` | `SMP_T_STR` | `SMP_T_STR` | `addons/51degrees/51d.c:1180` |
| 211 | `da-csv-conv` | `da_haproxy_conv` | `ARG12(1,STR,STR,STR,STR,STR,STR,STR,STR,STR,STR,STR,STR)` | `SMP_T_STR` | `SMP_T_STR` | `addons/deviceatlas/da.c:567` |

## 2. Type Conversion Matrix (Explicit Converters)

This matrix lists all explicit sample converters registered in HAProxy, mapping each input sample type (`in_type`, rows) to output sample type (`out_type`, columns).

| Input Type \ Output Type | `SMP_T_ANY` | `SMP_T_SAME` | `SMP_T_BOOL` | `SMP_T_SINT` | `SMP_T_ADDR` | `SMP_T_IPV4` | `SMP_T_IPV6` | `SMP_T_STR` | `SMP_T_BIN` | `SMP_T_METH` |
|---|---|---|---|---|---|---|---|---|---|---|
| `SMP_T_ANY` | `when`<br>`set-var`<br>`unset-var` | `debug` | `in_table` | `table_bytes_in_rate`<br>`table_bytes_out_rate`<br>`table_clr_gpc`<br>`table_clr_gpc0`<br>`table_clr_gpc1`<br>`table_conn_cnt`<br>`table_conn_cur`<br>`table_conn_rate`<br>`table_expire`<br>`table_gpt`<br>`table_gpt0`<br>`table_gpc`<br>`table_gpc0`<br>`table_gpc1`<br>`table_gpc_rate`<br>`table_gpc0_rate`<br>`table_gpc1_rate`<br>`table_glitch_cnt`<br>`table_glitch_rate`<br>`table_http_err_cnt`<br>`table_http_err_rate`<br>`table_http_fail_cnt`<br>`table_http_fail_rate`<br>`table_http_req_cnt`<br>`table_http_req_rate`<br>`table_idle`<br>`table_inc_gpc`<br>`table_inc_gpc0`<br>`table_inc_gpc1`<br>`table_kbytes_in`<br>`table_kbytes_out`<br>`table_server_id`<br>`table_sess_cnt`<br>`table_sess_rate`<br>`table_trackers` | - | - | - | `rfc7239_nn`<br>`rfc7239_np` | - | - |
| `SMP_T_SAME` | - | - | - | - | - | - | - | - | - | - |
| `SMP_T_BOOL` | - | - | - | - | - | - | - | `iif` | - | - |
| `SMP_T_SINT` | - | - | `bool`<br>`not`<br>`odd`<br>`even` | `map_int_int`<br>`and`<br>`or`<br>`xor`<br>`cpl`<br>`add`<br>`sub`<br>`mul`<br>`div`<br>`mod`<br>`neg` | `map_int_ip` | - | - | `http_date`<br>`map_int`<br>`map_int_key`<br>`ltime`<br>`ms_ltime`<br>`us_ltime`<br>`utime`<br>`ms_utime`<br>`us_utime`<br>`x509_v_err_str` | `htonl` | - |
| `SMP_T_ADDR` | - | - | - | `map_ip_int` | `map_ip_ip`<br>`ipmask` | - | - | `map_ip`<br>`map_ip_key` | - | - |
| `SMP_T_IPV4` | - | - | - | - | - | - | - | - | - | - |
| `SMP_T_IPV6` | - | - | - | - | - | - | - | - | - | - |
| `SMP_T_STR` | `rfc7239_n2nn`<br>`rfc7239_n2np`<br>`json_query` | - | `srv_is_up`<br>`fe_exists`<br>`rfc7239_is_valid` | `nbsrv`<br>`srv_queue`<br>`date`<br>`map_str_int`<br>`map_beg_int`<br>`map_sub_int`<br>`map_dir_int`<br>`map_dom_int`<br>`map_end_int`<br>`map_reg_int`<br>`length`<br>`hex2i`<br>`strcmp`<br>`port_only` | `map_str_ip`<br>`map_beg_ip`<br>`map_sub_ip`<br>`map_dir_ip`<br>`map_dom_ip`<br>`map_end_ip`<br>`map_reg_ip` | - | - | `language`<br>`capture-req`<br>`capture-res`<br>`url_dec`<br>`url_enc`<br>`rfc7239_field`<br>`map`<br>`map_str`<br>`map_beg`<br>`map_sub`<br>`map_dir`<br>`map_dom`<br>`map_end`<br>`map_reg`<br>`map_regm`<br>`map_str_key`<br>`map_beg_key`<br>`map_sub_key`<br>`map_dir_key`<br>`map_dom_key`<br>`map_end_key`<br>`map_reg_key`<br>`add_item`<br>`concat`<br>`upper`<br>`lower`<br>`json`<br>`field`<br>`word`<br>`param`<br>`regsub`<br>`host_only`<br>`reverse`<br>`reverse_dom`<br>`cut_crlf`<br>`ltrim`<br>`rtrim`<br>`51d.single`<br>`da-csv-conv` | `b64dec`<br>`ub64dec` | - |
| `SMP_T_BIN` | `jwt_header_query`<br>`jwt_payload_query` | - | `has_ctl`<br>`fix_is_valid`<br>`mqtt_is_valid`<br>`secure_memcmp` | `eth.proto`<br>`eth.vlan`<br>`ip.df`<br>`ip.proto`<br>`ip.tos`<br>`ip.ttl`<br>`ip.ver`<br>`tcp.dst`<br>`tcp.flags`<br>`tcp.options.mss`<br>`tcp.options.sack`<br>`tcp.options.tsopt`<br>`tcp.options.tsval`<br>`tcp.options.wscale`<br>`tcp.options.wsopt`<br>`tcp.seq`<br>`tcp.src`<br>`tcp.win`<br>`crc32`<br>`crc32c`<br>`djb2`<br>`sdbm`<br>`wt6`<br>`xxh3`<br>`xxh32`<br>`xxh64`<br>`jwt_verify`<br>`jwt_verify_cert` | `ip.dst`<br>`ip.src` | - | - | `base64`<br>`ub64enc`<br>`base2`<br>`be2dec`<br>`le2dec`<br>`be2hex`<br>`hex`<br>`mqtt_field_value` | `jwt_decrypt_secret`<br>`jwt_decrypt_cert`<br>`jwt_decrypt_jwk`<br>`eth.data`<br>`eth.dst`<br>`eth.hdr`<br>`eth.src`<br>`ip.data`<br>`ip.fp`<br>`ip.hdr`<br>`tcp.options_list`<br>`be_sort`<br>`bytes`<br>`sha1`<br>`ungrpc`<br>`protobuf`<br>`fix_tag_value`<br>`sha2`<br>`aes_gcm_enc`<br>`aes_gcm_dec`<br>`aes_cbc_enc`<br>`aes_cbc_dec`<br>`digest`<br>`hmac` | - |
| `SMP_T_METH` | - | - | - | - | - | - | - | - | - | - |

## 3. Analysis & Answers

### Question 1: Which type pairs have NO explicit converter between them?

Out of 100 possible ordered type pairs (`10 × 10`), **74 pairs** have no direct explicit converter registered:

| Input Type (`in_type`) | Output Type (`out_type`) | Reason / Notes |
|---|---|---|
| `SMP_T_ANY` | `SMP_T_ADDR` | No registered converter |
| `SMP_T_ANY` | `SMP_T_IPV4` | Converters emit `SMP_T_ADDR` instead of concrete IPv4/IPv6 |
| `SMP_T_ANY` | `SMP_T_IPV6` | Converters emit `SMP_T_ADDR` instead of concrete IPv4/IPv6 |
| `SMP_T_ANY` | `SMP_T_BIN` | No registered converter |
| `SMP_T_ANY` | `SMP_T_METH` | `SMP_T_METH` is only produced by fetch functions or `c_str2meth` implicit cast |
| `SMP_T_SAME` | `SMP_T_ANY` | `SMP_T_SAME` is a pseudo output type hint, never a valid runtime input type |
| `SMP_T_SAME` | `SMP_T_SAME` | `SMP_T_SAME` is a pseudo output type hint, never a valid runtime input type |
| `SMP_T_SAME` | `SMP_T_BOOL` | `SMP_T_SAME` is a pseudo output type hint, never a valid runtime input type |
| `SMP_T_SAME` | `SMP_T_SINT` | `SMP_T_SAME` is a pseudo output type hint, never a valid runtime input type |
| `SMP_T_SAME` | `SMP_T_ADDR` | `SMP_T_SAME` is a pseudo output type hint, never a valid runtime input type |
| `SMP_T_SAME` | `SMP_T_IPV4` | `SMP_T_SAME` is a pseudo output type hint, never a valid runtime input type |
| `SMP_T_SAME` | `SMP_T_IPV6` | `SMP_T_SAME` is a pseudo output type hint, never a valid runtime input type |
| `SMP_T_SAME` | `SMP_T_STR` | `SMP_T_SAME` is a pseudo output type hint, never a valid runtime input type |
| `SMP_T_SAME` | `SMP_T_BIN` | `SMP_T_SAME` is a pseudo output type hint, never a valid runtime input type |
| `SMP_T_SAME` | `SMP_T_METH` | `SMP_T_SAME` is a pseudo output type hint, never a valid runtime input type |
| `SMP_T_BOOL` | `SMP_T_ANY` | No registered converter |
| `SMP_T_BOOL` | `SMP_T_SAME` | `SMP_T_SAME` is only used by `debug` converter (`SMP_T_ANY -> SMP_T_SAME`) |
| `SMP_T_BOOL` | `SMP_T_BOOL` | No registered converter |
| `SMP_T_BOOL` | `SMP_T_SINT` | No registered converter |
| `SMP_T_BOOL` | `SMP_T_ADDR` | No registered converter |
| `SMP_T_BOOL` | `SMP_T_IPV4` | Converters emit `SMP_T_ADDR` instead of concrete IPv4/IPv6 |
| `SMP_T_BOOL` | `SMP_T_IPV6` | Converters emit `SMP_T_ADDR` instead of concrete IPv4/IPv6 |
| `SMP_T_BOOL` | `SMP_T_BIN` | No registered converter |
| `SMP_T_BOOL` | `SMP_T_METH` | `SMP_T_METH` is only produced by fetch functions or `c_str2meth` implicit cast |
| `SMP_T_SINT` | `SMP_T_ANY` | No registered converter |
| `SMP_T_SINT` | `SMP_T_SAME` | `SMP_T_SAME` is only used by `debug` converter (`SMP_T_ANY -> SMP_T_SAME`) |
| `SMP_T_SINT` | `SMP_T_IPV4` | Converters emit `SMP_T_ADDR` instead of concrete IPv4/IPv6 |
| `SMP_T_SINT` | `SMP_T_IPV6` | Converters emit `SMP_T_ADDR` instead of concrete IPv4/IPv6 |
| `SMP_T_SINT` | `SMP_T_METH` | `SMP_T_METH` is only produced by fetch functions or `c_str2meth` implicit cast |
| `SMP_T_ADDR` | `SMP_T_ANY` | No registered converter |
| `SMP_T_ADDR` | `SMP_T_SAME` | `SMP_T_SAME` is only used by `debug` converter (`SMP_T_ANY -> SMP_T_SAME`) |
| `SMP_T_ADDR` | `SMP_T_BOOL` | No registered converter |
| `SMP_T_ADDR` | `SMP_T_IPV4` | Converters emit `SMP_T_ADDR` instead of concrete IPv4/IPv6 |
| `SMP_T_ADDR` | `SMP_T_IPV6` | Converters emit `SMP_T_ADDR` instead of concrete IPv4/IPv6 |
| `SMP_T_ADDR` | `SMP_T_BIN` | No registered converter |
| `SMP_T_ADDR` | `SMP_T_METH` | `SMP_T_METH` is only produced by fetch functions or `c_str2meth` implicit cast |
| `SMP_T_IPV4` | `SMP_T_ANY` | Concrete IP types use `SMP_T_ADDR` or implicit casts (`src/sample.c:1080-1081`) |
| `SMP_T_IPV4` | `SMP_T_SAME` | Concrete IP types use `SMP_T_ADDR` or implicit casts (`src/sample.c:1080-1081`) |
| `SMP_T_IPV4` | `SMP_T_BOOL` | Concrete IP types use `SMP_T_ADDR` or implicit casts (`src/sample.c:1080-1081`) |
| `SMP_T_IPV4` | `SMP_T_SINT` | Concrete IP types use `SMP_T_ADDR` or implicit casts (`src/sample.c:1080-1081`) |
| `SMP_T_IPV4` | `SMP_T_ADDR` | Concrete IP types use `SMP_T_ADDR` or implicit casts (`src/sample.c:1080-1081`) |
| `SMP_T_IPV4` | `SMP_T_IPV4` | Concrete IP types use `SMP_T_ADDR` or implicit casts (`src/sample.c:1080-1081`) |
| `SMP_T_IPV4` | `SMP_T_IPV6` | Concrete IP types use `SMP_T_ADDR` or implicit casts (`src/sample.c:1080-1081`) |
| `SMP_T_IPV4` | `SMP_T_STR` | Concrete IP types use `SMP_T_ADDR` or implicit casts (`src/sample.c:1080-1081`) |
| `SMP_T_IPV4` | `SMP_T_BIN` | Concrete IP types use `SMP_T_ADDR` or implicit casts (`src/sample.c:1080-1081`) |
| `SMP_T_IPV4` | `SMP_T_METH` | Concrete IP types use `SMP_T_ADDR` or implicit casts (`src/sample.c:1080-1081`) |
| `SMP_T_IPV6` | `SMP_T_ANY` | Concrete IP types use `SMP_T_ADDR` or implicit casts (`src/sample.c:1080-1081`) |
| `SMP_T_IPV6` | `SMP_T_SAME` | Concrete IP types use `SMP_T_ADDR` or implicit casts (`src/sample.c:1080-1081`) |
| `SMP_T_IPV6` | `SMP_T_BOOL` | Concrete IP types use `SMP_T_ADDR` or implicit casts (`src/sample.c:1080-1081`) |
| `SMP_T_IPV6` | `SMP_T_SINT` | Concrete IP types use `SMP_T_ADDR` or implicit casts (`src/sample.c:1080-1081`) |
| `SMP_T_IPV6` | `SMP_T_ADDR` | Concrete IP types use `SMP_T_ADDR` or implicit casts (`src/sample.c:1080-1081`) |
| `SMP_T_IPV6` | `SMP_T_IPV4` | Concrete IP types use `SMP_T_ADDR` or implicit casts (`src/sample.c:1080-1081`) |
| `SMP_T_IPV6` | `SMP_T_IPV6` | Concrete IP types use `SMP_T_ADDR` or implicit casts (`src/sample.c:1080-1081`) |
| `SMP_T_IPV6` | `SMP_T_STR` | Concrete IP types use `SMP_T_ADDR` or implicit casts (`src/sample.c:1080-1081`) |
| `SMP_T_IPV6` | `SMP_T_BIN` | Concrete IP types use `SMP_T_ADDR` or implicit casts (`src/sample.c:1080-1081`) |
| `SMP_T_IPV6` | `SMP_T_METH` | Concrete IP types use `SMP_T_ADDR` or implicit casts (`src/sample.c:1080-1081`) |
| `SMP_T_STR` | `SMP_T_SAME` | `SMP_T_SAME` is only used by `debug` converter (`SMP_T_ANY -> SMP_T_SAME`) |
| `SMP_T_STR` | `SMP_T_IPV4` | Converters emit `SMP_T_ADDR` instead of concrete IPv4/IPv6 |
| `SMP_T_STR` | `SMP_T_IPV6` | Converters emit `SMP_T_ADDR` instead of concrete IPv4/IPv6 |
| `SMP_T_STR` | `SMP_T_METH` | `SMP_T_METH` is only produced by fetch functions or `c_str2meth` implicit cast |
| `SMP_T_BIN` | `SMP_T_SAME` | `SMP_T_SAME` is only used by `debug` converter (`SMP_T_ANY -> SMP_T_SAME`) |
| `SMP_T_BIN` | `SMP_T_IPV4` | Converters emit `SMP_T_ADDR` instead of concrete IPv4/IPv6 |
| `SMP_T_BIN` | `SMP_T_IPV6` | Converters emit `SMP_T_ADDR` instead of concrete IPv4/IPv6 |
| `SMP_T_BIN` | `SMP_T_METH` | `SMP_T_METH` is only produced by fetch functions or `c_str2meth` implicit cast |
| `SMP_T_METH` | `SMP_T_ANY` | `SMP_T_METH` has no dedicated converters; converted via implicit cast to `SMP_T_STR` (`src/sample.c:1084`) |
| `SMP_T_METH` | `SMP_T_SAME` | `SMP_T_METH` has no dedicated converters; converted via implicit cast to `SMP_T_STR` (`src/sample.c:1084`) |
| `SMP_T_METH` | `SMP_T_BOOL` | `SMP_T_METH` has no dedicated converters; converted via implicit cast to `SMP_T_STR` (`src/sample.c:1084`) |
| `SMP_T_METH` | `SMP_T_SINT` | `SMP_T_METH` has no dedicated converters; converted via implicit cast to `SMP_T_STR` (`src/sample.c:1084`) |
| `SMP_T_METH` | `SMP_T_ADDR` | `SMP_T_METH` has no dedicated converters; converted via implicit cast to `SMP_T_STR` (`src/sample.c:1084`) |
| `SMP_T_METH` | `SMP_T_IPV4` | `SMP_T_METH` has no dedicated converters; converted via implicit cast to `SMP_T_STR` (`src/sample.c:1084`) |
| `SMP_T_METH` | `SMP_T_IPV6` | `SMP_T_METH` has no dedicated converters; converted via implicit cast to `SMP_T_STR` (`src/sample.c:1084`) |
| `SMP_T_METH` | `SMP_T_STR` | `SMP_T_METH` has no dedicated converters; converted via implicit cast to `SMP_T_STR` (`src/sample.c:1084`) |
| `SMP_T_METH` | `SMP_T_BIN` | `SMP_T_METH` has no dedicated converters; converted via implicit cast to `SMP_T_STR` (`src/sample.c:1084`) |
| `SMP_T_METH` | `SMP_T_METH` | `SMP_T_METH` has no dedicated converters; converted via implicit cast to `SMP_T_STR` (`src/sample.c:1084`) |

### Question 2: Does HAProxy perform implicit casts between sample types?

**Yes.** HAProxy defines a static global matrix `sample_casts[SMP_TYPES][SMP_TYPES]` in [`src/sample.c:1073-1085`](file:///home/bhenc/reference/haproxy/src/sample.c#L1073-L1085), declared in [`include/haproxy/sample.h:31`](file:///home/bhenc/reference/haproxy/include/haproxy/sample.h#L31).

#### Role and Usage of Implicit Casts
1. **Configuration parsing / validation time:**
   - When chaining sample fetches and converters in expressions (e.g. `smp_parse_expr` in [`src/sample.c:1180`](file:///home/bhenc/reference/haproxy/src/sample.c#L1180) and [`src/sample.c:1191`](file:///home/bhenc/reference/haproxy/src/sample.c#L1191)), HAProxy verifies if `sample_casts[prev_type][conv->in_type]` is non-NULL.
   - When resolving return types for converter chains ([`src/sample.c:384,395`](file:///home/bhenc/reference/haproxy/src/sample.c#L384)), HAProxy checks for cast compatibility.
   - When checking ACL pattern match compatibility ([`src/acl.c:378`](file:///home/bhenc/reference/haproxy/src/acl.c#L378)).
   - When checking stick-table data types ([`src/stick_table.c:1854`](file:///home/bhenc/reference/haproxy/src/stick_table.c#L1854)).

2. **Runtime execution:**
   - In [`src/sample.c:1355-1360`](file:///home/bhenc/reference/haproxy/src/sample.c#L1355-L1360) (`sample_process_conv`): if `sample_casts[smp->data.type][conv->in_type]` is non-NULL and not `c_none`, the cast function is executed in-place on the sample prior to invoking the converter.
   - In [`src/sample.c:1752-1757`](file:///home/bhenc/reference/haproxy/src/sample.c#L1752-L1757) (`sample_convert`): converts a sample to a requested type `smp_type` using `sample_casts[smp->data.type][smp_type]`.
   - In [`include/haproxy/sample.h:74-81`](file:///home/bhenc/reference/haproxy/include/haproxy/sample.h#L74-L81) (`sample_cast`): inline helper executing the cast table entry.

#### The Implicit Cast Matrix (`sample_casts`)

Verbatim extraction from [`src/sample.c:1073-1085`](file:///home/bhenc/reference/haproxy/src/sample.c#L1073-L1085):

| From Type (`from`) \ To Type (`to`) | `SMP_T_ANY` | `SMP_T_SAME` | `SMP_T_BOOL` | `SMP_T_SINT` | `SMP_T_ADDR` | `SMP_T_IPV4` | `SMP_T_IPV6` | `SMP_T_STR` | `SMP_T_BIN` | `SMP_T_METH` |
|---|---|---|---|---|---|---|---|---|---|---|
| `SMP_T_ANY` | `c_none` | `NULL` | `c_pseudo` | `c_pseudo` | `c_pseudo` | `c_pseudo` | `c_pseudo` | `c_pseudo` | `c_pseudo` | `c_pseudo` |
| `SMP_T_SAME` | `NULL` | `NULL` | `NULL` | `NULL` | `NULL` | `NULL` | `NULL` | `NULL` | `NULL` | `NULL` |
| `SMP_T_BOOL` | `c_none` | `NULL` | `c_none` | `c_none` | `NULL` | `NULL` | `NULL` | `c_int2str` | `c_bool2bin` | `NULL` |
| `SMP_T_SINT` | `c_none` | `NULL` | `c_none` | `c_none` | `c_int2ip` | `c_int2ip` | `c_int2ipv6` | `c_int2str` | `c_int2bin` | `NULL` |
| `SMP_T_ADDR` | `c_none` | `NULL` | `NULL` | `NULL` | `c_pseudo` | `c_pseudo` | `c_pseudo` | `c_pseudo` | `c_pseudo` | `NULL` |
| `SMP_T_IPV4` | `c_none` | `NULL` | `NULL` | `c_ip2int` | `c_none` | `c_none` | `c_ip2ipv6` | `c_ip2str` | `c_addr2bin` | `NULL` |
| `SMP_T_IPV6` | `c_none` | `NULL` | `NULL` | `NULL` | `c_none` | `c_ipv62ip` | `c_none` | `c_ipv62str` | `c_addr2bin` | `NULL` |
| `SMP_T_STR` | `c_none` | `NULL` | `c_str2int` | `c_str2int` | `c_str2addr` | `c_str2ip` | `c_str2ipv6` | `c_none` | `c_none` | `c_str2meth` |
| `SMP_T_BIN` | `c_none` | `NULL` | `NULL` | `NULL` | `NULL` | `NULL` | `NULL` | `c_bin2str` | `c_none` | `c_str2meth` |
| `SMP_T_METH` | `c_none` | `NULL` | `NULL` | `NULL` | `NULL` | `NULL` | `NULL` | `c_meth2str` | `c_meth2str` | `c_none` |

#### Cast Functions Inventory

| Function | Source Citation | Behavior |
|---|---|---|
| `c_none` | [`src/sample.c:940-943`](file:///home/bhenc/reference/haproxy/src/sample.c#L940-L943) | No-op / identity cast (returns 1). Indicates types are directly compatible without alteration. |
| `c_pseudo` | [`src/sample.c:954-959`](file:///home/bhenc/reference/haproxy/src/sample.c#L954-L959) | Compatibility marker for pseudo-types at parse time. Calls `ABORT_NOW()` if executed at runtime. |
| `c_int2str` | [`src/sample.c:862-878`](file:///home/bhenc/reference/haproxy/src/sample.c#L862-L878) | Formats 64-bit signed integer `sint` into a base-10 string buffer via `lltoa_r`. |
| `c_bool2bin` | [`src/sample.c:1055-1064`](file:///home/bhenc/reference/haproxy/src/sample.c#L1055-L1064) | Converts boolean (0/1) to 8-byte network order binary integer buffer (`my_htonll`). |
| `c_int2bin` | [`src/sample.c:1043-1053`](file:///home/bhenc/reference/haproxy/src/sample.c#L1043-L1053) | Converts 64-bit integer `sint` to 8-byte network order binary buffer (`my_htonll`). |
| `c_int2ip` | [`src/sample.c:797-802`](file:///home/bhenc/reference/haproxy/src/sample.c#L797-L802) | Converts 32-bit integer to IPv4 address (`htonl`). |
| `c_int2ipv6` | [`src/sample.c:804-810`](file:///home/bhenc/reference/haproxy/src/sample.c#L804-L810) | Converts integer to IPv4 then maps to IPv6 (`v4tov6`). |
| `c_ip2int` | [`src/sample.c:739-744`](file:///home/bhenc/reference/haproxy/src/sample.c#L739-L744) | Converts IPv4 address to host-endian integer (`ntohl`). |
| `c_ip2str` | [`src/sample.c:746-759`](file:///home/bhenc/reference/haproxy/src/sample.c#L746-L759) | Formats IPv4 address to dotted-quad ASCII string (`inet_ntop(AF_INET)`). |
| `c_ip2ipv6` | [`src/sample.c:761-766`](file:///home/bhenc/reference/haproxy/src/sample.c#L761-L766) | Converts IPv4 to IPv4-mapped IPv6 address (`v4tov6`). |
| `c_ipv62ip` | [`src/sample.c:768-774`](file:///home/bhenc/reference/haproxy/src/sample.c#L768-L774) | Converts IPv4-mapped IPv6 address to IPv4 (`v6tov4`). Returns 0 if not mapped. |
| `c_ipv62str` | [`src/sample.c:776-788`](file:///home/bhenc/reference/haproxy/src/sample.c#L776-L788) | Formats IPv6 address to presentation ASCII string (`inet_ntop(AF_INET6)`). |
| `c_addr2bin` | [`src/sample.c:1023-1041`](file:///home/bhenc/reference/haproxy/src/sample.c#L1023-L1041) | Serializes IPv4 (4 bytes) or IPv6 (16 bytes) into binary chunk buffer. |
| `c_str2int` | [`src/sample.c:961-976`](file:///home/bhenc/reference/haproxy/src/sample.c#L961-L976) | Parses integer from ASCII string buffer (`read_int64`). |
| `c_str2addr` | [`src/sample.c:812-824`](file:///home/bhenc/reference/haproxy/src/sample.c#L812-L824) | Parses IP address from string (tries IPv4 `buf2ip`, then IPv6 `buf2ip6`). |
| `c_str2ip` | [`src/sample.c:826-833`](file:///home/bhenc/reference/haproxy/src/sample.c#L826-L833) | Parses IPv4 address from string buffer (`buf2ip`). |
| `c_str2ipv6` | [`src/sample.c:835-842`](file:///home/bhenc/reference/haproxy/src/sample.c#L835-L842) | Parses IPv6 address from string buffer (`buf2ip6`). |
| `c_str2meth` | [`src/sample.c:978-994`](file:///home/bhenc/reference/haproxy/src/sample.c#L978-L994) | Converts HTTP method string to `SMP_T_METH` structure (`find_http_meth`). |
| `c_bin2str` | [`src/sample.c:848-860`](file:///home/bhenc/reference/haproxy/src/sample.c#L848-L860) | Converts binary buffer to string, truncating at first NUL byte if present. |
| `c_meth2str` | [`src/sample.c:996-1021`](file:///home/bhenc/reference/haproxy/src/sample.c#L996-L1021) | Converts `SMP_T_METH` structure to string name via `http_known_methods`. |
