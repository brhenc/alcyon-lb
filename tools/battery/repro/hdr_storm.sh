#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
# T247 reproducer: Alcyon 362% CPU vs HAProxy 29%; fds 55 after 45s vs 28
# Needs the battery config (battery.py CFG) running on 127.0.0.1 (h2c bind 10081, h1 bind 10080)
# with a haterm on 8888. Watch the proxy with: ls /proc/PID/fd | wc -l ; ps -o rss,pcpu -p PID
exec python3 "$(dirname "$0")/../clients.py" attack hdr_storm 127.0.0.1 10080 60
