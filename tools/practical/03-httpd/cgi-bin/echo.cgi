#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
# GET: query string and REMOTE_PORT; POST: echoes the body back.
import os, sys
if os.environ.get('REQUEST_METHOD') == 'POST':
    n = int(os.environ.get('CONTENT_LENGTH') or 0)
    body = sys.stdin.buffer.read(n)
    sys.stdout.buffer.write(b'Content-Type: application/octet-stream\r\n\r\n' + body)
else:
    sys.stdout.write('Content-Type: text/plain\r\n\r\nq=%s port=%s\n' % (
        os.environ.get('QUERY_STRING', ''), os.environ.get('REMOTE_PORT', '')))
