#!/usr/bin/env python3
"""Nap cau hinh tu bien moi truong."""

import os


def _require(name):
    value = os.environ.get(name)
    if not value:
        raise RuntimeError(f"[config] Biến môi trường bắt buộc chưa được set: {name}")
    return value


VT_API_KEY    = _require('VT_API_KEY')
ABUSE_API_KEY = _require('ABUSE_API_KEY')
OTX_API_KEY   = _require('OTX_API_KEY')

TELEGRAM_BOT_TOKEN = _require('TELEGRAM_BOT_TOKEN')
TELEGRAM_CHAT_ID   = _require('TELEGRAM_CHAT_ID')

FLASK_HOST = os.getenv('FLASK_HOST', '127.0.0.1')
FLASK_PORT = int(os.getenv('FLASK_PORT', '8080'))
WEBHOOK_TOKEN = os.getenv('WEBHOOK_TOKEN', '')
MAX_ALERT_BYTES = int(os.getenv('MAX_ALERT_BYTES', str(256 * 1024)))

VT_WEIGHT    = 0.40
ABUSE_WEIGHT = 0.40
OTX_WEIGHT   = 0.20

CRITICAL_THRESHOLD = 80
HIGH_THRESHOLD     = 50
MEDIUM_THRESHOLD   = 20

DEDUP_WINDOW = 300

CACHE_TTL     = 3600
CACHE_MAXSIZE = 500

API_TIMEOUT = 8

LOG_FILE  = os.getenv('LOG_FILE', '/var/ossec/logs/ti_enrichment.log')
LOG_LEVEL = os.getenv('LOG_LEVEL', 'INFO')
