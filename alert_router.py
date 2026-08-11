#!/usr/bin/env python3
"""Phan loai, khu trung lap va gui Telegram."""

import logging
import threading
import time

import requests

from config import (
    TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID,
    DEDUP_WINDOW,
    CRITICAL_THRESHOLD,
    HIGH_THRESHOLD,
    MEDIUM_THRESHOLD,
)

logger = logging.getLogger(__name__)

ICON_CRITICAL = "\U0001F534"
ICON_HIGH     = "\U0001F7E0"
ICON_MEDIUM   = "\U0001F7E1"
ICON_BLOCKED  = "\U0001F512"
ICON_REPEAT   = "\U0001F501"
TELEGRAM_MAX_LENGTH = 4096
WAZUH_AR_TIMEOUT = 30

WAZUH_AR_BLOCK_RULES = {
    '100001',
    '100007',
}

_alert_groups: dict = {}
_alert_groups_lock = threading.Lock()
_DEDUP_STALE_AFTER = max(DEDUP_WINDOW * 2, 600)


def classify_severity(enriched_alert: dict) -> str:
    """Ket hop muc Wazuh va diem TI."""
    risk_score = enriched_alert.get('risk_score', 0)
    rule_level = enriched_alert.get('rule_level', 0)

    if risk_score > CRITICAL_THRESHOLD or rule_level >= 12:
        return 'CRITICAL'
    if rule_level >= 10 or risk_score > HIGH_THRESHOLD:
        return 'HIGH'
    if rule_level >= 6 or risk_score > MEDIUM_THRESHOLD:
        return 'MEDIUM'
    return 'LOW'


def _alert_key(enriched_alert: dict) -> tuple[str, str, str, str, str]:
    return (
        str(enriched_alert.get('rule_id', '')),
        str(enriched_alert.get('src_ip', '')),
        str(enriched_alert.get('dst_ip', '')),
        str(enriched_alert.get('risk_level', '')),
        str(enriched_alert.get('ioc_value', ''))[:64],
    )


def _cleanup_alert_groups(now: float):
    stale_keys = [
        key for key, group in _alert_groups.items()
        if group['last_seen'] and (now - group['last_seen']) > _DEDUP_STALE_AFTER
    ]
    for key in stale_keys:
        _alert_groups.pop(key, None)


def should_send(enriched_alert: dict) -> bool:
    """Bo qua ban lap, tru CRITICAL va dot bien lon."""
    severity = enriched_alert.get('risk_level', 'LOW')

    if severity == 'CRITICAL':
        return True

    key = _alert_key(enriched_alert)
    now = time.time()
    with _alert_groups_lock:
        _cleanup_alert_groups(now)
        grp = _alert_groups.get(key)

        if not grp or (now - grp['first_seen']) > DEDUP_WINDOW:
            _alert_groups[key] = {
                'count': 1,
                'first_seen': now,
                'last_seen': now,
            }
            return True

        grp['count'] += 1
        grp['last_seen'] = now

        if grp['count'] > 50 and (now - grp['first_seen']) < 60:
            grp['count'] = 1
            grp['first_seen'] = now
            return True

        return False


def get_alert_count(enriched_alert: dict) -> int:
    key = _alert_key(enriched_alert)
    with _alert_groups_lock:
        grp = _alert_groups.get(key)
        if not grp:
            return 1
        return grp.get('count', 1)


def _action_for_alert(rule_desc: str, rule_id) -> str:
    """Tao khuyen nghi xu ly ngan."""
    desc = rule_desc.lower()
    rid  = str(rule_id)

    if rid == '100002' or ('success' in desc and 'brute' in desc):
        return "Possible compromise | terminate session | reset credentials"
    if any(k in desc for k in ('brute', 'password', 'authentication')) or rid in ('100001', '2502'):
        return "Auth brute force | verify source | rotate creds"
    if any(k in desc for k in ('file', 'fim', 'eicar', 'syscheck')):
        return "FIM/file event | isolate host | scan system"
    if any(k in desc for k in ('outbound', 'connection')):
        return "Outbound conn | trace process | contain host"
    if any(k in desc for k in ('scan', 'port')):
        return "Recon/scan | review source | increase monitoring"
    return "Investigate in Wazuh | contain if confirmed"


def _ctx_line(src: str, dst: str, detail: str) -> str:
    if src != 'N/A' and dst != 'N/A':
        line = f"{src} -> {dst}"
    elif src != 'N/A':
        line = src
    elif dst != 'N/A':
        line = dst
    else:
        line = ''
    if detail and line:
        line = f"{line} ({detail})"
    elif detail:
        line = detail
    return line


def _compact_ti_summary(ti: dict) -> str:
    parts = []

    vt = ti.get('virustotal', {})
    if vt:
        parts.append(f"VT {vt.get('malicious', '?')}/{vt.get('total', '?')} | {vt.get('score', 0):.0f}/100")

    abuse = ti.get('abuseipdb', {})
    if abuse:
        parts.append(f"Abuse {abuse.get('score', 0)}% | {abuse.get('reports', 0)}r")

    otx = ti.get('otx', {})
    if otx:
        parts.append(f"OTX {otx.get('pulses', 0)}p")

    return " | ".join(parts)


def _shorten_text(value: str, limit: int = 84) -> str:
    text = (value or '').strip()
    if len(text) <= limit:
        return text
    return text[:max(limit - 1, 0)].rstrip() + "…"


def _fim_action(file_event: str, file_path: str) -> str:
    event = (file_event or '').lower()
    path = file_path or 'N/A'

    if event == 'added':
        return f"added | isolate {path} | review origin"
    if event == 'modified':
        return f"modified | verify {path} | check diff"
    if event == 'deleted':
        return "deleted | confirm integrity | restore if needed"
    return f"review {path}"


def _truncate_telegram_message(message: str, limit: int = TELEGRAM_MAX_LENGTH) -> str:
    if len(message) <= limit:
        return message

    suffix = "\n... (trimmed for Telegram limit)"
    keep = max(limit - len(suffix), 0)
    trimmed = message[:keep]
    last_break = trimmed.rfind("\n")
    if last_break > 0:
        trimmed = trimmed[:last_break]
    return trimmed + suffix


def _format_duration(seconds: int) -> str:
    if seconds <= 0:
        return "permanent"
    if seconds < 60:
        return f"{seconds}s"
    if seconds % 3600 == 0:
        return f"{seconds // 3600}h"
    if seconds % 60 == 0:
        return f"{seconds // 60}m"
    return f"{seconds}s"


def _block_status_lines(enriched_alert: dict, source_ip: str) -> list[str]:
    # Tich hop chi biet yeu cau AR da duoc kich hoat.
    rule_id = str(enriched_alert.get('rule_id', 'N/A'))
    wazuh_triggered = rule_id in WAZUH_AR_BLOCK_RULES and source_ip != 'N/A'

    if wazuh_triggered:
        return [
            f"{ICON_BLOCKED} AR   : firewall-drop requested",
            f"\u25aa IP   : {source_ip}",
            f"\u25aa TTL  : {_format_duration(WAZUH_AR_TIMEOUT)} (configured)",
        ]

    return []


def build_telegram_template(enriched_alert: dict, severity: str) -> str:
    """Tao thong bao HIGH hoac CRITICAL."""
    ti        = enriched_alert.get('ti_results', {})

    src_ip     = enriched_alert.get('src_ip', 'N/A')
    dst_ip     = enriched_alert.get('dst_ip', 'N/A')
    detail     = enriched_alert.get('detail', '')
    rule_desc  = enriched_alert.get('rule_description', 'Security Alert')
    rule_id    = enriched_alert.get('rule_id', 'N/A')
    rule_level = enriched_alert.get('rule_level', 0)
    agent      = enriched_alert.get('agent_name', 'Unknown')
    risk_score = enriched_alert.get('risk_score', 0)
    count      = get_alert_count(enriched_alert)
    context    = _ctx_line(src_ip, dst_ip, detail)
    action     = _action_for_alert(rule_desc, rule_id)
    ti_summary = _compact_ti_summary(ti)

    icon   = ICON_CRITICAL if severity == 'CRITICAL' else ICON_HIGH
    header = f"{icon} SOC {severity} | L{rule_level} | R{risk_score:.1f}"

    lines = [header]
    lines.append(f"\u25aa Agent: {agent}")
    lines.append(f"\u25aa Rule : {rule_id} - {_shorten_text(rule_desc)}")
    if context:
        lines.append(f"\u25aa Ctx  : {_shorten_text(context, 96)}")

    lines.extend(_block_status_lines(enriched_alert, src_ip))
    if count > 1:
        lines.append(f"{ICON_REPEAT} x{count}")

    if ti_summary:
        lines.append(f"\u25aa TI   : {_shorten_text(ti_summary, 96)}")
    lines.append(f"\u25aa Act  : {_shorten_text(action, 100)}")

    return _truncate_telegram_message('\n'.join(lines))


def build_fim_template(enriched_alert: dict, severity: str) -> str:
    """Tao thong bao FIM."""
    ti          = enriched_alert.get('ti_results', {})
    vt          = ti.get('virustotal', {})
    file_path   = enriched_alert.get('file_path', 'N/A')
    file_event  = enriched_alert.get('file_event', 'N/A')
    rule_desc   = enriched_alert.get('rule_description', 'Security Alert')
    rule_id     = enriched_alert.get('rule_id', 'N/A')
    rule_level  = enriched_alert.get('rule_level', 0)
    agent       = enriched_alert.get('agent_name', 'Unknown')
    risk_score  = enriched_alert.get('risk_score', 0)
    timestamp   = enriched_alert.get('timestamp', 'N/A')
    count       = get_alert_count(enriched_alert)
    action      = _fim_action(file_event, file_path)

    icon = {
        'CRITICAL': ICON_CRITICAL,
        'HIGH': ICON_HIGH,
        'MEDIUM': ICON_MEDIUM,
    }[severity]
    header = f"{icon} FIM {severity} | L{rule_level} | R{risk_score:.1f}"

    lines = [header]
    lines.append(f"\u25aa Agent: {agent}")
    lines.append(f"\u25aa File : {_shorten_text(file_path, 110)}")
    lines.append(f"\u25aa Event: {file_event}")
    lines.append(f"\u25aa Rule : {rule_id} - {_shorten_text(rule_desc)}")
    if vt:
        lines.append(f"\u25aa VT   : {vt.get('malicious', '?')}/{vt.get('total', '?')} | {vt.get('score', 0):.0f}/100")
    lines.append(f"\u25aa Act  : {_shorten_text(action, 100)}")
    lines.append(f"\u25aa Time : {timestamp}")

    lines.extend(_block_status_lines(enriched_alert, enriched_alert.get('src_ip', 'N/A')))
    if count > 1:
        lines.append(f"{ICON_REPEAT} x{count}")

    return _truncate_telegram_message('\n'.join(lines))


def build_medium_template(enriched_alert: dict) -> str:
    """Tao thong bao MEDIUM ngan gon."""
    count      = get_alert_count(enriched_alert)
    count_str  = f" (x{count})" if count > 1 else ""
    src_ip     = enriched_alert.get('src_ip', 'N/A')
    dst_ip     = enriched_alert.get('dst_ip', 'N/A')
    detail     = enriched_alert.get('detail', '')
    rule_level = enriched_alert.get('rule_level', 0)
    rule_desc  = enriched_alert.get('rule_description', 'N/A')
    context    = _ctx_line(src_ip, dst_ip, detail)
    action     = _action_for_alert(rule_desc, enriched_alert.get('rule_id', 'N/A'))

    header = f"{ICON_MEDIUM} SOC MEDIUM | L{rule_level}{count_str}"

    lines = [header]
    lines.append(f"\u25aa Agent: {enriched_alert.get('agent_name', 'Unknown')}")
    lines.append(f"\u25aa Rule : {enriched_alert.get('rule_id', 'N/A')} - {_shorten_text(rule_desc)}")
    if context:
        lines.append(f"\u25aa Ctx  : {_shorten_text(context, 96)}")
    lines.extend(_block_status_lines(enriched_alert, src_ip))
    lines.append(f"\u25aa Risk : {enriched_alert.get('risk_score', 0):.1f}/100")
    lines.append(f"\u25aa Act  : {_shorten_text(action, 100)}")

    return _truncate_telegram_message('\n'.join(lines))


def send_telegram(message: str):
    try:
        message = _truncate_telegram_message(message)
        resp = requests.post(
            f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage",
            json={"chat_id": TELEGRAM_CHAT_ID, "text": message},
            timeout=10
        )
        if resp.status_code == 200:
            logger.info("Telegram: Message sent successfully")
        else:
            logger.error(f"Telegram error: {resp.status_code} — {resp.text}")
    except requests.RequestException as e:
        logger.error(f"Telegram exception: {e}")


def route_alert(enriched_alert: dict) -> str:
    """Phan loai va gui canh bao theo chinh sach."""
    severity = classify_severity(enriched_alert)
    enriched_alert['risk_level'] = severity

    if severity == 'LOW':
        logger.info("Routing -> Dashboard only (LOW)")
        return severity

    logger.info(
        f"Alert — Severity: {severity} | Rule: {enriched_alert.get('rule_id')} "
        f"| Level: {enriched_alert.get('rule_level')} | Risk: {enriched_alert.get('risk_score', 0):.1f}"
    )

    if not should_send(enriched_alert):
        count = get_alert_count(enriched_alert)
        logger.info(f"Dedup: Skipped — occurred {count} times within {DEDUP_WINDOW}s")
        return severity

    if enriched_alert.get('ioc_type') == 'files':
        logger.info("Routing -> Telegram (FIM FILE)")
        send_telegram(build_fim_template(enriched_alert, severity))

    elif severity == 'CRITICAL':
        logger.info("Routing -> Telegram (CRITICAL)")
        send_telegram(build_telegram_template(enriched_alert, 'CRITICAL'))

    elif severity == 'HIGH':
        logger.info("Routing -> Telegram (HIGH)")
        send_telegram(build_telegram_template(enriched_alert, 'HIGH'))

    elif severity == 'MEDIUM':
        logger.info("Routing -> Telegram (MEDIUM)")
        send_telegram(build_medium_template(enriched_alert))

    return severity
