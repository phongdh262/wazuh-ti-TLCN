#!/usr/bin/env python3
"""Dich vu HTTP lam giau va dinh tuyen canh bao."""

import hmac
import logging
import sys

from flask import Flask, request, jsonify

from alert_router import route_alert
from config import (
    FLASK_HOST,
    FLASK_PORT,
    LOG_FILE,
    LOG_LEVEL,
    MAX_ALERT_BYTES,
    WEBHOOK_TOKEN,
)
from risk_score import calculate_risk_score
from ti_enrichment import enrich_ioc, get_metrics as get_ti_metrics
from utils import get_nested, first_value, is_private_ip, is_public_url

logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = MAX_ALERT_BYTES


def _authorized_request() -> bool:
    if not WEBHOOK_TOKEN:
        return True
    supplied = request.headers.get('X-Wazuh-TI-Token', '')
    return hmac.compare_digest(supplied, WEBHOOK_TOKEN)


def extract_ioc(alert: dict):
    """Trich xuat IP cong khai, URL hoac ma bam tep."""
    data = alert.get('data', {})
    syscheck = alert.get('syscheck', {})
    event = (syscheck.get('event') or '').lower()

    if syscheck and event not in ('added', 'modified'):
        return None, None

    if event in ('added', 'modified'):
        file_hash = first_value(
            syscheck.get('sha256_after'),
            syscheck.get('md5_after'),
        )
        if isinstance(file_hash, str) and len(file_hash) > 10:
            return 'files', file_hash
        return None, None

    src_ip = first_value(
        data.get('srcip'),
        data.get('src_ip'),
        get_nested(data, 'win.eventdata.ipAddress'),
        get_nested(data, 'win.eventdata.sourceIp'),
        get_nested(data, 'win.eventdata.clientAddress'),
    )
    if src_ip and not is_private_ip(src_ip):
        return 'ip_addresses', src_ip

    dst_ip = first_value(
        data.get('dstip'),
        data.get('dst_ip'),
        get_nested(data, 'win.eventdata.destinationIp'),
        get_nested(data, 'win.eventdata.destIp'),
    )
    if dst_ip and not is_private_ip(dst_ip):
        return 'ip_addresses', dst_ip

    url = data.get('url', '')
    if is_public_url(url):
        return 'urls', url

    return None, None


def extract_context(alert: dict) -> dict:
    """Tao ngu canh cho mau thong bao."""
    data = alert.get('data', {})
    rule   = alert.get('rule', {})
    groups = rule.get('groups', [])
    syscheck = alert.get('syscheck', {})
    win = data.get('win', {})
    is_windows = bool(win) or any(g in groups for g in (
        'windows', 'windows_security', 'powershell', 'sysmon', 'windows_service'
    ))

    src    = first_value(data.get('srcip'), data.get('src_ip'))
    dst    = first_value(data.get('dstip'), data.get('dst_ip'))
    detail = ''

    if syscheck or any(g in groups for g in ('syscheck', 'ossec', 'fim')):
        path   = syscheck.get('path', '')
        event  = syscheck.get('event', '')
        src    = syscheck.get('uname_after') or syscheck.get('uname_before') or 'system'
        dst    = path
        detail = event

    elif is_windows:
        event_id = get_nested(data, 'win.system.eventID')
        target_user = first_value(
            get_nested(data, 'win.eventdata.targetUserName'),
            get_nested(data, 'win.eventdata.TargetUserName'),
            data.get('dstuser'),
        )
        src = first_value(
            data.get('srcip'),
            get_nested(data, 'win.eventdata.ipAddress'),
            get_nested(data, 'win.eventdata.sourceIp'),
            get_nested(data, 'win.eventdata.clientAddress'),
            get_nested(data, 'win.eventdata.workstationName'),
            get_nested(data, 'win.eventdata.WorkstationName'),
            target_user,
        )
        dst = first_value(
            target_user,
            get_nested(data, 'win.eventdata.destinationIp'),
            get_nested(data, 'win.eventdata.destIp'),
            alert.get('agent', {}).get('name'),
        )
        detail = first_value(
            get_nested(data, 'win.eventdata.commandLine'),
            get_nested(data, 'win.eventdata.CommandLine'),
            get_nested(data, 'win.eventdata.image'),
            get_nested(data, 'win.eventdata.Image'),
            get_nested(data, 'win.eventdata.serviceName'),
            get_nested(data, 'win.eventdata.ServiceName'),
        )
        if event_id and detail:
            detail = f"EID {event_id}: {detail}"
        elif event_id:
            detail = f"EID {event_id}"

    elif any(g in groups for g in ('authentication_failures', 'authentication_failed',
                                    'authentication_success', 'pam')):
        src    = data.get('srcip') or data.get('src_ip') or data.get('srcuser', '')
        dst    = data.get('dstuser') or alert.get('agent', {}).get('name', '')
        detail = data.get('srcuser', '')

    elif any(g in groups for g in ('dpkg', 'yum', 'package')):
        src    = 'package-manager'
        dst    = data.get('package') or data.get('program_name', '')
        detail = data.get('status', '')

    elif any(g in groups for g in ('sudo', 'privilege_escalation')):
        src    = data.get('srcuser') or data.get('user', '')
        dst    = data.get('dstuser', 'root')
        detail = data.get('command', '')

    elif any(g in groups for g in ('web', 'attack')):
        src    = data.get('srcip', '')
        dst    = data.get('url') or data.get('dstip', '')
        detail = data.get('id', '')

    else:
        src = data.get('srcip') or data.get('src_ip', '')
        dst = data.get('dstip') or data.get('dst_ip', '')

    return {
        'src':    src    or 'N/A',
        'dst':    dst    or 'N/A',
        'detail': detail or '',
    }


@app.route('/alert', methods=['POST'])
def receive_alert():
    """Lam giau va dinh tuyen canh bao JSON."""
    try:
        if not _authorized_request():
            return jsonify({'status': 'error', 'message': 'Unauthorized'}), 401

        alert = request.get_json(silent=True)
        if not isinstance(alert, dict) or not alert:
            return jsonify({'status': 'error', 'message': 'No JSON body'}), 400

        rule       = alert.get('rule', {})
        agent      = alert.get('agent', {})
        syscheck   = alert.get('syscheck', {})

        rule_id    = rule.get('id', 'N/A')
        try:
            rule_level = int(rule.get('level', 0))
        except (TypeError, ValueError):
            rule_level = 0
        rule_desc  = rule.get('description', 'N/A')
        agent_name = agent.get('name', 'N/A')
        timestamp  = alert.get('timestamp', 'N/A')

        logger.info(f"Alert nhận được — Raw Rule: {rule_id} | Level: {rule_level} | Agent: {agent_name}")

        ioc_type, ioc_value = extract_ioc(alert)
        ctx = extract_context(alert)
        ti_results = {}
        risk_score = 0.0
        ti_risk_level = 'LOW'

        if ioc_type and ioc_value:
            logger.info(f"Tra cứu TI: {ioc_type} = {ioc_value}")
            ti_results = enrich_ioc(ioc_type, ioc_value)
            risk_score, ti_risk_level = calculate_risk_score(ti_results)
            logger.info(f"Risk Score: {risk_score} → {ti_risk_level}")
        else:
            logger.info("Không có IoC public — bỏ qua TI enrichment")

        enriched_alert = {
            'rule_id':          rule_id,
            'rule_description': rule_desc,
            'rule_level':       rule_level,
            'agent_name':       agent_name,
            'timestamp':        timestamp,
            'src_ip':           ctx['src'],
            'dst_ip':           ctx['dst'],
            'detail':           ctx['detail'],
            'file_path':        'N/A',
            'file_event':       'N/A',
            'ioc_type':         ioc_type,
            'ioc_value':        ioc_value,
            'ti_results':       ti_results,
            'risk_score':       risk_score,
        }

        if ioc_type == 'files':
            enriched_alert['file_path'] = syscheck.get('path') or 'N/A'
            enriched_alert['file_event'] = (syscheck.get('event') or 'N/A').lower()

        final_severity = route_alert(enriched_alert)

        return jsonify({
            'status':     'ok',
            'risk_score': risk_score,
            'ti_risk_level': ti_risk_level,
            'severity':   final_severity,
            'active_response': 'wazuh_rule_dependent',
        }), 200

    except Exception as e:
        logger.error(f"Lỗi xử lý alert: {e}", exc_info=True)
        return jsonify({'status': 'error', 'message': 'Internal processing error'}), 500


@app.route('/health', methods=['GET'])
def health():
    return jsonify({'status': 'ok', 'message': 'Wazuh TI Server running'}), 200


@app.route('/metrics', methods=['GET'])
def metrics():
    if not _authorized_request():
        return jsonify({'status': 'error', 'message': 'Unauthorized'}), 401
    return jsonify({
        'status': 'ok',
        'ti_metrics': get_ti_metrics(),
    }), 200


if __name__ == '__main__':
    logger.info(f"Khởi động Flask server tại {FLASK_HOST}:{FLASK_PORT}")
    app.run(host=FLASK_HOST, port=FLASK_PORT, debug=False)
