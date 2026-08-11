#!/usr/bin/env python3
"""Tinh diem rui ro TI theo trong so."""

from config import VT_WEIGHT, ABUSE_WEIGHT, OTX_WEIGHT, CRITICAL_THRESHOLD, HIGH_THRESHOLD, MEDIUM_THRESHOLD


def calculate_risk_score(ti_results: dict) -> tuple[float, str]:
    """Tra ve diem chuan hoa va muc rui ro."""
    vt_data    = ti_results.get('virustotal', {})
    abuse_data = ti_results.get('abuseipdb',  {})
    otx_data   = ti_results.get('otx',        {})

    vt_score    = vt_data.get('score', 0) if vt_data else 0
    abuse_score = abuse_data.get('score', 0) if abuse_data else 0
    otx_score   = otx_data.get('score', 0) if otx_data else 0

    sources = []
    if vt_data:    sources.append((vt_score, VT_WEIGHT))
    if abuse_data: sources.append((abuse_score, ABUSE_WEIGHT))
    if otx_data:   sources.append((otx_score, OTX_WEIGHT))

    if not sources:
        return 0.0, 'LOW'

    total_weight = sum(w for _, w in sources)
    risk_score = sum(s * (w / total_weight) for s, w in sources)

    confirmed_malicious = sum(1 for s, _ in sources if s >= 50)
    if confirmed_malicious >= 2:
        risk_score = min(risk_score * 1.10, 100)

    risk_score = round(risk_score, 1)

    if risk_score > CRITICAL_THRESHOLD:
        level = 'CRITICAL'
    elif risk_score > HIGH_THRESHOLD:
        level = 'HIGH'
    elif risk_score > MEDIUM_THRESHOLD:
        level = 'MEDIUM'
    else:
        level = 'LOW'

    return risk_score, level
