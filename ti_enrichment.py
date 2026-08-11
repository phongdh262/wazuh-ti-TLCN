#!/usr/bin/env python3
"""Truy van dong thoi VirusTotal, AbuseIPDB va OTX."""

import threading
import logging
import base64
import time
from concurrent.futures import ThreadPoolExecutor, TimeoutError, as_completed
from urllib.parse import quote

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from cache_manager import cache
from config import VT_API_KEY, ABUSE_API_KEY, OTX_API_KEY, API_TIMEOUT
from utils import is_private_ip

logger = logging.getLogger(__name__)

_thread_local = threading.local()
_executor = ThreadPoolExecutor(max_workers=3, thread_name_prefix='ti')
_metrics_lock = threading.Lock()
_metrics = {
    'requests_total': 0,
    'cache_hits': 0,
    'cache_misses': 0,
    'requests_completed': 0,
    'requests_timeout': 0,
    'duration_ms_total': 0.0,
    'source_duration_ms_total': {
        'virustotal': 0.0,
        'abuseipdb': 0.0,
        'otx': 0.0,
    },
    'source_calls_total': {
        'virustotal': 0,
        'abuseipdb': 0,
        'otx': 0,
    },
}


def _get_session() -> requests.Session:
    session = getattr(_thread_local, 'session', None)
    if session is None:
        session = requests.Session()
        retry = Retry(
            total=2,
            connect=2,
            read=2,
            backoff_factor=0.4,
            status_forcelist=(429, 500, 502, 503, 504),
            allowed_methods=frozenset({'GET'}),
            raise_on_status=False,
        )
        adapter = HTTPAdapter(pool_connections=3, pool_maxsize=3, max_retries=retry)
        session.mount('http://', adapter)
        session.mount('https://', adapter)
        _thread_local.session = session
    return session


def _record_metric(name: str, delta=1):
    with _metrics_lock:
        _metrics[name] += delta


def _record_source_metric(source: str, duration_ms: float):
    with _metrics_lock:
        _metrics['source_duration_ms_total'][source] += duration_ms
        _metrics['source_calls_total'][source] += 1


def _source_duration(source: str, started_at: float):
    _record_source_metric(source, (time.perf_counter() - started_at) * 1000)


def get_metrics() -> dict:
    with _metrics_lock:
        source_avg = {}
        for source, total in _metrics['source_duration_ms_total'].items():
            calls = _metrics['source_calls_total'][source]
            source_avg[source] = round(total / calls, 2) if calls else 0.0

        hit_rate = 0.0
        lookup_total = _metrics['cache_hits'] + _metrics['cache_misses']
        if lookup_total:
            hit_rate = round((_metrics['cache_hits'] / lookup_total) * 100, 2)

        return {
            'requests_total': _metrics['requests_total'],
            'requests_completed': _metrics['requests_completed'],
            'requests_timeout': _metrics['requests_timeout'],
            'cache_hits': _metrics['cache_hits'],
            'cache_misses': _metrics['cache_misses'],
            'cache_hit_rate_percent': hit_rate,
            'avg_duration_ms': round(
                _metrics['duration_ms_total'] / _metrics['requests_completed'], 2
            ) if _metrics['requests_completed'] else 0.0,
            'avg_source_duration_ms': source_avg,
            'source_calls_total': dict(_metrics['source_calls_total']),
        }


def _vt_object_id(ioc_type: str, ioc_value: str) -> str:
    if ioc_type == 'urls':
        return base64.urlsafe_b64encode(ioc_value.encode('utf-8')).decode('ascii').rstrip('=')
    return quote(ioc_value, safe='')


def _call_virustotal(ioc_type: str, ioc_value: str):
    started_at = time.perf_counter()
    cache_key = f'vt:{ioc_type}:{ioc_value}'
    cached = cache.get(cache_key)
    if cached is not None:
        _record_metric('cache_hits')
        _source_duration('virustotal', started_at)
        return 'virustotal', cached
    _record_metric('cache_misses')

    try:
        resp = _get_session().get(
            f'https://www.virustotal.com/api/v3/{ioc_type}/{_vt_object_id(ioc_type, ioc_value)}',
            headers={'x-apikey': VT_API_KEY},
            timeout=API_TIMEOUT
        )
        if resp.status_code == 200:
            attrs  = resp.json()['data']['attributes']
            stats  = attrs.get('last_analysis_stats', {})
            mal    = stats.get('malicious', 0)
            total  = mal + stats.get('undetected', 0) + stats.get('harmless', 0)
            score  = round(mal / total * 100, 1) if total > 0 else 0.0
            data   = {
                'score':     score,
                'malicious': mal,
                'total':     total,
            }
            cache.set(cache_key, data)
            return 'virustotal', data
        elif resp.status_code == 404:
            logger.debug(f"VT: không tìm thấy IoC {ioc_value}")
        else:
            logger.warning(f"VT: HTTP {resp.status_code} cho {ioc_value}")
    except (requests.RequestException, KeyError, TypeError, ValueError) as e:
        logger.error(f"VT exception [{ioc_value}]: {e}")
    finally:
        _source_duration('virustotal', started_at)
    return None


def _call_abuseipdb(ioc_type: str, ioc_value: str):
    started_at = time.perf_counter()
    if ioc_type != 'ip_addresses':
        return None
    if is_private_ip(ioc_value):
        return None

    cache_key = f'abuse:{ioc_type}:{ioc_value}'
    cached = cache.get(cache_key)
    if cached is not None:
        _record_metric('cache_hits')
        _source_duration('abuseipdb', started_at)
        return 'abuseipdb', cached
    _record_metric('cache_misses')

    try:
        resp = _get_session().get(
            'https://api.abuseipdb.com/api/v2/check',
            params={'ipAddress': ioc_value, 'maxAgeInDays': 90},
            headers={'Key': ABUSE_API_KEY, 'Accept': 'application/json'},
            timeout=API_TIMEOUT
        )
        if resp.status_code == 200:
            d = resp.json()['data']
            data = {
                'score':   d.get('abuseConfidenceScore', 0),
                'reports': d.get('totalReports', 0),
            }
            cache.set(cache_key, data)
            return 'abuseipdb', data
        else:
            logger.warning(f"AbuseIPDB: HTTP {resp.status_code} cho {ioc_value}")
    except (requests.RequestException, KeyError, TypeError, ValueError) as e:
        logger.error(f"AbuseIPDB exception [{ioc_value}]: {e}")
    finally:
        _source_duration('abuseipdb', started_at)
    return None


def _call_otx(ioc_type: str, ioc_value: str):
    started_at = time.perf_counter()
    if ioc_type == 'files':
        return None
    cache_key = f'otx:{ioc_type}:{ioc_value}'
    cached = cache.get(cache_key)
    if cached is not None:
        _record_metric('cache_hits')
        _source_duration('otx', started_at)
        return 'otx', cached
    _record_metric('cache_misses')

    otx_type_map = {
        'ip_addresses': 'IPv4',
        'urls':         'URL',
        'domains':      'domain',
    }
    otx_section = otx_type_map.get(ioc_type)
    if not otx_section:
        return None

    try:
        resp = _get_session().get(
            f'https://otx.alienvault.com/api/v1/indicators/{otx_section}/{quote(ioc_value, safe="")}/general',
            headers={'X-OTX-API-KEY': OTX_API_KEY},
            timeout=API_TIMEOUT
        )
        if resp.status_code == 200:
            d           = resp.json()
            pulse_info  = d.get('pulse_info', {})
            pulse_count = pulse_info.get('count', 0)
            data = {
                'score':  min(pulse_count * 10, 100),
                'pulses': pulse_count,
            }
            cache.set(cache_key, data)
            return 'otx', data
        else:
            logger.warning(f"OTX: HTTP {resp.status_code} cho {ioc_value}")
    except (requests.RequestException, KeyError, TypeError, ValueError) as e:
        logger.error(f"OTX exception [{ioc_value}]: {e}")
    finally:
        _source_duration('otx', started_at)
    return None


def enrich_ioc(ioc_type: str, ioc_value: str) -> dict:
    """Truy van cac nguon ho tro loai IoC."""
    started_at = time.perf_counter()
    _record_metric('requests_total')
    results: dict = {}
    connectors = [_call_virustotal]
    if ioc_type == 'ip_addresses':
        connectors.extend((_call_abuseipdb, _call_otx))
    elif ioc_type in ('urls', 'domains'):
        connectors.append(_call_otx)

    futures = [
        _executor.submit(connector, ioc_type, ioc_value)
        for connector in connectors
    ]
    try:
        for future in as_completed(futures, timeout=API_TIMEOUT + 2):
            try:
                outcome = future.result()
            except Exception as e:
                logger.error(f"TI worker exception [{ioc_value}]: {e}")
                continue
            if outcome:
                key, data = outcome
                results[key] = data
    except TimeoutError:
        _record_metric('requests_timeout')
        for future in futures:
            future.cancel()

    _record_metric('requests_completed')
    _record_metric('duration_ms_total', (time.perf_counter() - started_at) * 1000)
    logger.info(f"TI enrichment [{ioc_value}]: {list(results.keys())}")
    return results
