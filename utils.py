#!/usr/bin/env python3

import ipaddress
from urllib.parse import urlsplit


def get_nested(obj: dict, path: str, default=''):
    cur = obj
    for key in path.split('.'):
        if not isinstance(cur, dict):
            return default
        cur = cur.get(key)
    return cur if cur not in (None, '') else default


def first_value(*values):
    """Tra ve truong Wazuh dau tien khong rong."""
    for value in values:
        if value not in (None, '', '-'):
            return value
    return ''


def is_private_ip(ip: str) -> bool:
    """Loai IP khong hop le hoac khong cong khai."""
    if not ip or ip == '-':
        return True
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return True
    return (
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_reserved
        or addr.is_unspecified
        or addr.is_multicast
    )


def is_public_url(value: str) -> bool:
    """Chi nhan URL HTTP(S) cong khai."""
    try:
        parsed = urlsplit(value)
    except ValueError:
        return False

    hostname = (parsed.hostname or '').lower().rstrip('.')
    if parsed.scheme not in ('http', 'https') or not hostname:
        return False
    if hostname == 'localhost' or hostname.endswith(('.local', '.internal')):
        return False

    try:
        ipaddress.ip_address(hostname)
    except ValueError:
        return '.' in hostname
    return not is_private_ip(hostname)
