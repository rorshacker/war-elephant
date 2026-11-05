from __future__ import annotations

import sys
import uuid
from ctypes import POINTER, Structure, WinDLL, byref, c_byte, c_char_p, c_int, c_void_p

COMPUTER_LIMIT = 256
_NO_RESULTS = "No computer objects were fabricated."


class DirectoryUnavailable(Exception):
    pass


class _BerVal(Structure):
    _fields_ = [("bv_len", c_int), ("bv_val", c_char_p)]


def read_joined_computers() -> tuple[list[dict], str]:
    if sys.platform != "win32":
        raise DirectoryUnavailable(f"Active Directory scan is available on Windows. {_NO_RESULTS}")
    from ctypes import wintypes

    controller, domain = _locate_domain(wintypes)
    return _search(wintypes, controller, _base_dn(domain)), controller


def _locate_domain(wintypes) -> tuple[str, str]:
    class DomainControllerInfo(Structure):
        _fields_ = [
            ("DomainControllerName", wintypes.LPWSTR),
            ("DomainControllerAddress", wintypes.LPWSTR),
            ("DomainControllerAddressType", wintypes.ULONG),
            ("DomainGuid", c_byte * 16),
            ("DomainName", wintypes.LPWSTR),
            ("DnsForestName", wintypes.LPWSTR),
            ("Flags", wintypes.ULONG),
            ("DcSiteName", wintypes.LPWSTR),
            ("ClientSiteName", wintypes.LPWSTR),
        ]

    info = POINTER(DomainControllerInfo)()
    netapi = WinDLL("netapi32")
    netapi.DsGetDcNameW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.LPCWSTR,
        c_void_p,
        wintypes.LPCWSTR,
        wintypes.ULONG,
        POINTER(POINTER(DomainControllerInfo)),
    ]
    netapi.DsGetDcNameW.restype = wintypes.DWORD
    netapi.NetApiBufferFree.argtypes = [c_void_p]
    status = netapi.DsGetDcNameW(None, None, None, None, 0x40000010, byref(info))
    if status != 0 or not info:
        raise DirectoryUnavailable(f"This computer is not joined to a directory. {_NO_RESULTS}")
    try:
        controller = (info.contents.DomainControllerName or "").lstrip("\\")
        domain = info.contents.DomainName or ""
    finally:
        netapi.NetApiBufferFree(info)
    if not controller or "." not in domain:
        raise DirectoryUnavailable(f"The directory name was not a DNS name. {_NO_RESULTS}")
    return controller, domain


def _base_dn(domain: str) -> str:
    labels = [label for label in domain.split(".") if label]
    if not labels or any(not label.replace("-", "").isalnum() for label in labels):
        raise DirectoryUnavailable(f"The directory name could not be used as a search base. {_NO_RESULTS}")
    return ",".join(f"DC={label}" for label in labels)


def _search(wintypes, controller: str, base: str) -> list[dict]:
    ldap = WinDLL("wldap32")
    ldap.ldap_initW.argtypes = [wintypes.LPCWSTR, wintypes.ULONG]
    ldap.ldap_initW.restype = c_void_p
    ldap.ldap_set_option.argtypes = [c_void_p, c_int, c_void_p]
    ldap.ldap_set_option.restype = wintypes.ULONG
    ldap.ldap_connect.argtypes = [c_void_p, c_void_p]
    ldap.ldap_connect.restype = wintypes.ULONG
    ldap.ldap_bind_sW.argtypes = [c_void_p, wintypes.LPWSTR, wintypes.LPWSTR, wintypes.ULONG]
    ldap.ldap_bind_sW.restype = wintypes.ULONG
    ldap.ldap_search_sW.argtypes = [c_void_p, wintypes.LPWSTR, wintypes.ULONG, wintypes.LPWSTR, POINTER(wintypes.LPWSTR), wintypes.ULONG, POINTER(c_void_p)]
    ldap.ldap_search_sW.restype = wintypes.ULONG
    ldap.ldap_first_entry.argtypes = [c_void_p, c_void_p]
    ldap.ldap_first_entry.restype = c_void_p
    ldap.ldap_next_entry.argtypes = [c_void_p, c_void_p]
    ldap.ldap_next_entry.restype = c_void_p
    ldap.ldap_get_valuesW.argtypes = [c_void_p, c_void_p, wintypes.LPCWSTR]
    ldap.ldap_get_valuesW.restype = POINTER(wintypes.LPWSTR)
    ldap.ldap_value_freeW.argtypes = [POINTER(wintypes.LPWSTR)]
    ldap.ldap_get_values_lenW.argtypes = [c_void_p, c_void_p, wintypes.LPCWSTR]
    ldap.ldap_get_values_lenW.restype = POINTER(POINTER(_BerVal))
    ldap.ldap_value_free_len.argtypes = [POINTER(POINTER(_BerVal))]
    ldap.ldap_msgfree.argtypes = [c_void_p]
    ldap.ldap_unbind.argtypes = [c_void_p]

    connection = ldap.ldap_initW(controller, 389)
    if not connection:
        raise DirectoryUnavailable(f"The directory controller could not be opened. {_NO_RESULTS}")
    message = c_void_p()
    try:
        for option, value in ((0x11, 3), (0x95, 1), (0x96, 1), (0x03, COMPUTER_LIMIT)):
            stored = wintypes.ULONG(value)
            if ldap.ldap_set_option(connection, option, byref(stored)) != 0:
                raise DirectoryUnavailable(f"The directory connection could not be secured. {_NO_RESULTS}")
        if ldap.ldap_connect(connection, None) != 0 or ldap.ldap_bind_sW(connection, None, None, 0x0486) != 0:
            raise DirectoryUnavailable(f"The directory refused the current sign-in. Signing stayed on. {_NO_RESULTS}")
        attributes = (wintypes.LPWSTR * 8)(
            "cn",
            "dNSHostName",
            "operatingSystem",
            "operatingSystemVersion",
            "distinguishedName",
            "userAccountControl",
            "objectGUID",
            None,
        )
        searched = ldap.ldap_search_sW(
            connection,
            base,
            2,
            "(&(objectCategory=computer)(objectClass=computer))",
            attributes,
            0,
            byref(message),
        )
        if searched not in {0, 4}:
            raise DirectoryUnavailable(f"The directory search did not complete. {_NO_RESULTS}")
        computers = []
        entry = ldap.ldap_first_entry(connection, message)
        while entry and len(computers) < COMPUTER_LIMIT:
            record = _computer(ldap, connection, entry)
            if record:
                computers.append(record)
            entry = ldap.ldap_next_entry(connection, entry)
        return computers
    finally:
        if message:
            ldap.ldap_msgfree(message)
        ldap.ldap_unbind(connection)


def _computer(ldap, connection, entry) -> dict | None:
    guid = _guid(ldap, connection, entry)
    name = _text(ldap, connection, entry, "cn")
    if not guid or not name:
        return None
    try:
        disabled = bool(int(_text(ldap, connection, entry, "userAccountControl") or "0") & 2)
    except ValueError:
        disabled = False
    return {
        "object_guid": guid,
        "computer_name": name,
        "dns_hostname": _text(ldap, connection, entry, "dNSHostName"),
        "enabled": not disabled,
        "os_name": _text(ldap, connection, entry, "operatingSystem"),
        "os_version": _text(ldap, connection, entry, "operatingSystemVersion"),
        "distinguished_name": _text(ldap, connection, entry, "distinguishedName"),
        "last_logon_timestamp": "",
    }


def _text(ldap, connection, entry, attribute: str) -> str:
    values = ldap.ldap_get_valuesW(connection, entry, attribute)
    if not values:
        return ""
    try:
        return values[0] or ""
    finally:
        ldap.ldap_value_freeW(values)


def _guid(ldap, connection, entry) -> str:
    values = ldap.ldap_get_values_lenW(connection, entry, "objectGUID")
    if not values or not values[0]:
        return ""
    try:
        raw = values[0].contents.bv_val
        if not raw or values[0].contents.bv_len != 16:
            return ""
        return str(uuid.UUID(bytes_le=raw[:16]))
    finally:
        ldap.ldap_value_free_len(values)
