"""
agent/signature_check.py
------------------------
Verifies the Authenticode signature of a Windows executable using the
native WinVerifyTrust API via ctypes.

Design decisions:
  - Zero subprocesses spawned -- pure ctypes, runs in-memory
  - Results cached by SHA-256 of the binary to avoid repeated API calls
  - Thread-safe: Access to the cache is protected by an explicit threading.Lock
  - Returns one of: TRUSTED, UNSIGNED, UNKNOWN
"""

import ctypes
import ctypes.wintypes
import hashlib
import logging
import pathlib
import threading
from functools import lru_cache

logger = logging.getLogger(__name__)

# -- WinVerifyTrust return codes ----------------------------------
ERROR_SUCCESS          = 0x00000000
TRUST_E_NOSIGNATURE    = 0x800B0100
TRUST_E_BAD_DIGEST     = 0x80096010
CRYPT_E_SECURITY_SETTINGS = 0x80092026

# -- WinTrust structures ------------------------------------------
class WINTRUST_FILE_INFO(ctypes.Structure):
    _fields_ = [
        ("cbStruct",       ctypes.wintypes.DWORD),
        ("pcwszFilePath",  ctypes.c_wchar_p),
        ("hFile",          ctypes.wintypes.HANDLE),
        ("pgKnownSubject", ctypes.c_void_p),
    ]


class WINTRUST_DATA(ctypes.Structure):
    _fields_ = [
        ("cbStruct",                     ctypes.wintypes.DWORD),
        ("pPolicyCallbackData",           ctypes.c_void_p),
        ("pSIPClientData",                ctypes.c_void_p),
        ("dwUIChoice",                    ctypes.wintypes.DWORD),
        ("fdwRevocationChecks",           ctypes.wintypes.DWORD),
        ("dwUnionChoice",                 ctypes.wintypes.DWORD),
        ("pFile",                         ctypes.POINTER(WINTRUST_FILE_INFO)),
        ("dwStateAction",                 ctypes.wintypes.DWORD),
        ("hWVTStateData",                 ctypes.wintypes.HANDLE),
        ("pwszURLReference",              ctypes.c_wchar_p),
        ("dwProvFlags",                   ctypes.wintypes.DWORD),
        ("dwUIContext",                   ctypes.wintypes.DWORD),
    ]


# WinTrust constants
WTD_UI_NONE       = 2
WTD_REVOKE_NONE   = 0
WTD_CHOICE_FILE   = 1
WTD_STATEACTION_VERIFY = 1
WTD_STATEACTION_CLOSE  = 2

# Action GUID for generic verification: {00AAC56B-CD44-11d0-8CC2-00C04FC295EE}
WINTRUST_ACTION_GENERIC_VERIFY_V2 = ctypes.c_char_p(
    b"\x6b\xc5\xaa\x00\x44\xcd\xd0\x11\x8c\xc2\x00\xc0\x4f\xc2\x95\xee"
)


def _sha256_of_file(path: str) -> str | None:
    """Compute SHA-256 of a file. Returns None if the file is unreadable."""
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return None


# Cache is keyed by sha256 -- the SHA ensures correctness even if name changes.
# Thread safety is ensured by _cache_lock.
_cache: dict[str, str] = {}
_cache_lock = threading.Lock()


def get_signature_status(exe_path: str | pathlib.Path) -> str:
    """
    Returns one of:
      'TRUSTED'  -- valid Authenticode signature from trusted CA
      'UNSIGNED' -- no signature found
      'UNKNOWN'  -- error during verification (treat as untrusted)
    """
    path_str = str(exe_path)

    sha = _sha256_of_file(path_str)
    if sha:
        with _cache_lock:
            if sha in _cache:
                return _cache[sha]

    result = _run_winverifytrust(path_str)

    if sha:
        with _cache_lock:
            _cache[sha] = result

    return result


def _run_winverifytrust(path_str: str) -> str:
    try:
        wintrust = ctypes.windll.wintrust

        file_info = WINTRUST_FILE_INFO()
        file_info.cbStruct      = ctypes.sizeof(WINTRUST_FILE_INFO)
        file_info.pcwszFilePath = path_str
        file_info.hFile         = None
        file_info.pgKnownSubject = None

        trust_data = WINTRUST_DATA()
        trust_data.cbStruct            = ctypes.sizeof(WINTRUST_DATA)
        trust_data.pPolicyCallbackData = None
        trust_data.pSIPClientData      = None
        trust_data.dwUIChoice          = WTD_UI_NONE
        trust_data.fdwRevocationChecks = WTD_REVOKE_NONE
        trust_data.dwUnionChoice       = WTD_CHOICE_FILE
        trust_data.pFile               = ctypes.pointer(file_info)
        trust_data.dwStateAction       = WTD_STATEACTION_VERIFY
        trust_data.hWVTStateData       = None
        trust_data.pwszURLReference    = None
        trust_data.dwProvFlags         = 0
        trust_data.dwUIContext         = 0

        # Use a local GUID struct
        class GUID(ctypes.Structure):
            _fields_ = [
                ("Data1", ctypes.c_ulong),
                ("Data2", ctypes.c_ushort),
                ("Data3", ctypes.c_ushort),
                ("Data4", ctypes.c_ubyte * 8),
            ]

        action_guid = GUID(
            0x00AAC56B,
            0xCD44,
            0x11D0,
            (ctypes.c_ubyte * 8)(0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE),
        )

        result = wintrust.WinVerifyTrust(
            ctypes.wintypes.HANDLE(-1),         # INVALID_HANDLE_VALUE
            ctypes.byref(action_guid),
            ctypes.byref(trust_data),
        )

        # Close the state handle to free resources
        trust_data.dwStateAction = WTD_STATEACTION_CLOSE
        wintrust.WinVerifyTrust(
            ctypes.wintypes.HANDLE(-1),
            ctypes.byref(action_guid),
            ctypes.byref(trust_data),
        )

        if result == ERROR_SUCCESS:
            return "TRUSTED"
        elif result in (TRUST_E_NOSIGNATURE, TRUST_E_BAD_DIGEST):
            return "UNSIGNED"
        else:
            logger.debug("WinVerifyTrust returned 0x%08X for %s", result, path_str)
            return "UNSIGNED"

    except Exception as exc:
        logger.warning("WinVerifyTrust failed for %s: %s", path_str, exc)
        return "UNKNOWN"


def get_file_sha256(exe_path: str | pathlib.Path) -> str | None:
    """Public helper -- compute SHA-256 of a file."""
    return _sha256_of_file(str(exe_path))
