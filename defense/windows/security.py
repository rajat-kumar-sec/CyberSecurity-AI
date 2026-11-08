"""Small, reviewed Windows security primitives used by the defense subsystem.

The module has three jobs:

* reject symlinks, junctions and other reparse points before a file is read or
  replaced;
* create files atomically with an unpredictable temporary name instead of a
  predictable ``*.tmp`` path;
* apply and verify a real Windows DACL (not just ``os.chmod``, which does
  nothing useful to NTFS ACLs).

``os.chmod`` on Windows only changes the read-only attribute; it is **not** an
access-control boundary.  :func:`apply_restricted_acl` uses
``SetNamedSecurityInfoW`` with a protected DACL that grants access only to the
current user, ``SYSTEM`` and the local ``Administrators`` group.

Honest limitation
-----------------
An ACL that includes the current user cannot protect against another process
running as that same user.  CyberGuard's data directory is owned by the
interactive user, so same-user malware can still read or modify it.  The
helper-installation check uses :func:`acl_is_admin_only`, which does **not**
grant the current user access, because elevated helper code must be writable
only by administrators.
"""

from __future__ import annotations

import ctypes
import os
import secrets
import stat
import sys
from pathlib import Path

IS_WINDOWS = sys.platform == "win32"

FILE_ATTRIBUTE_REPARSE_POINT = getattr(
    stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400
)

# Win32 constants
_ERROR_SUCCESS = 0
_SE_FILE_OBJECT = 1
_DACL_SECURITY_INFORMATION = 0x00000004
_PROTECTED_DACL_SECURITY_INFORMATION = 0x80000000
_SE_DACL_PROTECTED = 0x1000
_ACL_REVISION = 2
_ACCESS_ALLOWED_ACE_TYPE = 0
_ACCESS_DENIED_ACE_TYPE = 1
_TOKEN_QUERY = 0x0008
_TOKEN_INFORMATION_USER = 1
_FILE_ALL_ACCESS = 0x1F01FF
_CONTAINER_INHERIT_ACE = 0x2
_OBJECT_INHERIT_ACE = 0x1
_ACL_SIZE_INFORMATION_CLASS = 2

SYSTEM_SID = "S-1-5-18"
ADMINISTRATORS_SID = "S-1-5-32-544"


class SecurityError(Exception):
    """A path, file or ACL failed a fail-closed safety check."""

    def __init__(self, message, category="security_error"):
        super().__init__(message)
        self.message = str(message)
        self.category = category


class WindowsAclError(SecurityError):
    def __init__(self, message):
        super().__init__(message, "acl_error")


# --------------------------------------------------------------------- paths


def is_reparse_point(path):
    """True for symlinks, junctions and any other reparse-point file."""
    path = Path(path)
    try:
        details = os.lstat(path)
    except OSError:
        return False
    if getattr(details, "st_file_attributes", 0) & FILE_ATTRIBUTE_REPARSE_POINT:
        return True
    try:
        if path.is_symlink():
            return True
    except OSError:
        return True
    return bool(getattr(details, "st_nlink", 1) and os.path.islink(path))


def assert_safe_path(path, kind=None, max_bytes=None, allow_missing=False):
    """Validate one path without following a symlink or junction.

    Returns the ``lstat`` result, or ``None`` when ``allow_missing`` is true
    and the path does not exist.  Raises :class:`SecurityError` for anything
    unexpected.
    """
    path = Path(path)

    if not path.exists() and not path.is_symlink():
        if allow_missing:
            return None
        raise SecurityError("The required path does not exist.", "path_missing")

    if is_reparse_point(path):
        raise SecurityError(
            "Refusing to use a symlink, junction or reparse point.",
            "reparse_point",
        )

    try:
        details = os.lstat(path)
    except OSError as exc:
        raise SecurityError(
            f"The path could not be inspected ({type(exc).__name__}).",
            "path_inspection_failed",
        ) from None

    if kind == "file":
        if not stat.S_ISREG(details.st_mode):
            raise SecurityError("The path is not a regular file.", "not_a_file")
        if getattr(details, "st_nlink", 1) != 1:
            raise SecurityError(
                "The file has multiple hard links; refusing to trust it.",
                "hardlink",
            )
        if max_bytes is not None and details.st_size > int(max_bytes):
            raise SecurityError(
                "The file is larger than the allowed limit.",
                "file_too_large",
            )
    elif kind == "dir":
        if not stat.S_ISDIR(details.st_mode):
            raise SecurityError(
                "The path is not a directory.", "not_a_directory"
            )

    return details


def secure_mkdir(path, restricted=False):
    """Create a directory and, on Windows, optionally give it a restricted DACL."""
    path = Path(path)
    path.mkdir(parents=True, exist_ok=True)
    assert_safe_path(path, kind="dir")
    if restricted and IS_WINDOWS:
        apply_restricted_acl(path)
        if not acl_is_restricted(path):
            raise WindowsAclError(
                "The directory ACL could not be verified as restricted."
            )
    return path


def secure_read(path, max_bytes):
    """Read at most ``max_bytes`` from a regular, non-reparse file."""
    assert_safe_path(path, kind="file", max_bytes=max_bytes)
    try:
        with open(path, "rb") as handle:
            data = handle.read(int(max_bytes) + 1)
    except OSError as exc:
        raise SecurityError(
            f"The file could not be read ({type(exc).__name__}).",
            "read_failed",
        ) from None
    if len(data) > int(max_bytes):
        raise SecurityError("The file is larger than the allowed limit.",
                            "file_too_large")
    return data


def secure_atomic_write(path, data, mode=0o600, restricted=False):
    """Write bytes atomically using an unpredictable, exclusively created temp file.

    ``os.replace`` replaces the directory entry, so a pre-created symlink at
    the destination is replaced rather than followed on Windows.
    """
    path = Path(path)
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("data must be bytes")

    parent = path.parent
    secure_mkdir(parent)
    secure_mkdir(parent, restricted=restricted)

    temporary = parent / (
        f".{path.name}.{secrets.token_hex(12)}.tmp"
    )
    descriptor = None
    try:
        descriptor = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0),
            mode,
        )
        with os.fdopen(descriptor, "wb") as handle:
            descriptor = None
            handle.write(bytes(data))
            handle.flush()
            try:
                os.fsync(handle.fileno())
            except OSError:
                pass
        if restricted and IS_WINDOWS:
            apply_restricted_acl(temporary)
        os.replace(temporary, path)
        if restricted and IS_WINDOWS:
            apply_restricted_acl(path)
            if not acl_is_restricted(path):
                raise WindowsAclError(
                    "The file ACL could not be verified as restricted."
                )
    except Exception:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass
        raise

    return path


# ---------------------------------------------------------------------- ACLs

if IS_WINDOWS:
    _advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    _kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

    class _SID_IDENTIFIER_AUTHORITY(ctypes.Structure):
        _fields_ = [("Value", ctypes.c_ubyte * 6)]

    class _ACL(ctypes.Structure):
        _fields_ = [
            ("AclRevision", ctypes.c_ubyte),
            ("Sbz1", ctypes.c_ubyte),
            ("AclSize", ctypes.c_ushort),
            ("AceCount", ctypes.c_ushort),
            ("Sbz2", ctypes.c_ushort),
        ]

    class _ACL_SIZE_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("AceCount", ctypes.c_ulong),
            ("AclBytesInUse", ctypes.c_ulong),
            ("AclBytesFree", ctypes.c_ulong),
        ]

    class _ACE_HEADER(ctypes.Structure):
        _fields_ = [
            ("AceType", ctypes.c_ubyte),
            ("AceFlags", ctypes.c_ubyte),
            ("AceSize", ctypes.c_ushort),
        ]

    class _SID_AND_ATTRIBUTES(ctypes.Structure):
        _fields_ = [
            ("Sid", ctypes.c_void_p),
            ("Attributes", ctypes.c_ulong),
        ]

    class _TOKEN_USER(ctypes.Structure):
        _fields_ = [("User", _SID_AND_ATTRIBUTES)]

    _advapi32.ConvertStringSidToSidW.argtypes = [
        ctypes.c_wchar_p,
        ctypes.POINTER(ctypes.c_void_p),
    ]
    _advapi32.ConvertStringSidToSidW.restype = ctypes.c_int

    _advapi32.ConvertSidToStringSidW.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_wchar_p),
    ]
    _advapi32.ConvertSidToStringSidW.restype = ctypes.c_int

    _advapi32.GetNamedSecurityInfoW.argtypes = [
        ctypes.c_wchar_p,
        ctypes.c_int,
        ctypes.c_ulong,
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
    ]
    _advapi32.GetNamedSecurityInfoW.restype = ctypes.c_ulong

    _advapi32.SetNamedSecurityInfoW.argtypes = [
        ctypes.c_wchar_p,
        ctypes.c_int,
        ctypes.c_ulong,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
    ]
    _advapi32.SetNamedSecurityInfoW.restype = ctypes.c_ulong

    _advapi32.InitializeAcl.argtypes = [
        ctypes.c_void_p,
        ctypes.c_ulong,
        ctypes.c_ulong,
    ]
    _advapi32.InitializeAcl.restype = ctypes.c_int

    _advapi32.AddAccessAllowedAceEx.argtypes = [
        ctypes.c_void_p,
        ctypes.c_ulong,
        ctypes.c_ulong,
        ctypes.c_ulong,
        ctypes.c_void_p,
    ]
    _advapi32.AddAccessAllowedAceEx.restype = ctypes.c_int

    _advapi32.GetSecurityDescriptorDacl.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_int),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_int),
    ]
    _advapi32.GetSecurityDescriptorDacl.restype = ctypes.c_int

    _advapi32.GetSecurityDescriptorControl.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_ushort),
        ctypes.POINTER(ctypes.c_ulong),
    ]
    _advapi32.GetSecurityDescriptorControl.restype = ctypes.c_int

    _advapi32.GetAclInformation.argtypes = [
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_ulong,
        ctypes.c_int,
    ]
    _advapi32.GetAclInformation.restype = ctypes.c_int

    _advapi32.GetAce.argtypes = [
        ctypes.c_void_p,
        ctypes.c_ulong,
        ctypes.POINTER(ctypes.c_void_p),
    ]
    _advapi32.GetAce.restype = ctypes.c_int

    _advapi32.OpenProcessToken.argtypes = [
        ctypes.c_void_p,
        ctypes.c_ulong,
        ctypes.POINTER(ctypes.c_void_p),
    ]
    _advapi32.OpenProcessToken.restype = ctypes.c_int

    _advapi32.GetTokenInformation.argtypes = [
        ctypes.c_void_p,
        ctypes.c_int,
        ctypes.c_void_p,
        ctypes.c_ulong,
        ctypes.POINTER(ctypes.c_ulong),
    ]
    _advapi32.GetTokenInformation.restype = ctypes.c_int

    _kernel32.GetCurrentProcess.argtypes = []
    _kernel32.GetCurrentProcess.restype = ctypes.c_void_p
    _kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    _kernel32.LocalFree.restype = ctypes.c_void_p
    _kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
    _kernel32.CloseHandle.restype = ctypes.c_int
else:  # pragma: no cover - exercised only on Windows
    _advapi32 = None
    _kernel32 = None


def _current_user_sid():
    if not IS_WINDOWS:
        raise WindowsAclError("Windows ACLs are only available on Windows.")
    token = ctypes.c_void_p()
    if not _advapi32.OpenProcessToken(
        _kernel32.GetCurrentProcess(), _TOKEN_QUERY, ctypes.byref(token)
    ):
        raise WindowsAclError("OpenProcessToken failed.")
    try:
        size = ctypes.c_ulong(0)
        _advapi32.GetTokenInformation(
            token, _TOKEN_INFORMATION_USER, None, 0, ctypes.byref(size)
        )
        if not size.value:
            raise WindowsAclError("GetTokenInformation failed.")
        buffer = ctypes.create_string_buffer(size.value)
        if not _advapi32.GetTokenInformation(
            token, _TOKEN_INFORMATION_USER, buffer, size, ctypes.byref(size)
        ):
            raise WindowsAclError("GetTokenInformation failed.")
        token_user = ctypes.cast(
            buffer, ctypes.POINTER(_TOKEN_USER)
        ).contents
        # The SID points into ``buffer``; convert it to a string while the
        # buffer is still alive.
        return _sid_to_string(token_user.User.Sid)
    finally:
        _kernel32.CloseHandle(token)


def _sid_to_string(sid):
    if not sid:
        return ""
    text = ctypes.c_wchar_p()
    if not _advapi32.ConvertSidToStringSidW(
        ctypes.c_void_p(sid), ctypes.byref(text)
    ):
        return ""
    try:
        return text.value or ""
    finally:
        _kernel32.LocalFree(text)


def _string_to_sid(text):
    sid = ctypes.c_void_p()
    if not _advapi32.ConvertStringSidToSidW(text, ctypes.byref(sid)):
        raise WindowsAclError(f"Could not resolve the SID {text}.")
    return sid


def current_user_sid_string():
    """Return the current process user's SID string (``S-1-5-...``)."""
    return _current_user_sid()


def _allowed_sids(admin_only=False):
    allowed = {SYSTEM_SID, ADMINISTRATORS_SID}
    if not admin_only:
        allowed.add(current_user_sid_string())
    return allowed


def acl_is_restricted(path, admin_only=False):
    """Verify that every allow-ACE belongs to an intended principal.

    ``admin_only=True`` accepts only ``SYSTEM`` and ``Administrators`` and is
    used for protected helper installations.  ``admin_only=False`` also allows
    the current user's SID, which is appropriate for the user-owned data
    directory (and explains why same-user malware is still a threat).
    """
    if not IS_WINDOWS:
        return False
    if not Path(path).exists():
        return False

    try:
        allowed = _allowed_sids(admin_only=admin_only)
    except WindowsAclError:
        return False

    security_descriptor = ctypes.c_void_p()
    dacl = ctypes.c_void_p()
    dacl_present = ctypes.c_int(0)
    dacl_defaulted = ctypes.c_int(0)
    result = _advapi32.GetNamedSecurityInfoW(
        str(Path(path)),
        _SE_FILE_OBJECT,
        _DACL_SECURITY_INFORMATION,
        None,
        None,
        ctypes.byref(dacl),
        None,
        ctypes.byref(security_descriptor),
    )
    if result != _ERROR_SUCCESS:
        return False

    try:
        if not _advapi32.GetSecurityDescriptorDacl(
            security_descriptor,
            ctypes.byref(dacl_present),
            ctypes.byref(dacl),
            ctypes.byref(dacl_defaulted),
        ):
            return False
        if not dacl_present.value or not dacl.value:
            return False

        info = _ACL_SIZE_INFORMATION()
        if not _advapi32.GetAclInformation(
            dacl,
            ctypes.byref(info),
            ctypes.sizeof(info),
            _ACL_SIZE_INFORMATION_CLASS,
        ):
            return False

        saw_allow = False
        for index in range(int(info.AceCount)):
            ace = ctypes.c_void_p()
            if not _advapi32.GetAce(
                dacl, index, ctypes.byref(ace)
            ):
                return False
            header = ctypes.cast(
                ace, ctypes.POINTER(_ACE_HEADER)
            ).contents
            if header.AceType != _ACCESS_ALLOWED_ACE_TYPE:
                continue
            saw_allow = True
            sid_address = ctypes.cast(ace, ctypes.c_void_p).value + 8
            sid_text = _sid_to_string(sid_address)
            if sid_text not in allowed:
                return False
        return saw_allow
    finally:
        _kernel32.LocalFree(security_descriptor)


def acl_is_admin_only(path):
    """True when only SYSTEM and Administrators can access ``path``."""
    return acl_is_restricted(path, admin_only=True)


def apply_restricted_acl(path, admin_only=False):
    """Apply a protected DACL to ``path`` and verify it.

    ``admin_only=True`` omits the current user, so the caller must already be
    able to access the object through administrator rights.  Raises
    :class:`WindowsAclError` if the ACL cannot be set or verified.
    """
    if not IS_WINDOWS:
        raise WindowsAclError(
            "Windows ACLs are only available on Windows."
        )

    path = Path(path)
    if not path.exists():
        raise WindowsAclError("The path does not exist.")

    try:
        sids = [
            _string_to_sid(SYSTEM_SID),
            _string_to_sid(ADMINISTRATORS_SID),
        ]
        if not admin_only:
            sids.insert(0, _string_to_sid(current_user_sid_string()))
    except Exception:
        for sid in locals().get("sids", []):
            try:
                _kernel32.LocalFree(sid)
            except Exception:
                pass
        raise

    # A fixed 4 KiB ACL buffer is enough for four ACEs and avoids an ACL that
    # could be sized from attacker-controlled input.
    acl_buffer = ctypes.create_string_buffer(4096)
    acl = ctypes.cast(acl_buffer, ctypes.c_void_p)
    if not _advapi32.InitializeAcl(
        acl, ctypes.sizeof(acl_buffer), _ACL_REVISION
    ):
        raise WindowsAclError("InitializeAcl failed.")

    flags = _CONTAINER_INHERIT_ACE | _OBJECT_INHERIT_ACE
    for sid in sids:
        if not _advapi32.AddAccessAllowedAceEx(
            acl,
            _ACL_REVISION,
            flags,
            _FILE_ALL_ACCESS,
            sid,
        ):
            for item in sids:
                _kernel32.LocalFree(item)
            raise WindowsAclError("AddAccessAllowedAceEx failed.")

    result = _advapi32.SetNamedSecurityInfoW(
        str(path),
        _SE_FILE_OBJECT,
        _DACL_SECURITY_INFORMATION | _PROTECTED_DACL_SECURITY_INFORMATION,
        None,
        None,
        acl,
        None,
    )
    for sid in sids:
        _kernel32.LocalFree(sid)

    if result != _ERROR_SUCCESS:
        raise WindowsAclError(
            f"SetNamedSecurityInfoW failed with Windows error {result}."
        )

    if not acl_is_restricted(path, admin_only=admin_only):
        raise WindowsAclError(
            "The ACL was written but could not be verified as restricted."
        )
    return True


# ------------------------------------------------------ trusted executables


def system_root():
    return os.environ.get("SystemRoot") or os.environ.get("WINDIR") or r"C:\Windows"


def trusted_system32_executable(name):
    """Absolute path to a Windows ``System32`` executable.

    ``name`` is always a constant from this codebase; no request data is ever
    passed here.  On non-Windows the bare name is returned so tests and
    development imports keep working, but the caller still refuses to run it
    because the platform guard fails first.
    """
    if not isinstance(name, str) or not name or os.sep in name:
        raise SecurityError("Invalid system executable name.", "invalid_path")
    if not IS_WINDOWS:
        return name
    return str(Path(system_root()) / "System32" / name)


def is_under_system32(path):
    """True when ``path`` is an absolute path inside ``%SystemRoot%\\System32``."""
    if not IS_WINDOWS:
        return False
    try:
        candidate = Path(path).resolve()
        root = (Path(system_root()) / "System32").resolve()
        candidate.relative_to(root)
    except (OSError, ValueError):
        return False
    return True
