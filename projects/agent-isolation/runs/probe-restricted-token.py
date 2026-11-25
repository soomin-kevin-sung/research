"""Compare Windows restricted-token flags on disposable synthetic files."""

import argparse
import ctypes
import tempfile
from ctypes import wintypes
from pathlib import Path

import pywintypes
import win32api
import win32con
import win32file
import win32security
from ntsecuritycon import (
    FILE_ALL_ACCESS,
    FILE_GENERIC_EXECUTE,
    FILE_GENERIC_READ,
    FILE_GENERIC_WRITE,
    FILE_LIST_DIRECTORY,
    FILE_READ_DATA,
    FILE_TRAVERSE,
)


class SidAndAttributes(ctypes.Structure):
    _fields_ = [("sid", ctypes.c_void_p), ("attributes", wintypes.DWORD)]


class GenericMapping(ctypes.Structure):
    _fields_ = [(name, wintypes.DWORD) for name in ("read", "write", "execute", "all")]


def access_check(path, token):
    advapi = ctypes.WinDLL("advapi32", use_last_error=True)
    get_descriptor = advapi.GetNamedSecurityInfoW
    get_descriptor.argtypes = [wintypes.LPWSTR, wintypes.DWORD, wintypes.DWORD] + [
        ctypes.c_void_p
    ] * 5
    get_descriptor.restype = wintypes.DWORD
    free = ctypes.windll.kernel32.LocalFree
    free.argtypes = [ctypes.c_void_p]
    free.restype = ctypes.c_void_p
    check = advapi.AccessCheck
    check.argtypes = [
        ctypes.c_void_p, wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(GenericMapping),
        ctypes.c_void_p, ctypes.POINTER(wintypes.DWORD), ctypes.POINTER(wintypes.DWORD),
        ctypes.POINTER(wintypes.BOOL),
    ]
    check.restype = wintypes.BOOL
    security_info = (
        win32security.OWNER_SECURITY_INFORMATION
        | win32security.GROUP_SECURITY_INFORMATION
        | win32security.DACL_SECURITY_INFORMATION
    )
    descriptor = ctypes.c_void_p()
    status = get_descriptor(
        str(path), win32security.SE_FILE_OBJECT, security_info,
        None, None, None, None, ctypes.byref(descriptor),
    )
    if status:
        raise ctypes.WinError(status)
    try:
        impersonation = win32security.DuplicateToken(token, win32security.SecurityImpersonation)
        try:
            mapping = GenericMapping(
                FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_GENERIC_EXECUTE, FILE_ALL_ACCESS
            )
            results = []
            for mask in (FILE_READ_DATA, FILE_GENERIC_READ):
                privileges = ctypes.create_string_buffer(4096)
                size = wintypes.DWORD(ctypes.sizeof(privileges))
                granted = wintypes.DWORD()
                allowed = wintypes.BOOL()
                if not check(
                    descriptor, int(impersonation), mask, ctypes.byref(mapping), privileges,
                    ctypes.byref(size), ctypes.byref(granted), ctypes.byref(allowed),
                ):
                    raise ctypes.WinError(ctypes.get_last_error())
                results.append("allow" if allowed.value else "deny")
            return "/".join(results)
        finally:
            impersonation.Close()
    finally:
        free(descriptor)


def create_native_token(base, flags, sids):
    advapi = ctypes.WinDLL("advapi32", use_last_error=True)
    create = advapi.CreateRestrictedToken
    create.argtypes = [
        wintypes.HANDLE, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p,
        wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD,
        ctypes.POINTER(SidAndAttributes), ctypes.POINTER(wintypes.HANDLE),
    ]
    create.restype = wintypes.BOOL
    sid_buffers = [ctypes.create_string_buffer(bytes(sid)) for sid, _ in sids]
    entries = (SidAndAttributes * len(sids))(
        *(SidAndAttributes(ctypes.addressof(buffer), 0) for buffer in sid_buffers)
    )
    token = wintypes.HANDLE()
    if not create(int(base), flags, 0, None, 0, None, len(entries), entries, ctypes.byref(token)):
        raise ctypes.WinError(ctypes.get_last_error())
    return pywintypes.HANDLE(token.value)


def probe(path, access, disposition, attributes=win32con.FILE_ATTRIBUTE_NORMAL):
    share = win32con.FILE_SHARE_READ | win32con.FILE_SHARE_WRITE | win32con.FILE_SHARE_DELETE
    try:
        handle = win32file.CreateFile(
            str(path), access, share, None, disposition, attributes, None
        )
        handle.Close()
        return "OK"
    except pywintypes.error as error:
        return f"WinError {error.winerror}"


def main(parent, inspect_ancestors):
    with tempfile.TemporaryDirectory(prefix="agent-isolation-token-flags-", dir=parent) as directory:
        folder = Path(directory)
        starter = folder / "starter.txt"
        starter.write_text("fixture-v1\n", encoding="ascii")
        cases = {
            "host": None,
            "DISABLE_MAX_PRIVILEGE": 0x01,
            "restricted SIDs only": 0x00,
            "WRITE_RESTRICTED": 0x08,
            "both flags": 0x09,
        }
        # Use a fresh SID with no grant on the fixture to expose restricted access checks.
        restrict_sid = win32security.ConvertStringSidToSid("S-1-5-21-111-222-333-444")
        allowed = folder / "explicit-read.txt"
        allowed.write_text("fixture-v1\n", encoding="ascii")
        descriptor = win32security.GetNamedSecurityInfo(
            str(allowed), win32security.SE_FILE_OBJECT, win32security.DACL_SECURITY_INFORMATION
        )
        dacl = descriptor.GetSecurityDescriptorDacl()
        dacl.AddAccessAllowedAce(win32security.ACL_REVISION, FILE_GENERIC_READ, restrict_sid)
        win32security.SetNamedSecurityInfo(
            str(allowed), win32security.SE_FILE_OBJECT, win32security.DACL_SECURITY_INFORMATION,
            None, None, dacl, None,
        )
        base = win32security.OpenProcessToken(
            win32api.GetCurrentProcess(), win32con.TOKEN_QUERY | win32con.TOKEN_DUPLICATE
        )
        try:
            base_groups = win32security.GetTokenInformation(base, win32security.TokenGroups)
            for index, (label, flags) in enumerate(cases.items()):
                sids = [] if flags == 0x01 else [(restrict_sid, 0)]
                token = None if flags is None else create_native_token(base, flags, sids)
                try:
                    inspection_token = base if token is None else token
                    inherited_acl = access_check(starter, inspection_token)
                    explicit_acl = access_check(allowed, inspection_token)
                    same_groups = token is None or base_groups == win32security.GetTokenInformation(
                        token, win32security.TokenGroups
                    )
                    if token is not None:
                        win32security.ImpersonateLoggedOnUser(token)
                    if inspect_ancestors and flags in (None, 0x09):
                        change_notify = win32security.LookupPrivilegeValue(None, "SeChangeNotifyPrivilege")
                        privileges = win32security.GetTokenInformation(
                            inspection_token, win32security.TokenPrivileges
                        )
                        enabled = any(
                            luid == change_notify and attributes & win32con.SE_PRIVILEGE_ENABLED
                            for luid, attributes in privileges
                        )
                        print(f"{label}: SeChangeNotifyPrivilege enabled={enabled}")
                        for ancestor in reversed((folder, *folder.parents)):
                            outcomes = [
                                probe(
                                    ancestor, mask, win32con.OPEN_EXISTING,
                                    win32con.FILE_FLAG_BACKUP_SEMANTICS,
                                )
                                for mask in (FILE_LIST_DIRECTORY, FILE_TRAVERSE)
                            ]
                            print(f"  {ancestor}: list={outcomes[0]}, traverse={outcomes[1]}")
                    read = probe(starter, win32con.GENERIC_READ, win32con.OPEN_EXISTING)
                    read_with_grant = probe(allowed, win32con.GENERIC_READ, win32con.OPEN_EXISTING)
                    read_data = probe(starter, FILE_READ_DATA, win32con.OPEN_EXISTING)
                    read_sync = probe(
                        starter,
                        FILE_READ_DATA | win32con.SYNCHRONIZE,
                        win32con.OPEN_EXISTING,
                    )
                    write = probe(
                        folder / f"result-{index}.txt",
                        win32con.GENERIC_WRITE,
                        win32con.CREATE_NEW,
                    )
                    print(
                        f"{label}: generic_read={read}, read_data={read_data}, "
                        f"read_data_sync={read_sync}, create={write}, "
                        f"read_with_restricting_sid_grant={read_with_grant}, "
                        f"access_check_inherited={inherited_acl}, access_check_explicit={explicit_acl}, "
                        f"same_group_sids_and_attributes={same_groups}"
                    )
                finally:
                    if token is not None:
                        win32security.RevertToSelf()
                        token.Close()
        finally:
            base.Close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--parent", type=Path, help="Existing directory for synthetic fixtures")
    parser.add_argument("--inspect-ancestors", action="store_true")
    options = parser.parse_args()
    main(options.parent, options.inspect_ancestors)
