"""Trusted host setup. Windows ACLs are distinct from agent filesystem capabilities.

Agent host-file tools remain disabled on Windows. State must live on a local ACL
filesystem under a trusted parent, not a share, junction or attacker-owned directory.
"""
import os
import stat
from pathlib import Path


class DirectoryGuard:
    def __init__(self, handle=None):
        self.handle = handle

    def close(self):
        if self.handle is not None:
            if isinstance(self.handle, int):
                os.close(self.handle)
            else:
                self.handle.Close()
            self.handle = None

    def __del__(self):
        self.close()


def runtime_binary(root):
    return Path(os.environ.get("SENTINEL_RUNTIME", str(Path(root) / "target" / "debug" /
                ("sentinel-runtime.exe" if os.name == "nt" else "sentinel-runtime"))))


def child_environment():
    environment = {"LANG": "C"}
    if os.name == "nt":
        # Windows loader requires SystemRoot. Do not inherit PATH or provider keys.
        system_root = os.environ.get("SystemRoot")
        if not system_root:
            raise RuntimeError("SystemRoot is required on Windows")
        environment["SystemRoot"] = system_root
    return environment


def private_directory(directory, *, initialize=True):
    path = Path(directory).absolute()
    if os.name != "nt":
        if initialize:
            path.mkdir(parents=True, exist_ok=True, mode=0o700)
        # Harden and inspect the same inode, never chmod through a symlink.
        # The parent must remain trusted; this is not isolation from same-UID code.
        try:
            fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        except OSError:
            raise ValueError("State requires a regular private directory") from None
        guard = DirectoryGuard(fd)
        try:
            info = os.fstat(fd)
            if info.st_uid != os.getuid():
                raise ValueError("State must be owned by the current user")
            if initialize:
                os.fchmod(fd, 0o700)
            if os.fstat(fd).st_mode & 0o077:
                raise ValueError("State directory must have mode 0700")
            if not initialize:
                for name in os.listdir(fd):
                    item = os.stat(name, dir_fd=fd, follow_symlinks=False)
                    if not stat.S_ISREG(item.st_mode) or item.st_nlink != 1 or item.st_uid != os.getuid():
                        raise ValueError("Linked or unexpected control-state files are forbidden")
            return guard
        except Exception:
            guard.close()
            raise
    # Imported only on Windows; absence fails closed, never falls back to chmod.
    import ntsecuritycon as nt
    import win32api
    import win32con as wc
    import win32file as wf
    import win32security as ws

    if not path.drive or str(path).startswith("\\\\") or ':' in str(path)[2:]:
        raise ValueError("Windows state requires a local drive path without streams")
    # Defense in depth; handle flags and a protected DACL provide the OS boundary.
    for ancestor in [path, *path.parents]:
        if ancestor.exists() and ancestor.lstat().st_file_attributes & 0x400:
            raise ValueError("Reparse points are not allowed in the state path")
    if not win32api.GetVolumeInformation(path.anchor)[3] & 0x8:
        raise ValueError("Persistent filesystem ACLs are required")
    token = ws.OpenProcessToken(win32api.GetCurrentProcess(), wc.TOKEN_QUERY)
    try:
        user = ws.GetTokenInformation(token, ws.TokenUser)[0]
    finally:
        token.Close()
    system = ws.CreateWellKnownSid(ws.WinLocalSystemSid, None)
    allowed = {ws.ConvertSidToStringSid(user), ws.ConvertSidToStringSid(system)}
    owners = allowed | {ws.ConvertSidToStringSid(ws.CreateWellKnownSid(ws.WinBuiltinAdministratorsSid, None))}
    acl = ws.ACL()
    flags = wc.OBJECT_INHERIT_ACE | wc.CONTAINER_INHERIT_ACE
    for sid in (user, system):
        acl.AddAccessAllowedAceEx(ws.ACL_REVISION, flags, nt.FILE_ALL_ACCESS, sid)
    if initialize and not path.exists():
        # Parent creation is deliberately not recursive: the administrator selects
        # an existing trusted parent. The DACL is applied at directory creation.
        import pywintypes
        attributes = pywintypes.SECURITY_ATTRIBUTES()
        descriptor = ws.SECURITY_DESCRIPTOR()
        descriptor.SetSecurityDescriptorDacl(1, acl, 0)
        descriptor.SetSecurityDescriptorControl(ws.SE_DACL_PROTECTED, ws.SE_DACL_PROTECTED)
        attributes.SECURITY_DESCRIPTOR = descriptor
        wf.CreateDirectory(str(path), attributes)
    handle = wf.CreateFile(str(path), wc.READ_CONTROL | wc.WRITE_DAC | nt.FILE_READ_ATTRIBUTES | nt.FILE_LIST_DIRECTORY,
                           wc.FILE_SHARE_READ | wc.FILE_SHARE_WRITE, None, wc.OPEN_EXISTING,
                           wc.FILE_FLAG_BACKUP_SEMANTICS | wf.FILE_FLAG_OPEN_REPARSE_POINT, None)
    guard = DirectoryGuard(handle)
    try:
        info = wf.GetFileInformationByHandle(handle)
        if info[0] & wc.FILE_ATTRIBUTE_REPARSE_POINT or not info[0] & wc.FILE_ATTRIBUTE_DIRECTORY:
            raise ValueError("State must be a regular directory")
        descriptor = ws.GetSecurityInfo(handle, ws.SE_FILE_OBJECT,
                                        ws.OWNER_SECURITY_INFORMATION | ws.DACL_SECURITY_INFORMATION)
        if ws.ConvertSidToStringSid(descriptor.GetSecurityDescriptorOwner()) not in owners:
            raise ValueError("State is not owned by the current administrator")
        # Empty TemporaryDirectory fixtures may inherit broad ACLs. Harden through
        # the pinned handle before writing any sensitive contents, never a path.
        if initialize and not any(path.iterdir()):
            ws.SetSecurityInfo(handle, ws.SE_FILE_OBJECT,
                               ws.DACL_SECURITY_INFORMATION | ws.PROTECTED_DACL_SECURITY_INFORMATION,
                               None, None, acl, None)
        def validate(file_handle, require_protected=False):
            sd = ws.GetSecurityInfo(file_handle, ws.SE_FILE_OBJECT,
                                    ws.OWNER_SECURITY_INFORMATION | ws.DACL_SECURITY_INFORMATION)
            if ws.ConvertSidToStringSid(sd.GetSecurityDescriptorOwner()) not in owners:
                raise ValueError("Unexpected state owner")
            if require_protected and not sd.GetSecurityDescriptorControl()[0] & ws.SE_DACL_PROTECTED:
                raise ValueError("State DACL must block inherited permissions")
            dacl = sd.GetSecurityDescriptorDacl()
            if dacl is None or dacl.GetAceCount() == 0:
                raise ValueError("State DACL is missing")
            for index in range(dacl.GetAceCount()):
                ace = dacl.GetAce(index)
                if ace[0][0] != ws.ACCESS_ALLOWED_ACE_TYPE or ws.ConvertSidToStringSid(ace[2]) not in allowed:
                    raise ValueError("State DACL grants unexpected access")
        validate(handle, True)
        # Reopened SQLite/auth files must not redirect to another inode or stream.
        # Other users cannot mutate this directory; same-user hostile code is out of scope.
        for child in path.iterdir():
            if child.is_dir():
                raise ValueError("Unexpected subdirectory in control state")
            item = wf.CreateFile(str(child), wc.READ_CONTROL | nt.FILE_READ_ATTRIBUTES,
                                 wc.FILE_SHARE_READ | wc.FILE_SHARE_WRITE, None, wc.OPEN_EXISTING,
                                 wf.FILE_FLAG_OPEN_REPARSE_POINT, None)
            try:
                data = wf.GetFileInformationByHandle(item)
                if data[0] & wc.FILE_ATTRIBUTE_REPARSE_POINT or data[7] != 1:
                    raise ValueError("Linked/reparse state files are forbidden")
                validate(item)
            finally:
                item.Close()
        return guard
    except Exception:
        guard.close()
        raise
