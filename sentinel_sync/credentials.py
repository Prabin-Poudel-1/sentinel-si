"""No plaintext credential fallback. Optional keyring uses native OS stores only."""
import sys


class CredentialUnavailable(RuntimeError):
    pass


class SystemCredentials:
    def __init__(self):
        try:
            import keyring
            backend = keyring.get_keyring()
            allowed = {"darwin": "keyring.backends.macOS", "linux": "keyring.backends.SecretService",
                       "win32": "keyring.backends.Windows"}
            if type(backend).__module__ != allowed.get(sys.platform):
                raise CredentialUnavailable("Native OS credential store unavailable")
            self.backend = backend
        except (ImportError, RuntimeError) as exc:
            raise CredentialUnavailable("Install keyring and enable the native OS credential store") from exc

    def get(self, name):
        return self.backend.get_password("Sentinel AI sync", name)

    def set(self, name, token):
        self.backend.set_password("Sentinel AI sync", name, token)

    def delete(self, name):
        if self.get(name) is not None:
            self.backend.delete_password("Sentinel AI sync", name)


class MemoryTestCredentials:
    """Test fixture only; caller must also enable allow_test_credentials explicitly."""
    def __init__(self):
        self.values = {}

    def get(self, name):
        return self.values.get(name)

    def set(self, name, token):
        self.values[name] = token

    def delete(self, name):
        self.values.pop(name, None)
