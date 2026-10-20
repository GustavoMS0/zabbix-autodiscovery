"""Minimal JSON-RPC client for the Zabbix API (6.0 to 8.0)."""
import time

import requests


class ZabbixError(Exception):
    pass


SECRET = "\0secret"             # global_macro() value of a secret macro (the API never returns it)
MACRO_TEXT, MACRO_SECRET = 0, 1  # usermacro "type"; secret macros exist since Zabbix 5.0


def _snippet(resp, size=200):
    """Start of a response body for error messages (e.g. an HTML error page from a proxy)."""
    return " ".join(str(getattr(resp, "text", "") or "")[:size].split())


class ZabbixAPI:
    MAX_ATTEMPTS = 3
    BACKOFF = 1.0          # seconds, doubled at each retry

    def __init__(self, url, token=None, user=None, password=None, verify_tls=True):
        url = url.rstrip("/")
        self.url = url if url.endswith(".php") else url + "/api_jsonrpc.php"
        self.session = requests.Session()
        self.session.verify = verify_tls
        self.session.headers["Content-Type"] = "application/json-rpc"
        self._id = 0
        self._auth = None
        self._groups = {}
        self.version_str = self.call("apiinfo.version", {})
        self.version = tuple(int(x) for x in self.version_str.split(".")[:2])
        if token:
            self._set_auth(token)
        elif user:
            self._set_auth(self.call("user.login", {"username": user, "password": password}))
        else:
            raise ZabbixError("set zabbix.token or zabbix.user/password in the config")
        if self.version < (6, 0):
            raise ZabbixError(f"Zabbix {self.version_str} is not supported (6.0 or newer required)")

    def _set_auth(self, secret):
        # The Authorization header exists since 6.4; older versions use the "auth" field
        if self.version >= (6, 4):
            self.session.headers["Authorization"] = f"Bearer {secret}"
        else:
            self._auth = secret

    def call(self, method, params, auth=True):
        """auth=False sends no credentials (required by user.checkAuthentication on 7.x/8.0)."""
        self._id += 1
        payload = {"jsonrpc": "2.0", "method": method, "params": params, "id": self._id}
        headers = {}
        if not auth:
            headers["Authorization"] = None      # None drops the header inherited from the session
        elif self._auth and method not in ("apiinfo.version", "user.login"):
            payload["auth"] = self._auth

        # Retries never repeat a write that may already have been executed: writes are retried only when
        # the request surely did not reach Zabbix (connection refused/reset, 502/503 from a proxy).
        # Read timeouts and 504 (the backend may have processed it) are retried for reads only.
        read_only = method.endswith(".get") or method in ("apiinfo.version", "user.checkAuthentication")
        retry_status = {502, 503} | ({504} if read_only else set())
        for attempt in range(self.MAX_ATTEMPTS):
            last = attempt == self.MAX_ATTEMPTS - 1
            try:
                resp = self.session.post(self.url, json=payload, headers=headers, timeout=60)
            except requests.ConnectionError as exc:              # includes ConnectTimeout: nothing was sent
                if last:
                    raise ZabbixError(f"connection failed calling {method}: {exc}") from exc
                time.sleep(self.BACKOFF * (2 ** attempt))
                continue
            except requests.Timeout as exc:                       # read timeout: Zabbix may have run it
                if last or not read_only:
                    raise ZabbixError(f"timeout calling {method}: {exc}") from exc
                time.sleep(self.BACKOFF * (2 ** attempt))
                continue
            if resp.status_code in retry_status and not last:
                time.sleep(self.BACKOFF * (2 ** attempt))
                continue
            if resp.status_code >= 400:
                raise ZabbixError(f"{method}: HTTP {resp.status_code} from {self.url}: {_snippet(resp)!r}")
            try:
                body = resp.json()
            except ValueError as exc:
                raise ZabbixError(f"{method}: invalid (non-JSON) response from {self.url} "
                                  f"(HTTP {resp.status_code}): {_snippet(resp)!r}") from exc
            if not isinstance(body, dict):
                raise ZabbixError(f"{method}: unexpected response from {self.url} (HTTP {resp.status_code})")
            if "error" in body:
                err = body["error"]
                raise ZabbixError(f"{method}: {err.get('message')} {err.get('data', '')}".strip())
            return body["result"]

    def close(self):
        """Close the underlying HTTP session."""
        self.session.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    # --- helpers ---

    def ensure_hostgroup(self, name):
        if name not in self._groups:
            found = self.call("hostgroup.get", {"output": ["groupid"], "filter": {"name": [name]}})
            if found:
                self._groups[name] = found[0]["groupid"]
            else:
                self._groups[name] = self.call("hostgroup.create", {"name": name})["groupids"][0]
        return self._groups[name]

    def ensure_templategroup(self, name):
        """Template groups are separate from host groups since 6.2."""
        if self.version < (6, 2):
            return self.ensure_hostgroup(name)
        found = self.call("templategroup.get", {"output": ["groupid"], "filter": {"name": [name]}})
        if found:
            return found[0]["groupid"]
        return self.call("templategroup.create", {"name": name})["groupids"][0]

    def template_ids(self):
        """Visible/technical name -> templateid for every template."""
        result = {}
        for t in self.call("template.get", {"output": ["templateid", "host", "name"]}):
            result[t["host"]] = t["templateid"]
            result[t["name"]] = t["templateid"]
        return result

    def _global_macro(self, macro):
        found = self.call("usermacro.get", {"globalmacro": True, "filter": {"macro": macro},
                                            "output": ["globalmacroid", "value", "type"]})
        return found[0] if found else None

    @staticmethod
    def _is_secret(found):
        return str(found.get("type", MACRO_TEXT)) == str(MACRO_SECRET) or "value" not in found

    def global_macro(self, macro):
        """Current value, None when missing, SECRET for a secret macro (the API does not return its value)."""
        found = self._global_macro(macro)
        if not found:
            return None
        return SECRET if self._is_secret(found) else found["value"]

    def ensure_global_macro(self, macro, value, secret=False):
        """Create the global macro if missing (as a secret macro when secret=True). Returns the current value.

        An existing macro is never changed, except that a plain-text macro holding exactly this value is
        turned into a secret one when secret=True (same value, only hidden)."""
        found = self._global_macro(macro)
        if found is None:
            self.call("usermacro.createglobal", {"macro": macro, "value": value,
                                                 "type": MACRO_SECRET if secret else MACRO_TEXT})
            return value
        if self._is_secret(found):
            return SECRET
        if secret and found["value"] == value:
            self.call("usermacro.updateglobal", {"globalmacroid": found["globalmacroid"],
                                                 "type": MACRO_SECRET, "value": value})
        return found["value"]
