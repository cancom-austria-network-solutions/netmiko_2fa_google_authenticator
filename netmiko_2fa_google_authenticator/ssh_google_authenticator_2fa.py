#  Copyright 2024 Wilhelm Putz, CANCOM Austria AG

#    Licensed under the Apache License, Version 2.0 (the "License");
#    you may not use this file except in compliance with the License.
#    You may obtain a copy of the License at

#        http://www.apache.org/licenses/LICENSE-2.0

#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS,
#    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#    See the License for the specific language governing permissions and
#    limitations under the License.

"""Google Auth 2FA driver."""
from typing import Any
import logging
import paramiko
from netmiko.linux import LinuxSSH
import socket

from typing import (
    Optional,
    Callable,
    Any,
    List,
    Dict,
    TypeVar,
    cast,
    Type,
    Sequence,
    Iterator,
    TextIO,
    Union,
    Tuple,
    Deque,
)
from netmiko.session_log import SessionLog

# otp code from https://github.com/grahammitchell/google-authenticator
import hmac, base64, struct, hashlib, time, json, os


def get_hotp_token(secret, intervals_no):
    """This is where the magic happens."""
    key = base64.b32decode(
        normalize(secret), True
    )  # True is to fold lower into uppercase
    msg = struct.pack(">Q", intervals_no)
    h = bytearray(hmac.new(key, msg, hashlib.sha1).digest())
    o = h[19] & 15
    h = str((struct.unpack(">I", h[o : o + 4])[0] & 0x7FFFFFFF) % 1000000)
    return prefix0(h)


def get_totp_token(secret):
    """The TOTP token is just a HOTP token seeded with every 30 seconds."""
    return get_hotp_token(secret, intervals_no=int(time.time()) // 30)


def normalize(key):
    """Normalizes secret by removing spaces and padding with = to a multiple of 8"""
    k2 = key.strip().replace(" ", "")
    # k2 = k2.upper()       # skipped b/c b32decode has a foldcase argument
    if len(k2) % 8 != 0:
        k2 += "=" * (8 - len(k2) % 8)
    return k2


def prefix0(h):
    """Prefixes code with leading zeros if missing."""
    if len(h) < 6:
        h = "0" * (6 - len(h)) + h
    return h


# end code from https://github.com/grahammitchell/google-authenticator


class SecretsFilter(logging.Filter):
    def __init__(self, no_log: Optional[Dict[Any, str]] = None) -> None:
        self.no_log = no_log

    def filter(self, record: logging.LogRecord) -> bool:
        """Removes secrets (no_log) from messages"""
        if self.no_log:
            for hidden_data in self.no_log.values():
                if isinstance(hidden_data, list):
                    for item in hidden_data:
                        record.msg = record.msg.replace(item, "********")
                else:
                    if hidden_data:
                        record.msg = record.msg.replace(hidden_data, "********")
        return True


import netmiko

netmiko.base_connection.SecretsFilter = SecretsFilter


class LinuxSSH2FAGoogleClient(paramiko.SSHClient):
    def _auth(
        self,
        username,
        password,
        pkey,
        key_filenames,
        allow_agent,
        look_for_keys,
        gss_auth,
        gss_kex,
        gss_deleg_creds,
        gss_host,
        passphrase,
    ):
        if not isinstance(password, list):
            password = [password, None]
            if self._otp_secret:
                password[1] = get_totp_token(self._otp_secret)
            else:
                password[1] = input("Enter OTP: ")

        def google_gw_pw_handler(title, instructions, prompt_list):
            resp = []
            for pr in prompt_list:
                if str(pr[0]).strip() == "Verification code:":
                    resp.append(password[1])
                if str(pr[0]).strip() == "Password:":
                    resp.append(password[0])
            return tuple(resp)

        self._transport.auth_interactive_dumb(username, google_gw_pw_handler)
        # self._transport.auth_interactive_dumb(username, google_gw_pw_handler)

        return


class LinuxSSH2FAGoogle(LinuxSSH):
    def _build_ssh_client(self):
        """Prepare for Paramiko SSH connection."""
        # Create instance of SSHClient object
        remote_conn_pre = LinuxSSH2FAGoogleClient()
        remote_conn_pre._otp_secret = self._otp_secret

        # Load host_keys for better SSH security
        if self.system_host_keys:
            remote_conn_pre.load_system_host_keys()
        if self.alt_host_keys and os.path.isfile(self.alt_key_file):
            remote_conn_pre.load_host_keys(self.alt_key_file)

        # Default is to automatically add untrusted hosts (make sure appropriate for your env)
        remote_conn_pre.set_missing_host_key_policy(self.key_policy)
        return remote_conn_pre

    def __init__(
        self,
        ip: str = "",
        host: str = "",
        username: str = "",
        password: Optional[str] = None,
        secret: str = "",
        port: Optional[int] = None,
        device_type: str = "",
        verbose: bool = False,
        global_delay_factor: float = 1,
        global_cmd_verify: Optional[bool] = None,
        use_keys: bool = False,
        key_file: Optional[str] = None,
        pkey: Optional[paramiko.PKey] = None,
        passphrase: Optional[str] = None,
        disabled_algorithms: Optional[Dict[str, Any]] = None,
        allow_agent: bool = False,
        ssh_strict: bool = False,
        system_host_keys: bool = False,
        alt_host_keys: bool = False,
        alt_key_file: str = "",
        ssh_config_file: Optional[str] = None,
        conn_timeout: int = 10,
        auth_timeout: Optional[int] = None,
        banner_timeout: int = 15,
        blocking_timeout: int = 20,
        timeout: int = 100,
        session_timeout: int = 60,
        read_timeout_override: Optional[float] = None,
        keepalive: int = 0,
        default_enter: Optional[str] = None,
        response_return: Optional[str] = None,
        serial_settings: Optional[Dict[str, Any]] = None,
        fast_cli: bool = True,
        _legacy_mode: bool = False,
        session_log: Optional[SessionLog] = None,
        session_log_record_writes: bool = False,
        session_log_file_mode: str = "write",
        allow_auto_change: bool = False,
        encoding: str = "utf-8",
        sock: Optional[socket.socket] = None,
        auto_connect: bool = True,
        delay_factor_compat: bool = False,
        target_device_type: str = "linux",
        otp_secret: Optional[str] = None,
    ) -> None:
        self._target_device_type = target_device_type
        self._otp_secret = otp_secret
        super().__init__(
            ip,
            host,
            username,
            password,
            secret,
            port,
            device_type,
            verbose,
            global_delay_factor,
            global_cmd_verify,
            use_keys,
            key_file,
            pkey,
            passphrase,
            disabled_algorithms,
            allow_agent,
            ssh_strict,
            system_host_keys,
            alt_host_keys,
            alt_key_file,
            ssh_config_file,
            conn_timeout,
            auth_timeout,
            banner_timeout,
            blocking_timeout,
            timeout,
            session_timeout,
            read_timeout_override,
            keepalive,
            default_enter,
            response_return,
            serial_settings,
            fast_cli,
            _legacy_mode,
            session_log,
            session_log_record_writes,
            session_log_file_mode,
            allow_auto_change,
            encoding,
            sock,
            auto_connect,
            delay_factor_compat,
        )

    def _open(self) -> None:
        """Decouple connection creation from __init__ for mocking."""
        self._modify_connection_params()
        self.establish_connection(511, 511)
        self._try_session_preparation()
        if self._target_device_type:
            netmiko.redispatch(self, self._target_device_type)
            self.find_prompt()


import netmiko
from netmiko.ssh_dispatcher import CLASS_MAPPER

netmiko.platforms.append("2fa_google_authenticator")
CLASS_MAPPER["2fa_google_authenticator"] = LinuxSSH2FAGoogle
