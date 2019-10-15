from __future__ import print_function, absolute_import
import os
import logging
import subprocess  # call
from pyparsing import (
    Literal,
    CaselessLiteral,
    CaselessKeyword,
    White,
    Word,
    alphanums,
    Empty,
    CharsNotIn,
    Forward,
    Group,
    SkipTo,
    Optional,
    OneOrMore,
    ZeroOrMore,
    pythonStyleComment,
    lineEnd,
    Suppress,
    indentedBlock,
    ParseException,
)

from pyparsing import Dict as pyparsing_Dict

from typing import List, Dict, Any

logger = logging.getLogger(__name__)


class EmptySSHConfig(Exception):
    def __init__(self, path):
        super().__init__("Empty SSH Config: %s" % path)


class WrongSSHConfig(Exception):
    def __init__(self, path):
        super().__init__("Wrong SSH Config: %s" % path)


class Host(object):
    """
    """
    keywords = [
        ("AddressFamily", str), # any, inet, inet6
        ("BatchMode", str),
        ("BindAddress", str),
        ("ChallengeResponseAuthentication", str), # yes, no
        ("CheckHostIP", str), # yes, no
        ("Cipher", str),
        ("Ciphers", str),
        ("ClearAllForwardings", str), # yes, no
        ("Compression", str), # yes, no
        ("CompressionLevel", int), # 1 to 9
        ("ConnectionAttempts", int), # default: 1
        ("ConnectTimeout", int),
        ("ControlMaster", str), # yes, no
        ("ControlPath", str), 
        ("DynamicForward", str), #[bind_address:]port, [bind_adderss/]port
        ("EnableSSHKeysign", str), # yes, no
        ("EscapeChar", str), #default: '~'
        ("ExitOnForwardFailure", str), #yes, no
        ("ForwardAgent", str), # yes, no
        ("ForwardX11", str), # yes, no
        ("ForwardX11Trusted", str), # yes, no
        ("GatewayPorts", str), # yes, no
        ("GlobalKnownHostsFile", str), # yes, no
        ("GSSAPIAuthentication", str), # yes, no
        ("HostName", str),
        ("User", str),
        ("Port", int),
        ("IdentityFile", str),
        ("LocalCommand", str),
        ("LocalForward", str),
        ("LogLevel", str),
        ("ProxyCommand", str),
        ("Match", str),
        ("AddKeysToAgent", str),
        ("BindInterface", str),
        ("CanonialDomains", str),
        ("CnonicalizeFallbackLocal", str),
        ("IdentityAgent", str),
        ("PreferredAuthentications", str),
        ("ServerAliveInterval", int),
        ("UsePrivilegedPort", str), # yes, no
    ]

    def __init__(self, host: List, attrs: Dict) -> None:
        if not isinstance(host, List):
            raise TypeError(f"host must be a List, but given {type(host)}")
        
        if not isinstance(attrs, Dict):
            raise TypeError(f"host must be a Dict, but given {type(host)}")
        self._host = host
        self._attrs = dict()
        attrs = {key.upper(): value for key, value in attrs.items()}
        for attr, attr_type in Host.keywords:
            if attrs.get(attr.upper()):
                try:
                    self._attrs[attr] = attr_type(attrs.get(attr.upper()))
                except TypeError:
                    raise TypeError(f"{attr} value is not expected type, {attr_type}, {type(attrs.get('attr.uppe()'))}")

    def attributes(self, exclude=[], include=[]):
        if exclude and include:
            raise Exception("exclude and include cannot be together")
        if exclude:
            return {
                key: self._attrs[key] for key in self._attrs if key not in exclude
            }
        elif include:
            return {key: self._attrs[key] for key in self._attrs if key in include}
        return self._attrs

    def __str__(self):
        return self.as_string()

    def __getattr__(self, key):
        return self._attrs.get(key)

    @property
    def host(self) -> List:
        return self._host
    
    @property
    def rawhost(self) -> str:
        return ' '.join(self._host)

    def update(self, attrs: Dict):
        if isinstance(attrs, dict):
            self._attrs.update(attrs)
            return self
        raise AttributeError

    def get(self, key: str, default=None):
        return self._attrs.get(key, default)

    def set(self, key: str, value: Any):
        self._attrs[key] = value

    def command(self, cmd="ssh"):
        if self.Port and self.Port != 22:
            port = "-p {port} ".format(port=self.Port)
        else:
            port = ""

        if self.User:
            user = "%s@" % self.User
        else:
            user = ""

        return "{cmd} {port}{username}{host}".format(
            cmd=cmd, port=port, username=user, host=self.HostName
        )
    
    def as_dict(self) -> Dict:
        d = {'host': self.host}
        d.update(self._attrs)
        return d
    
    def as_string(self) -> str:
        s = (f"Host {self.rawhost}\n")
        for attr in self.attributes():
            s += ("    %s %s\n" % (attr, self.get(attr)))
    def ansible(self):
        pass


class SSHConfig(object):
    def __init__(self, path):
        self.__path = path
        self.__hosts = []
        self.raw = None

    @classmethod
    def load(cls, config_path):
        logger.debug("Load: %s" % config_path)
        ssh_config = cls(config_path)

        with open(config_path, "r") as f:
            ssh_config.raw = f.read()
        if len(ssh_config.raw) <= 0:
            raise EmptySSHConfig(config_path)
        # logger.debug("DATA: %s", data)
        parsed = ssh_config.parse()
        if parsed is None:
            raise WrongSSHConfig(config_path)
        for name, config in sorted(parsed.asDict().items()):
            attrs = dict()
            for attr in config:
                attrs.update(attr)
            ssh_config.append(
                Host(name.split(), attrs)
            )
        return ssh_config

    def parse(self, data=""):
        if data:
            self.raw = data

        SPACE = White().suppress()
        SEP = Suppress(SPACE) | Suppress("=")
        HOST_KEY = CaselessLiteral("Host").suppress()
        KEY = Word(alphanums)
        HOST = Word(alphanums + '~%*?!._-+/,"')
        paramValueDef = SkipTo("#" | lineEnd)
        indentStack = [1]

        HostDecl = HOST_KEY + SEP + HOST
        paramDef = pyparsing_Dict(Group(KEY + SEP + paramValueDef))
        block = indentedBlock(paramDef, indentStack)
        HostBlock = pyparsing_Dict(Group(HostDecl + block))
        try:
            return OneOrMore(HostBlock).ignore(pythonStyleComment).parseString(self.raw)
        except ParseException as e:
            print(e)
            return None

    def __iter__(self):
        return self.__hosts.__iter__()

    def __next__(self):
        return self.__hosts.next()

    def __getitem__(self, idx):
        return self.__hosts[idx]

    def hosts(self):
        return self.__hosts

    def update(self, name, attrs:dict):
        for idx, host in enumerate(self.__hosts):
            if name == host.rawhost:
                host.update(attrs)
                self.__hosts[idx] = host

    def get(self, name, raise_exception=True):
        for host in self.__hosts:
            if host.host == name:
                return host
        if raise_exception:
            raise KeyError
        return None

    def append(self, host: Host) -> None:
        if not isinstance(host, Host):
            raise TypeError
        self.__hosts.append(host)

    def remove(self, name):
        host = self.get(name, raise_exception=False)
        if host:
            self.__hosts.remove(host)
            return True
        return False

    def write(self, filename: str="") -> str:
        if filename:
            self.__path = filename
        with open(self.__path, "w") as f:
            for host in self.__hosts:
                f.write(host.as_string())
        return self.__path

    def as_dict(self):
        return [host.as_dict() for host in self.__hosts]
