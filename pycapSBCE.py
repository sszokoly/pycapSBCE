#!/usr/bin/env python
# -*- encoding: utf-8 -*-
"""
#############################################################################
## Name: pycapSBCE
## This tool monitors SIP sessions in Avaya SBCE for the purpose of tracking
## and displaying flow and RTP connection details for audio media. It can
## take tcpdump samples of RTP streams and provides RTP statistics from those
## samples. The collected information can be dumpped to a file every time
## when the max number of call limit is reached automatically or manually.
## Options: see help, -h
## Date: 2020-11-29
## Author: sszokoly@protonmail.com
#############################################################################
"""
from __future__ import print_function
import bz2
import cPickle
import curses
import curses.textpad
import fcntl
import gzip
import locale
import logging
import os
import re
import resource
import shlex
import signal
import string
import sys
from datetime import datetime, timedelta
from collections import deque, namedtuple, Counter, MutableMapping, OrderedDict
from copy import copy
from functools import wraps
from glob import glob
from itertools import chain, islice, izip_longest
from math import ceil
from netifaces import interfaces, ifaddresses
from operator import itemgetter
from optparse import OptionParser, SUPPRESS_HELP
from platform import node
from Queue import Queue
from subprocess import Popen, PIPE
from textwrap import wrap
from threading import Thread, Lock


############################################################################
#                                 Globals                                  #
############################################################################


HELP = """
This tool monitors SIP sessions in Avaya SBCE for the purpose of tracking and
displaying flow and RTP connection details for audio media.It can take tcpdump
snapshots of RTP streams and provides RTP statistics for those samples. The
collected information is written to a file every time when the maximum number
of calls limit is reached.                                                    
Version: {0}
"""
MAX_AUTODUMP_HRS = 24       # max noof hrs's worth of dumps kept on disc
MAXLEN = 2000               # max noof calls retained in memory
MAX_PACKETS = 20000         # max noof packets per tcpdump samples
MIN_FLOW_UPDATE_SECS = 2    # min noof secs between showflow runs
MIN_TSHARK_UPDATE_SECS = 2  # min noof secs between pcap analysis updates

TERM = os.environ["TERM"]
LOCALE = locale.getlocale()
DEBUG_LOG = "pycapSBCE.log"
VERSION = 0.1

##############################################################################
#                                   MODULES                                  #
##############################################################################

##############################################################################
#                                    asbce                                   #
##############################################################################


Server = namedtuple("Server", ["name", "type"])


def memoize(func):
    """A decorator to cache the return value of func.

    Args:
        func: function to decorate

    Returns:
        wrapper: decorated function
    """
    cache = {}

    def wrapper(args):
        try:
            return cache[args]
        except KeyError:
            cache[args] = func(args)
            return cache[args]
    return wrapper


class Flow(object):
    """Data structure to store flow counters."""
    __slots__ = [
        "InIf", "InSrcIP", "InSrcPort", "InDstIP", "InDstPort", "OutIf",
        "OutSrcIP", "OutSrcPort", "OutDstIP", "OutDstPort", "InVlan",
        "OutVlan", "Enc", "Dec", "Snt", "Drp", "Rx", "Rly", "Ech"
    ]

    def __init__(self, InIf, InSrcIP, InSrcPort, InDstIP, InDstPort, OutIf,
                 OutSrcIP, OutSrcPort, OutDstIP, OutDstPort, InVlan, OutVlan,
                 Enc, Dec, Snt, Drp, Rx, Rly, Ech):
        self.InIf = InIf
        self.InSrcIP = InSrcIP
        self.InSrcPort = InSrcPort
        self.InDstIP = InDstIP
        self.InDstPort = InDstPort
        self.OutIf = OutIf
        self.OutSrcIP = OutSrcIP
        self.OutSrcPort = OutSrcPort
        self.OutDstIP = OutDstIP
        self.OutDstPort = OutDstPort
        self.InVlan = InVlan
        self.OutVlan = OutVlan
        self.Enc = Enc
        self.Dec = Dec
        self.Snt = Snt
        self.Drp = Drp
        self.Rx = Rx
        self.Rly = Rly
        self.Ech = Ech

    def __lt__(self, other):
        return self.InIf < other.InIf

    def __gt__(self, other):
        return self.InIf > other.InIf

    def _asdict(self):
        return {slot: getattr(self, slot, None) for slot in self.__slots__}

    def __repr__(self):
        return "Flow({0})".format(
            ", ".join(repr(getattr(self, k)) for k in self.__slots__)
        )


class Msg(object):
    """Data structure to store trace log message info."""
    __slots__ = ["srcip", "srcport", "dstip", "dstport", "timestamp",
                 "direction", "body", "proto", "method"]

    def __init__(self, srcip="", srcport=None, dstip="", dstport=None,
                 timestamp=None, direction="", body="", proto="", method=""):
        self.srcip = srcip
        self.srcport = srcport
        self.dstip = dstip
        self.dstport = dstport
        self.timestamp = timestamp
        self.direction = direction
        self.body = body
        self.proto = proto
        self.method = method

    def __str__(self):
        return str({k: getattr(self, k) for k in self.__slots__})


class SsyndiSIPReader(object):
    """Generator class which parses SSYNDI log files, extracts CALL CONTROL
    type SIP messages and yields Msg class instance.
    """
    LOGDIR = "/usr/local/ipcs/log/ss/logfiles/elog/SSYNDI"
    SSYNDI_GLOB = "SSYNDI_*_ELOG_*"

    def __init__(self, logfiles=None, logdir=None, methods=None,
                 ignore_fnu=False):
        """Initializes a SsyndiSIPReader instance.

        Args:
            logfiles (list(str), optional): a collection of SSYNDI log files
                to parse, if not provided it starts reading the latest SSYNDI
                log in LOGDIR and keep doing it so when the log file rotates
            logdir (str): path to directory if SSYNDI logs are not under the
                default LOGDIR folder
            methods (list): list of methods to capture
            ignore_fnu (bool): to ignore "off-hook" "ec500" fnu requests

        Returns:
            gen (SsyndiSIPReader): a SsyndiSIPReader generator

        Raises:
            StopIteration: when logfiles is not None and reached the end
                of the last logfile
        """
        self.logdir = logdir or self.LOGDIR
        self.ssyndi_glob = os.path.join(self.logdir, self.SSYNDI_GLOB)
        self.methods = set(methods) if methods else None
        self.ignore_fnu = ignore_fnu

        if logfiles:
            self.logfiles = logfiles
            self.total_logfiles = len(logfiles)
            try:
                self.filename = self.logfiles.pop(0)
            except IndexError:
                raise StopIteration
            self.fd = open(self.filename)
        else:
            self.total_logfiles = 0
            self.filename = self.last_ssyndi()
            self.fd = open(self.filename)
            self.fd.seek(0, 2)

    def __next__(self):
        """Generator"""
        readaline = self.fd.readline
        while True:
            line = readaline()
            if not line:
                if self.total_logfiles:
                    self.fd.close()
                    try:
                        self.filename = self.logfiles.pop(0)
                    except IndexError:
                        raise StopIteration
                elif (
                        os.stat(self.filename).st_size < 10482000 or
                        self.filename == self.last_ssyndi()
                ):
                    return None
                else:
                    self.fd.close()
                    self.filename = self.last_ssyndi()
                self.fd = open(self.filename)
                readaline = self.fd.readline
            elif "SIP MSG AT CALL CONTROL" in line:
                lines = [line]
                while not lines[-1].startswith("IP:"):
                    lines.append(readaline())

                if self.methods and self._method(lines) not in self.methods:
                    continue
                if self.ignore_fnu and self._is_fnu(lines[1]):
                    continue

                msg = Msg(**self.splitaddr(lines[-1]))
                msg.timestamp = self.strptime(lines[0][1:27])
                msg.direction = lines[0][-5:-2].lstrip()
                msg.body = "".join(lines[1:-1])
                msg.proto = self.get_proto(msg.body)
                msg.method = self._method(lines)
                return msg

    def __iter__(self):
        return self

    def next(self):
        return self.__next__()

    def last_ssyndi(self):
        """str: Returns the last SSYNDI log file by file name."""
        return max(x for x in glob(self.ssyndi_glob))

    @property
    def progress(self):
        """int: Returns the percentage of processed input logfiles."""
        if self.total_logfiles > 0:
            return int(100-(len(self.logfiles)/float(self.total_logfiles)*100))
        return 100

    @staticmethod
    @memoize
    def splitaddr(line):
        """Parses address line which contains the source and destination
        host IP address and transport protocol port numbers. To speed up
        processing @memoize caches previous responses.

        Args:
            line (str): log line containing IP address and port info

        Returns:
            dict: {"srcip": <str srcip>, "srcport": <str srcport>,
                   "dstip": <str dstip>, "dstport": <str dstport>}
        """
        p = r"IP:(?P<srcip>[a-fx0-9.]*):(?P<srcport>\d+) --> (?P<dstip>[a-fx0-9.]*):(?P<dstport>\d+)"

        try:
            d = re.search(p, line).groupdict()
        except:
            return {"srcip": "", "srcport": None, "dstip": "", "dstport": None}

        if "x" in line:
            d["srcip"] = ".".join(str(int(x, 16)) for x in
                                  wrap(d["srcip"][2:].zfill(8), 2))
            d["dstip"] = ".".join(str(int(x, 16)) for x in
                                  wrap(d["dstip"][2:].zfill(8), 2))
        d["srcport"] = int(d["srcport"])
        d["dstport"] = int(d["dstport"])
        return d

    @staticmethod
    def get_proto(body):
        """Extracts protocol type from the top most Via header.

        Args:
            body (str): SIP message body

        Returns:
            str: Transport protocol type (UDP, TCP or TLS)
        """
        start = body.find("Via:")
        if start == -1:
            start = body.find("v:")
            if start == -1:
                return "UDP"
            else:
                start += 11
        else:
            start += 13
        return body[start:start+3].upper()

    @staticmethod
    def _method(lines):
        """Returns SIP message method from CSeq line.

        Args:
            lines (list): list of SIP message lines

        Returns:
            str: SIP method or empty str
        """
        try:
            hdr = next(x for x in lines if x.startswith("CSeq"))
            if hdr:
                params = hdr.split()
                if len(params) == 3:
                    return params[2]
            return ""
        except StopIteration:
            return ""

    @staticmethod
    def _is_fnu(line):
        """Returns True if line contains FNU.

        Args:
            line (str): SIP Request URI line

        Returns:
            bool: True if line contians off-hook or ec500 FNU
        """
        return ("avaya-cm-fnu=off-hook" in line or
                "avaya-cm-fnu=ec500" in line)

    @staticmethod
    def strptime(s):
        """Converts SSYNDI timestamp to datetime object.

        Note:
            This is 6 times faster than datetime.strptime

        Args:
            s (str): SSYNDI timestamp

        Returns:
            datetime obj: datetime object
        """
        return datetime(
            int(s[6:10]), int(s[0:2]), int(s[3:5]), int(s[11:13]),
            int(s[14:16]), int(s[17:19]), int(s[20:26])
        )


class TracesbcSIPReader(object):
    """Generator class which parses tracesbc_sip log files, extracts
    message details and yields Msg class instance.
    """
    LOGDIR = "/archive/log/tracesbc/tracesbc_sip"
    TRACESBCSIP_GLOB = "tracesbc_sip_[1-9][0-9][0-9]*[!_][!_]"

    def __init__(self, logfiles=None, logdir=None, methods=None,
                 ignore_fnu=False):
        """Initializes a TracesbcSIPReader instance.

        Args:
            logfiles (list(str), optional): a collection of tracesbc_sip
                log files to parse, if not provided it starts reading the
                latest tracesbc_sip log in LOGDIR and keep doing it so
                when the log file rotates
            logdir (str): path to directory if tracesbc_sip logs are not
                under the default LOGDIR folder
            methods (list): list of methods to capture
            ignore_fnu (bool): to ignore "off-hook" "ec500" fnu requests

        Returns:
            gen (TracesbcSIPReader): a TracesbcSIPReader generator

        Raises:
            StopIteration: when logfiles is not None and reached the end
                of the last logfile
        """
        self.logdir = logdir or self.LOGDIR
        self.tracesbc_glob = os.path.join(self.logdir, self.TRACESBCSIP_GLOB)
        self.methods = set(methods) if methods else None
        self.ignore_fnu = ignore_fnu

        if logfiles:
            self.logfiles = logfiles
            self.total_logfiles = len(logfiles)
            try:
                self.filename = self.logfiles.pop(0)
            except IndexError:
                raise StopIteration
            self.fd = self.zopen(self.filename)
        else:
            self.total_logfiles = 0
            if not self._is_last_tracesbc_gzipped():
                self.fd = self.zopen(self.filename)
                self.fd.seek(0, 2)

    def __next__(self):
        if self.fd is None:
            if self._is_last_tracesbc_gzipped():
                return None
            self.fd = self.zopen(self.filename)
        readaline = self.fd.readline
        while True:
            line = readaline()
            if not line:
                if self.total_logfiles:
                    self.fd.close()
                    try:
                        self.filename = self.logfiles.pop(0)
                    except IndexError:
                        raise StopIteration
                elif not os.path.exists(self.filename):
                    self.fd.close()
                    if self._is_last_tracesbc_gzipped():
                        return None
                else:
                    return None
                self.fd = self.zopen(self.filename)
                readaline = self.fd.readline
            elif line.startswith("["):
                lines = [line]
                while not lines[-1].startswith("--"):
                    lines.append(readaline().lstrip("\r\n"))

                if self.methods and self._method(lines[2:]) not in self.methods:
                    continue
                if self.ignore_fnu and self._is_fnu(lines[2]):
                    continue

                msg = Msg(**self.splitaddr(lines[1]))
                msg.timestamp = self.strptime(lines[0][1:-3])
                msg.body = "".join(x for x in lines[2:-1] if x)
                msg.method = self._method(lines)
                return msg

    def __iter__(self):
        return self

    def next(self):
        return self.__next__()

    def last_tracesbc_sip(self):
        """str: Returns the last tracesbc_sip log file."""
        return max(glob(self.tracesbc_glob))

    def _is_last_tracesbc_gzipped(self):
        """bool: Return True if last tracesbce_sip is gzipped."""
        self.filename = self.last_tracesbc_sip()
        if self.filename.endswith(".gz"):
            self.fd = None
            return True
        return False

    @property
    def progress(self):
        """int: Returns the percentage of processed logfiles."""
        if self.total_logfiles:
            return int(100-(len(self.logfiles)/float(self.total_logfiles)*100))
        return 100

    @staticmethod
    @memoize
    def splitaddr(line):
        """Parses line argument which contains the source and destination
        host IP address, transport port numbers, protocol type and message
        direction. To speed up processing @memoize caches previous responses.

        Args:
            line (str): log line containing IP address and port info

        Returns:
            dict: {"direction": <str direction>, "srcip": <str srcip>,
                   "srcport": <str srcport>, "dstip": <str dstip>,
                   "dstport": <str dstport>, "proto": <str proto>}
        """
        pattern = r"(IN|OUT): ([0-9.]*):(\d+) --> ([0-9.]*):(\d+) \((\D+)\)"
        keys = ("direction", "srcip", "srcport", "dstip", "dstport", "proto")
        m = re.search(pattern, line)
        try:
            return dict((k, v) for k, v in zip(keys, m.groups()))
        except:
            return dict((k, None) for k in keys)

    @staticmethod
    def _method(lines):
        """Returns SIP message method from CSeq line.

        Args:
            lines (list): list of SIP message lines

        Returns:
            str: SIP method or empty str
        """
        try:
            hdr = next(x for x in lines if x.startswith("CSeq"))
            if hdr:
                params = hdr.split()
                if len(params) == 3:
                    return params[2]
            return ""
        except StopIteration:
            return ""

    @staticmethod
    def _is_fnu(line):
        return ("avaya-cm-fnu=off-hook" in line or
                "avaya-cm-fnu=ec500" in line)

    @staticmethod
    def strptime(s):
        """Converts SSYNDI timestamp to datetime object.

        Note:
            This is 6 times faster than datetime.strptime()

        Args:
            s (str): SSYNDI timestamp

        Returns:
            datetime obj: datetime object
        """
        return datetime(int(s[6:10]), int(s[0:2]), int(s[3:5]), int(s[11:13]),
                        int(s[14:16]), int(s[17:19]), int(s[20:26]))

    @staticmethod
    def zopen(filename):
        """Return file handle depending on file extension type:

        Args:
            filename (str): name of the logfile including path

        Returns:
            obj: file handler
        """
        if filename.endswith(".gz"):
            return gzip.open(filename)
        elif filename.endswith(".bz2"):
            return bz2.BZ2File(filename)
        else:
            return open(filename)


class ASBCE(object):
    """Simple ASBCE obejct to enable turning ON and OFF debug logging
    for SIPCC subprocess for SSYNDI and obtain basic configuration info.
    """
    SYSINFO_PATH = "/usr/local/ipcs/etc/sysinfo"
    LOGLEVEL_ERR = "Incorrect LOGLEVEL value: {0}"
    RE_FLOW = (
        r"(?P<InIf>\d+) \[",
        r"(?P<InSrcIP>[\d+.]*):",
        r"(?P<InSrcPort>\d+) -> ",
        r"(?P<InDstIP>[\d+.]*):",
        r"(?P<InDstPort>\d+)\] .*OUT ",
        r"(?P<OutIf>\d+) RELAY ",
        r"(?P<OutSrcIP>[\d+.]*):",
        r"(?P<OutSrcPort>\d+) -> ",
        r"(?P<OutDstIP>[\d+.]*):",
        r"(?P<OutDstPort>\d+).*in VLAN ",
        r"(?P<InVlan>\w+) out VLAN ",
        r"(?P<OutVlan>\w+) Enc ",
        r"(?P<Enc>\w+) Dec ",
        r"(?P<Dec>\w+) Snt ",
        r"(?P<Snt>\w+) Drp ",
        r"(?P<Drp>\w+) Rx ",
        r"(?P<Rx>\w+) Rly ",
        r"(?P<Rly>\w+) ECH ",
        r"(?P<Ech>\w+)",
    )

    def __init__(self, mock=False):
        """Initializes Aasbce instance.

        Args:
            mock (bool): if the instance should not make changes in the DB.
        Returns:
            obj: Asbce instance
        """
        self.mock = mock
        self.capture_active = False
        self._ifaces = None
        self._ems_ip = None
        self._mgmt_ip = None
        self._signaling_ifaces = None
        self._media_ifaces = None
        self._publics = None
        self._servers = None
        self._sysinfo = None
        self._version = None
        self._hostname = node()
        self._hardware = None
        self.lastflows = {}
        self.lastflows_timestamp = None
        self.sipcc_loglevel_inital = self.sipcc_loglevel
        self.Flow = Flow
        self.reFlow = re.compile("".join(self.RE_FLOW), re.I)

    @property
    def ems_ip(self):
        """str: Returns the EMS IP address."""
        if self._ems_ip is None:
            cmd = "ps --columns 999 -f -C ssyndi"
            output = self._exec_cmd(cmd)
            m = re.search(r"--ems-node-ip=(\d+\.\d+\.\d+\.\d+)", output)
            if not m:
                self._ems_ip = ""
            else:
                self._ems_ip = m.group(1)
        return self._ems_ip

    @property
    def ifaces(self):
        """dict: Returns the IP addresses of all interface as keys
        and interface names as values. This includes signaling, media
        and IPv6 addresses as well.
        """
        if self._ifaces is None:
            self._ifaces = {
                ifaddr["addr"]:iface for iface in interfaces() for ifaddrs in
                ifaddresses(iface).values() for ifaddr in ifaddrs
            }
            self._ifaces.update({k: self._ifaces[self.publics[k]] for k in
                        set(self.publics).difference(set(self.ifaces))})
        return self._ifaces

    @property
    def mgmt_ip(self):
        """str: Returns the IP address of the SBCE's M1 interface."""
        if self._mgmt_ip is None:
            reverse_ifaces = dict((v, k) for k, v in self.ifaces.items())
            self._mgmt_ip = reverse_ifaces.get("M1", "")
        return self._mgmt_ip

    @property
    def signaling_ifaces(self):
        """dict: Returns the IP addresses of the signaling interfaces
        as keys and namedtuples as values containing the administered
        signaling interface name and public IP address of it as values.
        """
        if self._signaling_ifaces is None:
            self._signaling_ifaces = {}
            SigIface = namedtuple('signaling_iface', ["name", "public_ip"])
            sqlcmd = "SELECT SIGNAL_NAME, IP_ADDRESS, PUBLIC_IP\
                      FROM SIP_SIGNALING_INTERFACE_VIEW"
            signaling_ifaces = self._exec_sql(sqlcmd)
            if signaling_ifaces:
                for signaling_iface in signaling_ifaces.split("\n"):
                    l = signaling_iface.replace("|", "").split()
                    name, ip, public_ip = " ".join(l[0:-2]), l[-2], l[-1]
                    self._signaling_ifaces.update({ip: SigIface(name, public_ip)})
        return self._signaling_ifaces

    @property
    def media_ifaces(self):
        """dict: Returns the IP addresses of the media interfaces
        as keys and namedtuples as values containing the administered
        media interface name, ethernet interface name and public IP address.
        """
        if self._media_ifaces is None:
            self._media_ifaces = {}
            MedIface = namedtuple("media_iface", ["name", "iface", "public_ip"])
            sqlcmd = "SELECT MEDIA_NAME, INTERFACE, IP_ADDRESS, PUBLIC_IP\
                      FROM SIP_MEDIA_INTERFACE_VIEW"
            media_ifaces = self._exec_sql(sqlcmd)
            if media_ifaces:
                for media_iface in media_ifaces.split("\n"):
                    l = media_iface.replace("|", "").split()
                    name, iface, ip, public_ip = " ".join(l[0:-3]), l[-3], l[-2], l[-1]
                    self._media_ifaces.update({ip: MedIface(name, iface, public_ip)})
        return self._media_ifaces

    @property
    def servers(self):
        """dict: Returns the IP addresses of the administered SIP servers
        as keys and namedtuples as values containing the administered SIP
        server name and its type as values.
        """
        if self._servers is None:
            self._servers = {}
            sqlcmd = "SELECT DISTINCT SERVER_CONFIG_NAME, SERVER_TYPE, SERVER_ADDRESS\
                      FROM SIP_SERVER_CONFIG, SIP_SERVER_CONFIG_ADDRESSES\
                      WHERE SIP_SERVER_CONFIG_ADDRESSES.SERVER_CONFIG_ID =\
                            SIP_SERVER_CONFIG.SERVER_CONFIG_ID"
            servers = self._exec_sql(sqlcmd)
            if servers:
                for server in servers.split("\n"):
                    l = server.replace("|", "").split()
                    name, type, ip = " ".join(l[0:-2]), l[-2], l[-1]
                    if type == "CALL_SERVER":
                        type = "Call"
                    else:
                        type = "Trk"
                    self._servers.update({ip: Server(name, type)})
        return self._servers

    @property
    def sysinfo(self):
        """str: Returns the content of the sysinfo file."""
        if self._sysinfo is None:
            with open(self.SYSINFO_PATH, "r") as handle:
                self._sysinfo = handle.read()
        return self._sysinfo

    @property
    def version(self):
        """str: Returns the software version of the SBCE in short format."""
        if self._version is None:
            m = re.search("VERSION=(.*)\n", self.sysinfo)
            if not m:
                self._version = ""
            else:
                self._version = m.group(1).split("-")[0]
        return self._version

    @property
    def publics(self):
        """dict: Returns the public/private interface map."""
        if self._publics is None:
            c = chain(self.signaling_ifaces.items(), self.media_ifaces.items())
            self._publics = dict((v.public_ip, k) for k, v in c)
        return self._publics

    @property
    def hardware(self):
        """str: Returns HARDWARE info from sysinfo."""
        if self._hardware is None:
            m = re.search("HARDWARE=(.*)\n", self.sysinfo)
            if not m:
                self._hardware = "310"
            else:
                self._hardware = m.group(1)
        return self._hardware

    @property
    def hostname(self):
        """str: Returns hostname."""
        return self._hostname

    @property
    def sipcc_loglevel(self):
        """str: Returns the value of 'LOG_SUB_SIPCC' for SSYNDI.

        Raises:
            RuntimeError: if the returned value is something unexpected
                          so as to stop corrupting the DB further
        """
        sqlcmd = "SELECT LOGLEVEL FROM EXECUTION_LOGLEVEL\
                  WHERE SUBSYSTEM='LOG_SUB_SIPCC'"
        value = self._exec_sql(sqlcmd)
        if not re.match("[01]{6}$", value):
            raise RuntimeError(value)
        return value

    @sipcc_loglevel.setter
    def sipcc_loglevel(self, value):
        """Setter method to set the value of 'LOG_SUB_SIPCC' for SSYNDI.

        Args:
            value (str): in a format of [01]{6}

        Returns:
            None

        Raises:
            ValueError: if value argument is unexpected, it can only
                differ from the current sipcc_loglevel value in position 3
                that is at index 2
        """
        pattern = "".join((self.sipcc_loglevel[:2], "[01]", self.sipcc_loglevel[3:]))
        if not re.match(pattern, value):
            raise ValueError(self.LOGLEVEL_ERR.format(value))
        sqlcmd = "UPDATE EXECUTION_LOGLEVEL SET LOGLEVEL='{0}'\
                  WHERE SUBSYSTEM='LOG_SUB_SIPCC'".format(value)
        _ = self._exec_sql(sqlcmd)

    def capture_start(self):
        """Turns on Debug loglevel for 'LOG_SUB_SIPCC' subsystem.

        Returns:
            bool: True if execution was successful, False otherwise
        """
        if self.mock:
            self.capture_active = True
            return True
        value = "".join((self.sipcc_loglevel[:2], "1", self.sipcc_loglevel[3:]))
        self.sipcc_loglevel = value
        if self.sipcc_loglevel == value:
            self.capture_active = True
            return True
        return False

    def capture_stop(self):
        """Turns off Debug loglevel for 'LOG_SUB_SIPCC' subsystem.

        Returns:
            bool: True if execution was successful, False otherwise
        """
        if self.mock:
            self.capture_active = False
            return True
        value = "".join((self.sipcc_loglevel[:2], "0", self.sipcc_loglevel[3:]))
        self.sipcc_loglevel = value
        if self.sipcc_loglevel == value:
            self.capture_active = False
            return True
        return False

    def showflow(self, level=9):
        """Return the result of "showflow".

        Args:
            level (int, optional): 'showflow' verbose level

        Returns:
            list: flows in list, one flow line per list item
        """
        cmd = "showflow {0} dynamic {1}".format(self.hardware, level)
        flows = self._exec_cmd(cmd)
        return [x.strip() for x in flows.splitlines()] if flows else []

    def flowstodict(self):
        """Returns the flows as dict where a key is the SBCE IP and port
        of a flow and the value is the Flow values as dictionary.

        Returns:
            dict: keys are tuples of SBCE IP and port of flows
        """
        self.lastflows = {(f["InDstIP"], f["InDstPort"]):f for f in
                          (self._flowtodict(x) for x in self.showflow())}
        self.lastflows_timestamp = datetime.now()
        return self.lastflows

    def _flowtodict(self, f):
        """Converts flow string to dict.

        Args:
            f (str): flow line from list returned by showflow

        Returns:
            dict: flow field names and values
        """
        m = self.reFlow.search(f)
        if m:
            return self._fmtflow(m.groupdict())
        return {}

    def flows(self):
        """Returns the flows as dict where a key is the SBCE IP and port
        of a flow and the value is the Flow values as namedtuple.

        Returns:
            dict: SBCE IP and port tuple as key and Flow instance as value
        """
        self.lastflows = {(f.InDstIP, f.InDstPort):f for f in
                          (self._flow(x) for x in self.showflow())}
        self.lastflows_timestamp = datetime.now()
        return self.lastflows

    def _flow(self, f):
        """Converts flow string to Flow class instance.

        Args:
            f (str): flow line from list returned by showflow

        Returns:
            Flow: Flow class instance
        """
        m = self.reFlow.search(f)
        return self.Flow(**self._fmtflow(m.groupdict())) if m else ()

    def flow(self, asbce_ip, asbce_port):
        """Combines and returns stats for flow identified by
        asbce_ip and asbce_port.

        Args:
            asbce_ip (str): SBCE audio ip address of flow
            asbce_port (str): SBCE audio RTP port of flow

        Returns:
            dict(): {<ifaceA>: Flow, <ifaceB>: Flow}
        """
        flows = self.flows()
        fwdflow = flows.get((asbce_ip, asbce_port), {})
        if fwdflow:
            revflow = flows.get((fwdflow.OutSrcIP, fwdflow.OutSrcPort), {})
            return ({fwdflow.InIf: fwdflow, revflow.InIf: revflow}
                    if revflow else {fwdflow.InIf: fwdflow})
        return {}

    @staticmethod
    def _fmtflow(flowdict, hex=False):
        """Converts hex values from flow tuple to decimal string and
        interface numbers to interface names.

        Args:
            flowdict (dict): dict returned by flowtodict
            hex (bool, optional): to convert counters from string hex to int

        Returns:
            dict: formated flowdict
        """
        for k in ("InIf", "OutIf"):
            flowdict[k] = {"0":"A1", "1":"A2", "2":"B1", "3":"B2"}.get(flowdict[k], "?")
        for k in ("InSrcPort", "InDstPort", "OutSrcPort", "OutDstPort"):
            flowdict[k] = int(flowdict[k])
        if not hex:
            for k in ("InVlan", "OutVlan", "Enc", "Dec", "Snt", "Drp", "Rx", "Rly", "Ech"):
                flowdict[k] = int(flowdict[k], 16)
        return flowdict

    def _exec_sql(self, sqlcmd):
        """Helper funtion to build SQL command.

        Args:
            sqlcmd (str): executable SQL command string

        Returns:
            str: return value of self._exec_cmd
        """
        if os.path.isdir("/var/lib/pgsql/"):
            cmd = " ".join(("psql -t -U postgres sbcedb -c \"", sqlcmd, "\""))
        else:
            cmd = " ".join(
                ("solsql -a -x onlyresults -e \"", sqlcmd, "\"",
                 "\"tcp {0} 1320\" savon savon".format(self.ems_ip))
            )
        return self._exec_cmd(cmd).strip()

    @staticmethod
    def _exec_cmd(cmd):
        """Helper method to execute the SQL command.

        Args:
            cmd (str): complete SQL client command executable from bash

        Returns:
            str: return value from database command

        Raises:
            RuntimeError: if the SQL bash command returns error
        """
        proc = Popen(shlex.split(cmd), shell=False, stdout=PIPE, stderr=PIPE)
        data, err = proc.communicate()
        if proc.returncode == 0:
            return data
        raise RuntimeError(err)

    def _restore_loglevel(self):
        """Restores SIPCC loglevel to its initial value."""
        if not self.mock:
            self.sipcc_loglevel = self.sipcc_loglevel_inital


##############################################################################
#                                   tcpdump                                  #
##############################################################################


class Tcpdump(object):
    """Forks/kills tcpdump and keeps track of generated pcap files."""
    PCAPDIR = "./"
    MAX_PACKETS = 10000
    MAXDISK_USAGE_PCT = 95

    def __init__(self, pcapdir=None, max_packets=None, maxdisk_usage_pct=None,
                 ifaces=None):
        """Initializes the instance."""
        self.pcapdir = pcapdir or self.PCAPDIR
        self.max_packets = max_packets or self.MAX_PACKETS
        self.maxdisk_usage_pct = maxdisk_usage_pct or self.MAXDISK_USAGE_PCT
        self.cmd_template = "{} -n -i {} -s 0 -c {} -w {} '{}'"
        self._ifaces = ifaces
        self._tcpdump = None
        self.pids = {}
        self.filenames = {}

    def _build_pair(self, pair, rtcp=True):
        """Builds tcpdump filter string for each ip/port pair.

        Args:
            pair (tuple): (local_ip, local_port)
            rtcp (bool, optional): if RTCP is captured too. Defaults to True

        Returns:
            str: built string, for example "(host 1.1.1.1 and ((port 2048)))"
        """
        out = []
        ports = self._build_ports(str(x) for x in pair if isinstance(x, int))
        hosts = self._build_hosts(x for x in pair if "." in str(x))
        if hosts:
            out.append("(" + hosts + " and ")
        if ports:
            if rtcp:
                rtcp_ports = self._build_ports(
                    str(x+1) for x in pair if isinstance(x, int)
                )
                ports = "(" + ports + " or " + rtcp_ports + ")"
            out.append(ports)
        if out:
            out.append(")")
        return "".join(out)

    def _build_filter(self, pairs, rtcp=True):
        out = []
        for pair in pairs:
            out.append(self._build_pair(pair, rtcp))
        return " or ".join(out)

    def fork(self, pairs=None, prefix="call", caller=None, callee=None,
             suffix="audio", max_packets=None, rtcp=True):
        """Forks tcpdump process for the hosts/ports provided in pairs.

        Args:
            pairs (list, optional): list of tuples. Defaults to None
            prefix (str, optional): tcpdump file prefix. Defaults to "call"
            caller (str, optional): caller number, Defaults to None
            callee (str, optional): callee number, Defaults to None
            suffix (str, optional): tcpdump file suffix, Defaults to ""
            max_packets (int, optional): max packet number, Defaults to None
            rtcp (bool, optional): if RTCP is captured too, Defaults to True

        Returns:
            tuple: tcpdump file names including path
        """
        if self.disk_usage(self.pcapdir) > self.maxdisk_usage_pct:
            return []

        stem = os.path.join(self.pcapdir, self._build_filename(
            prefix=prefix, caller=caller, callee=callee, suffix=suffix))
        filter = self._build_filter(pairs, rtcp)
        max_packets = max_packets if max_packets else self.max_packets

        filenames = []
        for ifacename, pairs in self._build_iface_pairs(pairs).items():
            filename = stem + "_{0}.pcap".format(ifacename)
            cmd = self.cmd_template.format(
                self.tcpdump, ifacename, max_packets, filename, filter
            )
            try:
                proc = Popen(
                    shlex.split(cmd), shell=False, preexec_fn=os.setpgrp,
                    stdout=PIPE, stderr=PIPE
                )
            except:
                continue
            self.pids[proc.pid] = filename
            self.filenames[filename] = proc.pid
            filenames.append(filename)
        return tuple(sorted(filenames))

    def kill(self, pids_or_filenames):
        """Kills processes in pids_or_filenames. If pids_or_filenames is
        not a container but an int it find's its sibling pids and kills
        those too.

        Args:
            pid_or_filename (int, str, list): filename, pid or list of these

        Returns:
            tuple: tcpdump file names whose processes were killed
        """
        if isinstance(pids_or_filenames, int):
            filename = self.pids.get(pids_or_filenames, None)
            if not filename:
                return None
            stem = os.path.splitext(filename)[0].rsplit("_", 1)[0]
            pids_or_filenames = [
                v for k, v in self.filenames.iteritems() if stem in k
            ]

        filenames = []
        for pid in pids_or_filenames:
            if not isinstance(pid, int):
                pid = self.filenames.get(pid, None)

            if not pid or pid not in self.pids:
                continue

            try:
                os.killpg(pid, signal.SIGTERM)
                if os.wait()[1]:
                    try:
                        os.killpg(pid, signal.SIGKILL)
                    except OSError:
                        pass
            except OSError:
                pass
            filename = self.pids.pop(pid, None)
            if filename:
                filenames.append(filename)
                self.filenames.pop(filename, None)
        return tuple(sorted(filenames))

    def killall(self):
        """Kills all running pid. Only used at exit."""
        for pid in self.pids.keys():
            self.kill(pid)

    @staticmethod
    def _build_hosts(hosts):
        """Builds host part of tcpdump filter.

        Args:
            hosts (list): host IP addresses

        Returns:
            str: built string, for example "host 1.1.1.1 and host 1.1.1.2"
        """
        if hosts:
            return " and ".join("host {}".format(x) for x in hosts)
        return ""

    @staticmethod
    def _build_ports(ports):
        """Builds ports part of tcpdump filter.

        Args:
            ports (list): RTP ports

        Returns:
            str: port string, for example "(udp port 2048 and udp port 2030)"
        """
        if ports:
            return "(" + " and ".join("udp port {}".format(x) for x in ports) + ")"
        return ""

    @staticmethod
    def _build_filename(prefix="", caller="", callee="", suffix=""):
        """Builds tcpdump filename from arguments

        Args:
            prefix (str, optional): filename prefix
            caller (str, optional): caller numer
            callee (str, optional): callee number
            suffix (str, optional): filename suffix

        Returns:
            str: filename including path
        """
        ts = datetime.now().strftime("%Y-%m%d-%H%M%S.%f")
        caller = "_".join(("From", caller.lstrip("+"))) if caller else ""
        callee = "_".join(("To", callee.lstrip("+"))) if callee else ""
        return "_".join(x for x in (prefix, ts, caller, callee, suffix) if x)

    def _build_iface_pairs(self, pairs):
        """Returns dict of iface names as keys and list if local_ip and
        Local_port tuples as host, port filters to be captured on the
        given iface.

        Args:
            pairs (list): list of (local_ip, local_port) tuples

        Returns:
            dict: {ifacename: [(local_ip, local_port,)], ...}
        """
        iface_pairs = {}
        for ip, port in pairs:
            iface_pairs.setdefault(self.ifaces[ip], []).append((ip, port))
        return iface_pairs

    @staticmethod
    def disk_usage(partition=None):
        """Returns the Use% disk usage percentage for partition or
        for partition of current working directory.

        Args:
            partition (str, optional): directory

        Returns:
            int: between 0-100
        """
        partition = partition or "./"
        stats = os.statvfs(partition)
        used_percent = (int(100.0 * (stats.f_blocks - stats.f_bfree) /
                        (stats.f_blocks - stats.f_bfree + stats.f_bavail)))
        return used_percent

    @property
    def ifaces(self):
        """dict: Returns interface names and corresponding IP addresses."""
        if self._ifaces is None:
            self._ifaces = {
                ifaddr["addr"]:iface for iface in interfaces() for ifaddrs in
                ifaddresses(iface).values() for ifaddr in ifaddrs
            }
        return self._ifaces

    @property
    def tcpdump(self):
        """str: Returns full path to tcpdump if found in $PATH."""
        if self._tcpdump is None:
            self._tcpdump = next(
                os.path.join(path, "tcpdump") for path in
                os.getenv("PATH").split(":") if
                os.path.exists(os.path.join(path, "tcpdump"))
            )
        return self._tcpdump


##############################################################################
#                                  pcapparser                                #
##############################################################################


class Frame(object):
    """RTP Frame data class to store a few RTP frame field values."""
    __slots__ = [
        "number", "time_relative", "ip_dsfield_dscp", "ip_src",
        "udp_srcport", "ip_dst", "udp_dstport", "rtp_ssrc", "rtp_p_type",
        "rtp_timestamp", "rtp_seq", "rtpevent_event_id",
        "rtpevent_end_of_event", "rtp_payload", "expert_message"
    ]

    toint = lambda x: int(x) if x else None
    tostr = lambda x: x.replace(":", "")
    types = [int, float, str, str, str, str, str, str, str, toint, str,
             str, str, tostr, str]

    def __init__(self, *fields):
        """Initializes Frame instance attributes from fields argument."""
        for attr, typefunc, v in zip(self.__slots__, Frame.types, fields):
            setattr(self, attr, typefunc(v))

    def __str__(self):
        return " ".join(
            "{0}:{1}".format(s, getattr(self, s)) for s in self.__slots__
        )

    @property
    def event_isend(self):
        """tuple(str, bool): Returns telephony event and end_of_event."""
        if self.rtpevent_event_id:
            return self.rtpevent_event_id, bool(int(self.rtpevent_end_of_event))
        elif 0 < len(self.rtp_payload) < 16 and int(self.rtp_p_type) > 95:
            return (string.translate(
                        self.rtp_payload[1], string.maketrans("abcdef", "*#ABCD")
                    ),
                    bool(int(self.rtp_payload[2]))
                )
        return None, False

    @property
    def Id(self):
        """tuple: Returns instance Id."""
        return (self.ip_src, self.udp_srcport, self.ip_dst, self.udp_dstport,
                self.rtp_ssrc)


class Stream(object):
    __slots__ = [
        "SrcIPAddr", "SrcPort", "DstIPAddr", "DstPort", "SSRC", "Payload",
        "Pkts", "PktLoss", "PktLossPct", "MaxDelta", "MaxJitter", "MeanJitter",
        "Problems", "DSCP", "MaxSkew", "Ptime", "Exception", "RFC2833Payload",
        "RFC2833Events",
    ]

    def __init__(self, *fields):
        """Initializes Stream instance attributes from fields argument."""
        for attr, v in izip_longest(self.__slots__, fields, fillvalue=None):
            setattr(self, attr, v)

    @property
    def Id(self):
        """tuple: Returns instance Id."""
        return (self.SrcIPAddr, self.SrcPort, self.DstIPAddr, self.DstPort,
                self.SSRC)

    def __str__(self):
        return " ".join(
            "{0}:{1}".format(s, getattr(self, s)) for s in self.__slots__
        )

    def _asdict(self):
        """dict: Returns instance as dict."""
        return {s: getattr(self, s, None) for s in self.__slots__}

    def __eq__(self, other):
        return self._asdict() == other._asdict()

    def __ne__(self, other):
        return self._asdict() != other._asdict()


class PCAPParser(object):
    """Extract RTP Statistics from PCAP file."""
    ARGS1 = [
        "-n", "-q", "-o", "rtp.heuristic_rtp:TRUE", "-z", "rtp,streams", "-r"
    ]
    ARGS2 = [
        "-n", "-l", "-E", "occurrence=l", "-E", "separator=,", "-T", "fields"
    ]
    OVERRIDES = [
        "rtp.heuristic_rtp:TRUE", "rtcp.heuristic_rtcp:TRUE",
        "rtpevent.event_payload_type_value:999",
    ]
    FIELDS = [
        "frame.number", "frame.time_relative", "ip.dsfield.dscp", "ip.src",
        "udp.srcport", "ip.dst", "udp.dstport", "rtp.ssrc", "rtp.p_type",
        "rtp.timestamp", "rtp.seq", "rtpevent.event_id",
        "rtpevent.end_of_event", "rtp.payload", "expert.message",
    ]

    def __init__(self):
        """Initializes class instance"""
        self._tshark = None
        self.streams = {}
        self.frames = {}
        self.pcapfile = None

    def parse(self, pcapfile):
        """Parses the pcapfile.

        Args:
            pcapfile (str): full path to pcapfile

        Returns:
            None
        """
        self.pcapfile = pcapfile
        self._rtp_streams()
        self._rtp_frames()
        self._rtp_dscp()
        self._rtp_events()
        self._rtp_maxskew_ptime()
        self._rtp_exception()

    def clear(self):
        """Clears internal state."""
        self.streams.clear()
        self.frames.clear()
        self.pcapfile = None

    def get(self):
        """dict: Returns copy of internal streams dict."""
        return copy(self.streams)

    def asdict(self, hexssrc=True, sorted=True):
        """Returns copy of internal streams converting values to dicts as well.

        Args:
            hexssrc (bool, optional): to conver SSRC to hex. Defaults to True
            sorted (bool, optional): to sort streams by SSRC and SrcIPAddr
                Defaults to True

        Returns:
            [type]: [description]
        """
        d = {k: v._asdict() for k, v in self.get().iteritems()}
        if hexssrc:
            d = self._hexlify_ssrc(d)
        if sorted:
            d = self._sort(d)
        return d

    def _rtp_streams(self):
        """Dumps RTP Stream Summary to streams dict."""
        cmd = "{0} {1} {2}".format(
            self.tshark, " ".join(self.ARGS1), self.pcapfile
        )
        raw = self._getoutput(cmd)
        if not raw:
            return

        lines = (l+"N" if l.endswith(" ") else l for l in raw.split("\n")[2:-1])
        columns_of_streams = (l.split() for l in lines)
        for columns_of_stream in columns_of_streams:
            try:
                stream = Stream(
                    columns_of_stream[0],
                    columns_of_stream[1],
                    columns_of_stream[2],
                    columns_of_stream[3],
                    str(int(columns_of_stream[4], 16)),
                    " ".join(columns_of_stream[5:-7]).strip("ITU-T "),
                    columns_of_stream[-7],
                    columns_of_stream[-6],
                    columns_of_stream[-5][1:-1],
                    columns_of_stream[-4],
                    columns_of_stream[-3],
                    columns_of_stream[-2],
                    columns_of_stream[-1],
                )
                self.streams[stream.Id] = stream
            except:
                continue

    def _rtp_frames(self):
        """Extracts RTP frame fields to fields dict."""
        cmd = self.tshark
        cmd += " ".join(" -o " + x for x in self.OVERRIDES)
        cmd += " ".join(" " + x for x in self.ARGS2)
        cmd += " ".join(" -e " + x for x in self.FIELDS)
        cmd += " -r {0}".format(self.pcapfile)
        frames = self._getoutput(cmd)

        if frames:
            frames = (tuple(x.split(",")) for x in frames.split("\n"))
            for frame in frames:
                try:
                    frame = Frame(*frame)
                    if frame.rtp_ssrc:
                        self.frames.setdefault(frame.Id, []).append(frame)
                except:
                    continue

    def _rtp_dscp(self):
        """Updates streams with DSCP value."""
        for Id in self.streams:
            try:
                dscp = next(
                    self.frames[f][0].ip_dsfield_dscp
                    for f in self.frames if f == Id
                )
            except StopIteration:
                dscp = "0"
            self.streams[Id].DSCP = dscp

    def _rtp_events(self):
        """Updates streams with RFC2833 events and payload type."""
        events = {}
        for Id, frames in self.frames.iteritems():
            for f in frames:
                if f.event_isend[0]:
                    events.setdefault(Id, []).append(
                        (f.event_isend, f.rtp_p_type)
                    )
        for Id, stream in self.streams.iteritems():
            if Id in events:
                self.streams[Id].RFC2833Events = self._get_events(events[Id])
                self.streams[Id].RFC2833Payload = events[Id][0][1]
            else:
                self.streams[Id].RFC2833Events = ""
                self.streams[Id].RFC2833Payload = ""

    def _rtp_maxskew_ptime(self):
        """Update streams with maximum skew and ptime values."""
        for Id, fs in self.frames.iteritems():
            if Id not in self.streams:
                continue
            payload = self.streams[Id].RFC2833Payload
            mediaframes = [f for f in fs if f.rtp_p_type != payload]
            max_skew, ptime = self._get_maxskew_ptime(mediaframes)
            self.streams[Id].MaxSkew = max_skew
            self.streams[Id].Ptime = ptime

    def _rtp_exception(self):
        """Updates streams with tshark exception boolean."""
        func = lambda x: "Exception" in x.expert_message

        for Id, fs in self.frames.iteritems():
            if Id not in self.streams:
                continue
            self.streams[Id].Exception = any(filter(func, fs))

    def _hexlify_ssrc(self, d):
        """dict: Returns d with SSRC values converted to hex."""
        for Id in d:
            d[Id]["SSRC"] = hex(int(d[Id]["SSRC"]))
        return d

    def _sort(self, d):
        """dict: Returns d sorted by SSRC and SrcIPAddr."""
        return OrderedDict((k, d[k]) for k in sorted(d, key=itemgetter(4, 0)))

    @staticmethod
    def _get_events(event_isend_tuples):
        """Extracts RFC2833 unrepeated end events.

        Args:
            event_isend_tuples (list): list of frame event_isend tuples

        Returns:
            str: unrepeated end events
        """
        if len(event_isend_tuples) < 3:
            return ""

        events = []
        for i, ((event, isend), _) in enumerate(event_isend_tuples[1:], start=1):
            if not isend and event_isend_tuples[i-1][0][1]:
                events.append(event)
        return "".join(events)

    @staticmethod
    def _get_maxskew_ptime(mediaframes):
        """Extracts maximum skew and ptime from packets.

        Args:
            mediaframes (list): list of media frames

        Returns:
            tuple(str, str): (absolute) maximum skew and ptime
        """
        fst_frametime = mediaframes[0].time_relative
        fst_rtptime = mediaframes[0].rtp_timestamp
        ptimes = []
        skews = []

        for i, x in enumerate(mediaframes[1:], start=1):
            frametime = x.time_relative
            try:
                prev_frametime = mediaframes[i-1].time_relative
            except IndexError:
                prev_frametime = frametime
            exp = (x.rtp_timestamp - fst_rtptime) / 8000.0
            real = frametime - fst_frametime
            skews.append(round((exp - real) * 1000, 2))
            ptimes.append("{0:.2f}".format(round(frametime - prev_frametime, 2)))

        try:
            ptime = str(int(float(Counter(ptimes).most_common(1)[0][0]) * 1000))
        except IndexError:
            ptime = "?"

        try:
            left_max = sorted(skews)[0]
            right_max = sorted(skews)[-1]
            if abs(left_max) > abs(right_max):
                max_skew = "{0:.2f}".format(left_max)
            else:
                max_skew = "{0:.2f}".format(right_max)
        except IndexError:
            max_skew = "?"

        return max_skew, ptime

    @property
    def tshark(self):
        """str: Returns full path to tshark if found in $PATH."""
        if self._tshark is None:
            self._tshark = next(
                os.path.join(path, "tshark") for path in
                os.getenv("PATH").split(":") if
                os.path.exists(os.path.join(path, "tshark"))
            )
        return self._tshark

    @staticmethod
    def _getoutput(cmd):
        """Runs cmd arg in subprocess and returns the output.

        Args:
            cmd (str): shell command to run

        Returns:
            str: output of cmd
        """
        proc = Popen(shlex.split(cmd), stdout=PIPE, stderr=PIPE)
        data, err = proc.communicate()
        if not data and proc.returncode:
            return ""
        return data.strip()

    def __len__(self):
        return len(self.streams)


##############################################################################
#                                  sipmessage                                #
##############################################################################


class SIPMessage(object):

    """Simple SIP message object to retrieve message body properties."""
    def __init__(self, body, reinvite=False):
        self._str = str(body).strip()
        self._sdp = None
        self._callid = None
        self._gsid = 0
        self._referto = 0
        self.reinvite = reinvite

    @property
    def size(self):
        """int: returns the size of the message"""
        return len(self._str)

    @property
    def sdp(self):
        """str: returns SDP object"""
        if self._sdp is None:
            self._sdp = SDP(self.get_sdp())
        return self._sdp

    @property
    def from_tag(self):
        """str: returns From header tag"""
        tag = self.header_param("From", "tag")
        if not tag:
            tag = self.header_param("f", "tag")
        return tag

    @property
    def to_tag(self):
        """str: returns To header tag"""
        tag = self.header_param("To", "tag")
        if not tag:
            tag = self.header_param("t", "tag")
        return tag

    @property
    def from_user(self):
        """str: returns From header user"""
        user = self.header_uri_user("From")
        if not user:
            user = self.header_uri_user("f")
        return user

    @property
    def to_user(self):
        """str: returns To header user"""
        user = self.header_uri_user("To")
        if not user:
            user = self.header_uri_user("t")
        return user

    @property
    def callid(self):
        """str: returns Call-ID"""
        if self._callid is None:
            self._callid = self.header("Call-ID")
        return self._callid

    @property
    def gsid(self):
        """str: returns Av-Global-Session-ID"""
        if self._gsid == 0:
            hdr = self.header("Av-Global-Session-ID")
            if hdr is None:
                gsid = self.header_param("Contact", "gsid")
                if gsid is None:
                    gsid = self.header_param("m", "gsid")
                self._gsid = gsid
            else:
                end = hdr.find(";")
                if end < 0:
                    end = len(hdr)
                self._gsid = hdr[:end]
        return self._gsid

    @property
    def referto_replaces_callid(self):
        hdr = self.header("Refer-To")
        if not hdr:
            hdr = self.header("r")
        if hdr:
            start = hdr.find(":")
            if start >= 0:
                end = hdr.find("@", start)
                if end >= 0:
                    referto = hdr[start+1:end]
                    if "Replaces" not in hdr:
                        return referto, None
                    start = hdr.find("Replaces=")
                    end = hdr.find("%", start)
                    return referto, hdr[start+9:end]
        return "", ""

    @property
    def replaces_callid(self):
        """str: returns Call-ID from the Replaces headers."""
        hdr = self.header("Replaces")
        if hdr:
            end = hdr.find(";")
            if end < 0:
                end = None
            return hdr[:end]
        return ""

    @property
    def request(self):
        """str: retrieves request type."""
        if self.is_response():
            return ""
        space = self._str.find(" ")
        if space >= 0:
            req = self._str[0:space]
            if req == "INVITE" and self.reinvite and self.is_indialog_request():
                req = "ReINVITE"
            return req
        return ""

    @property
    def response(self):
        """str: retrieves response type."""
        if self.is_request():
            return ""
        start = self._str.find(" ") + 1
        if start >= 1:
            end = self._str.find(" ", start)
            if end == -1:
                end = self._str.find("\n")
            if end > start:
                return self._str[start:end]
        return ""

    @property
    def method(self):
        """str: returns method from CSeq header."""
        return self.cseq()[1]

    @property
    def msgtype(self):
        """str:return descriptive message SIP type type."""
        if self.is_request():
            return self.request
        return self.response

    def msgtype_tostr(self):
        """str:return descriptive message SIP type type."""
        if self.is_request():
            return self.request
        return "{0} ({1})".format(self.response, self.method)

    def msgtype_method(self):
        """str:return descriptive message SIP type type."""
        if self.is_request():
            return self.request, self.method
        return self.response, self.method

    @property
    def protocol(self):
        """str: retrieves protocol type from top Via header."""
        hdr = self.header("Via")
        if not hdr:
            hdr = self.header("v")
        if hdr:
            start = hdr.find("/2.0/")
            if start >= 1:
                end = hdr.find(" ", start)
                return hdr[start+5:end]
        return "UDP"

    @property
    def cseqno(self):
        """str: returns CSeq number."""
        return self.cseq()[0]

    @property
    def local_tag(self):
        """str: returns local-tag from Endpoint-View header or None"""
        hdr = self.header("Endpoint-View")
        if hdr:
            start = hdr.find("local-tag=")
            if start >= 0:
                end = hdr.find(";", start)
                if end < 0:
                    end = len(hdr)
                return hdr[start+10:end]
        return ""

    @property
    def branch(self):
        """str: returns branch of top Via header"""
        param = self.header_param("Via", "branch")
        if not param:
            return self.header_param("v", "branch")
        return param

    @property
    def via_ipport(self):
        hdr = self.header("Via")
        if not hdr:
            hdr = self.header("v")
        if hdr:
            end = hdr.find(";", 12)
            ipport = hdr[12:end]
            if ":" in ipport:
                ip, port = hdr[12:end].split(":")
                return ip, int(port)
            return hdr[12:end], 5060
        return "", ""

    def header(self, header_name):
        """Retrieves the requested header.

        Args:
            header_name (str): header name without ":" to be retrieved

        Returns:
            str: requested header line
        """
        start = self._str.find(header_name + ":")
        if start == -1:
            return ""
        end = self._str.find("\n", start)
        if end == -1:
            end = self.size
        return self._str[start+len(header_name)+1:end].strip()

    def header_param(self, header_name, param):
        """Retrieves a specific parameter from the requested header.

        Args:
            header_name (str): header name without ":"
            param (str): parameter name to retrieve from header

        Returns:
            str: parameter
        """
        hdr = self.header(header_name)
        if hdr:
            start = hdr.find(param)
            if start >= 0:
                start += len(param)
                if hdr[start] == "=":
                    start += 1
                end = hdr.find(";", start)
                if end < 0:
                    end = hdr.find(">", start)
                    if end < 0:
                        end = len(hdr)
                if end > 0:
                    return hdr[start:end]
        return ""

    def header_uri_user(self, header_name):
        """Retrieves user from a specific (From/To, Request) header.

        Args:
            header_name (str): header name without ":"

        Returns:
            str: user
        """
        hdr = self.header(header_name)
        if not hdr:
            return ""
        start = hdr.find(":")
        if start >= 0:
            user = hdr[start + 1:]
        end = user.find(";")
        if end < 0:
            end = len(hdr)
        user = user[:end]
        end = user.find("@")
        if end < 0:
            end = user.find("%40")
        if end >= 0:
            user = user[0:end]
        return user.rstrip(">")

    def is_offhook_ec500_request(self):
        """bool: if first line contains offhook or ec500 fnu."""
        end = self._str.find("\n")
        hdr = self._str[0:end]
        return ("avaya-cm-fnu=off-hook" in hdr or
                "avaya-cm-fnu=ec500" in hdr)

    def cseq(self):
        """tuple: returns CSeq number and method."""
        hdr = self.header("CSeq")
        if hdr:
            lst = hdr.split()
            if len(lst) == 2:
                return int(lst[0]), lst[1].rstrip()
        return "", ""

    def get_sdp(self):
        """str: returns the SDP body."""
        start = self._str.find("\nv=")
        if start >= 0:
            end = self._str.find("\n", start)
            if end >= 0:
                return self._str[end:].lstrip()
        return ""

    def has_sdp(self):
        """bool: if message has SDP."""
        content_length = self.header("Content-Length")
        return False if not content_length else int(content_length) > 0

    def is_indialog_request(self):
        """bool, None: if message has "tag" paramater in the "To" header."""
        return None if not self.size else bool(
            self.header_param("To", "tag") or
            self.header_param("t", "tag")
        )

    def is_response(self):
        """bool, None: if message is a response."""
        return None if not self.size else (
               self._str.startswith(("SIP/2.0", "sip/2.0")))

    def is_request(self):
        """bool, None: if message is a request."""
        return None if not self.size else (
               not self.is_response())

    def has_replaces(self):
        """bool: if message has Replaces header"""
        return None if not self.size else bool(self.header("Replaces"))

    def tostring(self):
        """str: returns the SIP message as sting."""
        return self._str.strip()

    def __contains__(self, item):
        return item in self._str

    def __len__(self):
        return self.size

    def __str__(self):
        return self._str


class SDP(object):
    """SDP parser class."""
    PAYLOAD = {
         0: "G711U",
         4: "G723",
         8: "G711A",
         9: "G722",
        18: "G729",
    }

    def __init__(self, body):
        self._str = body
        self._session_attrs = None
        self._audio_attrs = None
        self._video_attrs = None
        self._image_attrs = None
        self._audio_ip = None
        self._audio_port = None
        self._audio_codec_name = None
        self._video_ip = None
        self._video_port = None
        self._video_codec_name = None
        self._session_info = None
        self.reConnAddr = re.compile(r"c=IN IP4 (\d+.\d+.\d+.\d+).*")
        self.rePortCodec = re.compile(r"m=\w+ (\d+) S?RTP/S?AVP (\d+).*")
        self.reSessIdVerOrig = re.compile(r"o=\S+ (\d+) (\d+) IN IP4 (\d+.\d+.\d+.\d+).*")

    @property
    def session_attrs(self):
        if self._session_attrs is None:
            self._session_attrs = self.get_session_attrs()
        return self._session_attrs

    @property
    def audio_attrs(self):
        if self._audio_attrs is None:
            self._audio_attrs = self.get_other_attrs("audio")
        return self._audio_attrs

    @property
    def video_attrs(self):
        if self._video_attrs is None:
            self._video_attrs = self.get_other_attrs("video")
        return self._video_attrs

    @property
    def image_attrs(self):
        if self._image_attrs is None:
            self._image_attrs = self.get_other_attrs("image")
        return self._image_attrs

    @property
    def audio_ip(self):
        if self._audio_ip is None:
            self._audio_ip = self.get_audio_addr()
        return self._audio_ip

    @property
    def audio_port(self):
        if self._audio_port is None:
            self._audio_port = self.get_audio_port_payload()[0]
        return self._audio_port

    @property
    def audio_codec_name(self):
        if self._audio_codec_name is None:
            _, payload = self.get_audio_port_payload()
            if payload is None:
                self._audio_codec_name = ""
            else:
                codec_name = self.PAYLOAD.get(payload, None)
                if codec_name is None:
                    codec_name = self.get_audio_payload_name_clockrate(payload)[0]
                if codec_name == "G729" and self.is_annexb_yes():
                    codec_name += "B"
                self._audio_codec_name = codec_name.upper()
        return self._audio_codec_name

    @property
    def video_ip(self):
        if self._video_ip is None:
            self._video_ip = self.get_video_addr()
        return self._video_ip

    @property
    def video_port(self):
        if self._video_port is None:
            self._video_port = self.get_video_port_payload()[0]
        return self._video_port

    @property
    def video_codec_name(self):
        if self._video_codec_name is None:
            payload = self.get_video_port_payload()[1]
            if payload is None:
                self._video_codec_name = ""
            else:
                codec_name = self.get_video_payload_name_clockrate(payload)[0]
                self._video_codec_name = codec_name.upper() if codec_name else ""
        return self._video_codec_name

    @property
    def session_info(self):
        if self._session_info is None:
            self._session_info = self.get_session_info()
        return self._session_info

    def get_session_attrs(self):
        end = self._str.find("m=")
        if end < 0:
            end = len(self._str)
        return self._str[:end].strip()

    def get_other_attrs(self, type):
        start = self._str.find("m=" + type)
        if start < 0:
            return ""
        end = self._str.find("m=", start+1)
        if end < 0:
            end = len(self._str)
        return self._str[start:end].strip()

    def get_session_addr(self):
        m = self.reConnAddr.search(self.session_attrs)
        try:
            return m.group(1)
        except AttributeError:
            return ""

    def get_audio_addr(self):
        m = self.reConnAddr.search(self.audio_attrs)
        if not m:
            m = self.reConnAddr.search(self.session_attrs)
        try:
            return m.group(1)
        except AttributeError:
            return ""

    def get_video_addr(self):
        m = self.reConnAddr.search(self.video_attrs)
        if not m:
            m = self.reConnAddr.search(self.session_attrs)
        try:
            return m.group(1)
        except AttributeError:
            return ""

    def get_image_addr(self):
        m = self.reConnAddr.search(self.image_attrs)
        if not m:
            m = self.reConnAddr.search(self.session_attrs)
            try:
                return m.group(1)
            except AttributeError:
                return ""

    def get_session_info(self):
        m = self.reSessIdVerOrig.search(self.session_attrs)
        try:
            return m.group(1, 2, 3)
        except AttributeError:
            return ""

    def get_audio_port_payload(self):
        m = self.rePortCodec.search(self.audio_attrs)
        try:
            return tuple(int(x) for x in m.group(1, 2))
        except AttributeError:
            return None, None

    def get_video_port_payload(self):
        m = self.rePortCodec.search(self.video_attrs)
        try:
            return tuple(int(x) for x in m.group(1, 2))
        except AttributeError:
            return None, None

    def get_audio_payload_name_clockrate(self, payload):
        m = re.search(r"a=rtpmap:%s (\w+)/(\d+).*" % payload, self.audio_attrs)
        try:
            return m.group(1, 2)
        except AttributeError:
            return "", ""

    def get_video_payload_name_clockrate(self, payload):
        m = re.search(r"a=rtpmap:%s (\w+)/(\d+).*" % payload, self.video_attrs)
        try:
            return m.group(1, 2)
        except AttributeError:
            return "", ""

    def is_annexb_yes(self):
        return "a=fmtp:18 annexb=yes" in self.audio_attrs

    def is_audio_onhold(self):
        return ("a=recvonly" in self.audio_attrs or
                "a=sendonly" in self.audio_attrs or
                "a=inactive" in self.audio_attrs)

    def is_video_inactive(self):
        return ("a=inactive" in self.video_attrs)

    def has_audio_crypto(self):
        """bool: returns True if audio has crypto key."""
        return "a=crypto:1" in self.audio_attrs

    def has_video(self):
        video_addr = self.get_video_addr()
        return (video_addr and video_addr != "0.0.0.0" and
                bool(self.get_video_port_payload()[0]) and
                not self.is_video_inactive())

    def tostring(self):
        """str: returns the SDP as sting."""
        return self._str.strip()

    def __str__(self):
        return self._str


##############################################################################
#                                   tracker                                  #
##############################################################################


class Audioconn(object):
    """Data structure to store audio connection information."""
    __slots__ = ["local_ip", "local_port", "remote_ip", "remote_port", "type"]

    def __init__(self, local_ip, local_port, remote_ip, remote_port, type):
        self.local_ip = local_ip
        self.local_port = local_port
        self.remote_ip = remote_ip
        self.remote_port = remote_port
        self.type = type

    def __eq__(self, other):
        return ((self.local_ip, self.local_port, self.remote_ip, self.remote_port) ==
                (other.local_ip, other.local_port, other.remote_ip, other.remote_port))

    def __str__(self):
        return "(local={0}:{1}  remote={2}:{3}  type={4})".format(self.local_ip,
                self.local_port, self.remote_ip, self.remote_port, self.type)


class TwoWayDict(MutableMapping):
    """Custom dictionary which stores key/value pairs both ways."""
    def __init__(self, data=()):
        self.mapping = {}
        self.update(data)

    def __getitem__(self, key):
        return self.mapping[key]

    def __delitem__(self, key):
        value = self[key]
        del self.mapping[key]
        self.pop(value, None)

    def __setitem__(self, key, value):
        if key in self:
            del self[self[key]]
        if value in self:
            del self[value]
        self.mapping[key] = value
        self.mapping[value] = key

    def __iter__(self):
        return iter(self.mapping)

    def __len__(self):
        return len(self.mapping)

    def __repr__(self):
        return "{0}({1})".format(type(self).__name__, self.mapping)


class SlicableODict(OrderedDict):
    """Slicale OrderedDict"""
    def index(self, k):
        return next(i for i, key in enumerate(self) if key==k)

    def __getitem__(self, k):
        if isinstance(k, slice):
            if k.start is None:
                start = 0
            elif k.start < 0:
                start = OrderedDict.__len__(self) + k.start
            else:
                start = k.start
            if k.stop is None:
                stop = OrderedDict.__len__(self)
            elif k.stop < 0:
                stop = OrderedDict.__len__(self) + k.stop
            else:
                stop = k.stop
            return SlicableODict(islice(self.items(), start, stop, k.step))
        elif isinstance(k, int):
            start = OrderedDict.__len__(self) + k if (k < 0) else k
            return next(islice(self.items(), start, start+1))
        else:
            return OrderedDict.__getitem__(self, k)


class UA(object):
    __slots__ = ["number", "tag", "sig_ip", "audio_ip", "audio_port",
                 "audio_codec_name", "audio_crypto"]

    def __init__(self, number="", tag="", sig_ip="", audio_ip="",
                 audio_port="", audio_codec_name="", audio_crypto=""):
        self.number = number
        self.tag = tag
        self.sig_ip = sig_ip
        self.audio_ip = audio_ip
        self.audio_port = audio_port
        self.audio_codec_name = audio_codec_name
        self.audio_crypto = audio_crypto

    def __str__(self):
        return str({k: getattr(self, k) for k in self.__slots__})


class SessionInfo(object):
    """Data structure to keep all SIP call related information."""
    __slots__ = ["caller", "callee", "starttime", "endtime", "status",
                 "audioconns", "callids", "flows"]

    def __init__(self, caller=None, callee=None, caller_tag=None,
                 caller_sig_ip=None, starttime=None, callids=None):
        self.caller = UA(number=caller, tag=caller_tag, sig_ip=caller_sig_ip)
        self.callee = UA(number=callee)
        self.callids = callids if callids else OrderedDict()
        self.audioconns = []
        self.flows = []
        self.starttime = starttime
        self.endtime = ""
        self.status = ""

    @property
    def duration(self):
        """Returns call duration in 'HH:MM:SS' format."""
        endtime = self.endtime or datetime.now()
        diff = (endtime.replace(microsecond=0) -
                self.starttime.replace(microsecond=0))
        if diff >= timedelta(hours=8):
            return "erroneous"
        return str(diff).rjust(8, "0")

    def __str__(self):
        f = "ts:{0} caller:({1} {2}:{3} {4}) callee:({5} {6}:{7} {8}) status:{9}"
        return f.format(
            self.starttime, self.caller.number, self.caller.audio_ip,
            self.caller.audio_port, self.caller.audio_codec_name,
            self.callee.number, self.callee.audio_ip,
            self.callee.audio_port, self.callee.audio_codec_name, self.status
        )

    def __getstate__(self):
        """For cPickle dump."""
        return (self.caller, self.callee, self.callids, self.flows,
                self.audioconns, self.starttime, self.endtime, self.status)

    def __setstate__(self, data):
        """For cPickle load."""
        (self.caller, self.callee, self.callids, self.flows,
         self.audioconns, self.starttime, self.endtime, self.status) = data


class MediaTracker():
    """Tracks SDP negotiation and retains RTP flow details for audio media."""
    def __init__(self, maxlen=None, ifacemap=None,
                 user_filter=None, ip_filter=None):
        self.maxlen = maxlen
        self.ifacemap = ifacemap if ifacemap else {}
        self.user_filter = user_filter
        self.ip_filter = ip_filter
        self.db = SlicableODict()
        self.gsid_to_tag = TwoWayDict()
        self.inprogess_callids = set()
        self.callid_to_tag = {}
        self.msg = None
        self.sipmsg = None
        self.tag = None
        self.cid = None
        self.msgtype = None
        self.method = None

    def callid_to_tag(self, callid):
        """Returns the tag of a callid.

        Args:
            callid (str): SIP callid

        Returns:
            str: tag of callid
        """
        return self.callid_to_tag.get(callid, None)

    def pprint(self, tag=None):
        """Prints internal dictionaries in a pretty format. If tag is not
        None it will print that tag only.

        Args:
            tag (str, optional): tag of session (call). Defaults to None.
        """
        if tag is not None:
            if tag not in self.db:
                return
            idx = self.db.index(tag)
            tags = self.db[idx:idx+1]
        else:
            tags = self.db
        d = {0: "OUT", 1: "IN"}
        for tag, sessionobj in tags.iteritems():
            print("TAG: {0}".format(tag))
            for callid, ifaceids in sessionobj.callids.iteritems():
                print("    CALL-ID: {0}".format(callid))
                for ifaceid, infos in ifaceids.iteritems():
                    print("        IFACEID: {0}".format(ifaceid))
                    for i, info in enumerate(infos):
                        print("          {0:>3}: {1}".format(d[i], info))
            print("    SUM: {0}\n".format(self.db[tag]))

    def keys(self):
        return self.db.keys()

    def iterkeys(self):
        return self.db.iterkeys()

    def items(self):
        return self.db.items()

    def iteritems(self):
        return self.db.iteritems()

    def clear(self):
        """Clears all containers."""
        self.db.clear()
        self.callid_to_tag.clear()
        self.gsid_to_tag.clear()
        self.inprogess_callids.clear()

    def audioconns(self, tag):
        """Returns the audio connections of the session identified by tag.

        Args:
            tag (str): tag of SIP session.

        Returns:
            list: the current state of audioconns of a tag which may
                not be complete if SDP negotiation has not finished yet.
        """
        return self._get_audioconns(tag)

    def update(self, msg):
        """Updates tracker state machine with a new message.

        Args:
            msg (dict): dictionary containing information about
                the SIP message.

        Returns:
            tuple (str, dict): the tag id of the message and either an
                audioconns dictionary if the msg argument resulted in a
                new audio connection or None otherwise.
        """
        if not msg:
            return None, None
        self.msg = msg
        self.sipmsg = sipmsg = SIPMessage(msg.body, reinvite=False)
        self.msgtype = sipmsg.msgtype
        if sipmsg.size == 0:
            return None, None

        self.cid = sipmsg.callid
        if self._is_msg_ignorable():
            return None, None

        self.tag = tag = self._get_tag()
        if tag and tag not in self.db:
            return None, None

        self.method = method = sipmsg.method

        if method == "INVITE":
            newstatus, audioconns = self._process_invite_method()
        elif method == "UPDATE":
            newstatus, audioconns = self._process_update_method()
        elif method == "BYE":
            newstatus, audioconns = self._process_bye_method()
        elif method == "CANCEL":
            newstatus, audioconns = self._process_cancel_method()
        elif method == "REFER":
            newstatus, audioconns = self._process_refer_method()
        elif sipmsg.has_sdp():
            self._update_callid_info()
            newstatus, audioconns = self._update_sessioninfo()
        else:
            newstatus, audioconns = None, None
        return tag if (newstatus or audioconns) else None, audioconns

    def dumpdb(self, filename):
        """Dumps db to a compressed cPickled file.

        Args:
            filename (str): filename including path.

        Returns:
            str: dump filename if successful or error otherwise.
        """
        try:
            filename += ".gz"
            with gzip.open(filename, "wb") as gzipfd:
                cPickle.dump(self.db, gzipfd, protocol=2)
            return filename
        except Exception as e:
            return str(e)

    def loaddb(self, filename):
        """Loads data from compressed cPickled file into db.

        Args:
            filename (str): cPickled compressed filename including path.

        Returns:
            bool: True if successful, False otherwise.
        """
        try:
            with gzip.open(filename, "rb") as gzipfd:
                self.db = cPickle.load(gzipfd)
            return True
        except Exception as e:
            return False

    def pop_oldest_tag(self):
        """str: Removes and returns oldest tag."""
        oldest = next(iter(self.db))
        for callid in self.db[oldest].callids:
            self.callid_to_tag.pop(callid, None)
            self.inprogess_callids.discard(callid)
        self.gsid_to_tag.pop(oldest, None)
        self.db.pop(oldest, None)
        return oldest

    def _is_audioconns_new(self, audioconns):
        """Returns True of audioconns is different from the last
        audioconns seen on the current tag.

        Args:
            audioconns (dict): audioconns dictionary.

        Returns:
            bool: True if audioconns argument is different from last
                seen audioconns.
        """
        if not self.db[self.tag].audioconns:
            return True
        if audioconns != self.db[self.tag].audioconns[-1]:
            return True
        return False

    def _is_msg_ignorable(self):
        """bool: Returns True if callid is not known and not new."""
        if (self.cid in self.callid_to_tag or
            self.sipmsg.from_tag in self.db or
            self.sipmsg.gsid in self.gsid_to_tag):
            return False
        elif (self.sipmsg.request != "INVITE" or
              self.sipmsg.is_indialog_request() or
              self.msg.direction == "OUT"):
            return True
        elif self._is_user_ignorable():
            return True
        elif self._is_ip_ignorable():
            return True
        return False

    def _is_user_ignorable(self):
        """bool: Returns True if msg is ignorable based on its From/To user."""
        if not self.user_filter:
            return False
        from_user = self.sipmsg.from_user
        to_user = self.sipmsg.to_user
        if (not any(from_user.endswith(x) for x in self.user_filter) and
            not any(to_user.endswith(x) for x in self.user_filter)):
            return True
        return False

    def _is_ip_ignorable(self):
        """bool: Returns True if msg is ignorable based on its signaling IP."""
        if not self.ip_filter:
            return False
        srcip = self.msg["srcip"]
        if not any(srcip.startswith(x) for x in self.ip_filter):
            return True
        return False

    def _is_incoming_initial_inprogress(self):
        """Return True for incoming initial provisional response."""
        if self.msg.direction == "IN" and not self.db[self.tag].status:
            self.db[self.tag].status = "SETUP"
            self.db[self.tag].callee.sig_ip = self.msg.srcip
            return True
        return False

    def _is_sdp_negotiation_complete(self):
        """bool: Returns status of SDP negotiation of the current tag
        considering all callids and legs of callids involved.
        """
        for callid, ifaces in self.db[self.tag].callids.iteritems():
            if not ifaces:
                return False
            for iface, legs in ifaces.iteritems():
                # if local or remote info list is missing
                if not legs[0] or not legs[1]:
                    return False
                # if local or remote audio_ip is missing
                if not legs[0][4] or not legs[1][4]:
                    return False
                # if CSeq no. of last sent and received sipmsg are different
                if legs[0][2] != legs[1][2]:
                    return False
        return True

    def _process_invite_method(self):
        """Processes sipmsg of INVITE method."""
        if self.sipmsg.is_response():
            if self.sipmsg.has_sdp():
                self._update_callid_info()

            if ((not self.msgtype.startswith(("1", "2", "484"))) and
                (self.cid in self.inprogess_callids)):
                self._process_bye_method()
            elif self.msgtype.startswith("18"):
                return self._is_incoming_initial_inprogress(), None
            elif self.msgtype.startswith("200"):
                self.inprogess_callids.discard(self.cid)
                if self.sipmsg.has_sdp():
                    self._update_callid_info()
                return self._update_sessioninfo()
        else:
            direction, ifaceid = self._get_direction_ifaceid()
            existing_ifaceids = [k for k in self.db[self.tag].callids[self.cid]
                                 if k[0] == ifaceid[0]]
            if existing_ifaceids:
                for existing_ifaceid in existing_ifaceids:
                    del self.db[self.tag].callids[self.cid][existing_ifaceid]
            self._update_callid_info()
        return False, None

    def _process_refer_method(self):
        """tuple: Processes sipmsg of REFER method."""
        if self.sipmsg.is_request():
            referto_num, replaces_callid = self.sipmsg.referto_replaces_callid
            if not replaces_callid:
                return False, None
            self._update_callid_info()
        else:
            dir, ifaceid = self._get_direction_ifaceid()
            last = self._get_last_ifaceid_of_callid_on_same_iface(ifaceid[0])
            try:
                if self.db[self.tag].callids[self.cid][last][dir ^ 1][10]:
                    self._update_callid_info()
                complete, accepted = self._get_refer_state()
            except:
                complete, accepted = False, False
            if complete:
                if accepted:
                    rv = self._replace_callid_in_tag()
                    return rv, None
                else:
                    self._clear_replace_info()
        return False, None

    def _process_bye_method(self, min_num_callid=2):
        """Processes sipmsg of BYE method.

        Args:
            min_num_callid (int, optional): minimum number of active callids
                in session for the call to be considered active (ONCALL).
                Defaults to 2.

        Returns:
            tuple: if session has at least the min_num_callid
                active callids returns the audioconns of the remaining
                callids, else None.
        """
        if self.cid in self.db[self.tag].callids.keys()[1:-1]:
            cid_middle = True
        else:
            cid_middle = False

        if self.cid in self.inprogess_callids:
            self.inprogess_callids.remove(self.cid)
            cid_inprogess = True
        else:
            cid_inprogess = False

        self.callid_to_tag.pop(self.cid, None)
        self.db[self.tag].callids.pop(self.cid, None)
        if cid_middle:
            return self._update_sessioninfo()

        elif (not cid_inprogess and
              getattr(self.db.get(self.tag, None), "endtime", "") == ""):
            self._end_sessioninfo()
            return True, None
        return False, None

    def _process_cancel_method(self):
        """Processes sipmsg of CANCEL method."""
        if self.cid in self.db[self.tag].callids.keys():
            self.callid_to_tag.pop(self.cid, None)
            self.db[self.tag].callids.pop(self.cid, None)
            if self.cid in self.inprogess_callids:
                self.inprogess_callids.remove(self.cid)
        if (len(self.db[self.tag].callids.keys()) <= 1 and
            getattr(self.db.get(self.tag, None), "endtime", "") == ""):
            self.gsid_to_tag.pop(self.tag, None)
            self._end_sessioninfo()
            return True, None
        return False, None

    def _process_update_method(self):
        """Processes sipmsg of UPDATE method."""
        if not self.sipmsg.has_sdp():
            return False, None
        if self.sipmsg.is_response():
            self._update_callid_info()
        else:
            direction, ifaceid = self._get_direction_ifaceid()
            existing_ifaceids = [k for k in self.db[self.tag].callids[self.cid]
                                 if k[0] == ifaceid[0]]
            if existing_ifaceids:
                for existing_ifaceid in existing_ifaceids:
                    del self.db[self.tag].callids[self.cid][existing_ifaceid]
            self._update_callid_info()
        return False, None

    def _update_internal_dicts(self, tag):
        """Updates tags, db, callid_to_tag and gsid_to_tag dictionaries.

        Args:
            tag (str): tag identifying the session (call)
        """
        if tag not in self.db:
            # safeguard to limit the number of calls that can be tracked.
            if self.maxlen and len(self.db) >= self.maxlen:
                self.pop_oldest_tag()

            self.db[tag] = SessionInfo(
                caller=self.sipmsg.from_user,
                callee=self.sipmsg.to_user,
                caller_tag=self.sipmsg.from_tag,
                caller_sig_ip=self.msg.srcip,
                starttime=self.msg.timestamp,
                callids=OrderedDict([(self.cid, OrderedDict())]),
            )

        if self.cid not in self.callid_to_tag:
            self.callid_to_tag[self.cid] = tag
            self.db[tag].callids[self.cid] = OrderedDict()
            self.inprogess_callids.add(self.cid)

        if self.sipmsg.gsid and self.sipmsg.gsid not in self.gsid_to_tag:
            self.gsid_to_tag[self.sipmsg.gsid] = tag

    def _update_sessioninfo(self):
        """Updates SessionInfo attributes associtated with the session
        of current sipmsg.

        Returns:
            tuple: if SDP negotiation has completed and
                audioconns is different from the last one it returns
                the (True, audioconns) else (False, None).
        """
        if self._is_sdp_negotiation_complete():
            newstatus, audioconns = self._updatedb()
            return newstatus, audioconns
        return False, None

    def _updatedb(self):
        """Updates db (dashboard) dictionary.

        Returns:
            tuple (bool, list): (True, audioconn) if media status has
                changed and the list of the audioconns else (False, None).
        """
        newconns = None
        newstatus_sip = False
        newstatus_caller = self._updatedb_caller_info(self._get_caller_info())
        newstatus_callee = self._updatedb_callee_info(self._get_callee_info())

        audioconns = self._get_audioconns()
        if self._is_audioconns_new(audioconns):
            self.db[self.tag].audioconns.append(audioconns)
            self.db[self.tag].status = (
                "ONCALL"
                if self.db[self.tag].status != "ONCALL"
                else self.db[self.tag].status
            )
            newconns = audioconns
            newstatus_sip = True

        return newstatus_sip or newstatus_caller or newstatus_callee, newconns

    def _updatedb_caller_info(self, info):
        """Updates SessionInfo attributes associtated with caller from info.

        Args:
            info (list): list of list of infos for local and remote party.
        """
        local, remote = info
        self.db[self.tag].caller.audio_ip = remote[4]
        self.db[self.tag].caller.audio_port = remote[5]
        self.db[self.tag].caller.audio_crypto = local[8]
        if not local[7] or not self.db[self.tag].caller.audio_codec_name:
            self.db[self.tag].caller.audio_codec_name = local[6]

        if self.db[self.tag].status != "ONHOLD" and local[7]:
            self.db[self.tag].status = "ONHOLD"
            return True
        elif self.db[self.tag].status != "ONCALL" and not local[7]:
            self.db[self.tag].status = "ONCALL"
            return True
        return False

    def _updatedb_callee_info(self, info):
        """Updates SessionInfo attributes associtated with callee from info.

        Args:
            info (list): list of list of infos for local and remote party.
        """
        local, remote = info
        self.db[self.tag].callee.audio_ip = remote[4]
        self.db[self.tag].callee.audio_port = remote[5]
        self.db[self.tag].callee.audio_crypto = remote[8]
        if not remote[7] or not self.db[self.tag].callee.audio_codec_name:
            self.db[self.tag].callee.audio_codec_name = remote[6]

        if self.db[self.tag].status != "ONHOLD" and remote[7]:
            self.db[self.tag].status = "ONHOLD"
            return True
        elif self.db[self.tag].status != "ONCALL" and not remote[7]:
            self.db[self.tag].status = "ONCALL"
            return True
        return False

    def _update_callid_info(self):
        """Updates SIP info of current tag/callid."""
        info = self._get_sipmsg_info()
        direction, ifaceid = self._get_direction_ifaceid()

        if info[1] == "REFER":
            last = self._get_last_ifaceid_of_callid_on_same_iface(ifaceid[0])
            if not last:
                return
            self.db[self.tag].callids[self.cid][last][direction][0] = info[0]
            self.db[self.tag].callids[self.cid][last][direction][1] = info[1]
            self.db[self.tag].callids[self.cid][last][direction][2] = info[2]
            self.db[self.tag].callids[self.cid][last][direction][9] = info[9]
            self.db[self.tag].callids[self.cid][last][direction][10] = info[10]

        if info not in self.db[self.tag].callids[self.cid].get(ifaceid, []):
            self.db[self.tag].callids[self.cid].setdefault(
                ifaceid, [None, None]
            )[direction] = info

    def _get_audioconns(self, tag=None):
        """Returns the audio connection details for a given tag.

        Args:
            tag (str, optional): tag. Defaults to None in which case
                the tag of the current sipmsg is used.

        Returns:
            list: list of audioconns of a tag.
        """
        if tag is None:
            tag = self.tag

        l = []
        caller_ip, caller_port = self._get_caller_audio_ip_port()
        callee_ip, callee_port = self._get_callee_audio_ip_port()

        for _, ifaceids in self.db[tag].callids.iteritems():
            for ifaceid, pair in ifaceids.iteritems():
                if pair[0]:
                    local_ip, local_port = (pair[0][4], pair[0][5])
                else:
                    local_ip, local_port = None, None
                if pair[1]:
                    remote_ip, remote_port = (pair[1][4], pair[1][5])
                else:
                    remote_ip, remote_port = None, None

                if remote_ip == caller_ip and remote_port == caller_port:
                    l.insert(0, Audioconn(
                        local_ip, local_port, remote_ip, remote_port, "caller")
                    )
                elif remote_ip == callee_ip and remote_port == callee_port:
                    l.append(Audioconn(
                        local_ip, local_port, remote_ip, remote_port, "callee")
                    )
                else:
                    i = len(l)-1 if (l and l[-1].type == "callee") else len(l)
                    l.insert(i, Audioconn(
                        local_ip, local_port, remote_ip, remote_port, "other")
                    )
        return l

    def _get_caller_info(self):
        """list: Returns caller's info."""
        for leg in reversed(next(iter(self.db[self.tag].callids.values())).items()):
            if leg[0][1] == self.db[self.tag].caller.sig_ip:
                return leg[1]
        return leg[1]

    def _get_callee_info(self):
        """list: Returns callee's info."""
        for leg in next(reversed(self.db[self.tag].callids.values())).items():
            if leg[0][1] == self.db[self.tag].callee.sig_ip:
                return leg[1]
        return leg[1]

    def _get_caller_audio_ip_port(self):
        """tuple: return caller audio ip and port from db."""
        return (self.db[self.tag].caller.audio_ip,
                self.db[self.tag].caller.audio_port)

    def _get_callee_audio_ip_port(self):
        """tuple: return caller audio ip and port from db."""
        return (self.db[self.tag].callee.audio_ip,
                self.db[self.tag].callee.audio_port)

    def _get_tag(self):
        """str: Returns the tag associated with the current sipmsg."""
        if self.cid in self.callid_to_tag:
            tag = self.callid_to_tag[self.cid]
        elif self.sipmsg.from_tag in self.db:
            tag = self.sipmsg.from_tag
        elif self.sipmsg.local_tag in self.db:
            tag = self.sipmsg.local_tag
        elif self.sipmsg.replaces_callid in self.callid_to_tag:
            tag = self.callid_to_tag[self.sipmsg.replaces_callid]
        elif self.sipmsg.gsid in self.gsid_to_tag:
            tag = self.gsid_to_tag[self.sipmsg.gsid]
        else:
            tag = self.sipmsg.from_tag

        self._update_internal_dicts(tag)
        return tag

    def _get_last_ifaceid_of_callid_on_same_iface(self, ifaceip):
        """Returns last ifaceid contaning the same IP as ifaceip.

        Args:
            ifaceip (str): IP address of interface

        Returns:
            tuple: ifaceid
        """
        try:
            return next(x for x in self.db[self.tag].callids[self.cid]
                        if x[0] == ifaceip)
        except:
            return ()

    def _get_sipmsg_info(self):
        """Returns information from current sipmsg required for this class to
        track RTP audio connections.

        Returns:
            list: list of infos of type str, bool, int
        """
        if self.msgtype == "REFER":
            referto_num, replaces_callid = self.sipmsg.referto_replaces_callid
        else:
            referto_num, replaces_callid = "", self.sipmsg.replaces_callid
        return [
            self.msgtype,
            self.method,
            self.sipmsg.cseqno,
            self.sipmsg.from_tag,
            self.sipmsg.sdp.audio_ip,
            self.sipmsg.sdp.audio_port,
            self.sipmsg.sdp.audio_codec_name,
            self.sipmsg.sdp.is_audio_onhold(),
            self.sipmsg.sdp.has_audio_crypto(),
            referto_num,
            replaces_callid,
        ]

    def _get_direction_ifaceid(self):
        """Returns sipmsg direction and ifaceid of current msg. The
        sipmsg direction is encoded as 0="OUT", 1="IN" and the ifaceid
        is constructed of interface IP, top VIA header IP and transport port.

        Returns:
            tuple (int, tuple): sipmsg direction and ifaceid
        """
        via_ip, via_port = self.sipmsg.via_ipport
        if self.msg.direction == "OUT":
            return 0, (self.msg.srcip, via_ip, via_port)
        return 1, (self.msg.dstip, via_ip, via_port)

    def _get_refer_state(self):
        """Returns state of REFER request of current current REFER response.
        The first boolean indicates whether the REFER request received
        response end-to-end and the second if the request was accepted.

        Returns:
            tuple (bool, bool): REFER request completed and was accepted
        """
        pairs = [
            (l1[:3], l2[:3]) for l1, l2 in
            self.db[self.tag].callids[self.cid].values()
        ]
        complete = (
            (all(leg[1] == "REFER" for i in pairs for leg in i)) and
            (all(len(set([i[0][2], i[1][2]])) == 1 for i in pairs))
        )
        if not complete:
            return False, False

        accepted = all(leg[0] in ("202", "REFER") for i in pairs for leg in i)
        return complete, accepted

    def _get_replace_callid(self, cid=None):
        """Returns first replace_callid found in current tag and given callid.

        Args:
            cid (str, optional): callid to limit search for replace_callid in
                the legs of the given callid

        Returns:
            str: replace_callid or empty string
        """
        try:
            if cid is None:
                return next(z[10] for x in self.db[self.tag].callids.values()
                            for y in x.values() for z in y if z and z[10])
            return next(x[10] for x in iter(next(iter(
                        self.db[self.tag].callids[cid].values())))
                        if x and x[10])
        except:
            return ""

    def _end_sessioninfo(self):
        """Update session info when call has ended."""
        self.db[self.tag].endtime = self.msg.timestamp
        if self.sipmsg.method == "CANCEL":
            self.db[self.tag].status = "CANCEL"
        else:
            self.db[self.tag].status = "ENDED"

    def _clear_replace_info(self):
        """Clears referto_num and replaces_callid of current tag/callid."""
        for infos in self.db[self.tag].callids[self.cid].values():
            for info in infos:
                info[9] = ""
                info[10] = ""

    def _replace_callid_in_tag(self):
        """Replaces callid of current tag with replacing callid."""
        replace_callid = self._get_replace_callid(cid=self.cid)
        replace_tag = self.callid_to_tag.get(replace_callid, None)
        self._clear_replace_info()
        if not replace_tag:
            return False

        for k, v in self.db[self.tag].callids.iteritems():
            self.db[replace_tag].callids[k] = v
            self.callid_to_tag[k] = replace_tag
        # del self.db[self.tag]
        if tag in self.gsid_to_tag:
            gsid = self.gsid_to_tag[self.tag]
            self.gsid_to_tag[replace_tag] = gsid
        self.db[replace_tag].status = "ONCALL"
        self._end_sessioninfo()
        return True

    def __iter__(self):
        return self.db.__iter__()

    def __next__(self):
        return self.db.__next__()

    def __len__(self):
        return self.db.__len__()

    def __getitem__(self, key):
        return self.db[key]

    def __contains__(self, key):
        return key in self.db


##############################################################################
#                                   winmgr                                   #
##############################################################################


def coroutine(func):
    """Decorator: primes `func` by advancing to first `yield`"""
    @wraps(func)
    def primer(*args, **kwargs):
        gen = func(*args, **kwargs)
        next(gen)
        return gen
    return primer


class Flows(object):
    """Data class to contain all flow data of a call."""
    __slots__ = ["d", "timestamp"]

    def __init__(self, d=None, timestamp=None):
        self.d = d if d else {}
        self.timestamp = timestamp if timestamp else datetime.now()

    def iteritems(self):
        return self.d.iteritems()

    def iterkeys(self):
        return self.d.iterkeys()

    def __eq__(self, other):
        return self.timestamp == other.timestamp

    def __len__(self):
        return self.d.__len__()

    def __bool__(self):
        return any(self.d.itervalues())
    __nonzero__ = __bool__

    def __getitem__(self, k):
        return self.d.__getitem__(k)

    def __repr__(self):
        return "Flows({0}, {1})".format(
            repr(self.d), repr(self.timestamp.isoformat())
        )


class Winmgr(object):
    """Curses based window manager to parse SIP/SDP messages."""

    FRAME = [
        "│  TIME  │                    C A L L E R                    │                    C A L L E E                    │S T A T U S│",
        "│HH:MM:SS│            From    SDP Audio IP Codec Rx SRTP Type│              To    SDP Audio IP Codec Rx SRTP Type│Pcap    SIP│",
        "╞════════╪═══════════════════════════════════════════════════╪═══════════════════════════════════════════════════╪═══════════╡",
        "│        │                                                   │                                                   │           │",
        "╞════════╪═══════════════════════════════════════════════════╪═══════════════════════════════════════════════════╪═══════════╡",
        "│Duration│Caller Audio IP:Port   Iface   Port:ASBCE Audio IP │ ASBCE Audio IP:Port   Iface   Port:Callee Audio IP│Pcaps Conns│",
        "│        │                                                   │                                                   │           │",
        "╘════════╧═══════════════════════════════════════════════════╧═══════════════════════════════════════════════════╧═══════════╛",
    ]

    """Curses based window manager to parse SIP/SDP messages."""
    def __init__(self, maxlen=None, max_packets=1000, debug=False, ssyndi=False,
                 autodump=True, autodump_hrs=8, flow_update_secs=2,
                 tshark_update_secs=2, deadcall_timer_secs=60, logfiles=None,
                 dumpfile=None, skin_mono=False, skin_green=False):
        self.Reader = SsyndiSIPReader if ssyndi else TracesbcSIPReader
        self.reader = None
        self.asbce = ASBCE(mock=False if ssyndi else True)
        self.pcapparser = PCAPParser()
        self.tcpdump = Tcpdump(max_packets=max_packets, ifaces=self.asbce.ifaces)
        self.tracker = MediaTracker(ifacemap=self.asbce.ifaces)
        self.maxlen = maxlen
        self.deadcall_timedelta = timedelta(seconds=deadcall_timer_secs)
        self.flow_update_secs = flow_update_secs if flow_update_secs else 2
        self.tshark_update_secs = tshark_update_secs if tshark_update_secs else 1
        self.lasttshark_timestamp = None
        self.dumpfile = dumpfile
        self.lock = Lock()
        self.db = {}
        self.pcaps = {}
        self.tag_to_pcapfiles = {}
        self.pcapfiles_to_tag = {}
        self.servers = self.asbce.servers
        self.publics = self.asbce.publics
        self.ifaces = self.asbce.ifaces
        self.breakout = 0
        self.width = len(self.FRAME[0].decode("utf-8"))
        self.min_height = 20
        self.global_autotcpdump = 0
        self.max_autotcpdumps = 1
        self.autoscroll = 1
        self.curpos = -1
        self.trkpos = 0
        self.sdpidx = 0
        self.capidx = 0
        self.filteru = ""
        self.filterip = ""
        self.user_filter = None
        self.ip_filter = None
        self.running_queue = Queue(maxsize=1)
        self.refresh = False
        self.skin_mono = skin_mono
        self.skin_green = skin_green
        self.autodump = autodump
        self.autodump_hrs = autodump_hrs
        self.dumps = deque()
        self.dump_trigger_tag = None
        self.debug = debug
        self.logfiles = logfiles
        self.maxrss = self.memory_usage_resource()
        self.totalcalls = 0

        self.ch_methods = {
            "KEY_BACKSPACE": self._ch_backspace,
            "KEY_RESIZE": self._ch_resize,
            "KEY_UP": self._ch_up,
            "KEY_DOWN": self._ch_down,
            "KEY_PPAGE": self._ch_ppage,
            "KEY_NPAGE": self._ch_npage,
            "KEY_HOME": self._ch_home,
            "KEY_END": self._ch_end,
            "KEY_RIGHT": self._ch_right,
            "KEY_LEFT": self._ch_left,
            "KEY_ENTER": self._ch_enter,
            "^J": self._ch_enter,
            "C": self._ch_c,
            "B": self._ch_b,
            "D": self._ch_d,
            "F": self._ch_f,
            "G": self._ch_g,
            "H": self._ch_h,
            "N": self._ch_n,
            "P": self._ch_p,
            "R": self._ch_r,
            "S": self._ch_s,
            "T": self._ch_t,
            "Q": self._ch_q,
            "W": self._ch_w,
        }

        self.symbols = {
            "ok": u"\u2713".encode("utf-8"),
            "nok": u"\u2717".encode("utf-8"),
            "halt": u"\u2500".encode("utf-8"),
            "cap": u"\u25CB".encode("utf-8"),
            "capact": u"\u25CF".encode("utf-8"),
            "space": u"\u0020".encode("utf-8"),
        }

    def initcolors(self):
        for i in range(0, curses.COLORS):
            curses.init_pair(i + 1, i, -1)
        curses.init_pair(255, 21, 246)              # blue_grey

        self.colors = {
            "border": curses.color_pair(0),         # white
            "codec": curses.color_pair(213),        # magenta
            "fromto": curses.color_pair(229),       # yellow
            "ip": curses.color_pair(118),           # blue
            "time": curses.color_pair(0),           # white
            "rxok": curses.color_pair(84),          # green
            "rxnok": curses.color_pair(197),        # red
            "rxhalt": curses.color_pair(209),       # orange
            "srtp": curses.color_pair(84),          # green
            "trk": curses.color_pair(161),          # red
            "call": curses.color_pair(119),         # green
            "rw": curses.color_pair(203),           # orange
            "pcap": curses.color_pair(197),         # red
            "sipup": curses.color_pair(119),        # green
            "sipdown": curses.color_pair(0),        # white
            "iface": curses.color_pair(209),        # orange
            "port": curses.color_pair(78),          # green
            "inact": curses.color_pair(242),        # grey
            "subtitle": curses.color_pair(255),     # blue_grey
            "title": curses.color_pair(124),        # cyan
            "stopped": curses.color_pair(3),        # green
            "running": curses.color_pair(197),      # red
            "counts": curses.color_pair(159),       # blue
            "vlan": curses.color_pair(209),         # orange
            "skingreen": curses.color_pair(3),      # green
            "skinmono": curses.color_pair(0),       # white
            "text": curses.color_pair(84),          # green
            "pcapfile": curses.color_pair(84),      # green
            "error": curses.color_pair(197),        # red
            "capx": curses.color_pair(197),         # red
            "asbce": curses.color_pair(240),        # grey
        }

    def _initwins(self):
        self.maxy, self.maxx = self.stdscr.getmaxyx()
        self.stdscr.erase()
        self.stdscr.refresh()
        self.cheight = self.maxy - 8
        self.menwin_height = height = 1
        self.centwin = curses.newwin(self.maxy - 8, self.width + 1, 3, 0)
        self.bottomwin = curses.newwin(1, self.width + 1, self.maxy - 3, 0)
        self.menwin = curses.newwin(height, self.width+1, self.maxy-height, 0)
        self.active = self.centwin
        self.curpos = -1 if not self.db else 0
        self.trkpos = 0

    def main(self, stdscr):
        self.stdscr = stdscr
        curses.noecho()
        curses.start_color()
        curses.use_default_colors()
        curses.curs_set(0)
        self.initcolors()
        while not self.breakout:
            self.maxy, self.maxx = self.stdscr.getmaxyx()
            if (self.maxx <= self.width or self.maxy < self.min_height):
                self._draw_resizewin()
            else:
                self._initwins()
                self._event_loop()
        self.exit()

    def _event_loop(self):
        if self.dumpfile or self.logfiles:
            self._draw_loadwin()
        else:
            self._refresh_wins()
            self._draw_stdscr()
        self.stdscr.timeout(300)
        self._draw_menuwin()
        try:
            while True:
                if self.asbce.capture_active:
                    while True:

                        msg = next(self.reader)
                        if not msg:
                            break

                        tag, audioconns = self.tracker.update(msg)
                        if not tag:
                            continue

                        if self.tracker.db[tag].status == "SETUP":
                            self._process_setup(tag)
                        elif self.tracker.db[tag].status in ("ENDED", "CANCEL", "LOST"):
                            self._process_teardown(tag)

                        if audioconns:
                            if len(self.tracker.db) > self.maxlen:
                                pass
                            self._add_conn_to_flows(tag, audioconns)
                            self._remove_active_tcpdump(tag)
                            if self.global_autotcpdump:
                                self._ch_t()
                            self.refresh = True
                        self._update_title()

                    if self._is_flow_update_due():
                        self._update_flows()
                        self.maxrss = self.memory_usage_resource()

                    if self.active == self.centwin:
                        if self.refresh:
                            self._refresh_wins(active=True)
                            self.refresh = False

                ch = self.stdscr.getch()
                chstr = curses.keyname(ch) if ch != -1 else "NONE"
                if self.active == self.centwin:
                    key = chstr.upper()
                    if key in self.ch_methods:
                        self.ch_methods[key]()
                else:
                    if chstr == "KEY_RESIZE":
                        self._ch_resize()
                    try:
                        _ = self.active.send(chstr)
                    except Exception as e:
                        self.active = self.centwin
                        self._ch_r()
                        self._toggle_dimming(active=True)
                if self.breakout:
                    break
        except Exception as e:
            if self.debug:
                logging.exception("Exception In Event Loop")
                self._dump_debug(e=e)
            self.curpos = -1 if not self.db else 0

    def _process_setup(self, tag):
        """Processes new call (SETUP).

        Args:
            tag (str): call tag
        """
        self.totalcalls += 1
        if not self.dump_trigger_tag:
            self.dump_trigger_tag = tag

        while len(self.tracker.db) > self.maxlen:
            if self.autodump and self.dump_trigger_tag == self.tracker.db[0][0]:
                self.dump_trigger_tag = self.tracker.db[-1][0]
                self.dumpdb()
            oldest = self.tracker.pop_oldest_tag()
            if oldest in self.db:
                self.db = self.tracker.db[self.trkpos:self.trkpos+self.cheight]
                self.curpos = self.curpos - 1 if self.curpos > 0 else 0
                self.refresh = True
                return

        if len(self.tracker.db) < self.cheight:
            self.db = self.tracker.db[self.trkpos:self.trkpos+self.cheight]
            self.curpos = len(self.db) - 1 if self.autoscroll else self.curpos
            self.refresh = True
            return

        if self.autoscroll:
            if len(self.tracker.db) > self.cheight:
                self.trkpos = len(self.tracker.db) - self.cheight
            self.db = self.tracker.db[self.trkpos:self.trkpos+self.cheight]
            self.sdpidx = 0
            self.curpos = len(self.db) - 1
            self.refresh = True
            return

    def _process_teardown(self, tag):
        """Processes call teardown (ENDED).

        Args:
            tag (str): call tag
        """
        if tag in self.tag_to_pcapfiles:
            self._remove_active_tcpdump(tag)
        if tag in self.db:
            self.refresh = True

    def _draw_stdscr(self, active=True):
        """Draws standard screen.

        Args:
            active (bool, optional): if screen is on top or not.
        """
        self.stdscr.erase()
        color = self._get_color("border", active)
        title_color = self._get_color("title", active)|curses.A_REVERSE
        colname_color = self._get_color("border", active)|curses.A_BOLD
        self.stdscr.addstr(0, 0, self.FRAME[0], title_color)
        self.stdscr.addstr(1, 0, self.FRAME[1], colname_color)
        self.stdscr.addstr(2, 0, self.FRAME[2], color)
        for y in range(3, self.maxy - 5):
            self.stdscr.addstr(y, 0, self.FRAME[3], color)
        for y in range(4, 0, -1):
            self.stdscr.addstr(self.maxy - y - 1, 0, self.FRAME[-y], color)
        self.stdscr.refresh()

    def _draw_centwin(self, active=True):
        """Draws center window.

        Args:
            active (bool, optional): if screen is on top or not.
        """
        for y, tag_sess in enumerate(self.db.iteritems()):
            t, s = tag_sess
            for y, x, func, args in (
                (y, 0, self._get_border, (active,)),
                (y, 1, self._get_starttime, (s, active)),
                (y, 9, self._get_border, (active,)),
                (y, 10, self._get_number, (s, "caller", active)),
                (y, 27, self._get_audio_ip, (s, "caller", active)),
                (y, 43, self._get_audio_codec_name, (s, "caller", active)),
                (y, 50, self._get_rx, (t, s, "caller", active)),
                (y, 53, self._get_audio_srtp, (s, "caller", active)),
                (y, 57, self._get_type, (s, "caller", active)),
                (y, 61, self._get_border, (active,)),
                (y, 62, self._get_number, (s, "callee", active)),
                (y, 79, self._get_audio_ip, (s, "callee", active)),
                (y, 95, self._get_audio_codec_name, (s, "callee", active)),
                (y, 102, self._get_rx, (t, s, "callee", active)),
                (y, 105, self._get_audio_srtp, (s, "callee", active)),
                (y, 109, self._get_type, (s, "callee", active)),
                (y, 113, self._get_border, (active,)),
                (y, 115, self._get_pcap_status, (t, active,)),
                (y, 119, self._get_status, (s, active)),
                (y, 125, self._get_border, (active,)),
            ):
                try:
                    string, color = func(*args)
                    if self.curpos == y:
                        if x == 1:
                            color = color|curses.A_REVERSE
                        else:
                            color = color|curses.A_BOLD
                    self.centwin.addstr(y, x, string, color)
                except:
                    pass
        self.centwin.refresh()

    def _draw_bottomwin(self, active=True):
        """Draws the bottom window.

        Args:
            active (bool, optional): if screen is on top or not.
        """
        if self.curpos == -1:
            return

        try:
            t, s = self.db[self.curpos]
        except KeyError:
            return

        for x, func, args in (
            (0, self._get_border, (active,)),
            (1, self._get_uptime, (s, active)),
            (9, self._get_border, (active,)),
            (10, self._get_audio_ip, (s, "caller", active, self.sdpidx)),
            (25, self._get_colon, (active,)),
            (26, self._get_audio_port, (s, "caller", active, self.sdpidx)),
            (32, self._get_iface, (s, "caller", active)),
            (40, self._get_asbce_audio_port, (s, "caller", active)),
            (45, self._get_colon, (active,)),
            (46, self._get_asbce_audio_ip, (s, "caller", active)),
            (61, self._get_border, (active,)),
            (62, self._get_asbce_audio_ip, (s, "callee", active)),
            (77, self._get_colon, (active,)),
            (78, self._get_asbce_audio_port, (s, "callee", active)),
            (84, self._get_iface, (s, "callee", active)),
            (92, self._get_audio_port, (s, "callee", active, self.sdpidx)),
            (97, self._get_colon, (active,)),
            (98, self._get_audio_ip, (s, "callee", active, self.sdpidx, True)),
            (113, self._get_border, (active,)),
            (114, self._get_numofcaps, (t, active,)),
            (119, self._get_numofconns, (s, active,)),
            (125, self._get_border, (active,)),
        ):
            try:
                string, color = func(*args)
                self.bottomwin.addstr(0, x, string, color)
            except:
                pass
        self.bottomwin.refresh()

    def _draw_menuwin(self):
        """Draws menu window."""
        if self.curpos == -1:
            t, s = None, None
        else:
            t, s = self.db[self.curpos]

        d = {"q": "q=Quit", "c": "c=Clear"}
        d["s"] = "s=Start" if not self.asbce.capture_active else "s=Stop"
        d["t"] = "" if not self._can_menu_tcpdump(s) else "t=Tshark"
        d["p"] = "" if not self._can_menu_nextconn(s) else "</>=N/P Conn"
        d["n"] = "" if not self._can_menu_nextpcap(t) else "n/p=N/P Pcap"
        d["e"] = "" if not self._can_menu_pcapstat(t) else "Enter=Pcap Stats"
        d["f"] = "" if not self._can_menu_flow(s) else "f=Flows"
        d["d"] = "" if not self._can_menu_write() else "d=Dump"
        d["w"] = "" if not self._can_menu_write() else "w=Write"
        d["g"] = "" if not self._can_menu_goto() else "g=Goto"
        format = "{s:7}  {c}  {q}  {d:6}  {w:7}  {g:6}  {f:7}  {t:8}  {p:12}  {n:12}  {e:17}"

        height = self.menwin_height
        self.menwin = curses.newwin(height, self.width+1, self.maxy-height, 0)
        self.menwin.addstr(0, 0, " " * self.width, self._get_color("border")|curses.A_REVERSE)
        self.menwin.addstr(0, 8, format.format(**d), self._get_color("border")|curses.A_REVERSE)

        if self.asbce.capture_active:
            self.menwin.addstr(0, 0, "Running", self.colors["running"]|curses.A_REVERSE)
        else:
            self.menwin.addstr(0, 0, "Stopped", self.colors["stopped"]|curses.A_REVERSE)
        self.stdscr.refresh()
        self.menwin.refresh()

    def _draw_capwin(self):
        """Draws capture filter window."""
        box = [
            "╒═════════════════════════════════════════════════════════════════════════╕",
            "│                             Capture Filter                              │",
            "│                                                                         │",
            "│     From/To: caller or callee numbers, separated by | if multiple       │",
            "│  IP address: caller signaling address, separated by | if multiple       │",
            "│                                                                         │",
            "│ For example: 72001|1002|9966  and/or  172.16.100.11|172.16.100.12       │",
            "│ <<< From/To and IP address filters are in Boolean AND relationship! >>> │",
            "│                                                                         │",
            "│                                                                         │",
            "│                                                                         │",
            "│                                                                         │",
            "│                                                                         │",
            "╘═════════════════════════════════════════════════════════════════════════╛",
        ]
        height = len(box)
        width = len(box[0].decode("utf-8"))
        xpos = self.width // 2 - width // 2 - 2
        ypos = (self.maxy - 5) // 2 - height // 2
        ch = None
        pos = 12
        capture_start = 0
        self.global_autotcpdump = 0
        options = [
            (6, "From/To:"),
            (3, "IP address:"),
            (15, "[ ] Enable tcpdump when calls starts (requires filter)"),
            (34, "[S]tart"),
        ]

        win = curses.newwin(height, width+1, ypos, xpos)
        win.keypad(1)
        win.timeout(500)
        for i, elem in enumerate(box):
            win.addstr(i, 0, elem, self._get_color("border"))

        while True:
            for i, e in enumerate(options, start=9):
                color = self._get_color("border")
                win.addstr(i, e[0], e[1], color|curses.A_REVERSE
                           if pos == i else color)
                if i == 9:
                    win.addstr(i, 15, "{0:58}".format(self.filteru),
                               self._get_color("text"))
                elif i == 10:
                    win.addstr(i, 15, "{0:58}".format(self.filterip),
                               self._get_color("text"))
                elif i == 11 and (self.filteru or self.filterip):
                    color = self._get_color("capx")
                    win.addstr(i, e[0]+1, "X" * self.global_autotcpdump,
                               color|curses.A_REVERSE if pos==i else color)
            win.refresh()

            ch = win.getch()
            if ch == -1:
                continue

            chstr = curses.keyname(ch)
            if chstr in ("q", "Q", "^[", "KEY_EXIT"):
                return
            elif chstr in ("s", "S"):
                capture_start = 1
            elif chstr == "KEY_UP":
                pos = 12 if pos <= 9 else pos - 1
            elif chstr == "KEY_DOWN":
                pos = 9 if pos == 12 else pos + 1
            else:
                if pos in (9, 10) and chstr in ("KEY_RIGHT", "KEY_ENTER", "^J"):
                    curses.curs_set(1)
                    twin = win.derwin(1, 58, pos, 15)
                    twin.attron(self._get_color("text"))
                    txtbox = curses.textpad.Textbox(twin, insert_mode=True)
                    txtbox.edit(self._validator)
                    curses.curs_set(0)
                    text = txtbox.gather().strip()

                    if pos == 9:
                        self._update_filteru(text)
                    elif pos == 10:
                        self._update_filterip(text)
                        if self._is_ip_filter_valid():
                            win.addstr(8, 15, "".rjust(19), self._get_color("border"))
                        else:
                            win.addstr(8, 15, "Invalid IP detected", self._get_color("error"))
                        win.refresh()
                elif (pos == 11 and
                      (self.user_filter or self.ip_filter) and
                      (chstr in ("^J", "X", "x") or ch == 32)
                    ):
                    self.global_autotcpdump = self.global_autotcpdump ^ 1
                elif pos == 12 and chstr in ("KEY_ENTER", "^J"):
                    capture_start = 1

            self.tracker.user_filter = self.user_filter
            self.tracker.ip_filter = self.ip_filter
            if capture_start:
                self.asbce.flows()
                self.asbce.capture_start()
                return

    def _draw_resizewin(self):
        """Force user to enlarge terminal size."""
        box = [
            "╒══ Enlarge Terminal ══╕",
            "│ Minimum size:        │",
            "│ Current size:        │",
            "╘══════════════════════╛",
        ]
        ch = None
        ypos = self.maxy // 2 - len(box) // 2
        xpos = self.maxx // 2 - len(box[0].decode("utf-8")) // 2
        win = curses.newwin(len(box), len(box[0]), ypos, xpos)
        for i, elem in enumerate(box):
            win.addstr(i, 0, elem, self._get_color("border"))
        win.keypad(1)
        self.stdscr.erase()
        self.stdscr.refresh()
        self.active = win

        while ch != curses.KEY_RESIZE:
            win.addstr(1, 16, "{0:>2}x{1}".format(self.min_height, self.width+1),
                       self._get_color("border"))
            win.addstr(2, 16, "{0:>2}x{1}".format(self.maxy, self.maxx),
                       self._get_color("border"))
            win.refresh()
            ch = win.getch()
            if ch == ord("q") or ch == ord("Q"):
                self.breakout = 1
                break
        self.stdscr.erase()
        self.stdscr.refresh()
        del win

    def _draw_loadwin(self):
        """Force user to enlarge terminal size."""
        box = [
            "╒═════════╕",
            "│ Loading │",
            "╘═════════╛",
        ]
        ch = None
        ypos = self.maxy // 2 - len(box) // 2
        xpos = self.maxx // 2 - len(box[0].decode("utf-8")) // 2
        win = curses.newwin(len(box), len(box[0]), ypos, xpos)
        for i, elem in enumerate(box):
            win.addstr(i, 0, elem, self._get_color("border"))
        win.refresh()

        if self.dumpfile:
            self.loaddb()
            self.dumpfile = None
        elif self.logfiles:
            self.loadlogs()
            self.logfiles = None

        self._draw_stdscr()
        self._ch_r()

    def _update_title(self):
        """Updates terminal status line."""
        cur = self.trkpos + self.curpos + 1
        tot = len(self.tracker.db)
        l = [self.asbce.hostname, "Ver:{0}".format(self.asbce.version)]
        l.append("Current/In Memory/Total Calls: {0:>4} / {1:>4} / {2}".format(
            self.trkpos+self.curpos+1, len(self.tracker.db), self.totalcalls
        ))
        l.append("Flows/4:{0:>4}".format(len(self.asbce.lastflows)//4))
        l.append("Tcpdumps:{0:>3}".format(len(self.tcpdump.pids)))
        l.append("Pcaps:{0:>3}".format(len(self.tcpdump.filenames)))
        l.append("Dumps:{0:>3}".format(len(self.dumps)))
        l.append("MemUsage:{0:>4}MB".format(self.maxrss))
        sys.stdout.write("\x1b]2;%s\x07" % "      ".join(l).ljust(self.maxx*3))
        sys.stdout.flush()

    def _add_conn_to_flows(self, tag, audioconns):
        """Adds new connection to flow list.

        Args:
            tag (str): call tag
            audioconns (list): list of audioconns
        """
        self.tracker.db[tag].flows.append(deque([
            Flows(d={(x.local_ip, x.local_port, x.type): {} for x in audioconns})],
            maxlen=2
        ))
        if len(self.tracker.db[tag].flows) > 1:
            self.tracker.db[tag].flows[-2].popleft()

        if tag == self.db[self.curpos][0]:
            self.sdpidx = self._get_curpos_noofconns() - 1

    def _update_flows(self):
        """Appends Flow data to flow list for active calls.
        This is run by the threaded timer every flow_interval_secs.

        Args:
            lock (obj): Thread lock object.
        """
        ts = self.asbce.lastflows_timestamp
        fd = self.asbce.flows()
        for tag in (k for k, v in self.tracker.db.iteritems()
                    if v.status in ("ONCALL", "ONHOLD")):
            try:
                d = {}
                for k in self.tracker.db[tag].flows[-1][-1].iterkeys():
                    v = fd.get((k[0], k[1]), None)
                    if v:
                        d.update({k: v})
                    elif self._is_call_dead(tag, ts):
                        self.tracker.db[tag].status = "LOST"
                        self.tracker.db[tag].endtime = datetime.now()
                        self._remove_active_tcpdump(tag)
                if d:
                    self.tracker.db[tag].flows[-1].append(Flows(d=d, timestamp=ts))
            except:
                pass
        self.refresh = True

    @coroutine
    def _flowwin(self):
        """Draws Flows window.

        Note: yields control back to main even flow.

        Yields:
            None: None
        """
        sdpidx = self.sdpidx
        tag = self.db[self.curpos][0]
        flows = self.tracker[tag].flows[sdpidx][-1]
        prev_flows = Flows()
        autoscroll = 1

        title = "F L O W S"
        vlan = "{InIf}.{InVlan}"
        srcipB = "{InSrcIP:>22}"
        srcportB = "{InSrcPort}"
        dstportB = "{InDstPort:>5}"
        dstipB = "{InDstIP:16}"
        srcipA = "{InSrcIP:15}"
        srcportA = "{InSrcPort:>5}"
        dstipA = "{InDstIP:>15}"
        dstportA = "{InDstPort:5}"
        countB = "{Rx:>5} {Enc:>5} {Dec:>5} {Drp:>5} {Rly:>5}"
        countA = "{Rly:>5} {Drp:>5} {Dec:>5} {Enc:>5} {Rx:>5}"

        box = [
            "╒══════════════════╕",
            "│ Extracting flows │",
            "╘══════════════════╛",
        ]

        ASBCE = [
            "╒════════════════════════════════════════════════════════════╕",
            "│                                                            │",
            "╘════════════════════════════════════════════════════════════╛",
        ]

        HEADER = [
            "│                                                                                                                        │",
            "   Rx   Enc   Dec   Drp   Rly                            ASBCE                               Rly   Drp   Dec   Enc    Rx",
            "╘════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════╛",
        ]

        # draw window around pad
        width = len(box[0].decode("utf-8")) + 1
        height = len(box)
        ypos = self.maxy // 2 - len(box) // 2 - 1
        xpos = self.width // 2 - width // 2 - 2
        win = curses.newwin(height, width, ypos, xpos)
        for i, elem in enumerate(box):
            win.addstr(i, 0, elem, self._get_color("border"))
        win.refresh()

        # draw small pad
        padwidth = self.width - 4
        padheight = 2
        pad = curses.newpad(1, padwidth)
        padypos = 0
        padypos_prev = 0

        chstr = (yield)
        while tag in self.tracker:
            try:
                if autoscroll:
                    sdpidx = len(self.tracker[tag].flows) - 1
                if chstr in ("KEY_ENTER", "^J", "Q", "q", "^[", "F", "f"):
                    break
                elif chstr == "KEY_DOWN":
                    padypos_prev = padypos
                    padypos = padypos if padheight-padypos+3 <= height and flows\
                                      else padypos+2
                elif chstr == "KEY_UP":
                    padypos_prev = padypos
                    padypos = 0 if padypos==0 else padypos-2
                elif chstr == "KEY_LEFT":
                    if sdpidx > 0:
                        sdpidx -= 1
                        prev_flows = flows
                        flows = self.tracker[tag].flows[sdpidx][-1]
                        autoscroll = 0
                elif chstr == "KEY_RIGHT":
                    if sdpidx < len(self.tracker[tag].flows) - 1:
                        sdpidx += 1
                        prev_flows = flows
                        flows = self.tracker[tag].flows[sdpidx][-1]
                    if sdpidx == len(self.tracker[tag].flows) - 1:
                        autoscroll = 1

                timestamp = self.asbce.lastflows_timestamp
                if sdpidx == len(self.tracker[tag].flows) - 1:
                    if timestamp and flows.timestamp < timestamp:
                        flows = self.tracker[tag].flows[sdpidx][-1]

                if flows and flows != prev_flows:
                    if len(flows) < len(prev_flows):
                        self.stdscr.erase()
                        self.centwin.erase()
                        self._draw_stdscr(active=False)
                        self._draw_centwin(active=False)
                        self._draw_menuwin()
                    prev_flows = flows
                    box = HEADER
                    boxasbce = ASBCE
                    sdpstatus = "{0}({1})".format(sdpidx+1, len(self.tracker[tag].flows))
                    height = min((int(ceil(len(flows)/2.0)*2) + 5), (self.maxy - 8))
                    width = len(box[0].decode("utf-8")) + 1
                    xpos = 2
                    ypos = (self.maxy - 5) // 2 - height // 2 + 2
                    win.resize(height, width)
                    win.mvwin(ypos, xpos)

                    # define and draw frame
                    win.erase()
                    win.addstr(0, 0, box[0], self._get_color("border"))
                    win.addstr(1, 0, box[0], self._get_color("border"))
                    win.addstr(1, 1, box[1], self._get_color("border")|curses.A_BOLD)
                    for i in range(2, height - 1):
                        win.addstr(i, 0, box[0], self._get_color("border"))
                        win.refresh()
                    win.addstr(0, 1, title.center(width - 3), self._get_color("title")|curses.A_REVERSE)
                    win.addstr(0, 67, sdpstatus, self._get_color("title")|curses.A_REVERSE)
                    win.addstr(height-1, 0, box[-1], self._get_color("border"))
                    win.refresh()

                    # define pad
                    pad.erase()
                    padwidth = self.width - 6
                    padheight = int(ceil(len(flows)/2.0)*2) + 2
                    pad.resize(padheight, padwidth)

                    # draw ASBCE
                    xposasbce = width // 2 - len(boxasbce[1].decode("utf-8")) // 2 - 1
                    pad.addstr(0, xposasbce, boxasbce[0], self._get_color("asbce"))
                    for i in range(1, int(ceil(len(flows)/2.0)*2) + 1):
                        pad.addstr(i, xposasbce, boxasbce[1], self._get_color("asbce"))
                    pad.addstr(padheight-1, xposasbce, boxasbce[2], self._get_color("asbce"))
                    padypos = 0 if (padheight-1) < padypos else padypos

                    i = 0
                    kvs = sorted(flows.iteritems(), key=itemgetter(1), reverse=False)
                    while kvs:
                        k, v = kvs.pop(0)
                        type = k[2]
                        flowA = v._asdict()
                        try:
                            # draw A-side fVlan
                            pad.addstr((i*2)+1, 83, vlan.format(**flowA).rjust(7), self._get_color("vlan"))
                            # draw A-side IP:port
                            pad.addstr((i*2)+1, 61, dstipA.format(**flowA), self._get_color("ip"))
                            pad.addstr((i*2)+1, 76, ":", self._get_color("border"))
                            pad.addstr((i*2)+1, 77, dstportA.format(**flowA), self._get_color("port"))
                            pad.addstr((i*2)+1, 90, "┼", self._get_color("asbce"))
                            pad.addstr((i*2)+1, 91, srcportA.format(**flowA), self._get_color("port"))
                            pad.addstr((i*2)+1, 96, ":", self._get_color("border"))
                            pad.addstr((i*2)+1, 97, srcipA.format(**flowA), self._get_color("ip") if
                                       type in ("caller", "callee") else self._get_color("border"))
                            # draw A-side counter
                            pad.addstr((i*2)+2, 91, countA.format(**flowA), self._get_color("counts"))
                        except:
                            pad.addstr((i*2)+1, 90, "┼", self._get_color("asbce"))
                            pad.addstr((i*2)+2, 90, "│", self._get_color("asbce"))
                        try:
                            k, v = next((k, v) for k, v in flows.iteritems() if
                                (k[0], k[1]) == (flowA["OutSrcIP"], flowA["OutSrcPort"]))
                            type = k[2]
                            flowB = v._asdict()
                        except KeyError:
                            pass
                        try:
                            # draw B-side Vlan
                            pad.addstr((i*2)+1, 30, vlan.format(**flowB).ljust(7), self._get_color("vlan"))
                            # draw B-side IP:portf
                            pad.addstr((i*2)+1, 1, srcipB.format(**flowB), self._get_color("ip") if
                                       type in ("caller", "callee") else self._get_color("border"))
                            pad.addstr((i*2)+1, 23, ":", self._get_color("border"))
                            pad.addstr((i*2)+1, 24, srcportB.format(**flowB).ljust(5), self._get_color("port"))
                            pad.addstr((i*2)+1, 29, "┼", self._get_color("asbce"))
                            pad.addstr((i*2)+1, 38, dstportB.format(**flowB), self._get_color("port"))
                            pad.addstr((i*2)+1, 43, ":", self._get_color("border"))
                            pad.addstr((i*2)+1, 44, dstipB.format(**flowB), self._get_color("ip"))
                            # draw B-side counter
                            pad.addstr((i*2)+2, 0, countB.format(**flowB), self._get_color("counts"))
                        except:
                            pad.addstr((i*2)+1, 29, "┼", self._get_color("asbce"))
                            pad.addstr((i*2)+2, 29, "│", self._get_color("asbce"))
                        try:
                            idx = kvs.index((k, v))
                            kvs.pop(idx)
                        except:
                            pass
                        i += 1
                    try:
                        pad.refresh(padypos, 0, ypos+2, xpos+1, ypos+height-2, xpos+width-3)
                    except:
                        pass

                if flows and (padypos_prev != padypos or not padypos_prev):
                    try:
                        pad.refresh(padypos, 0, ypos+2, xpos+1, ypos+height-2, xpos+width-3)
                    except:
                        pass
            except:
                pass
            chstr = yield None

    @coroutine
    def _gotowin(self):
        """Draws Goto window.

        Note: yields control back to main even flow.

        Args:
            pcapfile_pcapstats (tuple): pcapfile str, pcapstat dict

        Yields:
            None: None
        """
        box = [
            "╒═══════════════════════════════════════╕",
            "│ Goto call timestamp:                  │",
            "│ Goto From/To number:                  │",
            "╘═══════════════════════════════════════╛",
        ]
        validchars = [str(x) for x in range(0, 10)] + [":"]
        width = len(box[0].decode("utf-8"))
        ypos = self.maxy // 2 - len(box) // 2 - 1
        xpos = self.width // 2 - width // 2 - 2
        win = curses.newwin(len(box), width+1, ypos, xpos)
        for i, elem in enumerate(box):
            win.addstr(i, 0, elem, self._get_color("border"))
        win.keypad(1)
        win.move(1, 23)
        win.refresh()
        curses.curs_set(1)

        ypos = 1
        xpos = 23
        chars = []
        chstr = (yield)
        while True:
            if chstr in validchars:
                if ypos == 1 and xpos < 31:
                    chars.append(chstr)
                    xpos += 1
                elif ypos == 2 and xpos < 39:
                    chars.append(chstr)
                    xpos += 1
            elif chstr in ("KEY_BACKSPACE", "^H"):
                chars = chars[:-1]
                xpos = xpos - 1 if xpos > 23 else xpos
            elif chstr in ("KEY_UP", "KEY_DOWN"):
                ypos = 1 if ypos == 2 else 2
                xpos = 23
                chars = []
            elif chstr in ("Q", "q", "G", "g"):
                break
            elif chstr in ("KEY_ENTER", "^J"):
                self.autoscroll = 0
                if ypos == 1:
                    chars = "".join(chars)[:9]
                    try:
                        self.trkpos = next(i for i, sess in
                            enumerate(self.tracker.db.itervalues()) if
                            sess.starttime.strftime("%H:%M:%S") >= chars)
                        self.curpos = 0
                    except:
                        pass
                    break
                elif ypos == 2 and chars:
                    chars = "".join(chars)
                    try:
                        self.trkpos = next(i for i, sess in
                            enumerate(
                                self.tracker.db[self.trkpos+1:].itervalues(),
                                start=self.trkpos+1
                            ) if (
                                    sess.caller.number.endswith(chars) or
                                    sess.callee.number.endswith(chars)
                                ))
                        self.curpos = 0
                    except:
                        pass
                    break

            if chstr != "NONE":
                for y in range(1, 3):
                    win.addstr(y, 23,
                              ("".join(chars) if ypos==y else "").ljust(16),
                               self._get_color("text"))
                win.move(ypos, xpos)
                win.refresh()
            chstr = yield None

        self.sdpidx = 0
        self.capidx = 0
        curses.curs_set(0)
        self.db = self.tracker.db[self.trkpos:self.trkpos+self.cheight]
        self._refresh_wins()

    @coroutine
    def _tsharkwin(self):
        """Draws Pcap stats window.

        Note: yields control back to main even flow.

        Args:
            pcapfiles_pcapstats (tuple): pcapfiles lst, pcapstat dict

        Yields:
            None: None
        """

        def draw_win():
            # resize win
            win.resize(height, width)
            win.mvwin(ypos, 2)
            win.erase()

            for i in range(0, height):
                win.addstr(i, 0, box[0], self._get_color("border")|curses.A_BOLD)

                win.addstr(0, 1, title.center(width-3), self._get_color("title")|curses.A_REVERSE)
                for i in range(0, len(pcapfiles)):
                    win.addstr(i+1, 1, "Pcap file:", self._get_color("border"))
                    win.addstr(i+1, 13, "{0}".format(pcapfiles[i]), self._get_color("pcapfile"))

                win.addstr(height-1, 0, box[1], self._get_color("border"))
                win.addstr(height//2-1, width-2, "»", self._get_color("border"))
                win.refresh()

        box = [
            "╒══════════════════════╕",
            "│ Processing pcap file │",
            "╘══════════════════════╛",
        ]

        # draw processing window
        pwidth = len(box[0].decode("utf-8")) + 1
        ypos = self.maxy // 2 - len(box) // 2 - 1
        xpos = self.width // 2 - pwidth // 2 - 2
        win = curses.newwin(len(box), pwidth, ypos, xpos)
        for i, elem in enumerate(box):
            win.addstr(i, 0, elem, self._get_color("border"))
        win.refresh()
    
        try:
            self.running_queue.get_nowait()
        except:
            pass

        tag = self.db[self.curpos][0]
        sdpidx = self.sdpidx
        capidx = self.capidx
        merged = {}
        prev_merged = {}
        can_update = True
        width = self.width - 3

        title = "P C A P   A N A L Y S I S"
        updinfo = "Updating every {0} secs".format(self.tshark_update_secs)
        cols = (
            ("SrcIPAddr", 15),
            ("SrcPort", 7),
            ("DstIPAddr", 15),
            ("DstPort", 7),
            ("SSRC", 10),
            ("DSCP", 4),
            ("Payload", 12),
            ("Pkts", 4),
            ("PktLossPct", 10),
            ("MaxDelta", 8),
            ("MaxSkew", 7),
            ("MaxJitter", 9),
            ("MeanJitter", 10),
            ("RFC2833Payload", 14),
            ("RFC2833Events", 13),
        )
        f = " ".join("{"+str(i)+":>"+str(c[1])+"}" for i, c in enumerate(cols))
        colnames = f.format(*map(itemgetter(0), cols))
        fmtrow = " ".join("{"+c[0]+":>"+str(c[1])+"}" for c in cols)
        box = [
            "│                                                                                                                        │",
            "╘════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════╛",
        ]
        
        # draw small pad
        padwidth = sum(x[1]+1 for x in cols) + 1
        pad = curses.newpad(1, padwidth)
        padxpos = 0
        padxpos_prev = None

        chstr = (yield)
        while True:
            
            if can_update and self._is_tshark_update_due():
                pcapfiles, merged = self.pcaps[tag][sdpidx][capidx]
                can_update = False
                if not merged:
                    th = self._pcap_thread(pcapfiles)
                else:
                    self._toggle_dimming(active=False)
                    height = len(merged) + len(pcapfiles) + 3
                    ypos = self.maxy // 2 - height // 2 - 1
                    draw_win()

            elif not self.running_queue.empty():
                self.lasttshark_timestamp = datetime.now()
                can_update = True
                merged = self.running_queue.get()
                th.join()

            if merged and len(merged) != len(prev_merged):
                if len(merged) < len(prev_merged):
                    self._toggle_dimming(active=False)
                height = len(merged) + len(pcapfiles) + 3
                ypos = self.maxy // 2 - height // 2 - 1
                draw_win()
                
                # resize pad
                padheight = len(merged) + 1
                pad.resize(padheight, padwidth)
                pad.erase()
                prev_merged = merged

            if chstr == "KEY_RESIZE":
                ypos = self.maxy // 2 - height // 2 - 1
                win.mvwin(ypos, 2)
                win.erase()
                for i in range(0, height - 1):
                    win.addstr(i, 0, box[0], self._get_color("border"))
                win.refresh()
            elif chstr == "KEY_LEFT":
                padxpos_prev = padxpos
                padxpos = 0 if padxpos==0 else padxpos-1
            elif chstr == "KEY_RIGHT":
                padxpos_prev = padxpos
                padxpos = padxpos+1 if padwidth-padxpos > width else padxpos
            elif chstr in ("KEY_ENTER", "^J", "Q", "q", "^[", "T"):
                try:
                    self.running_queue.get_nowait()
                except:
                    pass
                break

            if merged:
                if padwidth - padxpos > width:
                    win.addstr(height//2-1, width-2, "»", self._get_color("border"))
                else:
                    win.addstr(height//2-1, width-2, "│", self._get_color("border"))
                win.refresh()

                if padxpos_prev != padxpos or padxpos_prev is None or can_update:
                    for i, v in enumerate(merged.values(), start=1):
                        pad.addstr(i, 0, fmtrow.format(**v), self._get_color("border"))
                    pad.addstr(0, 0, colnames, self._get_color("border")|curses.A_BOLD)
                    pad.refresh(
                        0, padxpos, ypos + 3, 3,
                        ypos + len(merged) + len(pcapfiles) + 1, self.width-4
                    )
            chstr = yield None

    @coroutine
    def _quitwin(self):
        """Draws Quit window.

        Note: yields control back to main even flow.

        Yields:
            None: None
        """
        box = [
            "╒═══════════════════╕",
            "│ Are you sure? Y/N │",
            "╘═══════════════════╛",
        ]
        width = len(box[0].decode("utf-8"))
        ypos = self.maxy // 2 - len(box) // 2 - 1
        xpos = self.width // 2 - width // 2 - 2
        win = curses.newwin(len(box), width+1, ypos, xpos)
        for i, elem in enumerate(box):
            win.addstr(i, 0, elem, self._get_color("border"))
        win.keypad(1)
        win.refresh()
        chstr = (yield)
        while True:
            if chstr in ("Y", "y"):
                self.breakout = True
                break
            elif chstr in ("N", "n"):
                break
            chstr = yield None

    @coroutine
    def _writewin(self):
        """Draws Write window.

        Note: yields control back to main even flow.

        Yields:
            None: None
        """
        box = [
            "╒═══════════════════════════════════════════════════════════════════════════════════════╕",
            "│ Enter filename including path, press ENTER key to complete or ESC key twice to cancel │",
            "│ File name:                                                                            │",
            "│                                                                                       │",
            "╘═══════════════════════════════════════════════════════════════════════════════════════╛",
        ]
        chars = []
        validchars = string.letters + string.digits + "/_."
        width = len(box[0].decode("utf-8"))
        ypos = self.maxy // 2 - len(box) // 2 - 1
        xpos = self.width // 2 - width // 2 - 2
        win = curses.newwin(len(box), width+1, ypos, xpos)
        for i, elem in enumerate(box):
            win.addstr(i, 0, elem, self._get_color("border"))
        win.keypad(1)
        win.move(2, 13)
        win.refresh()
        curses.curs_set(1)

        xpos = 13
        rv = ""     
        chstr = (yield)
        while True:
            if chstr in validchars:
                if len(chars) < 74:
                    chars.append(chstr)
                    xpos += 1
            if chstr in ("KEY_BACKSPACE", "^H"):
                chars = chars[:-1]
                xpos = xpos - 1 if chars else 13
            elif chstr == "^[":
                curses.curs_set(0)
                break
            elif chstr in ("KEY_ENTER", "^J"):
                if not chars:
                    curses.curs_set(0)
                    break
                rv = self.dumpdb("".join(chars))
                if rv.startswith("".join(chars)):
                    curses.curs_set(0)
                    break
            if chstr != "NONE":
                win.addstr(2, 13, "".join(chars).ljust(74), self._get_color("text"))
                win.addstr(3, 2, rv[:74].ljust(74), self._get_color("error"))
                win.move(2, xpos)
                win.refresh()
            chstr = yield None

    @coroutine
    def _dumpwin(self):
        """Draws Dump window.

        Note: yields control back to main even flow.

        Yields:
            None: None
        """
        box = [
            "╒════════════════════════════════════════════════════════════╕",
            "│                                                            │",
            "╘════════════════════════════════════════════════════════════╛",
        ]
        dump_filename = None

        chstr = (yield)
        while True:
            if not dump_filename:
                dump_filename = self.dumpdb()
                width = len(box[0].decode("utf-8"))
                ypos = self.maxy // 2 - len(box) // 2 - 1
                xpos = self.width // 2 - width // 2 - 2
                win = curses.newwin(len(box), width+1, ypos, xpos)
                for i, elem in enumerate(box):
                    win.addstr(i, 0, elem, self._get_color("border"))
                if not dump_filename.startswith("dump"):
                    win.addstr(1, 2, dump_filename[:58], self._get_color("error"))
                else:
                    win.addstr(1, 2, dump_filename, self._get_color("text"))
                    win.addstr(1, 54, "created", self._get_color("border"))
                win.refresh()

            elif chstr in ("KEY_ENTER", "^J", "Q", "q", "d", "D") and dump_filename:
                break
            chstr = yield None

    @coroutine
    def _helpwin(self):
        """Draws Help window.

        Note: yields control back to main even flow.

        Yields:
            None: None
        """
        box = [
            "╒═══════════════════════════════════════════════════════════════════╕",
            "│ c = Clear                                s = Start/Stop           │",
            "│ d = Dump (quick write)                   t = Tshark (start/stop)  │",
            "│ g = Goto (timestamp/From-To number)    </> = Next/Prev Connection │",
            "│ h = Help                               n/p = Next/Prev Pcap File  │",
            "│ f = Flows                                w = Write                │",
            "│ r = Refresh (force refresh screen)   Enter = Pcap RTP Statistics  │",
            "╘═══════════════════════════════════════════════════════════════════╛",
        ]

        width = len(box[0].decode("utf-8"))
        ypos = self.maxy // 2 - len(box) // 2 - 1
        xpos = self.width // 2 - width // 2 - 2
        win = curses.newwin(len(box), width+1, ypos, xpos)
        for i, elem in enumerate(box):
            win.addstr(i, 0, elem, self._get_color("border"))
        win.refresh()

        chstr = (yield)
        while True:
            if chstr in ("KEY_ENTER", "^J", "Q", "q", "h", "H", "^["):
                break
            chstr = yield None

    def _get_pcap_status(self, tag, active=True):
        """tuple: Returns border string and curses color."""
        if tag in self.tag_to_pcapfiles:
            pcap = self.symbols["capact"]
        elif tag in self.pcaps:
            pcap = self.symbols["cap"]
        else:
            pcap = " "
        return (pcap, self._get_color("pcap", active))

    def _get_border(self, active=True):
        """tuple: Returns border string and color."""
        return ("│", self._get_color("border", active))

    def _get_colon(self, active=True):
        """tuple: Returns colon and color."""
        return (":", self._get_color("border", active))

    def _get_iface(self, sess, type, active=True, width=7):
        """tuple: Returns iface string and curses color."""
        color = self._get_color("iface", active)
        try:
            ip = next(c for c in sess.audioconns[self.sdpidx] if c.type==type).local_ip
            return (self.ifaces[ip].center(width), color)
        except:
            return (" ".center(width), color)

    def _get_asbce_audio_ip(self, sess, type, active=True, width=15):
        """tuple: Returns ASBCE audio ip string and curses color."""
        color = self._get_color("ip", active)
        try:
            ip = next(c for c in sess.audioconns[self.sdpidx] if c.type==type).local_ip
            if type == "caller":
                return (ip.ljust(width), color)
            return (ip.rjust(width), color)
        except:
            return (" ".center(width), color)

    def _get_asbce_audio_port(self, sess, type, active=True, width=5):
        """tuple: Returns ASBCE audio port string and curses color."""
        color = self._get_color("port", active)
        try:
            port = next(c for c in sess.audioconns[self.sdpidx] if c.type==type).local_port
            if type == "caller":
                return (str(port).rjust(width), color)
            return (str(port).ljust(width), color)
        except:
            return (" ".center(width), color)

    def _get_uptime(self, sess, active=True):
        """tuple: Returns duration string and curses color."""
        return (sess.duration, self._get_color("time", active))

    def _get_starttime(self, sess, active=True):
        """tuple: Returns starttime string and curses color."""
        color = self._get_color("time", active)
        try:
            return (sess.starttime.strftime("%H:%M:%S"), color)
        except:
            return (" ".rjust(8), color)

    def _get_number(self, sess, type, active=True, width=16):
        """tuple: Returns from/to number string and curses color."""
        color = self._get_color("fromto", active)
        try:
            return (getattr(sess, type).number[-width:].rjust(width), color)
        except:
            return (" ".rjust(width), color)

    def _get_audio_ip(self, sess, type, active=True, sdpidx=-1, ljust=False, width=15):
        """tuple: Returns caller/callee audio ip string and curses color."""
        color = self._get_color("ip", active)
        try:
            ip = next(c for c in sess.audioconns[sdpidx] if c.type==type).remote_ip
            return (ip.ljust(width) if ljust else ip.rjust(width), color)
        except:
            return (" ".rjust(width), color)

    def _get_audio_port(self, sess, type, active=True, sdpidx=-1, width=5):
        """tuple: Returns caller/callee audio port string and curses color."""
        color = self._get_color("port", active)
        try:
            port = next(c for c in sess.audioconns[sdpidx] if c.type==type).remote_port
            if type == "caller":
                return (str(port).ljust(width), color)
            return (str(port).rjust(width), color)
        except:
            return (" ".rjust(width), color)

    def _get_audio_codec_name(self, sess, type, active=True, width=6):
        """tuple: Returns audio codec name string and curses color."""
        color = self._get_color("codec", active)
        try:
            return (getattr(sess, type).audio_codec_name.ljust(width), color)
        except:
            return (" ".ljust(width), color)

    def _get_audio_srtp(self, sess, type, active=True):
        """tuple: Returns srtp symbol string and curses color."""
        color = self._get_color("inact", active)
        try:
            srtp = getattr(sess, type).audio_crypto
            if srtp:
                color = (self._get_color("srtp", active)
                         if sess.status not in ("ENDED", "LOST", "CANCEL")
                         else self.colors["inact"])
                return (self.symbols["ok"], color)
            return (" ", color)
        except:
            return (" ", color)

    def _get_type(self, sess, type, active=True, default="RW", width=4):
        """tuple: Returns caller/callee type string and curses color."""
        ip = getattr(sess, type).sig_ip
        try:
            if ip in self.servers:
                type = self.servers[ip].type
                if "Call" in type:
                    return (type.rjust(width), self._get_color("call", active))
                return (type.rjust(width), self._get_color("trk", active))
            return (default.rjust(width), self._get_color("rw", active))
        except:
            return (" ".rjust(width), self._get_color("border", active))

    def _get_rx(self, tag, sess, type, active=True):
        """tuple: Returns flow RX symbol string and curses color."""
        try:
            key = next(k for k in sess.flows[-1][-1].iterkeys() if k[2]==type)
            rx = sess.flows[-1][-1].d[key].Rx
        except:
            return "  ", self._get_color("rxok", active)
        try:
            prevkey = next(k for k in sess.flows[-1][-2].iterkeys() if k[2]==type)
            prevrx = sess.flows[-1][-2].d[prevkey].Rx
        except:
            prevkey, prevrx = None, 0

        if rx > 0:
            if rx > prevrx:
                symbol = self.symbols["ok"]
                color = self._get_color("rxok", active) 
            elif rx == prevrx:
                symbol = self.symbols["halt"]
                color = self._get_color("rxhalt", active)
        else:
            symbol = self.symbols["nok"]
            color = self._get_color("rxnok", active)

        return (symbol, (color if sess.status not in ("ENDED", "LOST")
                         else self.colors["inact"]))

    def _get_status(self, sess, active=True, width=6):
        """tuple: Returns call status string and curses color."""
        status = sess.status
        if status in ("ONCALL", "ONHOLD"):
            color = self._get_color("sipup", active)
        else:
            color = self._get_color("sipdown", active)
        try:
            return (status.rjust(width), color)
        except:
            return (" ".rjust(width), color)

    def _get_numofcaps(self, tag, active=True, width=5):
        """tuple: Returns number of pcaps string and curses color."""
        try:
            num = len(self.pcaps[tag][self.sdpidx])
        except:
            num = 0
        return ("{0}({1})".format(self.capidx+1 if num else 0, num).rjust(width),
                self._get_color("border", active))

    def _get_numofconns(self, sess, active, width=6):
        """tuple: Returns number of connections string and curses color."""
        try:
            num = len(sess.audioconns)
        except:
            num = 0
        return ("{0}({1})".format(self.sdpidx+1 if num else 0, num).rjust(width),
                self._get_color("border", active))

    def _get_pcapfile(self, tag=None):
        """Returns list of pcapfiles and list of pcap stat dicts
        at idx position.

        Args:
            tag (str, optional): call tag, Defaults to None.

        Returns:
            tuple(list, list): list of pcap files or list of their stats
        """
        if tag is None:
            tag = self.db[self.curpos][0]
        if tag in self.pcaps:
            try:
                pcaps = self.pcaps[tag][self.sdpidx]
                return pcaps[self.capidx]
            except:
                return [], []
        return [], []

    def _get_color(self, k, active=True):
        """Returns the color of k from self.colors.

        Args:
            k (str): name of key from "colors" attribute.
            active (bool, optional): If centwin is active. Defaults to True.

        Returns:
            obj: curses color object
        """
        if self.skin_green:
            return (self.colors["skingreen"] if active
                    else self.colors["inact"])
        elif self.skin_mono:
            return (self.colors["skinmono"] if active
                    else self.colors["inact"])
        return (self.colors.get(k, self.colors["border"]) if active
                else self.colors["inact"])

    def _get_curpos_noofconns(self):
        """int: Returns the number of connection at current cursor position."""
        try:
            return len(self.db[self.curpos][1].audioconns)
        except:
            return 1

    def _can_menu_tcpdump(self, sess):
        """bool: Returns True if call can be tcpdumped."""
        return (self.asbce.capture_active and
                sess.status not in ("ENDED", "SETUP") if sess else False)

    def _can_menu_nextconn(self, sess):
        """bool: Returns True if call has multiple connections."""
        return len(sess.audioconns) > 1 if sess else False

    def _can_menu_nextpcap(self, tag):
        """bool: Returns True if connection has multimple pcap files."""
        try:
            return (bool(len(self.pcaps[tag].get(self.sdpidx, [])) > 1)
                    if tag in self.pcaps else False)
        except:
            return False

    def _can_menu_pcapstat(self, tag):
        """bool: Returns True if connection has pcap file."""
        return any(self._get_pcapfile(tag)) if tag else None

    def _can_menu_flow(self, sess):
        """bool: Returns True if user can invoke 'f' button."""
        return bool(sess.flows) if sess else False

    def _can_menu_write(self):
        """bool: Returns True if user can invoke 'd' button."""
        return bool(self.db)

    def _can_menu_goto(self):
        """bool: Returns True if user can invoke 'g' button."""
        return bool(self.db)

    def _update_filteru(self, text):
        """Updates From/To number filter string and list. 

        Args:
            text (str): sting input from From/To Textbox.

        Returns:
            None
        """
        text = text.strip("|").replace(".", "")
        self.filteru = "" if (not text or text == self.filteru) else text
        self.user_filter = self.filteru.split("|") if self.filteru else []

    def _update_filterip(self, text):
        """Updates IP address filter string and list. 

        Args:
            text (str): sting input from IP Address Textbox.

        Returns:
            None
        """
        text = text.strip("|")
        self.filterip = "" if (not text or text == self.filterip) else text
        self.ip_filter = self.filterip.split("|") if self.filterip else []

    def _ch_b(self):
        """Processes B key stroke."""
        if self.debug:
            self._dump_debug()

    def _ch_c(self):
        """Processes C key stroke."""
        self.tracker.clear()
        self.db.clear()
        self.trkpos = 0
        self.curpos = -1
        self.autoscroll = 1
        self.totalcalls = 0
        self.db = self.tracker.db[self.trkpos:self.trkpos+self.cheight]
        self._draw_stdscr()
        self._draw_menuwin()
        self._update_title()

    def _ch_d(self):
        """Processes D key stroke."""
        self._toggle_dimming(active=False)
        self.active = self._dumpwin()

    def _ch_f(self):
        """Processes F key stroke."""
        if self.curpos == -1:
            return

        try:
            if self.db and self.db[self.curpos][1].flows[0]:
                self.autoscroll = 0
                self._toggle_dimming(active=False)
                self._draw_menuwin()
                self.active = self._flowwin()
        except IndexError:
            return

    def _ch_g(self):
        """Processes G key stroke."""
        if self.curpos == -1:
            return

        self._toggle_dimming(active=False)
        self._draw_stdscr(active=False)
        self._refresh_wins(active=False)
        self.active = self._gotowin()

    def _ch_h(self):
        """Processes H key stroke."""
        self._toggle_dimming(active=False)
        self._draw_stdscr(active=False)
        self._refresh_wins(active=False)
        self.active = self._helpwin()

    def _ch_n(self):
        """Processes N key stroke."""
        try:
            if (
                len(self.pcaps[self.db[self.curpos][0]][self.sdpidx]) >
                self.capidx + 1
            ):
                self.capidx += 1
                self._draw_bottomwin()
        except:
            pass

    def _ch_p(self):
        """Processes P key stroke."""
        if self.capidx > 0:
            self.capidx -= 1
            self._draw_bottomwin()

    def _ch_q(self):
        """Processes Q key stroke."""
        self._toggle_dimming(active=False)
        if self.asbce.capture_active:
            self.active = self._quitwin()
        else:
            self.breakout = True

    def _ch_r(self):
        """Processes R key stroke."""
        self.stdscr.clear()
        self.stdscr.refresh()
        self.centwin.clear()
        self.centwin.refresh()
        self.bottomwin.clear()
        self.bottomwin.refresh()
        self.menwin.clear()
        self.menwin.refresh()
        self._draw_stdscr(self.active==self.centwin)
        self._refresh_wins(self.active==self.centwin)

    def _ch_s(self):
        """Processes S key stroke."""
        if not self.asbce.capture_active:
            self._toggle_dimming(active=False)
            self._draw_capwin()
            self._toggle_dimming(active=True)
            self._draw_menuwin()
            self.reader = self.Reader(
                methods=["INVITE", "BYE", "CANCEL", "ACK", "REFER"],
                ignore_fnu=True
            )
        elif self.asbce.capture_stop():
            self._draw_menuwin()

    def _ch_t(self):
        """Processes T key stroke."""
        if self.curpos == -1:
            return

        try:
            tag, sess = self.db[self.curpos]
        except KeyError:
            return

        if tag in self.tag_to_pcapfiles:
            self._remove_active_tcpdump(tag)

        elif len(self.tag_to_pcapfiles) < self.max_autotcpdumps:
            kwargs = self._tcpdump_kwargs(tag, sess)
            if not kwargs:
                return
            pcapfiles = self.tcpdump.fork(**kwargs)
            if not pcapfiles:
                return
            self.tag_to_pcapfiles[tag] = pcapfiles
            self.pcapfiles_to_tag[pcapfiles] = tag

            sdpidx = len(sess.audioconns) - 1
            self.pcaps.setdefault(tag, {}).setdefault(sdpidx, []).append(
                [pcapfiles, []]
            )
            self.capidx = len(self.pcaps[tag][sdpidx]) - 1

        self._update_title()
        if tag in self.db:
            self._draw_centwin(self.active==self.centwin)
            self._draw_bottomwin(self.active==self.centwin)
        return

    def _ch_w(self):
        """Processes W key stroke."""
        if self.curpos == -1:
            return

        self._draw_stdscr(active=False)
        self._refresh_wins(active=False)
        self.active = self._writewin()

    def _ch_enter(self):
        """Processes Enter key stroke."""
        pcapfiles, pcapstats = self._get_pcapfile()
        if pcapfiles or pcapstats:
            self._draw_stdscr(active=False)
            self._refresh_wins(active=False)
            self.active = self._tsharkwin()

    def _ch_home(self):
        """Processes HOME key stroke."""
        self.curpos = 0 if self.db else self.cursor
        self.trkpos = 0
        self.capidx = 0
        self.autoscroll = 0
        self.db = self.tracker.db[self.trkpos:self.trkpos+self.cheight]
        self.sdpidx = self._get_curpos_noofconns() - 1
        self._refresh_wins()

    def _ch_end(self):
        """Processes END key stroke."""
        if len(self.tracker.db) > self.cheight:
            self.trkpos = len(self.tracker.db) - self.cheight
        else:
            self.trkpos = 0

        self.autoscroll = 1
        self.capidx = 0
        self.db = self.tracker.db[self.trkpos:self.trkpos+self.cheight]
        self.curpos = len(self.db) - 1
        self.sdpidx = self._get_curpos_noofconns() - 1
        self._refresh_wins()

    def _ch_up(self):
        """Processes UP arrow key stroke."""
        if self.curpos == -1:
            return

        if self.curpos > 0:
            self.curpos -= 1
        elif self.trkpos > 0:
            self.trkpos -= 1
            self.db = self.tracker.db[self.trkpos:self.trkpos+self.cheight]

        self.autoscroll = 0
        self.sdpidx = self._get_curpos_noofconns() - 1
        self.capidx = 0
        self._refresh_wins()  

    def _ch_down(self):
        """Processes DOWN arrow key stroke."""
        if self.curpos == -1:
            return

        if self.curpos < len(self.db) - 1:
            self.curpos += 1
        else: 
            if len(self.tracker.db) > self.trkpos + self.cheight:
                self.trkpos += 1
                self.db = self.tracker.db[self.trkpos:self.trkpos+self.cheight]
            else:
                self.autoscroll = 1

        self.sdpidx = self._get_curpos_noofconns() - 1
        self.capidx = 0
        self._refresh_wins()

    def _ch_npage(self):
        """Processes PGDOWN key stroke."""
        if self.curpos == -1:
            return

        if len(self.tracker.db) > self.trkpos + 2 * self.cheight:
            self.trkpos += self.cheight
            self.curpos = 0
        elif len(self.tracker.db) <= self.cheight:
            self.autoscroll = 1
            self.curpos = len(self.db) - 1
        else: 
            self.trkpos = len(self.tracker.db) - self.cheight
            self.autoscroll = 1
            self.curpos = len(self.db) - 1

        self.db = self.tracker.db[self.trkpos:self.trkpos+self.cheight]
        self.sdpidx = self._get_curpos_noofconns() - 1
        self.capidx = 0
        self._refresh_wins()

    def _ch_ppage(self):
        """Processes PGUP key stroke."""
        if self.curpos == -1:
            return

        if self.trkpos < self.cheight:
            self.trkpos = 0
            self.curpos = 0
        else:
            self.trkpos -= self.cheight
            self.curpos = len(self.db) - 1
            self.centwin.erase()

        self.autoscroll = 0
        self.db = self.tracker.db[self.trkpos:self.trkpos+self.cheight]
        self.sdpidx = self._get_curpos_noofconns() - 1
        self.capidx = 0
        self._refresh_wins()

    def _ch_right(self):
        """Processes RIGHT arrow key stroke."""
        if self.curpos == -1:
            return
        if self._get_curpos_noofconns() > self.sdpidx + 1:
            self.sdpidx += 1
            self.capidx = 0
            self._draw_bottomwin()
            self._draw_menuwin()

    def _ch_left(self):
        """Processes LEFT arrow key stroke."""
        if self.curpos == -1:
            return
        if self.sdpidx > 0:
            self.sdpidx -= 1
            self.capidx = 0
            self._draw_bottomwin()
            self._draw_menuwin()

    def _ch_resize(self):
        """Processes curses KEY_RESIZE stroke."""
        self.main(self.stdscr)

    def _ch_backspace(self):
        """Processes BACKSPACE key stroke."""
        pass

    def _validator(self, ch):
        """Validates chars in Textbox. Only digits, . and | are allowed. 

        Args:
            ch (int): decimal value of ASCII value of input char.

        Returns:
            int or "": int if input char is valid or "" otherwise.
        """
        if ch <= 16 or 48 <= ch <= 57 or ch > 256 or ch in (46, 124):
            return ch
        return ""

    def _is_ip_filter_valid(self):
        """bool: Returns True if IP filter is valid."""
        if not self.ip_filter:
            return True
        elif all(self.is_ip_valid(ip) for ip in self.ip_filter):
            return True
        return False

    def _is_call_dead(self, tag, timestamp=None):
        """Returns True if call is assumed ENDED.

        Note: this is required to mark potentially ended calls
            when the ASBCE's logging falters. 

        Args:
            tag (str): call tag
            timestamp (datetime obj): datetime timestamp of last showflow

        Returns:
            bool: True if the flows of call disappeared from last
                showflow output longer than deadcall_timedelta
        """
        if timestamp is None:
            timestamp = datetime.now()
        try:
            diff = timestamp - self.tracker.db[tag].flows[-1][-1].timestamp
            return diff > self.deadcall_timedelta
        except:
            return True

    def _is_flow_update_due(self):
        """bool: Returns True if ASBCE flow update is due."""
        diff = datetime.now() - self.asbce.lastflows_timestamp
        return diff > timedelta(seconds=self.flow_update_secs)

    def _is_tshark_update_due(self):
        """bool: Returns True if ASBCE flow update is due."""
        if self.lasttshark_timestamp is None:
            return True
        diff = datetime.now() - self.lasttshark_timestamp
        return diff > timedelta(seconds=self.tshark_update_secs)

    def _get_sdpidx_capidx_of_pcapfiles(self, tag, pcapfiles):
        try:
            return next((sdpidx, capidx) for sdpidx, v in
                         self.pcaps[tag].iteritems() for capidx, v2 in
                         enumerate(v) if pcapfiles in v2)
        except:
            return None, None

    def _worker(self, pcapfiles, tag, sdpidx, capidx):
        """Thread worker funcion."""
        self.lock.acquire()
        for pcapfile in pcapfiles:
            self.pcapparser.parse(pcapfile)
        merged = self.pcapparser.asdict(hexssrc=True, sorted=True)
        self.pcapparser.clear()
        self.lock.release()

        if tag:
            self.pcaps[tag][sdpidx][capidx][1] = merged
        else:
            self.running_queue.put(merged)

    def _pcap_thread(self, pcapfiles, tag=None, sdpidx=None, capidx=None):
        """Thread which runs to parse Pcap files with tshark."""
        th = Thread(target=self._worker, 
                    args=(pcapfiles, tag, sdpidx, capidx))
        th.start()
        return th

    def _tcpdump_kwargs(self, tag, sess):
        """Returns dict with tcpdump arguments

        Args:
            tag (str): call tag
            sess (SessionInfo obj): SessionInfo instance

        Returns:
            dict: dictionary containing tcpdump arguments.
        """
        if (not self.asbce.capture_active or
            sess.status in ("SETUP", "ENDED") or
            tag in self.tag_to_pcapfiles
        ):
            return None

        d = {}
        try:
            d["pairs"] = [(self.publics.get(x.local_ip, x.local_ip), x.local_port)
                          for x in sess.audioconns[-1]]
        except IndexError:
            return None
        d["caller"] = sess.caller.number
        d["callee"] = sess.callee.number
        return d

    def _update_pcap_with_pcapstats(self, tag, pcapfiles):
        """Updates pcap dict with pcapstas. This is called when call ends.
        Args:
            tag (str): call tag
            pcapfiles (list): list of pcap filenames
        """
        sdpidx, capidx = self._get_sdpidx_capidx_of_pcapfiles(tag, pcapfiles)
        th = self._pcap_thread(pcapfiles, tag, sdpidx, capidx)

    def _remove_active_tcpdump(self, tag):
        """Removes active tcpdump process.

        Args:
            tag (str): call tag.
        """
        pcapfiles = self.tag_to_pcapfiles.pop(tag, None)
        if not pcapfiles:
            return
        self.tcpdump.kill(pcapfiles)
        self.pcapfiles_to_tag.pop(pcapfiles, None)
        self._update_pcap_with_pcapstats(tag, pcapfiles)
        return pcapfiles

    def sigchld_handler(self, signum, frame):
        """Handles SIGCHLD signal and removes defunct pids."""
        try:
            child_pid, _ = os.waitpid(-1, os.WNOHANG)
            if child_pid not in self.tcpdump.pids:
                return
        except Exception as e:
            return
        pcapfiles = self.tcpdump.kill(child_pid)
        if pcapfiles in self.pcapfiles_to_tag:
            tag = self.pcapfiles_to_tag.pop(pcapfiles, None)
            if tag:
                self.tag_to_pcapfiles.pop(tag, None)
                self._update_pcap_with_pcapstats(tag, pcapfiles)
                if tag in self.db:
                    self._draw_centwin(self.active==self.centwin)
                    self._draw_bottomwin(self.active==self.centwin)
        self._update_title()


    def sigwinch_handler(self, signum, frame):
        """Handles SIGWINCH signal."""
        curses.endwin()
        self.main(self.stdscr)

    def sigterm_handler(self, signum, frame):
        """Handles SIGTERM and other signals."""
        self.breakout = True
        self.exit()

    def loadargs(self):
        """Loads dumpfile or logfiles args."""
        if self.dumpfile:
            self.loaddb()
            self.dumpfile = None
        elif self.logfiles:
            self.loadlogs()
            self.logfiles = None
        self._draw_stdscr()
        self._ch_r()

    def dumpdb(self, filename=None):
        """Dumps data to gzip file.

        Args:
            filename (str, optional): filename, Defaults to None.

        Returns:
            str: dump filename
        """
        diff = None
        if filename is None:
            first = self.tracker.db[0][1].starttime
            last = self.tracker.db[-1][1].starttime
            filename = "dump_from_{0}_till_{1}".format(
                first.strftime("%Y-%m%d-%H%M%S"),
                last.strftime("%Y-%m%d-%H%M%S"),
            )

        try:
            dump_filename = filename + ".gz"
            with gzip.open(dump_filename, "wb") as gzipfd:
                cPickle.dump(self.tracker.db, gzipfd, protocol=2)
                cPickle.dump(self.pcaps, gzipfd, protocol=2)
                cPickle.dump(self.servers, gzipfd, protocol=2)
                cPickle.dump(self.publics, gzipfd, protocol=2)
                cPickle.dump(self.ifaces, gzipfd, protocol=2)
                cPickle.dump(self.tag_to_pcapfiles, gzipfd, protocol=2)
            os.chmod(dump_filename, 0o644)
        except Exception as e:
            if self.debug:
                logging.exception("Exception in dumpdb:")
            try:
                os.remove(oldest_dump_filename)
            except:
                pass
            return e

        if dump_filename.startswith(filename):
            self.dumps.append((dump_filename, last))
            oldest_dump_filename, oldest_timestamp = self.dumps[0]
            diff = last - oldest_timestamp
            if diff > timedelta(hours=self.autodump_hrs):
                self.dumps.popleft()
                try:
                    os.remove(oldest_dump_filename)
                except:
                    pass
        return dump_filename

    def loaddb(self, filename=None):
        """Loads filename dumpfile.

        Args:
            filename (str, optional): path to dumpfile. Defaults to None.
        """
        if not filename:
            filename = self.dumpfile
        try:
            with gzip.open(filename, "rb") as gzipfd:
                self.tracker.db = cPickle.load(gzipfd)
                self.pcaps = cPickle.load(gzipfd)
                self.servers = cPickle.load(gzipfd)
                self.publics = cPickle.load(gzipfd)
                self.ifaces = cPickle.load(gzipfd)
                self.tag_to_pcapfiles = cPickle.load(gzipfd)
        except Exception as e:
            if self.debug:
                logging.exception("Exception in loaddb:")

        self.curpos = 0
        self.trkpos = 0
        self.db = self.tracker.db[self.trkpos:self.trkpos+self.cheight]

    def loadlogs(self, logfiles=None):
        """Loads SSINDY or Tracesbc_sip log files.

        Note: this is just for debugging.

        Args:
            logfiles ([type], optional): [description]. Defaults to None.
        """
        if not logfiles:
            logfiles = self.logfiles
        if "SSYNDI" in logfiles[0]:
            reader = SsyndiSIPReader(logfiles=logfiles)
        else:
            reader = TracesbcSIPReader(logfiles=logfiles)
        for msg in reader:
            self.tracker.update(msg)

        if self.tracker:
            self.db = self.tracker.db[self.trkpos:self.trkpos+self.cheight]
            self.curpos = 0

    def exit(self):
        """Performs cleanup before exit."""
        self.asbce.capture_stop()
        self.tcpdump.killall()
        curses.endwin()
        os.system("clear")

    def _toggle_dimming(self, active=True):
        """Dims main pane windows.

        Args:
            active (bool, optional): Dims in True otherwise
                turns them back on.
        """
        self._draw_stdscr(active=active)
        self._draw_centwin(active=active)
        self._draw_bottomwin(active=active)
        self._draw_menuwin()

    def _refresh_wins(self, active=True):
        """Refreshes the windows.

        Args:
            active (bool, optional): Dims if True.
        """
        self._draw_centwin(active=active)
        self._draw_bottomwin(active=active)
        self._draw_menuwin()
        self._update_title()

    @staticmethod
    def is_ip_valid(ip):
        """Validates ip.

        Args:
            ip (str): ip address

        Returns:
            bool: True if ip is valid IP address.
        """
        m = re.match(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$", ip)
        return bool(m) and all(int(n) <= 255 for n in m.groups())

    @staticmethod
    def memory_usage_resource():
        """int: Returns the current memory usage in MB."""
        rusage_denom = 1024.
        mem = int(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / rusage_denom)
        return mem

    def _dump_debug(self, e=None):
        """Dumps debug info.

        Args:
            e (Exception): Exception. Defaults to None.
        """
        timestamp = datetime.now()
        try:
            logging.debug("DATETIME: {0}".format(timestamp))
            if e:
                logging.debug("Exception: {0}".format(e))
            logging.debug("len(tracker): {0}".format(len(self.tracker)))
            logging.debug("len(db): {0}".format(len(self.db)))
            logging.debug("curpos: {0}".format(self.curpos))
            logging.debug("trkpos: {0}".format(self.trkpos))
            logging.debug("stdscr: %s" % self.stdscr)
            logging.debug("stdscr.getmaxyx: {0}".format(self.stdscr.getmaxyx()))
            logging.debug("centwin: %s" % self.centwin)
            logging.debug("centwin.getmaxyx: {0}".format(self.centwin.getmaxyx()))
        except:
            pass


##############################################################################
#                                  FUNCTIONS                                 #
##############################################################################


def initterm():
    os.environ["TERM"] = "screen-256color"
    locale.setlocale(locale.LC_ALL, "")

def restoreterm():
    os.environ["TERM"] = TERM
    sys.stdout.write("\x1b]2;%s\x07" % node().ljust(120))
    sys.stdout.flush()

def is_already_running():
    try:
        fcntl.flock(selffd, fcntl.LOCK_EX|fcntl.LOCK_NB)
    except IOError:
        return True
    return False

def is_user_root():
    return os.getuid() == 0

def main():
    parser = OptionParser(usage='%prog [<options>] [<dumpfile>]',
                          description=HELP.format(VERSION))
    parser.add_option('-a', '--autodump', action='store_true', default=False, dest='autodump',\
                    help='to dump data every time when max number of calls is reached')
    parser.add_option('-n', action='store', default=1000, dest='maxlen',\
                    help='number of calls retained in memory\n\
                          default 1000, maximum 2000', metavar='<number>')
    parser.add_option('-c', action='store', default=10000, dest='max_packets',\
                    help='number of packets captured in a tcpdump sample\n \
                         default 10000, maximum 20000 (on each iface)', metavar='<number>')
    parser.add_option('-f', action='store', default=3, dest='flow_update_secs',\
                    help='number of seconds between flow updates\n\
                          default 3, min 2', metavar='<secs>')
    parser.add_option('-t', action='store', default=3, dest='tshark_update_secs',\
                    help='number of seconds between tshark updates\n\
                          default 3, min 2', metavar='<secs>')
    parser.add_option('-i', action='store', default=8, dest='autodump_hrs',\
                    help='number of hours worth of dumps kept on disk\n\
                          default 8, max 24', metavar='<hrs>')
    parser.add_option('-b', '--black', action='store_true', default=False, dest='skin_mono',\
                    help='use mono color')
    parser.add_option('-g', '--green', action='store_true', default=False, dest='skin_green',\
                    help='use mono green color')
    parser.add_option('--debug', action='store_true', default=False, dest='debug',\
                    help=SUPPRESS_HELP)
    parser.add_option('--ssyndi', action='store_true', default=False, dest='ssyndi',\
                    help=SUPPRESS_HELP)
    opts, args = parser.parse_args()

    opts.max_packets = min(int(opts.max_packets), MAX_PACKETS)
    opts.maxlen = min(int(opts.maxlen), MAXLEN)
    opts.flow_update_secs = max(int(opts.flow_update_secs), MIN_FLOW_UPDATE_SECS)
    opts.tshark_update_secs = max(int(opts.tshark_update_secs), MIN_TSHARK_UPDATE_SECS)
    opts.dumpfile = args[0] if args and os.path.exists(args[0]) else None
    opts.autodump_hrs = min(int(opts.autodump_hrs), MAX_AUTODUMP_HRS)

    if args and os.path.exists(args[0]):
        if args[0].startswith(("SSYNDI", "tracesbc_sip")):
            opts.logfiles = args
            opts.dumpfile = None
        else:
            opts.logfiles = None
            opts.dumpfile = args[0]
    else:
        opts.dumpfile = None
        opts.logfiles = None

    winmgr = Winmgr(maxlen=opts.maxlen,
                    debug=opts.debug,
                    max_packets=opts.max_packets,
                    flow_update_secs=opts.flow_update_secs,
                    tshark_update_secs=opts.tshark_update_secs,
                    dumpfile=opts.dumpfile,
                    logfiles=opts.logfiles,
                    autodump=opts.autodump,
                    autodump_hrs=opts.autodump_hrs,
                    skin_mono=opts.skin_mono,
                    skin_green=opts.skin_green,
                    ssyndi=opts.ssyndi,
                )

    signal.signal(signal.SIGCHLD, winmgr.sigchld_handler)
    signal.signal(signal.SIGINT, winmgr.sigterm_handler)
    signal.signal(signal.SIGTERM, winmgr.sigterm_handler)
    signal.signal(signal.SIGTSTP, winmgr.sigterm_handler)
    signal.signal(signal.SIGQUIT, winmgr.sigterm_handler)

    if opts.debug:
        logging.basicConfig(filename=DEBUG_LOG, level=logging.DEBUG)

    curses.wrapper(winmgr.main)


##############################################################################
#                                    THE END                                 #
##############################################################################

if __name__ == "__main__":
    selffd = open(os.path.realpath(__file__), "r")
    if is_already_running():
        print("ERROR: {0} is already running.".format(
            os.path.basename(sys.argv[0]))
        )
        sys.exit(1)
    if not is_user_root():
        print("ERROR: only 'root' can run this tool.")
        sys.exit(2)

    try:
        initterm()
        main()
    except KeyboardInterrupt:
        winmgr.exit()
    finally:
        restoreterm()
