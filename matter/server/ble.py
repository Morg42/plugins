#!/usr/bin/env python3
# vim: set encoding=utf-8 tabstop=4 softtabstop=4 shiftwidth=4 expandtab
#########################################################################
#  Copyright 2026-  Sebastian Helms                 Morg @ knx-user-forum
#########################################################################
#  This file is part of SmartHomeNG.
#  https://www.smarthomeNG.de
#
#  Linux prerequisites for matter-server's BLE commissioning, read from
#  /proc and /sys: raw-socket capability of the running sidecar and of its
#  node binary, presence and rfkill state of the configured HCI adapter.
#
#  SmartHomeNG is free software: you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation, either version 3 of the License, or
#  (at your option) any later version.
#
#  SmartHomeNG is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with SmartHomeNG. If not, see <http://www.gnu.org/licenses/>.
#
#########################################################################

from __future__ import annotations

import enum
import errno
import glob
import os
import shutil
import struct
from dataclasses import dataclass, field
from typing import Callable

CAP_NET_RAW = 13
# vfs_cap_data.magic_etc flag: the file's permitted capabilities are raised into the effective set on exec.
VFS_CAP_FLAGS_EFFECTIVE = 0x000001


class CheckState(enum.Enum):
    OK = 'ok'
    FAIL = 'fail'
    # Not determinable here: not Linux, sidecar not running, unreadable file.
    UNKNOWN = 'unknown'


@dataclass(frozen=True)
class CheckResult:
    """Outcome of one BLE prerequisite check; hint says how to fix a FAIL."""

    name: str
    state: CheckState
    detail: str
    hint: str | None = None


@dataclass(frozen=True)
class BleEnvironment:
    """Where the checks read from: the real system by default, a prepared tree in tests."""

    proc_root: str = '/proc'
    sys_root: str = '/sys'
    # os.getxattr, which only exists on Linux
    read_xattr: Callable[[str, str], bytes] | None = field(default=getattr(os, 'getxattr', None))
    # PATH used to resolve a bare node_binary; None: the process environment's PATH, as for the sidecar itself
    search_path: str | None = None


@dataclass(frozen=True)
class BleProbe:
    """Subject of the checks: configured HCI id, sidecar pid (None if not running), configured node binary."""

    adapter: str
    pid: int | None
    node_binary: str
    env: BleEnvironment = field(default_factory=BleEnvironment)

    @property
    def hci(self) -> str:
        return f'hci{self.adapter}'


BleCheck = Callable[[BleProbe], CheckResult]


@dataclass(frozen=True)
class BleStatus:
    """Results of all BLE_CHECKS for one adapter."""

    adapter: str
    checks: tuple[CheckResult, ...]

    @property
    def failed(self) -> tuple[CheckResult, ...]:
        return tuple(check for check in self.checks if check.state is CheckState.FAIL)


def probe_ble(probe: BleProbe, checks: tuple[BleCheck, ...] | None = None) -> BleStatus:
    """Run *checks* (default: BLE_CHECKS) against *probe*."""
    return BleStatus(probe.adapter, tuple(check(probe) for check in (checks or BLE_CHECKS)))


def _proc_status(probe: BleProbe) -> dict[str, str] | None:
    """Fields of /proc/<pid>/status, None if there is no running sidecar or the file can't be read."""
    if probe.pid is None:
        return None
    try:
        with open(os.path.join(probe.env.proc_root, str(probe.pid), 'status')) as f:
            lines = f.read().splitlines()
    except OSError:
        return None
    return {key: value.strip() for key, _, value in (line.partition(':') for line in lines)}


def _binary_path(probe: BleProbe) -> str:
    """
    The executable the sidecar runs: /proc/<pid>/exe, else the configured
    node binary resolved via the search path and symlinks (setcap acts on
    the real file).

    /proc/<pid>/exe is unreadable for the sidecar's own user exactly when
    file capabilities took effect: the kernel marks such a process
    non-dumpable, which hides the link.
    """
    if probe.pid is not None:
        try:
            return os.readlink(os.path.join(probe.env.proc_root, str(probe.pid), 'exe'))
        except OSError:
            pass
    found = shutil.which(probe.node_binary, path=probe.env.search_path)
    return os.path.realpath(found) if found else probe.node_binary


def _binary_net_raw(probe: BleProbe, path: str) -> bool | None:
    """
    Whether *path*'s file capabilities raise CAP_NET_RAW into the effective
    set on exec (setcap ...+ep), None if file capabilities can't be read here.

    The security.capability xattr is a little-endian vfs_cap_data: magic_etc
    (revision and the effective flag), then the low permitted word.
    """
    if probe.env.read_xattr is None:
        return None
    try:
        raw = probe.env.read_xattr(path, 'security.capability')
    except OSError as ex:
        return False if ex.errno == errno.ENODATA else None
    if len(raw) < 8:
        return False
    magic_etc, permitted = struct.unpack_from('<2I', raw)
    return bool(magic_etc & VFS_CAP_FLAGS_EFFECTIVE) and bool(permitted >> CAP_NET_RAW & 1)


def _setcap_hint(path: str) -> str:
    return f'sudo setcap cap_net_raw+eip {path}, then restart the sidecar'


def check_process_net_raw(probe: BleProbe) -> CheckResult:
    """The running sidecar holds CAP_NET_RAW in its effective set - without it BLE scanning never starts."""
    name = 'process_net_raw'
    status = _proc_status(probe)
    try:
        cap_eff = int(status['CapEff'], 16) if status is not None else None
    except (KeyError, ValueError):
        cap_eff = None
    if cap_eff is None:
        return CheckResult(name, CheckState.UNKNOWN, 'sidecar process not readable')
    if cap_eff >> CAP_NET_RAW & 1:
        return CheckResult(name, CheckState.OK, 'CAP_NET_RAW effective')
    path = _binary_path(probe)
    if _binary_net_raw(probe, path):
        hint = f'{path} has the capability, restart the sidecar to pick it up'
    else:
        hint = _setcap_hint(path)
    return CheckResult(name, CheckState.FAIL, 'CAP_NET_RAW missing', hint)


def check_binary_net_raw(probe: BleProbe) -> CheckResult:
    """
    The sidecar's node binary carries CAP_NET_RAW as a file capability, so
    every (re)started sidecar gets it. Replacing the binary (node update)
    drops it again. Not needed while the sidecar runs as root.
    """
    name = 'binary_net_raw'
    status = _proc_status(probe)
    if status is not None and status.get('Uid', '').split()[1:2] == ['0']:
        return CheckResult(name, CheckState.OK, 'not needed, sidecar runs as root')
    path = _binary_path(probe)
    has_cap = _binary_net_raw(probe, path)
    if has_cap is None:
        return CheckResult(name, CheckState.UNKNOWN, f'file capabilities of {path} not readable')
    if has_cap:
        return CheckResult(name, CheckState.OK, f'{path}: cap_net_raw+ep')
    return CheckResult(name, CheckState.FAIL, f'{path}: cap_net_raw+ep missing', _setcap_hint(path))


def _rfkill_blocked(adapter_dir: str) -> dict[str, str]:
    """The adapter's set rfkill switches: 'soft'/'hard' -> path of the switch file."""
    blocked = {}
    for switch in ('soft', 'hard'):
        for path in glob.glob(os.path.join(adapter_dir, 'rfkill*', switch)):
            try:
                with open(path) as f:
                    if f.read().strip() == '1':
                        blocked[switch] = path
                        break
            except OSError:
                pass
    return blocked


def check_adapter(probe: BleProbe) -> CheckResult:
    """The configured HCI adapter exists and no rfkill switch blocks it."""
    name = 'adapter'
    bluetooth_dir = os.path.join(probe.env.sys_root, 'class', 'bluetooth')
    if not os.path.isdir(bluetooth_dir):
        return CheckResult(name, CheckState.UNKNOWN, f'{bluetooth_dir} not present (no Bluetooth support or not Linux)')
    adapter_dir = os.path.join(bluetooth_dir, probe.hci)
    if not os.path.isdir(adapter_dir):
        found = ', '.join(sorted(os.listdir(bluetooth_dir))) or 'none'
        return CheckResult(
            name,
            CheckState.FAIL,
            f'{probe.hci} not found (present: {found})',
            "check the adapter with 'bluetoothctl list' and server_bluetooth_adapter (HCI id, e.g. '0')",
        )
    blocked = _rfkill_blocked(adapter_dir)
    if 'hard' in blocked:
        return CheckResult(name, CheckState.FAIL, f'{probe.hci} hard blocked', 'release the hardware radio switch')
    if blocked:
        return CheckResult(name, CheckState.FAIL, f'{probe.hci} soft blocked', f'echo 0 | sudo tee {blocked["soft"]}')
    return CheckResult(name, CheckState.OK, f'{probe.hci} present, not blocked')


BLE_CHECKS: tuple[BleCheck, ...] = (check_adapter, check_process_net_raw, check_binary_net_raw)
