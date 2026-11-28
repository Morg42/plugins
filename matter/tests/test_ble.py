#!/usr/bin/env python3
# vim: set encoding=utf-8 tabstop=4 softtabstop=4 shiftwidth=4 expandtab
"""
Tests for plugins/matter/server/ble.py: the BLE prerequisite checks read a
temporary tree laid out like /proc and /sys, and a file-capability xattr
encoded the way the kernel stores it (vfs_cap_data).
"""

import errno
import os
import struct
import sys
import tempfile
import unittest

from plugins.matter.server.sidecar import MatterServerSidecar, ServerSidecarSettings
from plugins.matter.server.ble import (
    CAP_NET_RAW,
    VFS_CAP_FLAGS_EFFECTIVE,
    BleEnvironment,
    BleProbe,
    CheckState,
    probe_ble,
)

PID = 4242
NODE = '/usr/bin/node'
VFS_CAP_REVISION_2 = 0x02000000


def file_caps(permitted: int, effective: bool = True) -> bytes:
    """security.capability xattr value (revision 2) with *permitted* as the low capability word."""
    magic = VFS_CAP_REVISION_2 | (VFS_CAP_FLAGS_EFFECTIVE if effective else 0)
    return struct.pack('<5I', magic, permitted, 0, 0, 0)


class _BleTest(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.tmp = tmp.name
        self.proc = os.path.join(tmp.name, 'proc')
        self.sys = os.path.join(tmp.name, 'sys')
        self.bin = os.path.join(tmp.name, 'bin')
        self.xattrs: dict[str, bytes] = {}

    def _process(self, cap_eff: int, euid: int = 1000, exe: str | None = NODE):
        """A /proc/<PID> entry for a process with effective capabilities *cap_eff*, running *exe* (None: exe link unreadable)."""
        pid_dir = os.path.join(self.proc, str(PID))
        os.makedirs(pid_dir)
        with open(os.path.join(pid_dir, 'status'), 'w') as f:
            f.write(f'Name:\tnode\nUid:\t{euid}\t{euid}\t{euid}\t{euid}\nCapEff:\t{cap_eff:016x}\n')
        if exe is not None:
            os.symlink(exe, os.path.join(pid_dir, 'exe'))

    def _adapter(self, hci: str = 'hci0', soft: int = 0, hard: int = 0):
        """A /sys/class/bluetooth/<hci> entry with one rfkill switch."""
        rfkill = os.path.join(self.sys, 'class', 'bluetooth', hci, 'rfkill3')
        os.makedirs(rfkill)
        for name, value in (('soft', soft), ('hard', hard)):
            with open(os.path.join(rfkill, name), 'w') as f:
                f.write(f'{value}\n')

    def _env(self, read_xattr=True) -> BleEnvironment:
        return BleEnvironment(self.proc, self.sys, self._read_xattr if read_xattr else None, self.bin)

    def _installed_node(self, link_target: str | None = None) -> str:
        """An executable ``node`` on the search path, optionally a symlink to *link_target*; return its real path."""
        os.makedirs(self.bin, exist_ok=True)
        real = os.path.join(self.tmp, link_target) if link_target else os.path.join(self.bin, 'node')
        os.makedirs(os.path.dirname(real), exist_ok=True)
        with open(real, 'w') as f:
            f.write('#!/bin/sh\n')
        os.chmod(real, 0o755)
        if link_target:
            os.symlink(real, os.path.join(self.bin, 'node'))
        return os.path.realpath(real)

    def _read_xattr(self, path: str, name: str) -> bytes:
        try:
            return self.xattrs[path]
        except KeyError:
            raise OSError(errno.ENODATA, 'No data available') from None

    def _status(self, pid: int | None = PID, adapter: str = '0', node_binary: str = NODE):
        probe = BleProbe(adapter, pid, node_binary, self._env())
        return {check.name: check for check in probe_ble(probe).checks}


class TestProcessCapability(_BleTest):
    def test_process_with_net_raw_passes(self):
        self._process(cap_eff=1 << CAP_NET_RAW)

        self.assertIs(self._status()['process_net_raw'].state, CheckState.OK)

    def test_process_without_net_raw_fails_with_setcap_hint_for_its_real_binary(self):
        self._process(cap_eff=0, exe='/opt/node-v22/bin/node')

        check = self._status()['process_net_raw']

        self.assertIs(check.state, CheckState.FAIL)
        self.assertIn('setcap cap_net_raw+eip /opt/node-v22/bin/node', check.hint)

    def test_process_without_net_raw_but_capable_binary_asks_for_a_restart(self):
        self._process(cap_eff=0)
        self.xattrs[NODE] = file_caps(1 << CAP_NET_RAW)

        check = self._status()['process_net_raw']

        self.assertIs(check.state, CheckState.FAIL)
        self.assertIn('restart', check.hint)
        self.assertNotIn('setcap', check.hint)

    def test_status_without_capability_line_is_unknown(self):
        os.makedirs(os.path.join(self.proc, str(PID)))
        with open(os.path.join(self.proc, str(PID), 'status'), 'w') as f:
            f.write('Name:\tnode\n')

        self.assertIs(self._status()['process_net_raw'].state, CheckState.UNKNOWN)

    def test_no_running_sidecar_is_unknown(self):
        self.assertIs(self._status(pid=None)['process_net_raw'].state, CheckState.UNKNOWN)


class TestBinaryCapability(_BleTest):
    def test_binary_with_effective_net_raw_passes(self):
        self._process(cap_eff=1 << CAP_NET_RAW)
        self.xattrs[NODE] = file_caps(1 << CAP_NET_RAW)

        self.assertIs(self._status()['binary_net_raw'].state, CheckState.OK)

    def test_binary_without_file_capabilities_fails_with_setcap_hint(self):
        self._process(cap_eff=0)

        check = self._status()['binary_net_raw']

        self.assertIs(check.state, CheckState.FAIL)
        self.assertIn(f'setcap cap_net_raw+eip {NODE}', check.hint)

    def test_binary_with_net_raw_permitted_but_not_effective_fails(self):
        self._process(cap_eff=0)
        self.xattrs[NODE] = file_caps(1 << CAP_NET_RAW, effective=False)

        self.assertIs(self._status()['binary_net_raw'].state, CheckState.FAIL)

    def test_sidecar_running_as_root_needs_no_file_capability(self):
        self._process(cap_eff=(1 << 41) - 1, euid=0)

        self.assertIs(self._status()['binary_net_raw'].state, CheckState.OK)

    def test_capable_process_with_unreadable_exe_link_checks_the_node_found_on_the_search_path(self):
        node = self._installed_node()
        self._process(cap_eff=1 << CAP_NET_RAW, exe=None)
        self.xattrs[node] = file_caps(1 << CAP_NET_RAW)

        check = self._status(node_binary='node')['binary_net_raw']

        self.assertIs(check.state, CheckState.OK)
        self.assertIn(node, check.detail)

    def test_setcap_hint_names_the_real_file_behind_a_symlinked_node(self):
        node = self._installed_node(link_target='opt/node-v22/bin/node')
        self._process(cap_eff=0, exe=None)

        check = self._status(node_binary='node')['binary_net_raw']

        self.assertIs(check.state, CheckState.FAIL)
        self.assertIn(f'setcap cap_net_raw+eip {node}', check.hint)

    def test_unreadable_file_capabilities_are_unknown(self):
        self._process(cap_eff=0)
        probe = BleProbe('0', PID, NODE, self._env(read_xattr=False))

        checks = {check.name: check for check in probe_ble(probe).checks}

        self.assertIs(checks['binary_net_raw'].state, CheckState.UNKNOWN)


class TestAdapter(_BleTest):
    def test_present_unblocked_adapter_passes(self):
        self._adapter('hci0')

        self.assertIs(self._status()['adapter'].state, CheckState.OK)

    def test_missing_adapter_fails(self):
        self._adapter('hci1')

        check = self._status(adapter='0')['adapter']

        self.assertIs(check.state, CheckState.FAIL)
        self.assertIn('hci0', check.detail)

    def test_soft_blocked_adapter_fails(self):
        self._adapter('hci0', soft=1)

        check = self._status()['adapter']

        self.assertIs(check.state, CheckState.FAIL)
        self.assertIn('rfkill', check.hint)

    def test_hard_blocked_adapter_fails(self):
        self._adapter('hci0', hard=1)

        self.assertIs(self._status()['adapter'].state, CheckState.FAIL)

    def test_no_bluetooth_sysfs_is_unknown(self):
        self.assertIs(self._status()['adapter'].state, CheckState.UNKNOWN)


class TestServerSidecar(_BleTest, unittest.IsolatedAsyncioTestCase):
    """MatterServerSidecar runs the checks against its own process; a Python script stands in for matter-server."""

    def setUp(self):
        super().setUp()
        self.entry = os.path.join(self.tmp, 'entry.py')
        with open(self.entry, 'w') as f:
            f.write("import time\nprint('Webserver listening on', flush=True)\ntime.sleep(60)\n")

    def _sidecar(self, adapter: str | None) -> MatterServerSidecar:
        settings = ServerSidecarSettings(port=0, bluetooth_adapter=adapter)
        storage = os.path.join(self.tmp, 'storage')
        return MatterServerSidecar(sys.executable, self.entry, storage, settings, ble_env=self._env())

    async def test_status_covers_the_running_sidecar_process(self):
        sidecar = self._sidecar('0')
        await sidecar.start()
        self.addAsyncCleanup(sidecar.stop)
        os.makedirs(os.path.join(self.proc, str(sidecar.pid)))
        with open(os.path.join(self.proc, str(sidecar.pid), 'status'), 'w') as f:
            f.write(f'Uid:\t1000\t1000\t1000\t1000\nCapEff:\t{1 << CAP_NET_RAW:016x}\n')

        checks = {check.name: check for check in sidecar.ble_status().checks}

        self.assertIs(checks['process_net_raw'].state, CheckState.OK)

    async def test_failed_check_is_logged_when_the_sidecar_starts(self):
        self._adapter('hci1')
        sidecar = self._sidecar('0')

        with self.assertLogs(sidecar.logger, level='WARNING') as logs:
            await sidecar.start()
        self.addAsyncCleanup(sidecar.stop)

        self.assertTrue(any('hci0 not found' in line for line in logs.output))

    async def test_no_configured_adapter_has_no_status(self):
        self.assertIsNone(self._sidecar(None).ble_status())


if __name__ == '__main__':
    unittest.main()
