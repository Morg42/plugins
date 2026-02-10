#!/usr/bin/env python3
# vim: set encoding=utf-8 tabstop=4 softtabstop=4 shiftwidth=4 expandtab
#########################################################################
#  Copyright 2014-2018 Thomas Ernst                       offline@gmx.net
#  Copyright 2019- Onkel Andy                       onkelandy@hotmail.com
#########################################################################
#  Finite state machine plugin for SmartHomeNG
#
#  This plugin is free software: you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation, either version 3 of the License, or
#  (at your option) any later version.
#
#  This plugin is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this plugin. If not, see <http://www.gnu.org/licenses/>.
#########################################################################
from queue import Queue
from threading import RLock
import datetime as datetime


class BaseScheduler:

    def __init__(self, smarthome, se_plugin, logger, name):
        self._queue = Queue()
        self._scheduled = {}
        self._pending = {}
        self._sh = smarthome
        self._se_plugin = se_plugin
        self.logger = logger
        self._lock = RLock()
        self._dirty = False
        self._next_wakeup = None
        self._name = name

    # ---------- API ----------
    def add(self, key, job, next_run, overwrite=True, callback=None):
        with self._lock:
            if key in self._scheduled and not overwrite:
                added = False
                new_next = self._scheduled[key]['next']
            else:
                self._pending[key] = {
                'job': job,
                'next': next_run,
                'callback': callback
                }
                added = True
                new_next = next_run

        self._queue.put(('commit', key))
        self._mark_dirty(next_run)

        if callback:
            callback(added, new_next)

    def remove(self, key, callback=None):
        with self._lock:
            removed = (
                self._scheduled.pop(key, None) is not None
                or self._pending.pop(key, None) is not None
            )

        self._queue.put(('remove', key))
        self._mark_dirty()

        if callback:
            callback(removed)

    def remove_all(self, predicate=None, callback=None):
        self._queue.put(('remove_all', predicate, callback))
        self._mark_dirty()

    def get(self, key):
        with self._lock:
            return self._scheduled.get(key) or self._pending.get(key)

    def _mark_dirty(self, next_run=None):
        with self._lock:
            self._dirty = True
            self._trigger(next_run)

    def _trigger(self, next_run=None):
        # Nur Scheduler wecken, niemals Jobs sofort ausführen!
        if next_run is None:
            self._se_plugin.scheduler_trigger(self._name, by=self._se_plugin.get_fullname())
        else:
            if self._next_wakeup is None or next_run < self._next_wakeup:
                self._next_wakeup = next_run
                self._se_plugin.scheduler_trigger(self._name, by=self._se_plugin.get_fullname(), dt=next_run)


    # ---------- MAIN LOOP ----------
    def run(self):
        self._dirty = False
        now = self._sh.shtime.now()

        # --- Process queue ---
        while not self._queue.empty():
            cmd = self._queue.get()
            if cmd[0] == 'commit':
                _, key = cmd
                with self._lock:
                    entry = self._pending.pop(key, None)
                    if entry:
                        if entry['next'] <= self._sh.shtime.now():
                            # Job noch nicht ausführen, ggf. minimalen delta setzen
                            entry['next'] = self._sh.shtime.now() + datetime.timedelta(seconds=0.1)
                        self._scheduled[key] = entry

            elif cmd[0] == 'remove':
                _, key = cmd
                with self._lock:
                    # Only remove if no new pending job exists
                    if key not in self._pending:
                        self._scheduled.pop(key, None)

            elif cmd[0] == 'remove_all':
                _, predicate, callback = cmd
                removed = 0

                with self._lock:
                    keys = list(self._scheduled.keys())

                    for key in keys:
                        if predicate is None or predicate(key):
                            # only remove if no new pending overwrite exists
                            if key not in self._pending:
                                self._scheduled.pop(key, None)
                                removed += 1

                if callback:
                    callback(removed)

        # --- Execute due jobs ---
        execute = []
        with self._lock:
            for key, entry in self._scheduled.items():
                if entry['next'] is not None and now >= entry['next']:
                    execute.append(key)

        for key in execute:
            with self._lock:
                entry = self._scheduled.pop(key, None)
            if entry:
                try:
                    self._execute_job(key, entry['job'])
                    cb = entry.get('callback')
                    if cb:
                        cb(True, entry['next'])
                    self.logger.info(f"{self._name} job {entry['job']} done. key: {key}")
                except Exception as e:
                    self.logger.error(f"{self._name} job failed {key}: {e}")

        # --- Calculate next wakeup ---
        next_times = []
        with self._lock:
            for entry in self._scheduled.values():
                next_times.append(entry['next'])
            for entry in self._pending.values():
                next_times.append(entry['next'])

        if next_times:
            next_wakeup = min(next_times)
            self._next_wakeup = next_wakeup

            self.logger.debug(
                f"{self._name}: scheduling next wakeup at {next_wakeup}"
            )

            self._se_plugin.scheduler_trigger(
                self._name,
                by=self._se_plugin.get_fullname(),
                dt=next_wakeup
            )
        else:
            self._next_wakeup = None

    # ---------- OVERRIDE ----------
    def _execute_job(self, key, job):
        raise NotImplementedError


class ActionScheduler(BaseScheduler):

    def __init__(self, smarthome, se_plugin, logger):
        super().__init__(smarthome, se_plugin, logger, "actionscheduler")

    def add(self, abitem, name, action, value, next_run, overwrite=True, callback=None):
        key = (abitem, name)
        job = {
            "action": action,
            "value": value or {}
        }
        super().add(key, job, next_run, overwrite, callback)

    def remove(self, abitem, name, callback=None):
        key = (abitem, name)
        super().remove(key, callback)

    def remove_all(self, abitem, callback=None):
        super().remove_all(lambda k: k[0] is abitem, callback)

    def get(self, abitem, name=None):
        if name is None:
            key = abitem
        else:
            key = (abitem, name)
        return super().get(key)

    def _execute_job(self, key, job):
        action = job["action"]
        values = job.get("value", {})
        action.delayed_execute(**values)


class ItemScheduler(BaseScheduler):

    def __init__(self, smarthome, se_plugin, logger):
        super().__init__(smarthome, se_plugin, logger, "itemscheduler")

   # ---------- SANITIZERS ----------
    def _sanitize_cron(self, cron):
        if cron is None:
            return None, False

        new_cron = {}
        changed = False

        for entry, value in cron.items():
            if value is None:
                value = 1
                changed = True
            new_cron[entry] = value

        return new_cron, changed

    def _sanitize_cycle(self, cycle):
        if cycle is None:
            return None, False, None

        changed = False
        key = list(cycle.keys())[0]
        value = cycle[key]

        if value is None:
            value = "1"
            changed = True

        new_cycle = {key: value}

        return new_cycle, changed, key

    def add_startup(self, item, name, startup_delay=0, callback=None):
        next_run = self._sh.shtime.now() + datetime.timedelta(seconds=startup_delay)
        key = (item, name)
        job = {"item": item, "startup_delay": True}
        # Immer über pending hinzufügen, damit run() entscheidet, wann es fällig ist
        with self._lock:
            self._pending[key] = {
                "job": job,
                "next": next_run,
                "callback": callback
            }
        self._queue.put(('commit', key))
        self._mark_dirty(next_run)

    def add(self, item, name, next_run, callback=None):
        key = (item, name)
        job = {"item": item}

        def job_callback(added, new_next):
            if added and callback:
                callback(added, new_next)

        with self._lock:
            self._pending[key] = {
                'job': job,
                'next': next_run,
                'callback': job_callback
            }

        self._queue.put(('commit', key))
        self._mark_dirty(next_run)

    def remove(self, item, name, callback=None):
        key = (item, name)
        super().remove(key, callback)

    def remove_all(self, item, callback=None):
        super().remove_all(lambda k: k[0] is item, callback)

    def get(self, item, name=None):
        if name is None:
            key = item
        else:
            key = (item, name)
        return super().get(key)

    def _execute_job(self, key, job):
        item = job["item"]
        callback = None

        # Check if callback exists (from pending)
        with self._lock:
            entry = self._scheduled.get(key)
            if entry and "callback" in entry:
                callback = entry.pop("callback")

        # Run the item
        item(True, "ItemScheduler")

        # Trigger callback **nach tatsächlicher Ausführung**
        if callback:
            try:
                callback(True, entry['next'])
            except Exception as e:
                self.logger.error(f"{self._name} callback failed for {key}: {e}")

        # Reschedule if cycle or cron exists
        next_run = None
        if job.get("cycle"):
            next_run = self._sh.shtime.now() + job["cycle"]
        elif job.get("cron"):
            cron = job["cron"]
            now_dt = self._sh.shtime.now()
            next_dt = now_dt.replace(
                hour=cron.get("hour", now_dt.hour),
                minute=cron.get("minute", now_dt.minute),
                second=cron.get("second", now_dt.second),
                microsecond=0
            )
            if next_dt <= now_dt:
                next_dt += datetime.timedelta(days=1)
            next_run = next_dt
        if next_run:
            super().add(key, job, next_run, overwrite=True)
