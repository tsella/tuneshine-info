#!/usr/bin/env python3
"""Tests for tuneshine_info.

Run them with either:

    python3 test_tuneshine_info.py
    python3 -m unittest discover -v

Nothing here touches the network or a real Tuneshine. The mDNS packet parsers are
driven with synthetic packets, the HTTP calls are stubbed, and every state path is
pointed at a temporary directory.

The hang test and the lock race run in subprocesses on purpose: a test that must
prove something *terminates* cannot be trusted to finish in its own process.
"""

import glob
import json
import os
import struct
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from io import BytesIO

import importlib.util

HERE = os.path.dirname(os.path.abspath(__file__))
SOURCE = os.path.join(HERE, "tuneshine_info.py")

spec = importlib.util.spec_from_file_location("tuneshine_info", SOURCE)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

FIXTURE = os.path.join(HERE, "example-frame.png")
NOW = 1_700_000_000.0


def dns_name(name):
    out = b""
    for label in name.strip(".").split("."):
        b = label.encode()
        out += bytes([len(b)]) + b
    return out + b"\x00"


def dns_packet(records=(), qd=0, an=0, ns=0, ar=0):
    return struct.pack(">HHHHHH", 0, 0, qd, an, ns, ar) + b"".join(records)


def rr(name, rtype, rdata):
    return dns_name(name) + struct.pack(">HHIH", rtype, 1, 60, len(rdata)) + rdata


def txt_record(name, pairs):
    """A TXT record whose strings are length-prefixed, as the spec requires."""
    rdata = b""
    for k, v in pairs:
        chunk = ("%s=%s" % (k, v)).encode()
        rdata += bytes([len(chunk)]) + chunk
    return rr(name, 16, rdata)


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="tuneshine-test-")
        self.cfg = mod.load_config(os.path.join(self.tmp, "missing.json"))
        self.cfg["state_dir"] = self.tmp
        self.cfg["timezone"] = "local"
        mod.apply_paths(self.cfg)

    def tearDown(self):
        mod._FONT_CACHE.clear()

    def config(self, path=None, **over):
        """A config built from the defaults plus overrides, written to disk."""
        cfg = mod.load_config(path or os.path.join(self.tmp, "missing.json"))
        cfg["state_dir"] = self.tmp
        cfg["timezone"] = "local"
        cfg.update(over)
        return cfg

    def weather(self, **over):
        base = dict(now=59, code=0, is_day=1, max=69, min=55, rain=20, aqi=30,
                    sunrise="2026-10-15T07:07", sunset="2026-10-15T18:15",
                    fc_ts=time.time(), aqi_ts=time.time())
        base.update(over)
        return base


# --------------------------------------------------------------------------
# mDNS parsing
# --------------------------------------------------------------------------
class TestMdnsParsing(Base):
    def run_child(self, body, timeout=15):
        """Run a snippet against the module in a fresh process. Returns stdout."""
        prog = (
            "import importlib.util, sys\n"
            "spec = importlib.util.spec_from_file_location('t', %r)\n"
            "t = importlib.util.module_from_spec(spec); spec.loader.exec_module(t)\n"
            "t.apply_paths({'state_dir': %r})\n" % (SOURCE, self.tmp)
        ) + body
        return subprocess.run([sys.executable, "-c", prog], capture_output=True,
                              text=True, timeout=timeout)

    def test_compression_pointer_cycle_terminates(self):
        """A name that points at itself must not spin forever.

        This hung indefinitely before the jump budget was added, with no exception
        to catch, so the assertion is on the subprocess finishing at all.
        """
        packet = dns_packet([b"\xc0\x0c"], an=1)
        body = (
            "import struct\n"
            "pkt = %r\n"
            "recs = t._parse_records(pkt)\n"
            "print('parsed', len(recs))\n" % packet
        )
        try:
            done = self.run_child(body, timeout=15)
        except subprocess.TimeoutExpired:
            self.fail("_parse_records hung on a compression-pointer cycle")
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertIn("parsed", done.stdout)

    def test_pointer_chain_within_budget_still_resolves(self):
        """A legitimate pointer chain must still parse, not be cut short."""
        head = struct.pack(">HHHHHH", 0, 0, 0, 2, 0, 0)
        target = len(head) + 2 + 10 + 4        # where the second record's name starts
        packet = (head + struct.pack(">H", 0xC000 | target)
                  + struct.pack(">HHIH", 1, 1, 60, 4) + b"\x7f\x00\x00\x01"
                  + dns_name("host")
                  + struct.pack(">HHIH", 1, 1, 60, 4) + b"\x7f\x00\x00\x02")
        name, _off = mod._parse_name(packet, 12)
        self.assertEqual(name, "host")

    def test_truncated_pointer_does_not_raise(self):
        packet = dns_packet([b"\x00", b"\xc0"], an=1)
        self.assertEqual(mod._parse_records(packet), [])

    def test_short_packet_returns_empty(self):
        self.assertEqual(mod._parse_records(b"\x00\x01\x02"), [])

    def test_txt_strings_are_length_prefixed_not_nul_separated(self):
        """The real bug: splitting TXT rdata on NUL lost every key."""
        packets = mod._parse_records(dns_packet(
            [txt_record("tuneshine-89B8._tuneshine._tcp.local",
                        [("deviceName", "Kitchen"), ("deviceId", "be2cf4b9-x"),
                         ("version", "2.7.5")])], an=1))
        fields = [r["value"] for r in packets if r["type"] == "TXT"][0]
        self.assertEqual(fields["deviceName"], "Kitchen")
        self.assertEqual(fields["deviceId"], "be2cf4b9-x")
        self.assertEqual(fields["version"], "2.7.5")

    def test_a_record_parses(self):
        recs = mod._parse_records(dns_packet(
            [rr("host.local", 1, b"\x7f\x00\x00\x01")], an=1))
        self.assertEqual([r["value"] for r in recs if r["type"] == "A"], ["127.0.0.1"])

    def test_srv_record_parses(self):
        rdata = struct.pack(">HHH", 0, 0, 8080) + dns_name("host.local")
        recs = mod._parse_records(dns_packet([rr("inst._t._tcp.local", 33, rdata)], an=1))
        srv = [r for r in recs if r["type"] == "SRV"][0]
        self.assertEqual(srv["port"], 8080)
        self.assertEqual(srv["target"], "host.local")

    def test_encode_name_roundtrip(self):
        self.assertEqual(mod._encode_name("a.bc"), b"\x01a\x02bc\x00")


# --------------------------------------------------------------------------
# Device selection
# --------------------------------------------------------------------------
class TestDeviceSelection(Base):
    def device(self, **over):
        dev = dict(name="Kitchen Tuneshine", hardware_id="80:65:99:c2:89:b8",
                   device_id="be2cf4b9-7e13-4865-af6f-1312033c71da",
                   ip="192.168.1.19", hostname="tuneshine-89B8.local",
                   instance="Tuneshine 89B8", port=80)
        dev.update(over)
        dev["identities"] = [x for x in (dev["name"], dev["hardware_id"],
                                         dev["device_id"], dev["ip"],
                                         dev["hostname"], dev["instance"]) if x]
        return dev

    def test_matches_every_identity_field(self):
        dev = self.device()
        for entry in ("Kitchen Tuneshine", "kitchen tuneshine", "192.168.1.19",
                      "80:65:99:c2:89:b8", "806599c289b8", "tuneshine-89B8.local",
                      "be2cf4b9-7e13-4865-af6f-1312033c71da", "*Kitchen*",
                      "192.168.1.*", "tuneshine-*.local", "*89B8*"):
            self.assertTrue(mod.device_matches(entry, dev), "should match: %r" % entry)

    def test_rejects_non_matching_entries(self):
        dev = self.device()
        for entry in ("Bedroom", "10.0.0.1", "80:65:99:ff:ff:ff", "", "   "):
            self.assertFalse(mod.device_matches(entry, dev), "should not match: %r" % entry)

    def test_mode_all_selects_everything(self):
        devs = [self.device(), self.device(ip="192.168.1.20", name="Bedroom")]
        sel, skip = mod.select_devices(devs, self.config(devices={"mode": "all"}))
        self.assertEqual(len(sel), 2)
        self.assertEqual(skip, [])

    def test_mode_include(self):
        devs = [self.device(), self.device(ip="192.168.1.20", name="Bedroom")]
        sel, skip = mod.select_devices(
            devs, self.config(devices={"mode": "include", "include": ["Kitchen*"]}))
        self.assertEqual([d["name"] for d in sel], ["Kitchen Tuneshine"])
        self.assertEqual(len(skip), 1)

    def test_mode_exclude(self):
        devs = [self.device(), self.device(ip="192.168.1.20", name="Bedroom")]
        sel, skip = mod.select_devices(
            devs, self.config(devices={"mode": "exclude", "exclude": ["*Bedroom*"]}))
        self.assertEqual([d["name"] for d in sel], ["Kitchen Tuneshine"])
        self.assertEqual(len(skip), 1)

    def test_empty_include_falls_back_to_all(self):
        devs = [self.device()]
        sel, _ = mod.select_devices(
            devs, self.config(devices={"mode": "include", "include": []}))
        self.assertEqual(len(sel), 1)

    def test_device_base_omits_default_port(self):
        self.assertEqual(mod.device_base(self.device()), "http://192.168.1.19")
        self.assertEqual(mod.device_base(self.device(port=8080)),
                         "http://192.168.1.19:8080")


# --------------------------------------------------------------------------
# Config
# --------------------------------------------------------------------------
class TestConfig(Base):
    def test_missing_file_uses_defaults(self):
        cfg = mod.load_config(os.path.join(self.tmp, "nope.json"))
        self.assertEqual(cfg["units"], mod.DEFAULT_CONFIG["units"])
        self.assertFalse(cfg["brightness"]["set"])

    def test_malformed_file_uses_defaults(self):
        p = os.path.join(self.tmp, "bad.json")
        open(p, "w").write("{not json")
        self.assertEqual(mod.load_config(p)["units"], "fahrenheit")

    def test_non_object_file_uses_defaults(self):
        p = os.path.join(self.tmp, "list.json")
        open(p, "w").write("[1, 2, 3]")
        self.assertEqual(mod.load_config(p)["units"], "fahrenheit")

    def test_unknown_key_is_ignored(self):
        p = os.path.join(self.tmp, "c.json")
        json.dump({"nonsenseKey": 1, "units": "celsius"}, open(p, "w"))
        self.assertEqual(mod.load_config(p)["units"], "celsius")

    def test_invalid_enums_fall_back(self):
        p = os.path.join(self.tmp, "c.json")
        json.dump({"units": "kelvin", "clock": "13h", "location": "moon"}, open(p, "w"))
        cfg = mod.load_config(p)
        self.assertEqual(cfg["units"], "fahrenheit")
        self.assertEqual(cfg["clock"], "24h")
        self.assertEqual(cfg["location"], "auto")

    def test_zero_night_percent_is_accepted(self):
        p = os.path.join(self.tmp, "c.json")
        json.dump({"night_dim": {"percent": 0}}, open(p, "w"))
        self.assertEqual(mod.load_config(p)["night_dim"]["percent"], 0)

    def test_negative_night_percent_clamps_to_zero(self):
        p = os.path.join(self.tmp, "c.json")
        json.dump({"night_dim": {"percent": -20}}, open(p, "w"))
        self.assertEqual(mod.load_config(p)["night_dim"]["percent"], 0)

    def test_numeric_bounds_clamped(self):
        p = os.path.join(self.tmp, "c.json")
        json.dump({"frame_brightness": 500, "night_dim": {"percent": 999},
                   "weather_ttl": -5}, open(p, "w"))
        cfg = mod.load_config(p)
        self.assertEqual(cfg["frame_brightness"], 100)
        self.assertEqual(cfg["night_dim"]["percent"], 100)
        self.assertEqual(cfg["weather_ttl"], 0)

    def test_non_numeric_numerics_fall_back(self):
        p = os.path.join(self.tmp, "c.json")
        json.dump({"frame_brightness": "bright"}, open(p, "w"))
        self.assertEqual(mod.load_config(p)["frame_brightness"], 100)

    def test_devices_block_validation(self):
        p = os.path.join(self.tmp, "c.json")
        json.dump({"devices": {"mode": "sideways", "include": "not-a-list"}}, open(p, "w"))
        cfg = mod.load_config(p)
        self.assertEqual(cfg["devices"]["mode"], "all")
        self.assertEqual(cfg["devices"]["include"], [])

    def test_legacy_device_host_maps_to_hosts(self):
        p = os.path.join(self.tmp, "c.json")
        json.dump({"device_host": "192.168.1.19"}, open(p, "w"))
        self.assertIn("192.168.1.19", mod.load_config(p)["devices"]["hosts"])

    def test_legacy_device_host_auto_is_dropped(self):
        p = os.path.join(self.tmp, "c.json")
        json.dump({"device_host": "auto"}, open(p, "w"))
        self.assertEqual(mod.load_config(p)["devices"]["hosts"], [])

    def test_bool_keys_reject_non_bool(self):
        p = os.path.join(self.tmp, "c.json")
        json.dump({"antialias": "yes", "night_dim": {"enabled": 1}}, open(p, "w"))
        cfg = mod.load_config(p)
        self.assertTrue(cfg["antialias"])
        self.assertTrue(cfg["night_dim"]["enabled"])

    def test_unknown_timezone_falls_back_to_local(self):
        p = os.path.join(self.tmp, "c.json")
        json.dump({"timezone": "Mars/Olympus"}, open(p, "w"))
        self.assertEqual(mod.load_config(p)["timezone"], "local")

    def test_init_config_bare_relative_filename(self):
        """Regression: os.makedirs('') raised FileNotFoundError."""
        cwd = os.getcwd()
        os.chdir(self.tmp)
        try:
            self.assertTrue(mod.write_default_config("bare.json"))
            self.assertTrue(os.path.exists("bare.json"))
            self.assertFalse(mod.write_default_config("bare.json"))
            self.assertTrue(mod.write_default_config("bare.json", force=True))
        finally:
            os.chdir(cwd)

    def test_init_config_nested_path(self):
        target = os.path.join(self.tmp, "a", "b", "config.json")
        self.assertTrue(mod.write_default_config(target))
        self.assertEqual(json.load(open(target))["units"], "fahrenheit")


# --------------------------------------------------------------------------
# Logging and state
# --------------------------------------------------------------------------
class TestLoggingAndState(Base):
    def test_log_rotates_at_the_cap(self):
        small = 4000
        original = mod.LOG_MAX_BYTES
        mod.LOG_MAX_BYTES = small
        try:
            for i in range(2000):
                mod.log("padding line %d" % i)
        finally:
            mod.LOG_MAX_BYTES = original
        rotated = mod.LOG_FILE + ".1"
        self.assertTrue(os.path.exists(rotated), "expected a rolled backup")
        self.assertGreaterEqual(os.path.getsize(rotated), small)
        self.assertLess(os.path.getsize(mod.LOG_FILE), small * 2)

    def test_state_roundtrip(self):
        mod.save_state({"a": 1, "nested": {"b": [1, 2]}})
        self.assertEqual(mod.load_state(), {"a": 1, "nested": {"b": [1, 2]}})

    def test_load_state_tolerates_corrupt_file(self):
        open(mod.STATE_FILE, "w").write("{{{")
        self.assertEqual(mod.load_state(), {})

    def test_load_state_tolerates_missing_file(self):
        self.assertEqual(mod.load_state(), {})

    def test_apply_paths_follows_state_dir(self):
        other = tempfile.mkdtemp(prefix="tuneshine-test2-")
        mod.apply_paths({"state_dir": other})
        self.assertEqual(os.path.dirname(mod.LOG_FILE), other)
        self.assertEqual(os.path.dirname(mod.STATE_FILE), other)
        mod.apply_paths(self.cfg)


# --------------------------------------------------------------------------
# Weather and degradation
# --------------------------------------------------------------------------
class TestWeather(Base):
    def stub_fetch(self, **fields):
        out = {"now": None, "code": None, "is_day": None, "max": None, "min": None,
               "rain": None, "aqi": None, "sunrise": None, "sunset": None,
               "fc_ts": None, "aqi_ts": None, "errors": [], "sources": {}}
        out.update(fields)
        saved = mod.fetch_weather
        mod.fetch_weather = lambda lat, lon, units: dict(out)
        self.addCleanup(lambda: setattr(mod, "fetch_weather", saved))

    def test_merge_prefers_fresh_then_cache_per_field(self):
        fresh = {"now": 60, "code": None, "rain": 10, "aqi": None,
                 "fc_ts": NOW, "aqi_ts": None, "errors": [], "sources": {}}
        cached = {"now": 55, "code": 3, "rain": 99, "aqi": 42,
                  "fc_ts": NOW - 100, "aqi_ts": NOW - 100}
        merged = mod.merge_weather(fresh, cached)
        self.assertEqual(merged["now"], 60)      # fresh wins
        self.assertEqual(merged["code"], 3)      # gap filled from cache
        self.assertEqual(merged["rain"], 10)
        self.assertEqual(merged["aqi"], 42)
        self.assertEqual(merged["fc_ts"], NOW)

    def test_merge_handles_no_cache(self):
        merged = mod.merge_weather({"now": 60, "errors": [], "sources": {}}, None)
        self.assertEqual(merged["now"], 60)
        self.assertIsNone(merged["code"])

    def test_total_failure_is_retried_next_run(self):
        """Regression: a fully failed fetch used to be cached for the full TTL."""
        self.stub_fetch(errors=["forecast: boom", "aqi: boom"],
                        sources={"forecast": "fail", "aqi": "fail"})
        cfg = self.config(weather_ttl=600)
        st = {}
        w1, fetched1, _ = mod.weather_for(cfg, st)
        self.assertTrue(fetched1)
        self.assertEqual(w1["last_fetch"], 0)
        st["weather"] = w1
        _w2, fetched2, _ = mod.weather_for(cfg, st)
        self.assertTrue(fetched2, "a total failure must not suppress the next fetch")

    def test_partial_failure_still_starts_the_ttl(self):
        self.stub_fetch(aqi=42, aqi_ts=NOW, sources={"forecast": "fail", "aqi": "ok"})
        cfg = self.config(weather_ttl=600)
        st = {}
        w1, fetched1, _ = mod.weather_for(cfg, st)
        self.assertTrue(fetched1)
        self.assertGreater(w1["last_fetch"], 0)
        st["weather"] = w1
        _w2, fetched2, _ = mod.weather_for(cfg, st)
        self.assertFalse(fetched2, "one good source should start the TTL")

    def test_fresh_cache_is_reused(self):
        self.stub_fetch(now=60, fc_ts=NOW, aqi_ts=NOW, sources={"forecast": "ok"})
        cfg = self.config(weather_ttl=600)
        cached = dict(self.weather(), last_fetch=time.time())
        _w, fetched, _ = mod.weather_for(cfg, {"weather": cached})
        self.assertFalse(fetched)

    def test_locate_backs_off_after_a_failure(self):
        """Regression: retrying the weather each run made locate() hammer ipinfo."""
        calls = {"n": 0}

        def boom(url, **kw):
            calls["n"] += 1
            raise mod.requests.RequestException("network down")

        saved = mod.requests.get
        mod.requests.get = boom
        self.addCleanup(lambda: setattr(mod.requests, "get", saved))
        cfg = self.config(location="auto", location_ttl=86400)
        st = {}
        for _ in range(5):
            mod.locate(cfg, st)
        self.assertEqual(calls["n"], 1, "a failed lookup must not retry every run")

    def test_locate_success_caches_and_clears_backoff(self):
        class Resp:
            def raise_for_status(self): pass
            def json(self): return {"loc": "40.7,-74.0", "city": "NYC"}
        calls = {"n": 0}

        def ok(url, **kw):
            calls["n"] += 1
            return Resp()

        saved = mod.requests.get
        mod.requests.get = ok
        self.addCleanup(lambda: setattr(mod.requests, "get", saved))
        cfg = self.config(location="auto")
        st = {}
        self.assertEqual(mod.locate(cfg, st)[:2], (40.7, -74.0))
        mod.locate(cfg, st)
        self.assertEqual(calls["n"], 1, "a success should be cached and reused")
        self.assertNotIn("loc_fail_ts", st)

    def test_pinned_location_never_calls_out(self):
        def never(url, **kw):
            raise AssertionError("must not make a request when pinned")
        saved = mod.requests.get
        mod.requests.get = never
        self.addCleanup(lambda: setattr(mod.requests, "get", saved))
        cfg = self.config(location="pinned", lat=1.5, lon=2.5, label="X")
        self.assertEqual(mod.locate(cfg, {}), (1.5, 2.5, "X"))

    def test_num_coercion(self):
        self.assertEqual(mod._num("3.6"), 4)
        self.assertEqual(mod._num(3.4), 3)
        self.assertIsNone(mod._num(None))
        self.assertIsNone(mod._num("n/a"))

    def test_dim_factor(self):
        cfg = self.config(stale_after_seconds=100)
        self.assertEqual(mod.dim_factor(time.time(), cfg), 1.0)
        self.assertLess(mod.dim_factor(time.time() - 1000, cfg), 1.0)
        self.assertLess(mod.dim_factor(None, cfg), 1.0)


# --------------------------------------------------------------------------
# Night dimming
# --------------------------------------------------------------------------
class TestNightBrightness(Base):
    def test_window_boundaries(self):
        cfg = self.config(frame_brightness=100, night_dim={"enabled": True, "percent": 50})
        w = {"sunrise": "2026-10-15T07:07", "sunset": "2026-10-15T18:15"}
        cases = [((6, 59), 50, True), ((7, 6), 50, True), ((7, 7), 100, False),
                 ((12, 0), 100, False), ((18, 14), 100, False), ((18, 15), 50, True),
                 ((23, 59), 50, True), ((0, 0), 50, True)]
        for (h, m), want_b, want_night in cases:
            b, night = mod.night_brightness(cfg, w, datetime(2026, 10, 15, h, m))
            self.assertEqual((b, night), (want_b, want_night), "at %02d:%02d" % (h, m))

    def test_percent_is_of_frame_brightness(self):
        cfg = self.config(frame_brightness=60, night_dim={"enabled": True, "percent": 50})
        w = {"sunrise": "2026-10-15T07:07", "sunset": "2026-10-15T18:15"}
        b, night = mod.night_brightness(cfg, w, datetime(2026, 10, 15, 23, 0))
        self.assertTrue(night)
        self.assertEqual(b, 30)      # 50 percent OF 60, not 50

    def test_zero_percent_gives_zero_brightness(self):
        cfg = self.config(frame_brightness=100, night_dim={"enabled": True, "percent": 0})
        w = {"sunrise": "2026-10-15T07:07", "sunset": "2026-10-15T18:15"}
        self.assertEqual(mod.night_brightness(cfg, w, datetime(2026, 10, 15, 23, 0)),
                         (0, True))

    def test_zero_percent_leaves_daylight_alone(self):
        cfg = self.config(frame_brightness=100, night_dim={"enabled": True, "percent": 0})
        w = {"sunrise": "2026-10-15T07:07", "sunset": "2026-10-15T18:15"}
        self.assertEqual(mod.night_brightness(cfg, w, datetime(2026, 10, 15, 12, 0)),
                         (100, False))

    def test_brightness_is_never_negative(self):
        cfg = self.config(frame_brightness=1, night_dim={"enabled": True, "percent": 1})
        w = {"sunrise": "2026-10-15T07:07", "sunset": "2026-10-15T18:15"}
        self.assertGreaterEqual(
            mod.night_brightness(cfg, w, datetime(2026, 10, 15, 23, 0))[0], 0)

    def test_missing_times_keep_full_brightness(self):
        cfg = self.config(frame_brightness=100, night_dim={"enabled": True, "percent": 50})
        for w in ({}, {"sunrise": None, "sunset": None}, {"sunrise": "2026-10-15T07:07"}):
            self.assertEqual(mod.night_brightness(cfg, w, datetime(2026, 10, 15, 23, 0)),
                             (100, False))

    def test_unparsable_times_keep_full_brightness(self):
        cfg = self.config(frame_brightness=100, night_dim={"enabled": True, "percent": 50})
        w = {"sunrise": "not-a-time", "sunset": "nope"}
        self.assertEqual(mod.night_brightness(cfg, w, datetime(2026, 10, 15, 23, 0)),
                         (100, False))

    def test_disabled_schedule(self):
        cfg = self.config(frame_brightness=100, night_dim={"enabled": False, "percent": 50})
        w = {"sunrise": "2026-10-15T07:07", "sunset": "2026-10-15T18:15"}
        self.assertEqual(mod.night_brightness(cfg, w, datetime(2026, 10, 15, 23, 0)),
                         (100, False))

    def test_aware_datetime_does_not_explode(self):
        cfg = self.config(frame_brightness=100, night_dim={"enabled": True, "percent": 50})
        w = {"sunrise": "2026-10-15T07:07", "sunset": "2026-10-15T18:15"}
        aware = datetime(2026, 10, 15, 23, 0)
        self.assertEqual(mod.night_brightness(cfg, w, aware)[0], 50)


# --------------------------------------------------------------------------
# Frame rendering
# --------------------------------------------------------------------------
class TestFrame(Base):
    def build(self, **over):
        w = self.weather(**{k: v for k, v in over.items() if k in
                            ("now", "code", "is_day", "max", "min", "rain", "aqi",
                             "sunrise", "sunset", "fc_ts", "aqi_ts")})
        cfg = self.config(**{k: v for k, v in over.items() if k not in
                             ("now", "code", "is_day", "max", "min", "rain", "aqi",
                              "sunrise", "sunset", "fc_ts", "aqi_ts")})
        return mod.build_frame(cfg, w, datetime(2026, 10, 15, 9, 41))[0]

    def test_no_layout_problems_for_a_full_frame(self):
        self.assertEqual(self.build().problems(), [])

    def test_no_layout_problems_across_degradation_cases(self):
        cases = [
            dict(),
            dict(now=None, code=None, max=None, min=None, rain=None, aqi=None,
                 fc_ts=None, aqi_ts=None),
            dict(fc_ts=NOW - 9000, aqi_ts=NOW - 9000),
            dict(now=100, code=95, rain=100, aqi=188),
            dict(now=-5, code=71, rain=0, aqi=0),
            dict(now=15, code=0, is_day=0),
            dict(units="celsius", now=15, rain=80, aqi=155),
            dict(clock="12h"),
        ]
        for over in cases:
            frame = self.build(**over)
            self.assertEqual(frame.problems(), [], "case %r" % (over,))

    def test_slots_land_where_the_layout_says(self):
        frame = self.build()
        boxes = {label.split(":")[0]: (x0, x1, y0, y1)
                 for label, x0, y0, x1, y1 in frame.boxes}
        hour = boxes["hour"]
        minute = boxes["minute"]
        self.assertLessEqual(hour[1], 37, "hour must stay in the left column")
        self.assertGreaterEqual(minute[2], 32, "minutes must sit below the hour")
        self.assertEqual(boxes["icon"], (38, 57, 3, 22))
        for slot in ("temp", "rain", "aqi"):
            self.assertGreaterEqual(boxes[slot][0], 38, "%s must be in the right column" % slot)
            self.assertLessEqual(boxes[slot][1], 63, "%s must fit" % slot)

    def test_frame_is_64x64(self):
        self.assertEqual(self.build().img.size, (64, 64))

    def test_render_is_deterministic(self):
        a = self.build().img.tobytes()
        b = self.build().img.tobytes()
        self.assertEqual(a, b)

    def test_ascii_dump_is_64_rows_of_64(self):
        lines = mod.frame_ascii(self.build().img)
        self.assertEqual(len(lines), 64)
        for line in lines:
            self.assertEqual(len(line), 64)

    def test_missing_values_render_the_placeholder(self):
        frame = self.build(now=None, rain=None, aqi=None, code=None,
                           fc_ts=None, aqi_ts=None)
        self.assertEqual(frame.problems(), [])

    def test_icon_follows_the_weather_code(self):
        pairs = [(0, 1, "sun"), (0, 0, "moon"), (1, 1, "sun"), (2, 1, "partly"),
                 (3, 1, "cloud"), (45, 1, "fog"), (53, 1, "drizzle"), (63, 1, "rain"),
                 (73, 1, "snow"), (95, 1, "thunder"), (None, None, "unknown")]
        for code, is_day, want in pairs:
            info = mod.build_frame(
                self.config(), self.weather(code=code, is_day=is_day),
                datetime(2026, 10, 15, 12, 29))[1]
            self.assertIn("icon=%s" % want, info, "code=%r is_day=%r" % (code, is_day))

    def test_antialias_comes_from_the_cfg_argument_not_a_global(self):
        mod.CFG = dict(self.cfg)
        mod.CFG["antialias"] = False                    # hostile global
        soft = self.build(antialias=True)
        hard = self.build(antialias=False)
        self.assertGreater(len(set(soft.img.getdata())), len(set(hard.img.getdata())))

    def test_stale_weather_renders_dimmer_than_fresh(self):
        fresh = self.build()
        stale = self.build(fc_ts=NOW - 9000, aqi_ts=NOW - 9000)

        def total(img):
            return sum(sum(px) for px in img.getdata())
        self.assertLess(total(stale.img), total(fresh.img))

    def test_night_frame_is_dimmer_than_day(self):
        cfg = self.config(night_dim={"enabled": True, "percent": 50})
        w = self.weather()
        night = mod.build_frame(cfg, w, datetime(2026, 10, 15, 23, 0))[0]

        def total(img):
            return sum(sum(px) for px in img.getdata())
        self.assertLess(total(night.img), total(self.build().img))

    def test_zero_percent_night_frame_is_fully_black(self):
        cfg = self.config(night_dim={"enabled": True, "percent": 0})
        frame = mod.build_frame(cfg, self.weather(), datetime(2026, 10, 15, 23, 0))[0]
        self.assertEqual(set(frame.img.getdata()), {(0, 0, 0)})
        self.assertEqual(frame.problems(), [])

    def test_zero_percent_frame_still_encodes_and_stays_small(self):
        cfg = self.config(night_dim={"enabled": True, "percent": 0})
        frame = mod.build_frame(cfg, self.weather(), datetime(2026, 10, 15, 23, 0))[0]
        buf = BytesIO()
        frame.img.save(buf, format="WEBP", lossless=True, quality=100)
        data = buf.getvalue()
        self.assertEqual(data[:4], b"RIFF")
        self.assertEqual(data[8:12], b"WEBP")
        self.assertLess(len(data), 200, "a black frame should compress to almost nothing")


# --------------------------------------------------------------------------
# Fonts
# --------------------------------------------------------------------------
class TestFonts(Base):
    def test_configured_path_is_used_verbatim_when_present(self):
        mod._FONT_CACHE.clear()
        cfg = self.config()
        chosen = mod.font_path_for(cfg, "bold")
        self.assertEqual(os.path.realpath(chosen), os.path.realpath(cfg["font_bold"]))

    def test_missing_font_falls_back_and_logs(self):
        mod._FONT_CACHE.clear()
        cfg = self.config(font_bold="/no/such/font.ttf", font_reg="/no/such/font2.ttf")
        chosen = mod.font_path_for(cfg, "bold")
        self.assertTrue(os.path.exists(chosen))
        self.assertNotEqual(chosen, "/no/such/font.ttf")
        logged = open(mod.LOG_FILE).read()
        self.assertIn("font_bold", logged)
        self.assertIn("/no/such/font.ttf", logged)

    def test_no_font_anywhere_raises_a_named_error(self):
        mod._FONT_CACHE.clear()
        saved = mod.FONT_CANDIDATES
        mod.FONT_CANDIDATES = {"bold": ("/no/x.ttf",), "reg": ("/no/y.ttf",)}
        self.addCleanup(lambda: setattr(mod, "FONT_CANDIDATES", saved))
        cfg = self.config(font_bold="/no/a.ttf")
        with self.assertRaises(RuntimeError) as ctx:
            mod.font_path_for(cfg, "bold")
        self.assertIn("font_bold", str(ctx.exception))
        self.assertIn("/no/a.ttf", str(ctx.exception))

    def test_fallback_result_is_cached(self):
        mod._FONT_CACHE.clear()
        cfg = self.config(font_bold="/no/such/font.ttf")
        first = mod.font_path_for(cfg, "bold")
        second = mod.font_path_for(cfg, "bold")
        self.assertEqual(first, second)


# --------------------------------------------------------------------------
# Locking
# --------------------------------------------------------------------------
class TestLock(Base):
    def test_acquire_then_second_acquire_fails(self):
        self.assertTrue(mod.acquire_lock())
        self.assertFalse(mod.acquire_lock())
        mod.release_lock()
        self.assertFalse(os.path.exists(mod.LOCK_FILE))

    def test_stale_lock_is_replaced(self):
        open(mod.LOCK_FILE, "w").write("999999")
        old = time.time() - mod.LOCK_MAX_AGE - 60
        os.utime(mod.LOCK_FILE, (old, old))
        self.assertTrue(mod.acquire_lock())
        with open(mod.LOCK_FILE) as fh:
            self.assertEqual(fh.read().strip(), str(os.getpid()))
        mod.release_lock()

    def test_release_by_a_non_owner_leaves_the_lock(self):
        open(mod.LOCK_FILE, "w").write("424242")
        mod.release_lock()
        self.assertTrue(os.path.exists(mod.LOCK_FILE))

    def test_release_is_safe_when_no_lock_exists(self):
        mod.release_lock()          # must not raise

    def test_only_one_of_many_processes_wins(self):
        """The old check-then-write let two runs start together."""
        child = (
            "import importlib.util, sys, time\n"
            "spec = importlib.util.spec_from_file_location('t', %r)\n"
            "t = importlib.util.module_from_spec(spec); spec.loader.exec_module(t)\n"
            "t.apply_paths({'state_dir': sys.argv[1]})\n"
            "if t.acquire_lock():\n"
            "    print('WON', flush=True)\n"
            "    time.sleep(1.0)\n"
            "    t.release_lock()\n"
            "else:\n"
            "    print('lost', flush=True)\n" % SOURCE
        )
        n = 8
        procs = [subprocess.Popen([sys.executable, "-c", child, self.tmp],
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                  text=True) for _ in range(n)]
        outs = []
        for p in procs:
            try:
                out, _err = p.communicate(timeout=60)
            except subprocess.TimeoutExpired:
                p.kill()
                self.fail("a lock contender hung")
            outs.append(out.strip())
        self.assertEqual(outs.count("WON"), 1, "exactly one run may hold the lock: %r" % outs)
        self.assertEqual(outs.count("lost"), n - 1, "the rest must back off: %r" % outs)
        self.assertFalse(os.path.exists(mod.LOCK_FILE), "the winner must clean up")


# --------------------------------------------------------------------------
# End to end against a stub device on localhost
# --------------------------------------------------------------------------
class StubDevice:
    """A stand-in Tuneshine: /health, /state, /image and /brightness.

    Serves on an ephemeral port so the whole suite stays offline.
    """

    def __init__(self, name="Stub Tuneshine", playing=False):
        self.name = name
        self.playing = playing
        self.uploads = []
        self.seen = []
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def _json(self, obj, code=200):
                body = json.dumps(obj).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self):
                outer.seen.append(("GET", self.path))
                if self.path == "/health":
                    return self._json({"ok": True})
                if self.path == "/state":
                    return self._json({
                        "name": outer.name,
                        "hardwareId": "80:65:99:c2:89:b8",
                        "firmwareVersion": "9.9.9",
                        "imageSource": "local",
                        "remoteMetadata": {"idle": not outer.playing,
                                           "itemId": "track-1"},
                        "localMetadata": {"idle": True, "overridable": True},
                        "config": {"brightness": {"idle": 50, "active": 50}},
                    })
                self._json({"error": "not found"}, 404)

            def do_POST(self):
                length = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(length)
                outer.seen.append(("POST", self.path))
                if self.path == "/image":
                    outer.uploads.append(body)
                    return self._json({"ok": True})
                if self.path == "/brightness":
                    return self._json({"ok": True})
                self._json({"error": "not found"}, 404)

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.port = self.httpd.server_address[1]
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()

    @property
    def host(self):
        return "127.0.0.1:%d" % self.port

    def stop(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(timeout=5)


class TestCli(Base):
    def setUp(self):
        super().setUp()
        self.stub = StubDevice()
        self.addCleanup(self.stub.stop)
        self.cfg_path = self.write_config(hosts=[self.stub.host])

    def write_config(self, hosts=(), **over):
        cfg = {"state_dir": self.tmp,
               "devices": {"mdns": False, "mdns_timeout": 1, "hosts": list(hosts)}}
        cfg.update(over)
        path = os.path.join(self.tmp, "config.json")
        json.dump(cfg, open(path, "w"))
        return path

    def run_cli(self, *args, timeout=90):
        return subprocess.run([sys.executable, SOURCE, *args],
                              capture_output=True, text=True, timeout=timeout, cwd=HERE)

    def test_version_flag(self):
        done = self.run_cli("--version")
        self.assertEqual(done.returncode, 0)
        self.assertIn(mod.VERSION, done.stdout)

    def test_init_config_writes_and_refuses_to_clobber(self):
        target = os.path.join(self.tmp, "fresh.json")
        self.assertIn("wrote", self.run_cli("--init-config", "--config", target).stdout)
        self.assertIn("already exists",
                      self.run_cli("--init-config", "--config", target).stdout)
        self.assertIn("wrote", self.run_cli(
            "--init-config", "--config", target, "--overwrite-config").stdout)

    def test_list_devices_finds_the_stub(self):
        done = self.run_cli("--list-devices", "--config", self.cfg_path)
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertIn("Stub Tuneshine", done.stdout)
        self.assertIn("127.0.0.1", done.stdout)

    def test_status_reports_the_stub(self):
        done = self.run_cli("--status", "--config", self.cfg_path)
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertIn("Stub Tuneshine", done.stdout)
        self.assertIn("1 found, 1 selected", done.stdout)

    def test_dump_prints_a_frame(self):
        done = self.run_cli("--dump", "--config", self.cfg_path)
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertEqual(len(done.stdout.strip().splitlines()), 64)

    def test_preview_says_where_it_would_push(self):
        done = self.run_cli("--preview", "--config", self.cfg_path)
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertIn("would push to 1 device(s)", done.stdout)
        self.assertIn("Stub Tuneshine", done.stdout)
        self.assertTrue(os.path.exists(mod.PREVIEW_FILE))
        self.assertEqual(self.stub.uploads, [], "--preview must not upload")

    def test_push_delivers_a_webp_frame_that_the_device_accepts(self):
        done = self.run_cli("--force", "--config", self.cfg_path)
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertEqual(len(self.stub.uploads), 1, "expected exactly one upload")
        body = self.stub.uploads[0]
        self.assertIn(b'name="image"', body)
        self.assertIn(b"WEBP", body, "the uploaded part must be a WebP")
        self.assertIn(b'"idle": true', body, "metadata must mark the frame idle")
        self.assertIn(b'"overridable": true', body)

    def test_push_is_skipped_while_music_plays(self):
        self.stub.playing = True
        done = self.run_cli("--config", self.cfg_path)
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertEqual(self.stub.uploads, [],
                         "a device that is playing must be left alone")

    def test_force_overrides_the_playing_guard(self):
        self.stub.playing = True
        self.run_cli("--force", "--config", self.cfg_path)
        self.assertEqual(len(self.stub.uploads), 1,
                         "--force is documented to upload while playing")

    def test_push_goes_ahead_when_idle(self):
        self.stub.playing = False
        self.run_cli("--config", self.cfg_path)
        self.assertEqual(len(self.stub.uploads), 1)

    def test_an_already_pushed_minute_is_not_pushed_again(self):
        """Seed the state as if this minute was already pushed.

        Racing two CLI runs instead would straddle a minute boundary once in a
        while and fail for a reason that has nothing to do with the dedup rule.
        """
        now = datetime.now().strftime("%Y-%m-%d %H:%M")
        mod.save_state({"devices": {"127.0.0.1": {"last_upload_minute": now}}})
        self.run_cli("--config", self.cfg_path)
        if datetime.now().strftime("%Y-%m-%d %H:%M") != now:
            self.skipTest("the minute rolled over during the run")
        self.assertEqual(self.stub.uploads, [],
                         "a minute that was already pushed must not be pushed again")

    def test_read_only_commands_leave_a_live_lock_alone(self):
        open(mod.LOCK_FILE, "w").write("999999")
        os.utime(mod.LOCK_FILE, (time.time(), time.time()))
        before = os.path.getmtime(mod.LOCK_FILE)
        for flag in ("--status", "--preview", "--list-devices", "--dump"):
            done = self.run_cli(flag, "--config", self.cfg_path)
            self.assertEqual(done.returncode, 0, "%s failed: %s" % (flag, done.stderr))
            self.assertTrue(os.path.exists(mod.LOCK_FILE),
                            "%s removed a live run's lock" % flag)
            self.assertEqual(os.path.getmtime(mod.LOCK_FILE), before,
                             "%s rewrote a live run's lock" % flag)

    def test_push_run_releases_its_lock(self):
        self.run_cli("--force", "--config", self.cfg_path)
        self.assertFalse(os.path.exists(mod.LOCK_FILE), "the lock must be released")

    def test_push_run_backs_off_while_another_run_holds_the_lock(self):
        open(mod.LOCK_FILE, "w").write("999999")
        os.utime(mod.LOCK_FILE, (time.time(), time.time()))
        self.run_cli("--config", self.cfg_path)
        self.assertEqual(self.stub.uploads, [], "a live lock must block the push")

    def test_no_devices_reports_and_exits_cleanly(self):
        cfgp = self.write_config(hosts=[])
        done = self.run_cli("--force", "--config", cfgp)
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertFalse(os.path.exists(mod.LOCK_FILE), "the lock must be released")

    def test_unreachable_host_is_skipped_not_fatal(self):
        cfgp = self.write_config(hosts=["127.0.0.1:1"])
        done = self.run_cli("--force", "--config", cfgp)
        self.assertEqual(done.returncode, 0, done.stderr)

    def test_include_mode_can_filter_out_the_only_device(self):
        cfgp = self.write_config(hosts=[self.stub.host],
                                 devices={"mdns": False, "mode": "include",
                                          "include": ["Nothing Matches This"]})
        done = self.run_cli("--force", "--config", cfgp)
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertEqual(self.stub.uploads, [])

    def test_exclude_mode_skips_the_named_device(self):
        cfgp = self.write_config(hosts=[self.stub.host],
                                 devices={"mdns": False, "mode": "exclude",
                                          "exclude": ["*Stub*"]})
        done = self.run_cli("--force", "--config", cfgp)
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertEqual(self.stub.uploads, [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
