#!/usr/bin/env python3
"""Tuneshine info: a clock + local weather frame for every Tuneshine on the LAN.

Finds every Tuneshine advertising `_tuneshine._tcp.local`, renders one 64x64
frame, and pushes it to each device while that device is idle. Devices that are
playing music are left alone, so their album art stays.

Layout (measured from a drawn mockup, not described):

    +------------------+----------------+
    |  HH (big, bold)  |      (icon)    |
    |                  |     59F        |
    |                  |                |
    |  MM (big)        |     20%        |
    |                  |                |
    |                  |     30         |
    +------------------+----------------+

No labels. One temperature, with its unit letter. The right column is centred.

CONFIG
    ~/.config/tuneshine/config.json  (override with --config or $TUNESHINE_CONFIG)
    Run `tuneshine_info.py --init-config` to write the defaults.
    Every key is optional. A missing or malformed file falls back to built-in
    defaults, and an unknown or invalid value is ignored with a log line.

DEVICE SELECTION
    "devices": {"mode": "all"}            push to every Tuneshine found
    "devices": {"mode": "include", "include": [...]}   only the listed devices
    "devices": {"mode": "exclude", "exclude": [...]}   everything but the listed
    A list entry matches any of: device name, hardwareId (MAC), IP, hostname,
    deviceId (UUID), or the mDNS instance name. Matching is case-insensitive,
    ignores MAC punctuation, and accepts shell globs such as "*Kitchen*".
    Run `tuneshine_info.py --list-devices` to see what is on the network.

TEXT RENDERING
    Glyphs are rasterised to a coverage mask and blended toward the black
    background. "antialias": true keeps FreeType's grayscale coverage, so edges
    blend the way a high-resolution mockup does. Set it false to ask for MONO
    (font.getmask(mode="1")), which is strictly bilevel and hints the outlines
    onto the pixel grid.

    Never render antialiased text and then throw the coverage away with a
    threshold. That yields uneven stroke weights and can split a curve, such as
    the bowl of "2" or the tail of "Q", into disconnected blobs.

DEGRADATION
    The clock is the primary content and always renders. Weather is optional,
    per field:
      * forecast and air-quality are fetched independently, each with its own
        timeout, so one failing does not lose the other;
      * a failed fetch falls back to the last cached value, per field;
      * a value that was never obtained renders as "--" in the dim palette
        colour rather than a plausible-looking zero;
      * values older than `stale_after_seconds` render dimmed, so stale data is
        visibly stale;
      * a failed upload leaves the previous frame on the device untouched;
      * a device that is unreachable is skipped, and the run alerts at most once
        per `alert_ttl` seconds.

Usage:
    tuneshine_info.py                    normal run (what cron calls)
    tuneshine_info.py --list-devices     show every Tuneshine found
    tuneshine_info.py --preview          write a PNG, do not upload
    tuneshine_info.py --dump             print the frame as ASCII
    tuneshine_info.py --status           config, devices, cached weather
    tuneshine_info.py --force            upload even while music plays
    tuneshine_info.py --init-config      write the default config file
"""

import argparse
import copy
import fnmatch
import io
import json
import os
import re
import socket
import struct
import sys
import time
import traceback
from datetime import datetime

import requests
from PIL import Image, ImageFont

try:
    from zoneinfo import ZoneInfo
except Exception:                                   # pragma: no cover
    ZoneInfo = None

VERSION = "1.1.0"

# --------------------------------------------------------------------------
# Defaults
# --------------------------------------------------------------------------
MDNS_SERVICE = "_tuneshine._tcp.local"
MAX_POINTER_JUMPS = 20          # DNS name compression: give up after this many
LOG_MAX_BYTES = 1_000_000       # rotate the log past this size, keep one backup

DEFAULT_CONFIG = {
    "devices": {
        "mode": "all",              # "all" | "include" | "exclude"
        "include": [],              # identifiers, used when mode is "include"
        "exclude": [],              # identifiers, used when mode is "exclude"
        "hosts": [],                # extra hosts, for networks that block mDNS
        "mdns_timeout": 4,          # seconds to listen for mDNS answers
    },
    "location": "auto",             # "auto" (IP geolocation) or "pinned"
    "lat": 40.7128,                 # used by "pinned", and as the "auto" fallback
    "lon": -74.0060,
    "label": "",                    # shown in --status only
    "units": "fahrenheit",          # "fahrenheit" | "celsius"
    "clock": "24h",                 # "24h" | "12h"
    "timezone": "local",            # "local" or an IANA name e.g. "America/New_York"
    "frame_brightness": 100,        # 1-100, scales this frame's pixels only
    "night_dim": {                  # dim the frame between sunset and sunrise
        "enabled": True,
        "percent": 50,              # percent OF frame_brightness, not of full
    },
    "antialias": True,              # blend glyph edges (matches a high-res mockup)
                                    # false = hard bilevel pixels (mode "1" MONO)
    "brightness": {                 # device brightness, only when "set" is true
        "set": False,
        "idle": 50,
        "active": 50,
    },
    "weather_ttl": 600,             # seconds a reading stays fresh
    "location_ttl": 86400,          # seconds an IP-geolocation result is reused
    "stale_after_seconds": 1800,    # older than this and values render dimmed
    "alert_ttl": 21600,             # min seconds between failure alerts
    "state_dir": "~/.cache/tuneshine-info",
    "font_bold": "/usr/share/fonts/truetype/liberation/LiberationSans-Bold.ttf",
    "font_reg": "/usr/share/fonts/truetype/liberation/LiberationSans-Regular.ttf",
}

CONFIG_PATH = os.path.expanduser(
    os.environ.get("TUNESHINE_CONFIG", "~/.config/tuneshine/config.json"))

NA = "--"                                   # placeholder for missing data

WHITE = (255, 255, 255)
DIM = (140, 145, 155)
DIM_DARK = (86, 90, 98)
RAINBLUE = (70, 140, 255)
GREEN = (105, 225, 130)
SUNC = (255, 196, 0)
CLOUDC = (196, 203, 216)
FOGBC = (168, 176, 190)

AQI_BANDS = [(50, GREEN), (100, (235, 215, 90)), (150, (255, 150, 60)),
             (200, (255, 90, 90)), (300, (190, 120, 235)), (10 ** 9, (200, 70, 110))]

WMO_ICON = {0: "sun", 1: "sun", 2: "partly", 3: "cloud",
            45: "fog", 48: "fog",
            51: "drizzle", 53: "drizzle", 55: "drizzle", 56: "drizzle", 57: "drizzle",
            61: "rain", 63: "rain", 65: "rain", 66: "rain", 67: "rain",
            71: "snow", 73: "snow", 75: "snow", 77: "snow",
            80: "rain", 81: "rain", 82: "rain", 85: "snow", 86: "snow",
            95: "thunder", 96: "thunder", 99: "thunder"}

# Slot geometry. The reference string fixes the font size for the slot so the
# layout does not jump when a value changes width ("1%" -> "100%") or when a
# value is missing and renders as NA. Worst-case strings that still overflow at
# the reference size are shrunk to fit.
SLOTS = {
    "hour":   dict(box=(0, 6, 37, 26),  ref="88",   font="bold", align="center"),
    "minute": dict(box=(0, 32, 37, 27), ref="88",   font="reg",  align="center"),
    "temp":   dict(box=(38, 25, 26, 11), ref="88F", font="reg",  align="center"),
    "rain":   dict(box=(38, 38, 26, 9),  ref="88%", font="reg",  align="center"),
    "aqi":    dict(box=(38, 48, 26, 12), ref="88",  font="reg",  align="center"),
}

CFG = copy.deepcopy(DEFAULT_CONFIG)
STATE_DIR = os.path.expanduser(DEFAULT_CONFIG["state_dir"])
STATE_FILE = os.path.join(STATE_DIR, "state.json")
LOCK_FILE = os.path.join(STATE_DIR, "run.lock")
LOG_FILE = os.path.join(STATE_DIR, "tuneshine_info.log")
PREVIEW_FILE = os.path.join(STATE_DIR, "preview.png")


def apply_paths(cfg):
    """Point the module-level state paths at cfg['state_dir']."""
    global STATE_DIR, STATE_FILE, LOCK_FILE, LOG_FILE, PREVIEW_FILE
    STATE_DIR = os.path.expanduser(cfg["state_dir"])
    STATE_FILE = os.path.join(STATE_DIR, "state.json")
    LOCK_FILE = os.path.join(STATE_DIR, "run.lock")
    LOG_FILE = os.path.join(STATE_DIR, "tuneshine_info.log")
    PREVIEW_FILE = os.path.join(STATE_DIR, "preview.png")


# --------------------------------------------------------------------------
# Small helpers
# --------------------------------------------------------------------------
def log(msg):
    try:
        os.makedirs(STATE_DIR, exist_ok=True)
        if os.path.exists(LOG_FILE) and os.path.getsize(LOG_FILE) > LOG_MAX_BYTES:
            os.replace(LOG_FILE, LOG_FILE + ".1")
        with open(LOG_FILE, "a") as fh:
            fh.write("%s %s\n" % (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), msg))
    except OSError:
        pass


def load_state():
    try:
        with open(STATE_FILE) as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return {}


def save_state(st):
    try:
        os.makedirs(STATE_DIR, exist_ok=True)
        tmp = STATE_FILE + ".tmp"
        with open(tmp, "w") as fh:
            json.dump(st, fh, indent=1)
        os.replace(tmp, STATE_FILE)
    except OSError as exc:
        log("state save failed: %s" % exc)


def load_config(path=None):
    """Merge the user config over the defaults. Never raises."""
    cfg = copy.deepcopy(DEFAULT_CONFIG)
    path = path or CONFIG_PATH
    user = {}
    try:
        with open(path) as fh:
            user = json.load(fh)
        if not isinstance(user, dict):
            log("config %s is not a JSON object; ignoring" % path)
            user = {}
    except FileNotFoundError:
        pass
    except (OSError, ValueError) as exc:
        log("config %s unreadable (%s); using defaults" % (path, exc))
        user = {}

    for key, val in user.items():
        if key == "device_host":                    # legacy single-host key
            if val and val != "auto":
                cfg["devices"]["hosts"].append(val)
            continue
        if key not in cfg:
            log("config: unknown key %r ignored" % key)
            continue
        if key in ("brightness", "night_dim", "devices"):
            if isinstance(val, dict):
                cfg[key].update({k: v for k, v in val.items() if k in cfg[key]})
            else:
                log("config: %s must be an object; ignored" % key)
            continue
        cfg[key] = val

    # validate the values that change behaviour
    if cfg["units"] not in ("fahrenheit", "celsius"):
        log("config: units %r invalid, using fahrenheit" % cfg["units"])
        cfg["units"] = "fahrenheit"
    if cfg["clock"] not in ("24h", "12h"):
        log("config: clock %r invalid, using 24h" % cfg["clock"])
        cfg["clock"] = "24h"
    if cfg["location"] not in ("auto", "pinned"):
        log("config: location %r invalid, using auto" % cfg["location"])
        cfg["location"] = "auto"
    if cfg["devices"]["mode"] not in ("all", "include", "exclude"):
        log("config: devices.mode %r invalid, using all" % cfg["devices"]["mode"])
        cfg["devices"]["mode"] = "all"
    for key in ("include", "exclude", "hosts"):
        if not isinstance(cfg["devices"].get(key), list):
            log("config: devices.%s must be a list; using []" % key)
            cfg["devices"][key] = []
    if not isinstance(cfg["antialias"], bool):
        log("config: antialias must be true or false, using %s"
            % DEFAULT_CONFIG["antialias"])
        cfg["antialias"] = DEFAULT_CONFIG["antialias"]
    if not isinstance(cfg["night_dim"].get("enabled"), bool):
        log("config: night_dim.enabled must be true or false, using %s"
            % DEFAULT_CONFIG["night_dim"]["enabled"])
        cfg["night_dim"]["enabled"] = DEFAULT_CONFIG["night_dim"]["enabled"]
    try:
        cfg["night_dim"]["percent"] = max(1, min(100, int(cfg["night_dim"]["percent"])))
    except (TypeError, ValueError):
        log("config: night_dim.percent invalid, using %s"
            % DEFAULT_CONFIG["night_dim"]["percent"])
        cfg["night_dim"]["percent"] = DEFAULT_CONFIG["night_dim"]["percent"]
    try:
        cfg["frame_brightness"] = max(1, min(100, int(cfg["frame_brightness"])))
    except (TypeError, ValueError):
        log("config: frame_brightness invalid, using %s" % DEFAULT_CONFIG["frame_brightness"])
        cfg["frame_brightness"] = DEFAULT_CONFIG["frame_brightness"]
    for key in ("weather_ttl", "location_ttl", "stale_after_seconds", "alert_ttl"):
        try:
            cfg[key] = max(0, int(cfg[key]))
        except (TypeError, ValueError):
            log("config: %s invalid, using %s" % (key, DEFAULT_CONFIG[key]))
            cfg[key] = DEFAULT_CONFIG[key]
    try:
        cfg["devices"]["mdns_timeout"] = max(1, int(cfg["devices"]["mdns_timeout"]))
    except (TypeError, ValueError):
        cfg["devices"]["mdns_timeout"] = DEFAULT_CONFIG["devices"]["mdns_timeout"]
    for key in ("lat", "lon"):
        try:
            cfg[key] = float(cfg[key])
        except (TypeError, ValueError):
            cfg[key] = DEFAULT_CONFIG[key]
    if cfg["timezone"] != "local" and ZoneInfo is not None:
        try:
            ZoneInfo(cfg["timezone"])
        except Exception:
            log("config: timezone %r unknown, using local" % cfg["timezone"])
            cfg["timezone"] = "local"
    cfg["path"] = path
    return cfg


def write_default_config(path, force=False):
    if os.path.exists(path) and not force:
        return False
    directory = os.path.dirname(path)
    if directory:
        os.makedirs(directory, exist_ok=True)
    with open(path, "w") as fh:
        json.dump(DEFAULT_CONFIG, fh, indent=2)
        fh.write("\n")
    return True


_TZ_CACHE = {}


def now_in(cfg):
    name = cfg["timezone"]
    if name == "local" or ZoneInfo is None:
        return datetime.now()
    tz = _TZ_CACHE.get(name)
    if tz is None:
        try:
            tz = ZoneInfo(name)
        except Exception:
            return datetime.now()
        _TZ_CACHE[name] = tz
    return datetime.now(tz)


def scale(color, factor):
    if factor >= 1.0:
        return color
    return tuple(max(0, min(255, int(round(c * factor)))) for c in color)


def blend(color, coverage):
    """Blend a colour toward the black background by a 0-255 coverage value."""
    return scale(color, coverage / 255.0)


def aqi_color(aqi):
    for limit, col in AQI_BANDS:
        if aqi <= limit:
            return col
    return GREEN


# --------------------------------------------------------------------------
# Fonts and text rasterisation (coverage masks)
# --------------------------------------------------------------------------
FONT_CANDIDATES = {
    "bold": (
        "/usr/share/fonts/truetype/liberation/LiberationSans-Bold.ttf",
        "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
        "/usr/share/fonts/truetype/freefont/FreeSansBold.ttf",
        "/usr/share/fonts/TTF/DejaVuSans-Bold.ttf",
        "/System/Library/Fonts/Supplemental/Arial Bold.ttf",
        "/Library/Fonts/Arial Bold.ttf",
    ),
    "reg": (
        "/usr/share/fonts/truetype/liberation/LiberationSans-Regular.ttf",
        "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
        "/usr/share/fonts/truetype/freefont/FreeSans.ttf",
        "/usr/share/fonts/TTF/DejaVuSans.ttf",
        "/System/Library/Fonts/Supplemental/Arial.ttf",
        "/Library/Fonts/Arial.ttf",
    ),
}

_FONT_CACHE = {}


def font_path_for(cfg, weight):
    """Return a usable font file for this weight.

    The configured path wins. When it is missing, the platform candidates are
    tried in order and the substitution is logged, so a wrong config key shows up
    as a log line rather than as an opaque failure inside the renderer.
    """
    key = "font_bold" if weight == "bold" else "font_reg"
    configured = cfg.get(key)
    cache_key = (key, configured)
    hit = _FONT_CACHE.get(cache_key)
    if hit is not None:
        return hit
    chosen = None
    if configured and os.path.exists(configured):
        chosen = configured
    else:
        for candidate in FONT_CANDIDATES[weight]:
            if os.path.exists(candidate):
                chosen = candidate
                break
    if chosen is None:
        raise RuntimeError(
            "no usable font: %s=%r does not exist and none of the fallbacks do "
            "either (%s). Point %s at a .ttf file."
            % (key, configured, ", ".join(FONT_CANDIDATES[weight]), key))
    if chosen != configured:
        log("font: %s=%r unusable, using %s" % (key, configured, chosen))
    _FONT_CACHE[cache_key] = chosen
    return chosen


BLANK_MASK = Image.new("L", (1, 1), 0)


def font_mask(text, font_path, size, antialias):
    """Rasterise text to a trimmed coverage mask (mode "L", 0-255).

    antialias=True keeps FreeType's grayscale coverage, so edges blend the way a
    high-resolution mockup does. antialias=False asks for MONO (mode "1"), which
    hints the outlines onto the pixel grid for hard bilevel pixels.

    antialias is an explicit argument and never read from a module global: a
    function handed a config must not silently use a different one.
    """
    font = ImageFont.truetype(font_path, size)
    core = font.getmask(text, mode="L" if antialias else "1")
    if core.size == (0, 0):
        return None
    try:
        gray = Image.frombytes("L", core.size, bytes(core))
    except ValueError:
        gray = Image.frombytes("1", core.size, bytes(core)).convert("L")
    box = gray.getbbox()
    if box is None:
        return None
    return gray.crop(box)


def fit_mask(text, font_path, bw, bh, antialias, max_size=48):
    """Largest size at or below max_size whose mask fits bw x bh."""
    for size in range(max_size, 4, -1):
        mask = font_mask(text, font_path, size, antialias)
        if mask is not None and mask.width <= bw and mask.height <= bh:
            return mask, size
    mask = font_mask(text, font_path, 5, antialias)
    return (mask if mask is not None else BLANK_MASK), 5


class Frame:
    """64x64 canvas that tracks placed elements so overlap is caught, not shipped.

    Holds the config it was built with. Every font lookup and the antialias choice
    come from that config, never from a module global, so render(cfg) means what it
    says.
    """

    def __init__(self, cfg):
        self.cfg = cfg
        self.img = Image.new("RGB", (64, 64), (0, 0, 0))
        self.boxes = []
        self._sizes = {}

    def slot_size(self, slot, ref=None):
        key = (slot, ref)
        if key not in self._sizes:
            spec = SLOTS[slot]
            font_path = font_path_for(self.cfg, spec["font"])
            _mask, size = fit_mask(ref or spec["ref"], font_path,
                                   spec["box"][2], spec["box"][3],
                                   self.cfg["antialias"])
            self._sizes[key] = (size, font_path)
        return self._sizes[key]

    def put(self, slot, text, color, ref=None):
        """Draw text into a slot at the slot's fixed size, shrinking only if needed."""
        spec = SLOTS[slot]
        x0, y0, bw, bh = spec["box"]
        size, font_path = self.slot_size(slot, ref)
        mask, size = fit_mask(text, font_path, bw, bh, self.cfg["antialias"],
                              max_size=size)
        if spec["align"] == "center":
            x = x0 + (bw - mask.width) // 2
        elif spec["align"] == "right":
            x = x0 + bw - mask.width
        else:
            x = x0
        y = y0 + (bh - mask.height) // 2
        for mx in range(mask.width):
            for my in range(mask.height):
                cov = mask.getpixel((mx, my))
                if cov:
                    self.px(x + mx, y + my, blend(color, cov))
        self.boxes.append((slot, x, y, x + mask.width - 1, y + mask.height - 1))
        return x, y, mask.width, mask.height

    def px(self, x, y, color):
        if 0 <= x < 64 and 0 <= y < 64:
            self.img.putpixel((x, y), color)

    def icon(self, kind, x, y, factor=1.0):
        art = make_icon(kind, self.cfg)
        for mx in range(20):
            for my in range(20):
                col = art.getpixel((mx, my))
                if col != (0, 0, 0):
                    self.px(x + mx, y + my, scale(col, factor))
        self.boxes.append(("icon", x, y, x + 19, y + 19))

    def problems(self):
        out = []
        for i in range(len(self.boxes)):
            for j in range(i + 1, len(self.boxes)):
                a, b = self.boxes[i], self.boxes[j]
                if (min(a[3], b[3]) - max(a[1], b[1]) + 1 > 0 and
                        min(a[4], b[4]) - max(a[2], b[2]) + 1 > 0):
                    out.append("overlap %s x %s" % (a[0], b[0]))
        for label, x0, y0, x1, y1 in self.boxes:
            if x0 < 0 or y0 < 0 or x1 > 63 or y1 > 63:
                out.append("out of bounds %s (%d,%d)-(%d,%d)" % (label, x0, y0, x1, y1))
        return out


# --------------------------------------------------------------------------
# Colour pixel-art weather icons (20x20)
# --------------------------------------------------------------------------
def make_icon(kind, cfg):
    ic = Image.new("RGB", (20, 20), (0, 0, 0))

    def p(x, y, c):
        if 0 <= x < 20 and 0 <= y < 20:
            ic.putpixel((x, y), c)

    def r(x0, y0, x1, y1, c):
        for x in range(x0, x1 + 1):
            for y in range(y0, y1 + 1):
                p(x, y, c)

    if kind == "sun":
        for x in range(-7, 8):
            for y in range(-7, 8):
                if x * x + y * y <= 42:
                    p(10 + x, 10 + y, SUNC)
    elif kind == "moon":
        for x in range(-7, 8):
            for y in range(-7, 8):
                if x * x + y * y <= 49:
                    p(10 + x, 10 + y, (214, 220, 236))
        for x in range(-10, 6):
            for y in range(-10, 6):
                if x * x + y * y <= 49:
                    p(13 + x, 8 + y, (0, 0, 0))
        p(4, 5, (255, 255, 255))
    elif kind == "cloud":
        r(4, 9, 16, 14, CLOUDC)
        r(7, 5, 13, 9, CLOUDC)
    elif kind == "partly":
        for x in range(-5, 6):
            for y in range(-5, 6):
                if x * x + y * y <= 25:
                    p(13 + x, 6 + y, SUNC)
        r(2, 11, 15, 16, CLOUDC)
        r(5, 7, 12, 11, CLOUDC)
    elif kind == "rain":
        r(3, 5, 16, 10, CLOUDC)
        r(6, 1, 13, 5, CLOUDC)
        for i in (5, 9, 13):
            for k in range(3):
                p(i, 12 + k, RAINBLUE)
            p(i + 1, 15, RAINBLUE)
    elif kind == "drizzle":
        r(3, 6, 16, 11, CLOUDC)
        r(6, 2, 13, 6, CLOUDC)
        for i in (6, 10, 14):
            p(i, 14, RAINBLUE)
            p(i, 15, RAINBLUE)
    elif kind == "snow":
        r(3, 5, 16, 10, CLOUDC)
        r(6, 1, 13, 5, CLOUDC)
        for i in (5, 10, 14):
            p(i, 13, WHITE)
            p(i - 1, 14, WHITE)
            p(i + 1, 14, WHITE)
            p(i, 15, WHITE)
    elif kind == "thunder":
        r(3, 4, 16, 9, CLOUDC)
        r(6, 1, 13, 4, CLOUDC)
        for k in range(7):
            p(10 - k // 2, 10 + k, (255, 215, 0))
    elif kind == "fog":
        for y, a, b in ((6, 5, 15), (9, 2, 17), (12, 6, 16), (15, 3, 14)):
            r(a, y, b, y, FOGBC)
    else:                                       # "unknown" - no weather data
        mask, _size = fit_mask("?", font_path_for(cfg, "bold"), 16, 16,
                               cfg["antialias"], max_size=16)
        ox, oy = (20 - mask.width) // 2, (20 - mask.height) // 2
        for mx in range(mask.width):
            for my in range(mask.height):
                cov = mask.getpixel((mx, my))
                if cov:
                    p(ox + mx, oy + my, blend(DIM, cov))
    return ic


# --------------------------------------------------------------------------
# Frame layout
# --------------------------------------------------------------------------
def render(cfg, hour_text, hour_ref, minute_text, icon, temp_v, rain_v, aqi_v, unit,
           weather_dim=1.0, aqi_dim=1.0, brightness=None):
    """Render one frame.

    temp_v / rain_v / aqi_v may be None (missing) and then render as NA.
    weather_dim / aqi_dim are 1.0 for fresh data and below 1.0 for stale data.
    brightness overrides cfg["frame_brightness"] (see night_brightness).
    """
    frame = Frame(cfg)
    frame.put("hour", hour_text, WHITE, ref=hour_ref)
    frame.put("minute", minute_text, WHITE)

    frame.icon(icon, 38, 3, weather_dim)

    frame.put("temp", "%d%s" % (temp_v, unit) if temp_v is not None else NA,
              scale(WHITE, weather_dim) if temp_v is not None else DIM_DARK)
    frame.put("rain", "%d%%" % rain_v if rain_v is not None else NA,
              scale(RAINBLUE, weather_dim) if rain_v is not None else DIM_DARK)
    frame.put("aqi", str(aqi_v) if aqi_v is not None else NA,
              scale(aqi_color(aqi_v), aqi_dim) if aqi_v is not None else DIM_DARK)

    if brightness is None:
        brightness = cfg["frame_brightness"]
    if brightness < 100:
        factor = brightness / 100.0
        frame.img = frame.img.point(lambda v: int(v * factor + 0.5))
    return frame


def frame_ascii(img):
    """Ground-truth dump. Buckets each pixel to the nearest palette colour so that
    blended (antialiased) edge pixels still classify correctly."""
    palette = [(WHITE, "#"), (DIM, "d"), (DIM_DARK, "x"), (RAINBLUE, "b"),
               (GREEN, "G"), (SUNC, "Y"), (CLOUDC, "C"), (FOGBC, "f")]
    lines = []
    for y in range(64):
        row = []
        for x in range(64):
            r, g, b = img.getpixel((x, y))
            if r < 12 and g < 12 and b < 12:
                row.append(".")
                continue
            best, best_d = "o", 10 ** 9
            for col, ch in palette:
                d = (r - col[0]) ** 2 + (g - col[1]) ** 2 + (b - col[2]) ** 2
                if d < best_d:
                    best, best_d = ch, d
            row.append(best)
        lines.append("".join(row))
    return lines


# --------------------------------------------------------------------------
# mDNS discovery (stdlib only)
# --------------------------------------------------------------------------
def _encode_name(name):
    out = b""
    for label in name.strip(".").split("."):
        b = label.encode()
        out += bytes([len(b)]) + b
    return out + b"\x00"


def _parse_name(data, off):
    labels, start, jumped, jumps = [], off, False, 0
    while True:
        if off >= len(data):
            return ".".join(labels), start
        ln = data[off]
        if ln == 0:
            off += 1
            if not jumped:
                start = off
            return ".".join(labels), start
        if ln & 0xC0 == 0xC0:
            if off + 2 > len(data):
                return ".".join(labels), start
            ptr = struct.unpack(">H", data[off:off + 2])[0] & 0x3FFF
            # A malformed or hostile packet can point a name at itself, or chain
            # pointers in a loop. Bound the jumps so the parser terminates instead
            # of spinning in this loop forever.
            jumps += 1
            if jumps > MAX_POINTER_JUMPS:
                log("mDNS: compression pointer loop, name truncated")
                return ".".join(labels), start
            if not jumped:
                start = off + 2
            off = ptr
            jumped = True
            continue
        off += 1
        labels.append(data[off:off + ln].decode("utf-8", "replace"))
        off += ln
        if not jumped:
            start = off


def _parse_records(data):
    """Return DNS records as dicts: {"name", "type", ...}."""
    if len(data) < 12:
        return []
    _, _, qd, an, ns, ar = struct.unpack(">HHHHHH", data[:12])
    off = 12
    for _ in range(qd):
        _, off = _parse_name(data, off)
        off += 4
    recs = []
    for _ in range(an + ns + ar):
        name, off = _parse_name(data, off)
        if off + 10 > len(data):
            break
        rtype, _rclass, _ttl, rdlen = struct.unpack(">HHIH", data[off:off + 10])
        off += 10
        rdata = data[off:off + rdlen]
        name = name.rstrip(".")
        if rtype == 12:                                  # PTR
            val, _ = _parse_name(data, off)
            recs.append({"name": name, "type": "PTR", "value": val.rstrip(".")})
        elif rtype == 33 and rdlen >= 6:                 # SRV
            _prio, _weight, port = struct.unpack(">HHH", rdata[:6])
            target, _ = _parse_name(data, off + 6)
            recs.append({"name": name, "type": "SRV",
                         "port": port, "target": target.rstrip(".")})
        elif rtype == 16:                                # TXT
            # TXT strings are length-prefixed, not null-separated.
            fields, i = {}, 0
            while i < len(rdata):
                ln = rdata[i]
                i += 1
                chunk = rdata[i:i + ln]
                i += ln
                if b"=" in chunk:
                    k, _, v = chunk.partition(b"=")
                    fields[k.decode("utf-8", "replace")] = v.decode("utf-8", "replace")
            recs.append({"name": name, "type": "TXT", "value": fields})
        elif rtype == 1 and rdlen == 4:                  # A
            recs.append({"name": name, "type": "A",
                         "value": socket.inet_ntoa(rdata)})
        elif rtype == 28 and rdlen == 16:                # AAAA
            recs.append({"name": name, "type": "AAAA",
                         "value": socket.inet_ntop(socket.AF_INET6, rdata)})
        off += rdlen
    return recs


def _mdns_socket():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    except (AttributeError, OSError):
        pass
    sock.bind(("", 5353))
    mreq = struct.pack("=4sl", socket.inet_aton("224.0.0.251"), socket.INADDR_ANY)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
    return sock


def _mdns_query(sock, name, qtype, wait):
    header = struct.pack(">HHHHHH", 0, 0, 1, 0, 0, 0)
    packet = header + _encode_name(name) + struct.pack(">HH", qtype, 1)
    sock.sendto(packet, ("224.0.0.251", 5353))
    sock.settimeout(0.4)
    deadline = time.time() + wait
    recs = []
    while time.time() < deadline:
        try:
            data, _addr = sock.recvfrom(9000)
        except socket.timeout:
            continue
        recs.extend(_parse_records(data))
    return recs


def discover_mdns(wait=4.0):
    """Find every _tuneshine._tcp.local instance on the LAN.

    Returns a list of dicts: instance, hostname, ip, port, txt.
    """
    instances, srv, addrs, txt = {}, {}, {}, {}
    try:
        sock = _mdns_socket()
    except OSError as exc:
        log("mDNS socket failed: %s" % exc)
        return []

    try:
        for rec in _mdns_query(sock, MDNS_SERVICE, 12, wait):
            if rec["type"] == "PTR" and rec["value"].endswith(MDNS_SERVICE):
                instances[rec["value"]] = True
            elif rec["type"] == "SRV":
                srv[rec["name"]] = (rec["target"], rec["port"])
            elif rec["type"] == "TXT":
                txt[rec["name"]] = rec["value"]
            elif rec["type"] == "A":
                addrs[rec["name"]] = rec["value"]

        # An instance with no A record yet gets its own follow-up query.
        for inst in list(instances):
            target, _port = srv.get(inst, (None, None))
            if target and target not in addrs:
                for rec in _mdns_query(sock, target, 1, 2.0):
                    if rec["type"] == "A":
                        addrs[rec["name"]] = rec["value"]
    except OSError as exc:
        log("mDNS query failed: %s" % exc)
    finally:
        try:
            sock.close()
        except OSError:
            pass

    out = []
    for inst in sorted(instances):
        target, port = srv.get(inst, (None, 80))
        ip = addrs.get(target) if target else None
        if not ip:
            continue
        out.append({"instance": inst.rsplit("." + MDNS_SERVICE, 1)[0],
                    "hostname": target, "ip": ip,
                    "port": port or 80, "txt": txt.get(inst, {})})
    return out


# --------------------------------------------------------------------------
# Device identity and selection
# --------------------------------------------------------------------------
NON_ALNUM = re.compile(r"[^a-z0-9]")


def _variants(value):
    v = str(value).strip().lower()
    return {v, NON_ALNUM.sub("", v)}


def device_matches(entry, dev):
    """Does a config list entry name this device?

    Matches name, hardwareId, deviceId, IP, hostname or mDNS instance.
    Case-insensitive, MAC punctuation ignored, shell globs allowed.
    """
    e = str(entry).strip().lower()
    if not e:
        return False
    e_flat = NON_ALNUM.sub("", e)
    for ident in dev.get("identities", []):
        if fnmatch.fnmatch(str(ident).strip().lower(), e):
            return True
        for v in _variants(ident):
            if fnmatch.fnmatch(v, e) or v == e_flat:
                return True
    return False


def device_base(dev):
    if dev.get("port") and dev["port"] != 80:
        return "http://%s:%d" % (dev["ip"], dev["port"])
    return "http://%s" % dev["ip"]


def device_state(dev, timeout=3):
    try:
        resp = requests.get(device_base(dev) + "/state", timeout=timeout)
        resp.raise_for_status()
        return resp.json()
    except (requests.RequestException, ValueError):
        return None


def discover_devices(cfg, st):
    """Every reachable Tuneshine, with identity fields for selection."""
    candidates = {}
    for dev in discover_mdns(cfg["devices"]["mdns_timeout"]):
        candidates[dev["ip"]] = dev

    # configured and previously seen hosts, for networks that block multicast
    extras = list(cfg["devices"]["hosts"]) + list(st.get("known_hosts") or [])
    for host in extras:
        host = str(host).strip()
        if not host:
            continue
        ip = host
        if not re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host):
            try:
                ip = socket.gethostbyname(host)
            except OSError:
                continue
        candidates.setdefault(ip, {"instance": host, "hostname": host,
                                   "ip": ip, "port": 80, "txt": {}})

    devices = []
    for ip, dev in candidates.items():
        state = device_state(dev)
        if state is None:
            continue
        dev["state"] = state
        dev["name"] = state.get("name") or dev.get("instance") or ip
        dev["hardware_id"] = state.get("hardwareId") or ""
        dev["device_id"] = dev.get("txt", {}).get("deviceId", "")
        dev["firmware"] = state.get("firmwareVersion") or ""
        dev["identities"] = [x for x in (dev["name"], dev["hardware_id"],
                                         dev["device_id"], dev["ip"],
                                         dev.get("hostname"), dev.get("instance"))
                             if x]
        devices.append(dev)

    devices.sort(key=lambda d: d["ip"])
    st["known_hosts"] = [d["ip"] for d in devices]
    return devices


def select_devices(devices, cfg):
    """Apply devices.mode / include / exclude. Returns (selected, skipped)."""
    spec = cfg["devices"]
    mode = spec["mode"]
    if mode == "include":
        if not spec["include"]:
            log("config: devices.mode is 'include' but the list is empty; pushing to all")
            return devices, []
        selected = [d for d in devices
                    if any(device_matches(e, d) for e in spec["include"])]
        return selected, [d for d in devices if d not in selected]
    if mode == "exclude":
        selected, skipped = [], []
        for dev in devices:
            if any(device_matches(e, dev) for e in spec["exclude"]):
                skipped.append(dev)
            else:
                selected.append(dev)
        return selected, skipped
    return devices, []


# --------------------------------------------------------------------------
# Weather
# --------------------------------------------------------------------------
def locate(cfg, st):
    """Return (lat, lon, label). Pinned config wins; otherwise IP, then config."""
    if cfg["location"] == "pinned":
        return cfg["lat"], cfg["lon"], cfg["label"]
    age = time.time() - st.get("loc_ts", 0)
    if st.get("lat") and age < cfg["location_ttl"]:
        return st["lat"], st["lon"], st.get("loc_label") or cfg["label"]
    try:
        resp = requests.get("https://ipinfo.io/json", timeout=8)
        resp.raise_for_status()
        payload = resp.json()
        loc = payload.get("loc", "")
        if "," in loc:
            lat, lon = (float(v) for v in loc.split(",")[:2])
            label = payload.get("city") or cfg["label"]
            st.update(lat=lat, lon=lon, loc_ts=time.time(), loc_label=label)
            return lat, lon, label
    except (requests.RequestException, ValueError, KeyError) as exc:
        log("ipinfo lookup failed: %s" % exc)
    return cfg["lat"], cfg["lon"], cfg["label"]


def _num(value):
    """Coerce a possibly-missing API value to a rounded int, or None."""
    if value is None:
        return None
    try:
        return int(round(float(value)))
    except (TypeError, ValueError):
        return None


def fetch_weather(lat, lon, units):
    """Fetch forecast and air quality independently. Never raises.

    Returns a dict with any of now/code/max/min/rain/aqi possibly None, plus
    fc_ts / aqi_ts marking when each source last succeeded.
    """
    out = {"now": None, "code": None, "is_day": None, "max": None, "min": None,
           "rain": None, "aqi": None, "sunrise": None, "sunset": None,
           "fc_ts": None, "aqi_ts": None, "errors": [], "sources": {}}

    try:
        resp = requests.get(
            "https://api.open-meteo.com/v1/forecast",
            params={"latitude": lat, "longitude": lon,
                    "current": "temperature_2m,weather_code,is_day",
                    "daily": "temperature_2m_max,temperature_2m_min,"
                             "precipitation_probability_max,sunrise,sunset",
                    "temperature_unit": units, "timezone": "auto",
                    "forecast_days": 1},
            timeout=12)
        resp.raise_for_status()
        data = resp.json()
        current = data.get("current") or {}
        daily = data.get("daily") or {}
        out["now"] = _num(current.get("temperature_2m"))
        out["code"] = _num(current.get("weather_code"))
        out["is_day"] = _num(current.get("is_day"))
        out["max"] = _num((daily.get("temperature_2m_max") or [None])[0])
        out["min"] = _num((daily.get("temperature_2m_min") or [None])[0])
        out["rain"] = _num((daily.get("precipitation_probability_max") or [None])[0])
        out["sunrise"] = (daily.get("sunrise") or [None])[0]
        out["sunset"] = (daily.get("sunset") or [None])[0]
        out["fc_ts"] = time.time()
        out["sources"]["forecast"] = "ok"
        missing = [k for k in ("now", "code", "max", "min", "rain") if out[k] is None]
        if missing:
            out["errors"].append("forecast partial: %s missing" % ",".join(missing))
    except (requests.RequestException, ValueError) as exc:
        out["errors"].append("forecast: %s" % exc)
        out["sources"]["forecast"] = "fail"

    try:
        resp = requests.get(
            "https://air-quality-api.open-meteo.com/v1/air-quality",
            params={"latitude": lat, "longitude": lon, "current": "us_aqi",
                    "timezone": "auto"},
            timeout=12)
        resp.raise_for_status()
        current = resp.json().get("current") or {}
        out["aqi"] = _num(current.get("us_aqi"))
        out["aqi_ts"] = time.time()
        out["sources"]["aqi"] = "ok" if out["aqi"] is not None else "empty"
        if out["aqi"] is None:
            out["errors"].append("aqi: field missing")
    except (requests.RequestException, ValueError) as exc:
        out["errors"].append("aqi: %s" % exc)
        out["sources"]["aqi"] = "fail"

    return out


def merge_weather(fresh, cached):
    """Per-field: prefer fresh, else the last cached value, else None."""
    cached = cached or {}
    merged = {}
    for key in ("now", "code", "is_day", "sunrise", "sunset",
                "max", "min", "rain", "aqi"):
        merged[key] = fresh.get(key)
        if merged[key] is None:
            merged[key] = cached.get(key)
    merged["fc_ts"] = fresh.get("fc_ts") or cached.get("fc_ts") or cached.get("ts")
    merged["aqi_ts"] = fresh.get("aqi_ts") or cached.get("aqi_ts")
    merged["errors"] = fresh.get("errors") or []
    merged["sources"] = fresh.get("sources") or {}
    return merged


def weather_for(cfg, st):
    """Return (weather, fetched_now, notes)."""
    cached = st.get("weather") or {}
    fresh_age = time.time() - cached.get("last_fetch", 0)
    if cached and fresh_age < cfg["weather_ttl"]:
        return cached, False, []

    lat, lon, label = locate(cfg, st)
    fresh = fetch_weather(lat, lon, cfg["units"])
    merged = merge_weather(fresh, cached)
    # Start the TTL clock only when at least one source answered. Otherwise a
    # single transient failure caches an all-None result for a whole weather_ttl,
    # and the display shows "--" for minutes on end with no retry.
    merged["last_fetch"] = time.time() if (fresh.get("fc_ts") or fresh.get("aqi_ts")) else 0
    if not merged["last_fetch"]:
        log("weather: both sources failed, will retry on the next run")
    merged["lat"], merged["lon"], merged["label"] = lat, lon, label

    notes = list(fresh["errors"])
    reused = [k for k in ("now", "code", "max", "min", "rain", "aqi")
              if fresh.get(k) is None and cached.get(k) is not None]
    if reused:
        notes.append("reused cached: %s" % ",".join(reused))
    missing = [k for k in ("now", "code", "max", "min", "rain", "aqi")
               if merged.get(k) is None]
    return merged, True, notes + (["no data: %s" % ",".join(missing)] if missing else [])


def dim_factor(ts, cfg):
    """1.0 for fresh data, less once it is older than stale_after_seconds."""
    if not ts:
        return 0.45
    age = time.time() - ts
    if age <= cfg["stale_after_seconds"]:
        return 1.0
    return 0.45


def night_brightness(cfg, weather, at):
    """Frame brightness for right now, reduced between sunset and sunrise.

    Returns (brightness, is_night). Sunset and sunrise come from the same
    Open-Meteo call as the temperature, in the location's local time. Falls back
    to frame_brightness whenever the schedule is off or the times are unknown, so
    a failed forecast never leaves the display stuck dim.
    """
    base = cfg["frame_brightness"]
    schedule = cfg["night_dim"]
    if not schedule["enabled"]:
        return base, False
    sunrise, sunset = weather.get("sunrise"), weather.get("sunset")
    if not sunrise or not sunset:
        return base, False
    try:
        rise = datetime.fromisoformat(str(sunrise)).replace(tzinfo=None)
        sett = datetime.fromisoformat(str(sunset)).replace(tzinfo=None)
    except ValueError:
        log("night_dim: unparsable sunrise/sunset %r %r" % (sunrise, sunset))
        return base, False
    now = at.replace(tzinfo=None)
    if not (now >= sett or now < rise):         # daylight
        return base, False
    return max(1, int(round(base * schedule["percent"] / 100.0))), True


# --------------------------------------------------------------------------
# Run
# --------------------------------------------------------------------------
def _fail(st, msg, cfg):
    st["consecutive_failures"] = st.get("consecutive_failures", 0) + 1
    st["last_failure"] = msg
    st["last_failure_ts"] = time.time()
    save_state(st)
    log("FAIL (%d): %s" % (st["consecutive_failures"], msg))
    if time.time() - st.get("last_alert_ts", 0) > cfg["alert_ttl"]:
        st["last_alert_ts"] = time.time()
        save_state(st)
        print("Tuneshine info problem: %s" % msg)
    return 0


def build_frame(cfg, weather, at):
    """Build the frame for a given time and weather dict. Returns (frame, info)."""
    if cfg["clock"] == "12h":
        hour12 = at.hour % 12 or 12
        hour_text = "%d%s" % (hour12, "AM" if at.hour < 12 else "PM")
        hour_ref = "88PM"
    else:
        hour_text, hour_ref = at.strftime("%H"), "88"
    minute_text = at.strftime("%M")

    code = weather.get("code")
    if code is None:
        icon = "unknown"
    elif code in (0, 1) and weather.get("is_day") == 0:
        icon = "moon"                       # clear sky after dark
    else:
        icon = WMO_ICON.get(code, "cloud")

    temp_v = weather.get("now")
    rain_v = weather.get("rain")
    aqi_v = weather.get("aqi")
    unit = "F" if cfg["units"] == "fahrenheit" else "C"

    brightness, is_night = night_brightness(cfg, weather, at)
    frame = render(cfg, hour_text, hour_ref, minute_text, icon,
                   temp_v, rain_v, aqi_v, unit,
                   weather_dim=dim_factor(weather.get("fc_ts"), cfg),
                   aqi_dim=dim_factor(weather.get("aqi_ts"), cfg),
                   brightness=brightness)
    info = "%s:%s icon=%s temp=%s rain=%s aqi=%s%s" % (
        hour_text, minute_text, icon,
        ("%d%s" % (temp_v, unit)) if temp_v is not None else NA,
        ("%d%%" % rain_v) if rain_v is not None else NA,
        aqi_v if aqi_v is not None else NA,
        " [night %d%%]" % brightness if is_night else "")
    return frame, info


def print_devices(devices, cfg, selected=None):
    """One line per device. With `selected`, each device is marked -> or --."""
    sel_ids = {id(d) for d in (selected or [])}
    for dev in devices:
        mark = " "
        if selected is not None:
            mark = "->" if id(dev) in sel_ids else "--"
        print("%s %-28s %-15s %-17s %s" % (
            mark, dev["name"][:28], dev["ip"],
            dev.get("hardware_id", ""), dev.get("device_id", "")))
        print("     hostname=%s port=%s firmware=%s" % (
            dev.get("hostname") or "-", dev.get("port"), dev.get("firmware") or "-"))
    print()
    print("mode=%s include=%s exclude=%s" % (
        cfg["devices"]["mode"],
        cfg["devices"]["include"] or "-", cfg["devices"]["exclude"] or "-"))


def run(args, cfg):
    st = load_state()

    devices = discover_devices(cfg, st)
    if not devices:
        return _fail(st, "no Tuneshine found on the network (mDNS silent, "
                         "no configured hosts reachable)", cfg)

    selected, skipped = select_devices(devices, cfg)

    if args.list_devices:
        print_devices(devices, cfg, selected)
        save_state(st)
        return 0

    if not selected:
        return _fail(st, "no device selected: %d found, all filtered out by "
                         "devices.mode=%s" % (len(devices), cfg["devices"]["mode"]), cfg)

    at = now_in(cfg)
    minute_key = at.strftime("%Y-%m-%d %H:%M")

    if args.status:
        weather = st.get("weather") or {}
        print("config      : %s" % cfg["path"])
        print("units/clock : %s / %s  tz=%s" % (cfg["units"], cfg["clock"], cfg["timezone"]))
        print("location    : %s (%.4f, %.4f)" % (
            weather.get("label") or cfg["label"] or "auto",
            weather.get("lat", cfg["lat"]), weather.get("lon", cfg["lon"])))
        for key in ("now", "code", "is_day", "max", "min", "rain", "aqi",
                    "sunrise", "sunset"):
            print("  %-8s: %s" % (key, weather.get(key)))
        if weather.get("fc_ts"):
            print("  age     : forecast %ds, aqi %ds" % (
                time.time() - weather["fc_ts"],
                time.time() - (weather.get("aqi_ts") or 0)))
        brightness, is_night = night_brightness(cfg, weather, at)
        print("  frame brightness: %d%%%s" % (
            brightness, "  (night: dimmed from %d%%)" % cfg["frame_brightness"]
            if is_night else "  (day)"))
        print()
        print("devices (%d found, %d selected):" % (len(devices), len(selected)))
        print_devices(devices, cfg, selected)
        for dev in selected:
            rec = (st.get("devices") or {}).get(dev["ip"]) or {}
            remote = (dev["state"].get("remoteMetadata") or {})
            print("  %-16s imageSource=%-7s playing=%-5s last=%s" % (
                dev["ip"], dev["state"].get("imageSource"),
                remote.get("idle") is False,
                rec.get("last_upload_minute") or "-"))
        return 0

    # --- render once, push to every selected device ---
    weather, fetched, notes = weather_for(cfg, st)
    frame, info = build_frame(cfg, weather, at)

    problems = frame.problems()
    if problems:
        return _fail(st, "layout problems: %s" % "; ".join(problems), cfg)

    os.makedirs(STATE_DIR, exist_ok=True)
    frame.img.save(PREVIEW_FILE)

    if args.dump:
        for line in frame_ascii(frame.img):
            print(line)
        return 0

    if args.preview:
        print("preview written: %s" % PREVIEW_FILE)
        print("frame: %s" % info)
        print("would push to %d device(s): %s" % (
            len(selected), ", ".join("%s (%s)" % (d["name"], d["ip"]) for d in selected)))
        if skipped:
            print("skipped: %s" % ", ".join("%s (%s)" % (d["name"], d["ip"])
                                            for d in skipped))
        if notes:
            print("degraded: %s" % "; ".join(notes))
        return 0

    buf = io.BytesIO()
    frame.img.save(buf, format="WEBP", lossless=True, quality=100)
    payload = buf.getvalue()
    metadata = json.dumps({"idle": True, "overridable": True})
    device_records = st.setdefault("devices", {})

    pushed, skipped_playing, already, failed = [], [], [], []
    for dev in selected:
        rec = device_records.setdefault(dev["ip"], {})
        remote = dev["state"].get("remoteMetadata") or {}
        playing = remote.get("idle") is False

        if playing and not args.force:
            rec["last_skip_ts"] = time.time()
            skipped_playing.append(dev)
            continue
        if rec.get("last_upload_minute") == minute_key and not args.force:
            already.append(dev)
            continue

        if cfg["brightness"]["set"]:
            try:
                current = (dev["state"].get("config") or {}).get("brightness") or {}
                want = {"idle": cfg["brightness"]["idle"],
                        "active": cfg["brightness"]["active"]}
                if any(current.get(k) != v for k, v in want.items()):
                    requests.post(device_base(dev) + "/brightness", json=want, timeout=3)
            except requests.RequestException as exc:
                log("brightness set failed on %s: %s" % (dev["ip"], exc))

        try:
            resp = requests.post(
                device_base(dev) + "/image",
                files={"image": ("frame.webp", payload, "image/webp")},
                data={"metadata": metadata},
                timeout=8)
            if resp.status_code != 200:
                raise RuntimeError("HTTP %s: %s" % (resp.status_code, resp.text[:120]))
        except (requests.RequestException, RuntimeError) as exc:
            rec["last_error"] = str(exc)
            rec["last_error_ts"] = time.time()
            failed.append((dev, str(exc)))
            continue

        rec["last_upload_minute"] = minute_key
        rec["last_upload_ts"] = time.time()
        rec["last_error"] = None
        pushed.append(dev)

    if fetched:
        st["weather"] = weather

    detail = "%s %dB -> %s" % (info, len(payload),
                               ", ".join(d["ip"] for d in pushed) or "none")
    if skipped_playing:
        detail += " | playing, left alone: %s" % ", ".join(
            d["ip"] for d in skipped_playing)
    if skipped:
        detail += " | filtered out: %s" % ", ".join(d["ip"] for d in skipped)
    if failed:
        detail += " | FAILED: %s" % ", ".join("%s (%s)" % (d["ip"], e) for d, e in failed)
    if notes:
        detail += " | degraded: %s" % "; ".join(notes)
    log(detail)

    if failed and not pushed and not already:
        return _fail(st, "every selected device rejected the upload: %s" % (
            "; ".join("%s (%s)" % (d["ip"], e) for d, e in failed)), cfg)

    st["consecutive_failures"] = 0
    save_state(st)
    return 0


def main():
    parser = argparse.ArgumentParser(
        description="Tuneshine info: clock + weather frame for every Tuneshine on the LAN")
    parser.add_argument("--config", help="path to config.json")
    parser.add_argument("--force", action="store_true",
                        help="upload even while music is playing")
    parser.add_argument("--preview", action="store_true",
                        help="render a PNG and say what would be pushed, do not upload")
    parser.add_argument("--dump", action="store_true", help="print the frame as ASCII")
    parser.add_argument("--status", action="store_true",
                        help="print config, devices and cached weather")
    parser.add_argument("--list-devices", action="store_true",
                        help="list every Tuneshine found, with the selection applied")
    parser.add_argument("--init-config", action="store_true",
                        help="write the default config file and exit")
    parser.add_argument("--overwrite-config", action="store_true",
                        help="with --init-config, replace an existing file")
    parser.add_argument("--version", action="version", version="tuneshine-info %s" % VERSION)
    args = parser.parse_args()

    global CFG
    if args.init_config:
        path = args.config or CONFIG_PATH
        wrote = write_default_config(path, force=args.overwrite_config)
        print(("wrote %s" % path) if wrote else
              ("%s already exists (use --overwrite-config to replace)" % path))
        return 0

    CFG = load_config(args.config)
    apply_paths(CFG)
    os.makedirs(STATE_DIR, exist_ok=True)

    def execute():
        try:
            return run(args, CFG)
        except Exception:
            log("UNEXPECTED %s" % traceback.format_exc().replace("\n", " | "))
            return _fail(load_state(), "unexpected error, see log", CFG)

    if args.preview or args.dump or args.status or args.list_devices:
        # A read-only command must not create or remove the lock. Doing so clears
        # the lock of a push run that is still in flight, and the next minute's
        # run can then start beside it.
        return execute()

    if os.path.exists(LOCK_FILE):
        try:
            age = time.time() - os.path.getmtime(LOCK_FILE)
        except OSError:
            age = 10 ** 6
        if age < 50:
            return 0
    with open(LOCK_FILE, "w") as fh:
        fh.write(str(os.getpid()))
    try:
        return execute()
    finally:
        try:
            os.remove(LOCK_FILE)
        except OSError:
            pass


if __name__ == "__main__":
    sys.exit(main())
