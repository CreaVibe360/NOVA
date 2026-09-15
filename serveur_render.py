import os
import json
import time
import uuid
import base64
import queue
import shutil
import socket
import signal
import threading
import subprocess
import urllib.parse
import urllib.request
import atexit
import contextlib
import dataclasses
import functools
import gc
import hashlib
import logging
import math
import platform
import re
import statistics
import sys
import traceback
import zlib
from collections import defaultdict, deque
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple

from flask import Flask, request, jsonify, Response
from flask_sock import Sock
import websocket


# ============================================================
# NOVA SERVER RUNTIME TOOLKIT
#
# Ce bloc ajoute de la résilience sans modifier le contrat HTTP
# existant. Les classes sont volontairement autonomes : elles
# peuvent être testées séparément et ne bloquent jamais la boucle
# CDP lorsqu'une métrique ou un cache rencontre une erreur.
# ============================================================


SERVER_VERSION = "2.2.0-optimized"
SERVER_NAME = "NOVA Remote Browser Server"
SERVER_STARTED_AT = time.monotonic()


def utc_now_iso():
    return datetime.now(
        timezone.utc
    ).isoformat()


def monotonic_ms():
    return time.monotonic() * 1000.0


def safe_int(value, default=0, minimum=None, maximum=None):
    try:
        result = int(float(value))
    except (TypeError, ValueError, OverflowError):
        result = int(default)

    if minimum is not None:
        result = max(int(minimum), result)

    if maximum is not None:
        result = min(int(maximum), result)

    return result


def safe_float(value, default=0.0, minimum=None, maximum=None):
    try:
        result = float(value)
    except (TypeError, ValueError, OverflowError):
        result = float(default)

    if not math.isfinite(result):
        result = float(default)

    if minimum is not None:
        result = max(float(minimum), result)

    if maximum is not None:
        result = min(float(maximum), result)

    return result


def safe_bool(value, default=False):
    if isinstance(value, bool):
        return value

    if value is None:
        return bool(default)

    text = str(value).strip().lower()

    if text in ("1", "true", "yes", "on", "oui"):
        return True

    if text in ("0", "false", "no", "off", "non"):
        return False

    return bool(default)


def safe_text(value, default="", limit=4096):
    if value is None:
        return default

    text = str(value)

    if len(text) > limit:
        return text[:limit]

    return text


def compact_json(value):
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
    )


def pretty_json(value):
    return json.dumps(
        value,
        ensure_ascii=False,
        indent=2,
        sort_keys=True,
    )


def json_bytes(value):
    return compact_json(value).encode("utf-8")


def sha1_text(value):
    return hashlib.sha1(
        safe_text(value).encode("utf-8")
    ).hexdigest()


def sha256_text(value):
    return hashlib.sha256(
        safe_text(value).encode("utf-8")
    ).hexdigest()


def clamp(value, minimum, maximum):
    return max(
        minimum,
        min(maximum, value),
    )


def percentile(values, percent):
    if not values:
        return 0.0

    ordered = sorted(
        float(value)
        for value in values
    )

    index = (
        (len(ordered) - 1)
        * float(percent)
        / 100.0
    )

    lower = int(math.floor(index))
    upper = int(math.ceil(index))

    if lower == upper:
        return ordered[lower]

    fraction = index - lower

    return (
        ordered[lower]
        * (1.0 - fraction)
        + ordered[upper]
        * fraction
    )


def summarize_numbers(values):
    values = [
        float(value)
        for value in values
        if value is not None
    ]

    if not values:
        return {
            "count": 0,
            "min": 0.0,
            "max": 0.0,
            "mean": 0.0,
            "p50": 0.0,
            "p95": 0.0,
            "p99": 0.0,
        }

    return {
        "count": len(values),
        "min": min(values),
        "max": max(values),
        "mean": statistics.fmean(values),
        "p50": percentile(values, 50),
        "p95": percentile(values, 95),
        "p99": percentile(values, 99),
    }


def exception_text(error):
    if isinstance(error, BaseException):
        return (
            error.__class__.__name__
            + ": "
            + str(error)
        )

    return safe_text(error)


def traceback_text(error=None):
    if error is None:
        return traceback.format_exc()

    return "".join(
        traceback.format_exception(
            type(error),
            error,
            error.__traceback__,
        )
    )


def memory_size(value):
    try:
        return sys.getsizeof(value)
    except Exception:
        return 0


def is_blank(value):
    return not safe_text(value).strip()


def normalize_header(value):
    return re.sub(
        r"[^a-z0-9-]",
        "",
        safe_text(value).lower(),
    )


def redact_text(value, visible=4):
    text = safe_text(value)

    if len(text) <= visible:
        return "*" * len(text)

    return (
        text[:visible]
        + "…"
        + "*" * max(2, len(text) - visible - 1)
    )


def redact_mapping(mapping, secret_keys=None):
    secret_keys = {
        normalize_header(key)
        for key in (
            secret_keys
            or {
                "authorization",
                "cookie",
                "token",
                "session",
                "password",
                "secret",
            }
        )
    }

    result = {}

    for key, value in dict(mapping or {}).items():
        normalized = normalize_header(key)

        if normalized in secret_keys:
            result[key] = redact_text(value)
        else:
            result[key] = value

    return result


@dataclasses.dataclass
class NovaConfig:
    host: str = "0.0.0.0"
    port: int = 3000
    cdp_host: str = "127.0.0.1"
    cdp_port: int = 9222
    width: int = 412
    height: int = 915
    device_scale_factor: float = 1.0
    jpeg_quality: int = 70
    max_fps: int = 30
    max_sessions: int = 8
    session_idle_seconds: int = 3600
    state_cache_seconds: float = 0.18
    command_timeout: float = 10.0
    frame_wait_seconds: float = 1.0
    max_input_text: int = 65536
    max_json_bytes: int = 262144
    profile_dir: str = "nova_chromium_profile"
    log_level: str = "INFO"
    cors_origin: str = "*"


def env_value(name, default=None):
    value = os.environ.get(name)

    if value is None:
        return default

    return value


def config_from_environment():
    return NovaConfig(
        host=safe_text(
            env_value("NOVA_HOST", "0.0.0.0")
        ),
        port=safe_int(
            env_value("NOVA_PORT", env_value("PORT", 3000)),
            3000,
            1,
            65535,
        ),
        cdp_host=safe_text(
            env_value("NOVA_CDP_HOST", "127.0.0.1")
        ),
        cdp_port=safe_int(
            env_value("NOVA_CDP_PORT", 9222),
            9222,
            1,
            65535,
        ),
        width=safe_int(
            env_value("NOVA_WIDTH", 412),
            412,
            240,
            4096,
        ),
        height=safe_int(
            env_value("NOVA_HEIGHT", 915),
            915,
            320,
            4096,
        ),
        device_scale_factor=safe_float(
            env_value("NOVA_SCALE", 1),
            1,
            0.5,
            3,
        ),
        jpeg_quality=safe_int(
            env_value("NOVA_JPEG_QUALITY", 70),
            70,
            20,
            100,
        ),
        max_fps=safe_int(
            env_value("NOVA_MAX_FPS", 30),
            30,
            1,
            60,
        ),
        max_sessions=safe_int(
            env_value("NOVA_MAX_SESSIONS", 8),
            8,
            1,
            64,
        ),
        session_idle_seconds=safe_int(
            env_value(
                "NOVA_SESSION_IDLE_SECONDS",
                3600,
            ),
            3600,
            30,
            86400,
        ),
        state_cache_seconds=safe_float(
            env_value(
                "NOVA_STATE_CACHE_SECONDS",
                0.18,
            ),
            0.18,
            0.02,
            10,
        ),
        command_timeout=safe_float(
            env_value("NOVA_COMMAND_TIMEOUT", 10),
            10,
            0.5,
            120,
        ),
        frame_wait_seconds=safe_float(
            env_value("NOVA_FRAME_WAIT_SECONDS", 1),
            1,
            0.05,
            10,
        ),
        max_input_text=safe_int(
            env_value("NOVA_MAX_INPUT_TEXT", 65536),
            65536,
            128,
            1048576,
        ),
        max_json_bytes=safe_int(
            env_value("NOVA_MAX_JSON_BYTES", 262144),
            262144,
            4096,
            8388608,
        ),
        profile_dir=os.path.abspath(
            safe_text(
                env_value(
                    "NOVA_PROFILE_DIR",
                    "nova_chromium_profile",
                )
            )
        ),
        log_level=safe_text(
            env_value("NOVA_LOG_LEVEL", "INFO")
        ).upper(),
        cors_origin=safe_text(
            env_value("NOVA_CORS_ORIGIN", "*")
        ),
    )


CONFIG = config_from_environment()


def configure_logging():
    level = getattr(
        logging,
        CONFIG.log_level,
        logging.INFO,
    )

    logging.basicConfig(
        level=level,
        format=(
            "%(asctime)s %(levelname)s "
            "[%(threadName)s] %(message)s"
        ),
    )

    return logging.getLogger("nova")


LOGGER = configure_logging()


class AtomicInteger:
    def __init__(self, value=0):
        self._value = int(value)
        self._lock = threading.Lock()

    def get(self):
        with self._lock:
            return self._value

    def set(self, value):
        with self._lock:
            self._value = int(value)
            return self._value

    def increment(self, amount=1):
        with self._lock:
            self._value += int(amount)
            return self._value

    def decrement(self, amount=1):
        return self.increment(-int(amount))

    def maximum(self, value):
        with self._lock:
            self._value = max(
                self._value,
                int(value),
            )
            return self._value

    def __int__(self):
        return self.get()


class MetricCounter:
    def __init__(self):
        self._values = defaultdict(int)
        self._lock = threading.RLock()

    def add(self, name, amount=1):
        with self._lock:
            self._values[str(name)] += int(amount)
            return self._values[str(name)]

    def get(self, name):
        with self._lock:
            return int(self._values.get(str(name), 0))

    def snapshot(self):
        with self._lock:
            return dict(self._values)

    def reset(self):
        with self._lock:
            old = dict(self._values)
            self._values.clear()
            return old

    def merge(self, values):
        for key, value in dict(values or {}).items():
            self.add(key, value)


class LatencyMetric:
    def __init__(self, limit=512):
        self.limit = max(16, int(limit))
        self.values = deque(maxlen=self.limit)
        self.lock = threading.RLock()

    def observe(self, value):
        with self.lock:
            self.values.append(
                safe_float(value)
            )

    def snapshot(self):
        with self.lock:
            return list(self.values)

    def summary(self):
        return summarize_numbers(
            self.snapshot()
        )

    def clear(self):
        with self.lock:
            self.values.clear()


class NovaMetrics:
    def __init__(self):
        self.counters = MetricCounter()
        self.command_latency = LatencyMetric()
        self.request_latency = LatencyMetric()
        self.frame_latency = LatencyMetric()
        self.started_at = monotonic_ms()
        self.last_error = ""
        self.last_error_at = 0.0
        self.lock = threading.RLock()

    def count(self, name, amount=1):
        return self.counters.add(name, amount)

    def observe_command(self, value):
        self.command_latency.observe(value)
        self.count("cdp_commands")

    def observe_request(self, value):
        self.request_latency.observe(value)
        self.count("http_requests")

    def observe_frame(self, value):
        self.frame_latency.observe(value)
        self.count("frames_received")

    def error(self, error):
        with self.lock:
            self.last_error = exception_text(error)
            self.last_error_at = time.time()
            self.count("errors")

    def uptime_seconds(self):
        return max(
            0.0,
            (monotonic_ms() - self.started_at)
            / 1000.0,
        )

    def snapshot(self):
        with self.lock:
            return {
                "version": SERVER_VERSION,
                "uptimeSeconds": self.uptime_seconds(),
                "counters": self.counters.snapshot(),
                "commandLatencyMs": self.command_latency.summary(),
                "requestLatencyMs": self.request_latency.summary(),
                "frameLatencyMs": self.frame_latency.summary(),
                "lastError": self.last_error,
                "lastErrorAt": self.last_error_at,
            }


METRICS = NovaMetrics()


class Stopwatch:
    def __init__(self):
        self.started = monotonic_ms()
        self.finished = None

    def stop(self):
        if self.finished is None:
            self.finished = monotonic_ms()

        return self.elapsed()

    def elapsed(self):
        end = (
            self.finished
            if self.finished is not None
            else monotonic_ms()
        )

        return max(
            0.0,
            end - self.started,
        )

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        self.stop()
        return False


class TTLCache:
    def __init__(self, ttl=1.0, maximum=256):
        self.ttl = max(0.0, float(ttl))
        self.maximum = max(1, int(maximum))
        self.items = {}
        self.lock = threading.RLock()

    def _expired(self, item, now=None):
        now = time.monotonic() if now is None else now
        return now - item[1] >= self.ttl

    def get(self, key, default=None):
        with self.lock:
            item = self.items.get(key)

            if item is None:
                return default

            if self._expired(item):
                self.items.pop(key, None)
                return default

            return item[0]

    def set(self, key, value):
        with self.lock:
            if len(self.items) >= self.maximum:
                oldest = min(
                    self.items,
                    key=lambda name: self.items[name][1],
                )
                self.items.pop(oldest, None)

            self.items[key] = (
                value,
                time.monotonic(),
            )

        return value

    def get_or_set(self, key, factory):
        value = self.get(key, None)

        if value is not None:
            return value

        value = factory()
        return self.set(key, value)

    def delete(self, key):
        with self.lock:
            return self.items.pop(key, None)

    def clear(self):
        with self.lock:
            self.items.clear()

    def prune(self):
        with self.lock:
            now = time.monotonic()
            expired = [
                key
                for key, item in self.items.items()
                if self._expired(item, now)
            ]

            for key in expired:
                self.items.pop(key, None)

            return len(expired)

    def size(self):
        with self.lock:
            return len(self.items)


class SlidingWindow:
    def __init__(self, seconds=60.0, maximum=4096):
        self.seconds = max(0.1, float(seconds))
        self.maximum = max(1, int(maximum))
        self.events = deque()
        self.lock = threading.RLock()

    def add(self, value=1):
        now = time.monotonic()

        with self.lock:
            self.events.append(
                (now, float(value))
            )
            self._prune(now)

    def _prune(self, now=None):
        now = time.monotonic() if now is None else now
        threshold = now - self.seconds

        while self.events and (
            self.events[0][0] < threshold
            or len(self.events) > self.maximum
        ):
            self.events.popleft()

    def total(self):
        with self.lock:
            self._prune()
            return sum(
                value
                for _, value in self.events
            )

    def count(self):
        with self.lock:
            self._prune()
            return len(self.events)

    def rate(self):
        return self.total() / self.seconds

    def clear(self):
        with self.lock:
            self.events.clear()


class RateLimiter:
    def __init__(self, limit=120, window=60.0):
        self.limit = max(1, int(limit))
        self.window = max(0.1, float(window))
        self.buckets = {}
        self.lock = threading.RLock()

    def allow(self, key):
        now = time.monotonic()

        with self.lock:
            bucket = self.buckets.setdefault(
                safe_text(key, "unknown"),
                deque(),
            )

            threshold = now - self.window

            while bucket and bucket[0] < threshold:
                bucket.popleft()

            if len(bucket) >= self.limit:
                return False

            bucket.append(now)
            return True

    def remaining(self, key):
        now = time.monotonic()

        with self.lock:
            bucket = self.buckets.get(
                safe_text(key, "unknown"),
                deque(),
            )
            threshold = now - self.window

            while bucket and bucket[0] < threshold:
                bucket.popleft()

            return max(
                0,
                self.limit - len(bucket),
            )

    def reset(self, key=None):
        with self.lock:
            if key is None:
                self.buckets.clear()
            else:
                self.buckets.pop(
                    safe_text(key),
                    None,
                )


class CircuitBreaker:
    def __init__(
        self,
        failures=5,
        recovery_seconds=5.0,
    ):
        self.failure_limit = max(1, int(failures))
        self.recovery_seconds = max(
            0.1,
            float(recovery_seconds),
        )
        self.failures = 0
        self.opened_at = 0.0
        self.lock = threading.RLock()

    def is_open(self):
        with self.lock:
            if not self.opened_at:
                return False

            if (
                time.monotonic()
                - self.opened_at
                >= self.recovery_seconds
            ):
                self.opened_at = 0.0
                self.failures = 0
                return False

            return True

    def success(self):
        with self.lock:
            self.failures = 0
            self.opened_at = 0.0

    def failure(self):
        with self.lock:
            self.failures += 1

            if self.failures >= self.failure_limit:
                self.opened_at = time.monotonic()

    def state(self):
        with self.lock:
            return {
                "open": self.is_open(),
                "failures": self.failures,
                "openedAt": self.opened_at,
            }


class RetryPolicy:
    def __init__(
        self,
        attempts=3,
        delay=0.05,
        maximum_delay=1.0,
        multiplier=2.0,
    ):
        self.attempts = max(1, int(attempts))
        self.delay = max(0.0, float(delay))
        self.maximum_delay = max(
            self.delay,
            float(maximum_delay),
        )
        self.multiplier = max(
            1.0,
            float(multiplier),
        )

    def delays(self):
        delay = self.delay

        for _ in range(self.attempts):
            yield min(
                delay,
                self.maximum_delay,
            )
            delay *= self.multiplier

    def run(self, callback, retry_if=None):
        last_error = None

        for index, delay in enumerate(self.delays()):
            if index:
                time.sleep(delay)

            try:
                return callback()
            except Exception as error:
                last_error = error

                if retry_if is not None:
                    if not retry_if(error):
                        raise

        if last_error is not None:
            raise last_error

        return callback()


class BackgroundLoop:
    def __init__(self, name, callback, interval):
        self.name = safe_text(name, "nova-loop")
        self.callback = callback
        self.interval = max(0.01, float(interval))
        self.stop_event = threading.Event()
        self.thread = None
        self.lock = threading.RLock()
        self.last_error = ""
        self.runs = AtomicInteger()

    def _run(self):
        while not self.stop_event.is_set():
            started = time.monotonic()

            try:
                self.callback()
            except Exception as error:
                self.last_error = exception_text(error)
                METRICS.error(error)
                LOGGER.warning(
                    "%s failed: %s",
                    self.name,
                    self.last_error,
                )

            self.runs.increment()

            elapsed = time.monotonic() - started
            remaining = max(
                0.0,
                self.interval - elapsed,
            )

            self.stop_event.wait(remaining)

    def start(self):
        with self.lock:
            if self.thread and self.thread.is_alive():
                return False

            self.stop_event.clear()
            self.thread = threading.Thread(
                target=self._run,
                name=self.name,
                daemon=True,
            )
            self.thread.start()
            return True

    def stop(self, timeout=2.0):
        with self.lock:
            self.stop_event.set()
            thread = self.thread

        if thread and thread.is_alive():
            thread.join(timeout=max(0.0, timeout))

        return not thread or not thread.is_alive()

    def state(self):
        thread = self.thread

        return {
            "name": self.name,
            "interval": self.interval,
            "running": bool(
                thread and thread.is_alive()
            ),
            "runs": int(self.runs),
            "lastError": self.last_error,
        }


class JsonRing:
    def __init__(self, maximum=128):
        self.values = deque(
            maxlen=max(1, int(maximum))
        )
        self.lock = threading.RLock()

    def append(self, value):
        with self.lock:
            self.values.append(value)

    def snapshot(self):
        with self.lock:
            return list(self.values)

    def latest(self, default=None):
        with self.lock:
            if not self.values:
                return default

            return self.values[-1]

    def clear(self):
        with self.lock:
            self.values.clear()


def run_quietly(callback, default=None):
    try:
        return callback()
    except Exception as error:
        METRICS.error(error)
        return default


def run_logged(label, callback, default=None):
    try:
        return callback()
    except Exception as error:
        METRICS.error(error)
        LOGGER.warning(
            "%s: %s",
            safe_text(label, "operation"),
            exception_text(error),
        )
        return default


def retryable_network_error(error):
    text = exception_text(error).lower()

    markers = (
        "timeout",
        "temporarily",
        "connection reset",
        "connection refused",
        "broken pipe",
        "bad gateway",
        "disconnected",
    )

    return any(
        marker in text
        for marker in markers
    )


def ensure_directory(path):
    directory = Path(path)
    directory.mkdir(
        parents=True,
        exist_ok=True,
    )
    return str(directory)


def remove_file_quietly(path):
    try:
        Path(path).unlink(missing_ok=True)
        return True
    except Exception:
        return False


def process_alive(process):
    if process is None:
        return False

    try:
        return process.poll() is None
    except Exception:
        return False


def terminate_process(process, timeout=3.0):
    if not process:
        return True

    try:
        process.terminate()
    except Exception:
        return False

    try:
        process.wait(timeout=timeout)
        return True
    except Exception:
        try:
            process.kill()
            process.wait(timeout=timeout)
            return True
        except Exception:
            return False


def platform_snapshot():
    return {
        "system": platform.system(),
        "release": platform.release(),
        "machine": platform.machine(),
        "python": platform.python_version(),
        "implementation": platform.python_implementation(),
        "pid": os.getpid(),
        "cwd": os.getcwd(),
    }


def cpu_snapshot():
    return {
        "cpuCount": os.cpu_count() or 1,
        "loadAverage": run_quietly(
            os.getloadavg,
            (),
        ),
    }


def collect_garbage():
    collected = gc.collect()
    METRICS.count(
        "gc_collections",
        1,
    )
    return collected


class ResourceMonitor:
    def __init__(self):
        self.samples = JsonRing(64)
        self.loop = BackgroundLoop(
            "nova-resource-monitor",
            self.sample,
            15.0,
        )

    def sample(self):
        value = {
            "time": utc_now_iso(),
            "memory": run_quietly(
                lambda: {
                    "objects": len(gc.get_objects()),
                },
                {},
            ),
            "platform": platform_snapshot(),
            "cpu": cpu_snapshot(),
        }
        self.samples.append(value)
        return value

    def start(self):
        return self.loop.start()

    def stop(self):
        return self.loop.stop()

    def snapshot(self):
        return {
            "latest": self.samples.latest({}),
            "history": self.samples.snapshot(),
            "loop": self.loop.state(),
        }


RESOURCE_MONITOR = ResourceMonitor()


class SessionAccessLog:
    def __init__(self, maximum=256):
        self.events = JsonRing(maximum)

    def record(self, session_id, action, ok=True, error=""):
        self.events.append({
            "time": utc_now_iso(),
            "session": redact_text(session_id),
            "action": safe_text(action),
            "ok": bool(ok),
            "error": safe_text(error),
        })

    def snapshot(self):
        return self.events.snapshot()


ACCESS_LOG = SessionAccessLog()


class SessionActivity:
    def __init__(self):
        self.created_at = time.monotonic()
        self.last_seen = self.created_at
        self.requests = AtomicInteger()
        self.errors = AtomicInteger()
        self.frames = AtomicInteger()
        self.lock = threading.RLock()

    def touch(self):
        with self.lock:
            self.last_seen = time.monotonic()
            self.requests.increment()

    def frame(self):
        with self.lock:
            self.last_seen = time.monotonic()
            self.frames.increment()

    def error(self):
        with self.lock:
            self.errors.increment()

    def idle_seconds(self):
        with self.lock:
            return max(
                0.0,
                time.monotonic()
                - self.last_seen,
            )

    def snapshot(self):
        with self.lock:
            return {
                "createdAt": self.created_at,
                "lastSeen": self.last_seen,
                "idleSeconds": self.idle_seconds(),
                "requests": int(self.requests),
                "errors": int(self.errors),
                "frames": int(self.frames),
            }


class BoundedExecutor:
    def __init__(self, workers=4, queue_size=128, name="nova"):
        self.workers = max(1, int(workers))
        self.queue_size = max(1, int(queue_size))
        self.executor = ThreadPoolExecutor(
            max_workers=self.workers,
            thread_name_prefix=name,
        )
        self.pending = AtomicInteger()
        self.rejected = AtomicInteger()
        self.lock = threading.RLock()

    def submit(self, callback, *args, **kwargs):
        with self.lock:
            if self.pending.get() >= self.queue_size:
                self.rejected.increment()
                return None

            self.pending.increment()

        def run():
            try:
                return callback(*args, **kwargs)
            finally:
                self.pending.decrement()

        try:
            return self.executor.submit(run)
        except Exception:
            self.pending.decrement()
            self.rejected.increment()
            return None

    def shutdown(self, wait=False):
        self.executor.shutdown(
            wait=wait,
            cancel_futures=True,
        )

    def state(self):
        return {
            "workers": self.workers,
            "queueSize": self.queue_size,
            "pending": int(self.pending),
            "rejected": int(self.rejected),
        }


ACK_EXECUTOR = BoundedExecutor(
    workers=2,
    queue_size=256,
    name="nova-ack",
)


REQUEST_LIMITER = RateLimiter(
    limit=240,
    window=60.0,
)


def client_key():
    forwarded = request.headers.get(
        "X-Forwarded-For",
        "",
    )

    if forwarded:
        return forwarded.split(",")[0].strip()

    return request.remote_addr or "unknown"


def request_is_allowed():
    allowed = REQUEST_LIMITER.allow(
        client_key()
    )

    if not allowed:
        METRICS.count(
            "rate_limited_requests"
        )

    return allowed


def request_content_length():
    return safe_int(
        request.headers.get(
            "Content-Length",
            0,
        ),
        0,
        0,
    )


def request_user_agent():
    return safe_text(
        request.headers.get(
            "User-Agent",
            "",
        ),
        "unknown",
        512,
    )


def request_client_name():
    return safe_text(
        request.headers.get(
            "X-Nova-Client",
            "unknown",
        ),
        "unknown",
        128,
    )


def safe_request_summary():
    return {
        "method": request.method,
        "path": request.path,
        "remote": client_key(),
        "agent": request_user_agent(),
        "client": request_client_name(),
        "length": request_content_length(),
    }


def validate_json_size():
    length = request_content_length()

    if length <= 0:
        return True

    return length <= CONFIG.max_json_bytes


def valid_coordinate(value, maximum):
    number = safe_float(value, 0.0)
    return clamp(
        number,
        0.0,
        float(maximum),
    )


def validate_dimensions(width, height):
    return {
        "width": safe_int(
            width,
            CONFIG.width,
            240,
            4096,
        ),
        "height": safe_int(
            height,
            CONFIG.height,
            320,
            4096,
        ),
    }


def validate_text_input(value):
    text = safe_text(
        value,
        "",
        CONFIG.max_input_text,
    )
    return text


def make_error_payload(message, code="error"):
    return {
        "ok": False,
        "code": safe_text(code, "error"),
        "error": safe_text(message),
        "time": utc_now_iso(),
    }


def make_ok_payload(**values):
    payload = {
        "ok": True,
        "time": utc_now_iso(),
    }
    payload.update(values)
    return payload


def session_count():
    with sessions_lock:
        return len(sessions)


def session_ids():
    with sessions_lock:
        return list(sessions.keys())


def session_exists(session_id):
    if not session_id:
        return False

    with sessions_lock:
        return session_id in sessions


def session_snapshot(session_id):
    with sessions_lock:
        browser = sessions.get(session_id)

    if browser is None:
        return None

    return run_quietly(
        browser.diagnostics,
        {},
    )


def all_session_snapshots():
    snapshots = []

    with sessions_lock:
        current = list(sessions.items())

    for session_id, browser in current:
        snapshots.append(
            run_quietly(
                browser.diagnostics,
                {
                    "session": redact_text(
                        session_id
                    ),
                },
            )
        )

    return snapshots


def close_session_object(session_id, browser):
    if browser is None:
        return False

    ACCESS_LOG.record(
        session_id,
        "close",
    )

    return bool(
        run_quietly(
            browser.close,
            False,
        )
        is not False
    )


class SessionSweeper:
    def __init__(self):
        self.loop = BackgroundLoop(
            "nova-session-sweeper",
            self.sweep,
            30.0,
        )

    def sweep(self):
        expired = []

        with sessions_lock:
            current = list(sessions.items())

        for session_id, browser in current:
            activity = getattr(
                browser,
                "activity",
                None,
            )

            if activity is None:
                continue

            if (
                activity.idle_seconds()
                < CONFIG.session_idle_seconds
            ):
                continue

            expired.append(
                (session_id, browser)
            )

        for session_id, browser in expired:
            with sessions_lock:
                removed = sessions.pop(
                    session_id,
                    None,
                )

            if removed is not None:
                close_session_object(
                    session_id,
                    browser,
                )
                METRICS.count(
                    "sessions_expired"
                )

        return len(expired)

    def start(self):
        return self.loop.start()

    def stop(self):
        return self.loop.stop()

    def state(self):
        return self.loop.state()


SESSION_SWEEPER = SessionSweeper()


# ============================================================
# NOVA REMOTE BROWSER SERVER
# Chromium -> CDP Page.startScreencast -> WebSocket -> Client
# ============================================================

HOST = CONFIG.host
PORT = CONFIG.port

CDP_HOST = CONFIG.cdp_host
CDP_PORT = CONFIG.cdp_port

WIDTH = CONFIG.width
HEIGHT = CONFIG.height
DEVICE_SCALE_FACTOR = CONFIG.device_scale_factor

JPEG_QUALITY = CONFIG.jpeg_quality
MAX_FPS = CONFIG.max_fps

PROFILE_DIR = CONFIG.profile_dir

app = Flask(__name__)
sock = Sock(app)

sessions = {}
sessions_lock = threading.RLock()

chromium_process = None


# ============================================================
# CORS
# ============================================================

@app.after_request
def cors(response):
    response.headers["Access-Control-Allow-Origin"] = (
        CONFIG.cors_origin
    )
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    response.headers["Access-Control-Allow-Headers"] = (
        "Content-Type, X-Nova-Session, X-Nova-Client"
    )
    response.headers["Access-Control-Expose-Headers"] = "X-Nova-Session"
    response.headers["Cache-Control"] = "no-store"

    if request.headers.get("Access-Control-Request-Private-Network"):
        response.headers["Access-Control-Allow-Private-Network"] = "true"

    return response


@app.route("/api/<path:path>", methods=["OPTIONS"])
def options_api(path):
    return Response(status=204)


# ============================================================
# CHROMIUM
# ============================================================

def find_chromium():
    env = os.environ.get("CHROMIUM_BIN")

    candidates = [
        env,
        "chromium-browser",
        "chromium",
        "/data/data/com.termux/files/usr/bin/chromium-browser",
        "/data/data/com.termux/files/usr/bin/chromium",
    ]

    for candidate in candidates:
        if not candidate:
            continue

        if os.path.isabs(candidate) and os.path.exists(candidate):
            return candidate

        found = shutil.which(candidate)
        if found:
            return found

    raise RuntimeError("Chromium not found")


def port_open():
    try:
        with socket.create_connection(
            (CDP_HOST, CDP_PORT),
            timeout=0.5
        ):
            return True
    except Exception:
        return False


def launch_chromium():
    global chromium_process

    if port_open():
        return

    chromium = find_chromium()

    os.makedirs(PROFILE_DIR, exist_ok=True)

    common = [
        chromium,

        "--no-sandbox",
        "--disable-setuid-sandbox",
        "--disable-dev-shm-usage",

        f"--remote-debugging-address={CDP_HOST}",
        f"--remote-debugging-port={CDP_PORT}",

        f"--user-data-dir={PROFILE_DIR}",

        "--no-first-run",
        "--no-default-browser-check",

        "--disable-background-timer-throttling",
        "--disable-backgrounding-occluded-windows",
        "--disable-renderer-backgrounding",

        "--disable-component-update",
        "--disable-sync",
        "--disable-extensions",

        "--disable-features=Translate,OptimizationHints",

        "--autoplay-policy=no-user-gesture-required",

        f"--window-size={WIDTH},{HEIGHT}",

        "about:blank",
    ]

    commands = [
        [chromium, "--headless=new"] + common[1:],
        [chromium, "--headless"] + common[1:],
    ]

    last_error = None

    for cmd in commands:
        try:
            chromium_process = subprocess.Popen(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )

            deadline = time.time() + 15

            while time.time() < deadline:
                if port_open():
                    print("NOVA: Chromium ready")
                    return

                if chromium_process.poll() is not None:
                    break

                time.sleep(0.2)

        except Exception as e:
            last_error = e

    raise RuntimeError(
        f"Unable to launch Chromium: {last_error}"
    )


# ============================================================
# CDP HELPERS
# ============================================================

def http_json(url, method="GET"):
    req = urllib.request.Request(
        url,
        method=method,
        headers={
            "User-Agent": "NOVA/1.0"
        }
    )

    with urllib.request.urlopen(req, timeout=5) as r:
        return json.loads(r.read().decode())


def create_target():
    encoded = urllib.parse.quote("about:blank", safe="")

    try:
        return http_json(
            f"http://{CDP_HOST}:{CDP_PORT}/json/new?{encoded}",
            method="PUT"
        )
    except Exception:
        return http_json(
            f"http://{CDP_HOST}:{CDP_PORT}/json/new?{encoded}",
            method="GET"
        )


# ============================================================
# CDP CONNECTION
# ============================================================

class CDP:
    def __init__(self, ws_url, event_handler=None):
        self.ws_url = ws_url
        self.event_handler = event_handler

        self.ws = websocket.create_connection(
            ws_url,
            timeout=5,
            suppress_origin=True,
            enable_multithread=True,
        )

        self.counter = 0

        self.pending = {}
        self.pending_lock = threading.RLock()

        self.send_lock = threading.RLock()

        self.running = True

        self.reader = threading.Thread(
            target=self._reader,
            daemon=True
        )
        self.reader.start()

    def _reader(self):
        try:
            while self.running:
                raw = self.ws.recv()

                if not raw:
                    raise RuntimeError("CDP disconnected")

                message = json.loads(raw)

                msg_id = message.get("id")

                if msg_id is not None:
                    with self.pending_lock:
                        waiter = self.pending.get(msg_id)

                    if waiter:
                        try:
                            waiter.put_nowait(
                                message
                            )
                        except queue.Full:
                            METRICS.count(
                                "cdp_late_responses"
                            )

                    continue

                method = message.get("method")

                if method and self.event_handler:
                    try:
                        self.event_handler(
                            method,
                            message.get("params", {})
                        )
                    except Exception as e:
                        print(
                            "NOVA event error:",
                            repr(e)
                        )

        except Exception as e:
            if self.running:
                print(
                    "NOVA CDP reader stopped:",
                    repr(e)
                )

        finally:
            self.running = False

            with self.pending_lock:
                for waiter in self.pending.values():
                    try:
                        waiter.put({
                            "error": {
                                "message": "CDP disconnected"
                            }
                        })
                    except Exception:
                        pass

    def command(self, method, params=None, timeout=10):
        if not self.running:
            raise RuntimeError(
                "Chromium tab is no longer available."
            )

        with self.send_lock:
            self.counter += 1
            msg_id = self.counter

            waiter = queue.Queue(maxsize=1)

            with self.pending_lock:
                self.pending[msg_id] = waiter

            payload = {
                "id": msg_id,
                "method": method,
            }

            if params is not None:
                payload["params"] = params

            try:
                self.ws.send(
                    json.dumps(payload)
                )
            except Exception:
                with self.pending_lock:
                    self.pending.pop(
                        msg_id,
                        None
                    )
                raise

        try:
            response = waiter.get(
                timeout=timeout
            )
        except queue.Empty:
            raise RuntimeError(
                f"CDP timeout: {method}"
            )
        finally:
            with self.pending_lock:
                self.pending.pop(
                    msg_id,
                    None
                )

        if "error" in response:
            raise RuntimeError(
                response["error"].get(
                    "message",
                    str(response["error"])
                )
            )

        return response.get(
            "result",
            {}
        )

    def close(self):
        self.running = False

        try:
            self.ws.close()
        except Exception:
            pass


def optimized_cdp_command(
    cdp,
    method,
    params=None,
    timeout=10,
):
    started = monotonic_ms()
    command_name = safe_text(
        method,
        "unknown",
        256,
    )

    if timeout == 10:
        timeout = CONFIG.command_timeout

    try:
        result = cdp._nova_original_command(
            method,
            params,
            timeout,
        )
        METRICS.observe_command(
            monotonic_ms() - started
        )
        return result
    except Exception as error:
        METRICS.error(error)
        METRICS.count(
            "cdp_command_errors"
        )
        LOGGER.debug(
            "CDP command %s failed: %s",
            command_name,
            exception_text(error),
        )
        raise


def install_cdp_runtime_hooks():
    if getattr(
        CDP,
        "_nova_hooks_installed",
        False,
    ):
        return

    CDP._nova_original_command = (
        CDP.command
    )
    CDP.command = optimized_cdp_command
    CDP._nova_hooks_installed = True


install_cdp_runtime_hooks()


# ============================================================
# URL NORMALIZATION
# ============================================================

def normalize_url(value):
    value = (value or "").strip()

    if not value:
        return "about:blank"

    lower = value.lower()

    if lower.startswith(
        ("http://", "https://", "about:", "data:")
    ):
        return value

    if (
        " " not in value
        and "." in value
        and not value.startswith(".")
    ):
        return "https://" + value

    return (
        "https://www.google.com/search?q="
        + urllib.parse.quote(value)
    )


# ============================================================
# BROWSER SESSION
# ============================================================

class BrowserSession:
    def __init__(self, session_id):
        self.id = session_id
        self.created_at = time.monotonic()
        self.activity = SessionActivity()
        self.activity.touch()
        self.state_cache = TTLCache(
            ttl=CONFIG.state_cache_seconds,
            maximum=4,
        )
        self.state_lock = threading.RLock()
        self.command_metrics = MetricCounter()
        self.frame_metrics = MetricCounter()
        self.last_command = ""
        self.last_command_at = 0.0
        self.last_navigation_at = 0.0
        self.last_resize = None
        self.last_close_at = 0.0

        self.width = WIDTH
        self.height = HEIGHT

        self.requested_url = "about:blank"
        self.actual_url = "about:blank"
        self.last_real_url = ""
        self.title = ""

        self.target = create_target()
        self.target_id = self.target["id"]

        self.ws_url = self.target[
            "webSocketDebuggerUrl"
        ]

        self.cdp = CDP(
            self.ws_url,
            self.handle_event
        )

        self.stream_clients = set()
        self.stream_lock = threading.RLock()

        self.latest_frame = None
        self.latest_frame_id = 0

        self.frame_condition = threading.Condition()

        self.last_frame_time = 0
        self.frame_interval = 1 / MAX_FPS

        self.running = True

        self._configure()

    # --------------------------------------------------------

    def _configure(self):
        self.cdp.command("Page.enable")
        self.cdp.command("Runtime.enable")
        self.cdp.command("Network.enable")
        self.cdp.command("DOM.enable")

        try:
            self.cdp.command(
                "Security.enable"
            )
        except Exception:
            pass

        self.cdp.command(
            "Emulation.setDeviceMetricsOverride",
            {
                "width": self.width,
                "height": self.height,
                "deviceScaleFactor": DEVICE_SCALE_FACTOR,
                "mobile": True,
            }
        )

        self.cdp.command(
            "Emulation.setTouchEmulationEnabled",
            {
                "enabled": True,
                "maxTouchPoints": 5
            }
        )

        try:
            self.cdp.command(
                "Page.bringToFront"
            )
        except Exception:
            pass

        self.start_screencast()

    # --------------------------------------------------------

    def start_screencast(self):
        try:
            self.cdp.command(
                "Page.stopScreencast"
            )
        except Exception:
            pass

        self.cdp.command(
            "Page.startScreencast",
            {
                "format": "jpeg",
                "quality": JPEG_QUALITY,
                "maxWidth": self.width,
                "maxHeight": self.height,
                "everyNthFrame": 1,
            }
        )

    # --------------------------------------------------------

    def handle_event(self, method, params):
        if method == "Page.screencastFrame":
            self._handle_frame(params)
            return

        if method == "Page.frameNavigated":
            frame = params.get(
                "frame",
                {}
            )

            if not frame.get("parentId"):
                url = frame.get(
                    "url",
                    ""
                )

                if url:
                    self.actual_url = url

                    if url != "about:blank":
                        self.last_real_url = url

            return

        if method == "Runtime.exceptionThrown":
            details = params.get(
                "exceptionDetails",
                {}
            )

            text = details.get(
                "text",
                "JavaScript exception"
            )

            print(
                "NOVA JS:",
                text
            )

            return

        if method == "Inspector.targetCrashed":
            print(
                "NOVA: Chromium target crashed"
            )
            self.running = False

            with self.frame_condition:
                self.frame_condition.notify_all()

            return

        if method == "Network.loadingFailed":
            error = params.get(
                "errorText"
            )

            canceled = params.get(
                "canceled",
                False
            )

            if error and not canceled:
                print(
                    "NOVA NETWORK:",
                    error
                )

    # --------------------------------------------------------

    def _handle_frame(self, params):
        session_id = params.get(
            "sessionId"
        )

        data = params.get(
            "data"
        )

        # ACK immediately.
        #
        # Chromium will throttle/stop the screencast if
        # screencastFrameAck isn't returned.
        if session_id is not None:
            ACK_EXECUTOR.submit(
                self._ack_frame,
                session_id,
            )

        if not data:
            return

        now = time.monotonic()

        if (
            now - self.last_frame_time
            < self.frame_interval
        ):
            return

        self.last_frame_time = now
        self.activity.frame()
        self.frame_metrics.add(
            "accepted"
        )
        METRICS.observe_frame(
            (now - self.created_at) * 1000.0
        )

        with self.frame_condition:
            self.latest_frame = data
            self.latest_frame_id += 1
            self.frame_condition.notify_all()

    def _ack_frame(self, session_id):
        try:
            self.cdp.command(
                "Page.screencastFrameAck",
                {
                    "sessionId": session_id
                },
                timeout=2
            )
        except Exception:
            pass

    # --------------------------------------------------------

    def navigate(self, value):
        url = normalize_url(value)
        self.activity.touch()
        self.last_navigation_at = time.monotonic()
        self.last_command = "navigate"
        self.last_command_at = time.monotonic()

        self.requested_url = url

        try:
            self.cdp.command(
                "Page.bringToFront"
            )
        except Exception:
            pass

        try:
            result = self.cdp.command(
                "Page.navigate",
                {
                    "url": url
                }
            )

            error = result.get(
                "errorText"
            )

            if error and error != "net::ERR_ABORTED":
                raise RuntimeError(error)

        except RuntimeError as e:
            if "ERR_ABORTED" not in str(e):
                raise

        return url

    # --------------------------------------------------------

    def update_state(self):
        self.activity.touch()
        try:
            result = self.cdp.command(
                "Runtime.evaluate",
                {
                    "expression": """
                    (() => ({
                        url: location.href,
                        title: document.title,
                        ready: document.readyState
                    }))()
                    """,
                    "returnByValue": True,
                },
                timeout=3
            )

            value = (
                result
                .get("result", {})
                .get("value", {})
            )

            url = value.get(
                "url"
            )

            if url:
                self.actual_url = url

                if url != "about:blank":
                    self.last_real_url = url

            self.title = value.get(
                "title",
                self.title
            )

        except Exception:
            pass

        visible_url = self.actual_url

        if visible_url == "about:blank":
            visible_url = (
                self.last_real_url
                or self.requested_url
                or "about:blank"
            )

        return {
            "session": self.id,
            "url": visible_url,
            "actualUrl": self.actual_url,
            "requestedUrl": self.requested_url,
            "title": self.title,
            "width": self.width,
            "height": self.height,
            "connected": self.cdp.running,
            "stream": "cdp-screencast-websocket",
            "fps": MAX_FPS,
        }

    # --------------------------------------------------------

    def resize(self, width, height):
        self.activity.touch()
        dimensions = validate_dimensions(
            width,
            height,
        )
        width = dimensions["width"]
        height = dimensions["height"]

        if self.last_resize == (
            width,
            height,
        ):
            return

        self.width = width
        self.height = height
        self.last_resize = (
            width,
            height,
        )

        self.cdp.command(
            "Emulation.setDeviceMetricsOverride",
            {
                "width": width,
                "height": height,
                "deviceScaleFactor": DEVICE_SCALE_FACTOR,
                "mobile": True,
            }
        )

        self.start_screencast()

    # --------------------------------------------------------

    def click(self, x, y):
        self.activity.touch()
        x = valid_coordinate(
            x,
            self.width,
        )
        y = valid_coordinate(
            y,
            self.height,
        )

        self.cdp.command(
            "Input.dispatchTouchEvent",
            {
                "type": "touchStart",
                "touchPoints": [
                    {
                        "x": x,
                        "y": y
                    }
                ]
            }
        )

        self.cdp.command(
            "Input.dispatchTouchEvent",
            {
                "type": "touchEnd",
                "touchPoints": []
            }
        )

    # --------------------------------------------------------

    def mouse(self, event_type, x, y, button="none"):
        self.activity.touch()
        params = {
            "type": event_type,
            "x": valid_coordinate(
                x,
                self.width,
            ),
            "y": valid_coordinate(
                y,
                self.height,
            ),
            "button": button,
        }

        if event_type == "mousePressed":
            params["clickCount"] = 1

        if event_type == "mouseReleased":
            params["clickCount"] = 1

        self.cdp.command(
            "Input.dispatchMouseEvent",
            params
        )

    # --------------------------------------------------------

    def scroll(self, x, y, dx, dy):
        self.activity.touch()
        self.cdp.command(
            "Input.dispatchMouseEvent",
            {
                "type": "mouseWheel",
                "x": valid_coordinate(
                    x,
                    self.width,
                ),
                "y": valid_coordinate(
                    y,
                    self.height,
                ),
                "deltaX": safe_float(
                    dx,
                    0.0,
                    -10000,
                    10000,
                ),
                "deltaY": safe_float(
                    dy,
                    0.0,
                    -10000,
                    10000,
                ),
            }
        )

    # --------------------------------------------------------

    def type_text(self, text):
        self.activity.touch()
        text = validate_text_input(text)

        if not text:
            return

        self.cdp.command(
            "Input.insertText",
            {
                "text": str(text)
            }
        )

    # --------------------------------------------------------

    def key(self, key, code=None):
        self.activity.touch()
        key = safe_text(
            key,
            "",
            128,
        )
        code = safe_text(
            code or key,
            key,
            128,
        )

        if not key:
            return

        modifiers = 0

        self.cdp.command(
            "Input.dispatchKeyEvent",
            {
                "type": "keyDown",
                "key": key,
                "code": code,
                "modifiers": modifiers,
            }
        )

        self.cdp.command(
            "Input.dispatchKeyEvent",
            {
                "type": "keyUp",
                "key": key,
                "code": code,
                "modifiers": modifiers,
            }
        )

    # --------------------------------------------------------

    def history(self, direction):
        self.activity.touch()
        direction = -1 if int(
            direction
        ) < 0 else 1
        history = self.cdp.command(
            "Page.getNavigationHistory"
        )

        entries = history.get(
            "entries",
            []
        )

        current = history.get(
            "currentIndex",
            0
        )

        target_index = current + direction

        if target_index < 0:
            return

        if target_index >= len(entries):
            return

        entry = entries[target_index]

        self.cdp.command(
            "Page.navigateToHistoryEntry",
            {
                "entryId": entry["id"]
            }
        )

    # --------------------------------------------------------

    def reload(self):
        self.activity.touch()
        self.cdp.command(
            "Page.reload",
            {
                "ignoreCache": False
            }
        )

    # --------------------------------------------------------

    def stop(self):
        self.activity.touch()
        try:
            self.cdp.command(
                "Page.stopLoading"
            )
        except Exception:
            pass

    # --------------------------------------------------------

    def close(self):
        if not self.running:
            return False

        self.running = False
        self.last_close_at = time.monotonic()

        try:
            self.cdp.command(
                "Page.stopScreencast",
                timeout=2
            )
        except Exception:
            pass

        try:
            self.cdp.command(
                "Target.closeTarget",
                {
                    "targetId": self.target_id
                },
                timeout=2
            )
        except Exception:
            pass

        self.cdp.close()

        with self.frame_condition:
            self.frame_condition.notify_all()

        return True


# ============================================================
# PERFORMANCE AND RESILIENCE COMPONENTS
# ============================================================


class FrameBuffer:
    def __init__(self, maximum=2):
        self.maximum = max(1, int(maximum))
        self.frames = deque(maxlen=self.maximum)
        self.condition = threading.Condition()
        self.latest_id = 0
        self.total_received = AtomicInteger()
        self.total_dropped = AtomicInteger()

    def push(self, frame):
        if not frame:
            return 0

        with self.condition:
            if len(self.frames) >= self.maximum:
                self.total_dropped.increment()

            self.latest_id += 1
            item = {
                "id": self.latest_id,
                "data": frame,
                "time": time.monotonic(),
            }
            self.frames.append(item)
            self.total_received.increment()
            self.condition.notify_all()
            return self.latest_id

    def latest(self):
        with self.condition:
            if not self.frames:
                return None
            return self.frames[-1]

    def wait_for_new(self, previous_id, timeout=1.0):
        with self.condition:
            self.condition.wait_for(
                lambda: (
                    self.latest_id != previous_id
                    or not self.frames
                ),
                timeout=max(0.01, timeout),
            )

            item = self.latest()
            return item

    def discard_before(self, frame_id):
        with self.condition:
            while self.frames and (
                self.frames[0]["id"] < frame_id
            ):
                self.frames.popleft()

    def clear(self):
        with self.condition:
            self.frames.clear()
            self.condition.notify_all()

    def stats(self):
        with self.condition:
            return {
                "capacity": self.maximum,
                "queued": len(self.frames),
                "latestId": self.latest_id,
                "received": int(
                    self.total_received
                ),
                "dropped": int(
                    self.total_dropped
                ),
            }


class CommandJournal:
    def __init__(self, maximum=256):
        self.events = JsonRing(maximum)
        self.counts = MetricCounter()
        self.latencies = LatencyMetric(maximum)

    def begin(self, method):
        return {
            "method": safe_text(
                method,
                "unknown",
                256,
            ),
            "started": monotonic_ms(),
        }

    def finish(self, token, success=True, error=""):
        elapsed = (
            monotonic_ms()
            - safe_float(
                token.get("started", monotonic_ms())
            )
        )
        method = token.get(
            "method",
            "unknown",
        )
        self.latencies.observe(elapsed)
        self.counts.add(
            "success"
            if success
            else "errors"
        )
        self.events.append({
            "time": utc_now_iso(),
            "method": method,
            "elapsedMs": elapsed,
            "success": bool(success),
            "error": safe_text(error),
        })

    def snapshot(self):
        return {
            "counts": self.counts.snapshot(),
            "latency": self.latencies.summary(),
            "recent": self.events.snapshot(),
        }


class BrowserHealth:
    def __init__(self):
        self.checks = MetricCounter()
        self.failures = MetricCounter()
        self.last_check = 0.0
        self.last_success = 0.0
        self.last_error = ""
        self.lock = threading.RLock()

    def check(self, callback):
        started = monotonic_ms()

        with self.lock:
            self.last_check = time.time()

        try:
            result = callback()
        except Exception as error:
            with self.lock:
                self.last_error = exception_text(error)
            self.failures.add("total")
            METRICS.error(error)
            return {
                "ok": False,
                "error": exception_text(error),
                "elapsedMs": monotonic_ms() - started,
            }

        with self.lock:
            self.last_success = time.time()
            self.last_error = ""

        self.checks.add("success")
        return {
            "ok": True,
            "result": result,
            "elapsedMs": monotonic_ms() - started,
        }

    def snapshot(self):
        with self.lock:
            return {
                "checks": self.checks.snapshot(),
                "failures": self.failures.snapshot(),
                "lastCheck": self.last_check,
                "lastSuccess": self.last_success,
                "lastError": self.last_error,
            }


class InputNormalizer:
    KEY_ALIASES = {
        "return": "ENTER",
        "enter": "ENTER",
        "esc": "ESCAPE",
        "escape": "ESCAPE",
        "backspace": "BACKSPACE",
        "delete": "DELETE",
        "tab": "TAB",
        "space": " ",
        "arrowup": "ARROWUP",
        "arrowdown": "ARROWDOWN",
        "arrowleft": "ARROWLEFT",
        "arrowright": "ARROWRIGHT",
    }

    BUTTONS = {
        "none",
        "left",
        "middle",
        "right",
    }

    EVENTS = {
        "mousePressed",
        "mouseReleased",
        "mouseMoved",
        "mouseWheel",
    }

    def key(self, value):
        raw = safe_text(
            value,
            "",
            128,
        )
        normalized = raw.strip().lower()
        return self.KEY_ALIASES.get(
            normalized,
            raw[:64],
        )

    def button(self, value):
        normalized = safe_text(
            value,
            "left",
            16,
        ).lower()
        return (
            normalized
            if normalized in self.BUTTONS
            else "left"
        )

    def event(self, value):
        normalized = safe_text(
            value,
            "mouseMoved",
            32,
        )
        return (
            normalized
            if normalized in self.EVENTS
            else "mouseMoved"
        )

    def coordinates(self, data, width, height):
        payload = dict(data or {})
        return {
            "x": valid_coordinate(
                payload.get("x", 0),
                width,
            ),
            "y": valid_coordinate(
                payload.get("y", 0),
                height,
            ),
        }

    def scroll(self, data, width, height):
        point = self.coordinates(
            data,
            width,
            height,
        )
        payload = dict(data or {})
        point["dx"] = safe_float(
            payload.get("dx", 0),
            0,
            -10000,
            10000,
        )
        point["dy"] = safe_float(
            payload.get("dy", 0),
            0,
            -10000,
            10000,
        )
        return point

    def resize(self, data):
        payload = dict(data or {})
        return validate_dimensions(
            payload.get("width", WIDTH),
            payload.get("height", HEIGHT),
        )

    def text(self, value):
        return validate_text_input(value)


INPUTS = InputNormalizer()


class NavigationPolicy:
    ALLOWED_SCHEMES = {
        "http",
        "https",
        "about",
        "data",
        "file",
    }

    def __init__(self):
        self.blocked_hosts = set(
            filter(
                None,
                safe_text(
                    env_value(
                        "NOVA_BLOCKED_HOSTS",
                        "",
                    )
                ).split(","),
            )
        )

    def parse(self, value):
        normalized = normalize_url(value)
        parsed = urllib.parse.urlparse(
            normalized
        )
        return normalized, parsed

    def allowed(self, value):
        normalized, parsed = self.parse(value)

        if parsed.scheme.lower() not in (
            self.ALLOWED_SCHEMES
        ):
            return False

        hostname = safe_text(
            parsed.hostname,
            "",
        ).lower()

        if hostname in self.blocked_hosts:
            return False

        return bool(
            parsed.scheme == "about"
            or parsed.scheme == "data"
            or hostname
        )

    def normalize(self, value):
        normalized, _ = self.parse(value)

        if not self.allowed(normalized):
            raise ValueError(
                "Navigation URL blocked by policy."
            )

        return normalized

    def describe(self):
        return {
            "schemes": sorted(
                self.ALLOWED_SCHEMES
            ),
            "blockedHosts": sorted(
                self.blocked_hosts
            ),
        }


NAVIGATION_POLICY = NavigationPolicy()


class JsonCodec:
    def __init__(self):
        self.dumps_count = AtomicInteger()
        self.loads_count = AtomicInteger()
        self.errors = AtomicInteger()

    def dumps(self, value):
        self.dumps_count.increment()
        return compact_json(value)

    def loads(self, value):
        self.loads_count.increment()

        try:
            if isinstance(value, bytes):
                value = value.decode(
                    "utf-8",
                    "replace",
                )
            return json.loads(value)
        except Exception:
            self.errors.increment()
            raise

    def snapshot(self):
        return {
            "dumps": int(self.dumps_count),
            "loads": int(self.loads_count),
            "errors": int(self.errors),
        }


CODEC = JsonCodec()


class PayloadCompressor:
    def __init__(self, level=1):
        self.level = clamp(
            int(level),
            0,
            9,
        )
        self.compressed = AtomicInteger()
        self.bytes_in = AtomicInteger()
        self.bytes_out = AtomicInteger()

    def compress(self, payload):
        raw = (
            payload
            if isinstance(payload, bytes)
            else safe_text(payload).encode(
                "utf-8"
            )
        )
        encoded = zlib.compress(
            raw,
            self.level,
        )
        self.compressed.increment()
        self.bytes_in.increment(len(raw))
        self.bytes_out.increment(len(encoded))
        return encoded

    def ratio(self):
        source = int(self.bytes_in)
        target = int(self.bytes_out)

        if source <= 0:
            return 1.0

        return target / source

    def snapshot(self):
        return {
            "operations": int(self.compressed),
            "bytesIn": int(self.bytes_in),
            "bytesOut": int(self.bytes_out),
            "ratio": self.ratio(),
        }


COMPRESSOR = PayloadCompressor(
    level=1
)


class WebSocketState:
    def __init__(self, ws_id):
        self.id = ws_id
        self.connected_at = time.monotonic()
        self.last_send_at = 0.0
        self.last_receive_at = 0.0
        self.sent = AtomicInteger()
        self.received = AtomicInteger()
        self.errors = AtomicInteger()
        self.closed = False
        self.lock = threading.RLock()

    def sent_message(self):
        with self.lock:
            self.last_send_at = time.monotonic()
            self.sent.increment()

    def received_message(self):
        with self.lock:
            self.last_receive_at = time.monotonic()
            self.received.increment()

    def failed(self):
        with self.lock:
            self.errors.increment()

    def close(self):
        with self.lock:
            self.closed = True

    def snapshot(self):
        with self.lock:
            return {
                "id": self.id,
                "connectedSeconds": max(
                    0.0,
                    time.monotonic()
                    - self.connected_at,
                ),
                "lastSend": self.last_send_at,
                "lastReceive": self.last_receive_at,
                "sent": int(self.sent),
                "received": int(self.received),
                "errors": int(self.errors),
                "closed": self.closed,
            }


def websocket_send(ws, payload, state=None):
    try:
        text = (
            payload
            if isinstance(payload, str)
            else CODEC.dumps(payload)
        )
        ws.send(text)

        if state is not None:
            state.sent_message()

        METRICS.count(
            "websocket_messages_sent"
        )
        return True
    except Exception as error:
        if state is not None:
            state.failed()
        METRICS.error(error)
        return False


def websocket_receive(ws, state=None):
    try:
        raw = ws.receive()

        if state is not None:
            state.received_message()

        if raw is None:
            return None

        return CODEC.loads(raw)
    except Exception as error:
        if state is not None:
            state.failed()
        METRICS.error(error)
        return None


class Heartbeat:
    def __init__(self, interval=15.0):
        self.interval = max(
            1.0,
            float(interval),
        )
        self.last = time.monotonic()
        self.count = AtomicInteger()
        self.lock = threading.RLock()

    def tick(self):
        with self.lock:
            self.last = time.monotonic()
            self.count.increment()

    def due(self):
        with self.lock:
            return (
                time.monotonic()
                - self.last
                >= self.interval
            )

    def snapshot(self):
        with self.lock:
            return {
                "interval": self.interval,
                "last": self.last,
                "count": int(self.count),
                "due": self.due(),
            }


class SafeCall:
    def __init__(self, name, timeout=None):
        self.name = safe_text(
            name,
            "operation",
        )
        self.timeout = timeout
        self.breaker = CircuitBreaker(
            failures=4,
            recovery_seconds=3,
        )
        self.policy = RetryPolicy(
            attempts=3,
            delay=0.03,
            maximum_delay=0.4,
        )

    def __call__(self, callback, *args, **kwargs):
        if self.breaker.is_open():
            raise RuntimeError(
                self.name
                + " circuit is open."
            )

        def invoke():
            started = monotonic_ms()

            try:
                result = callback(
                    *args,
                    **kwargs,
                )
                self.breaker.success()
                METRICS.observe_command(
                    monotonic_ms() - started
                )
                return result
            except Exception as error:
                self.breaker.failure()
                METRICS.error(error)
                raise

        return self.policy.run(
            invoke,
            retryable_network_error,
        )

    def state(self):
        return {
            "name": self.name,
            "timeout": self.timeout,
            "breaker": self.breaker.state(),
        }


class SessionCommandRouter:
    def __init__(self, browser):
        self.browser = browser
        self.calls = CommandJournal()
        self.heartbeat = Heartbeat()
        self.lock = threading.RLock()

    def call(self, method, callback):
        token = self.calls.begin(method)

        with self.lock:
            try:
                result = callback()
                self.calls.finish(token, True)
                self.heartbeat.tick()
                return result
            except Exception as error:
                self.calls.finish(
                    token,
                    False,
                    exception_text(error),
                )
                self.browser.activity.error()
                raise

    def navigate(self, value):
        return self.call(
            "navigate",
            lambda: self.browser.navigate(
                NAVIGATION_POLICY.normalize(
                    value
                )
            ),
        )

    def state(self):
        return self.call(
            "state",
            self.browser.update_state,
        )

    def resize(self, width, height):
        dimensions = validate_dimensions(
            width,
            height,
        )
        return self.call(
            "resize",
            lambda: self.browser.resize(
                dimensions["width"],
                dimensions["height"],
            ),
        )

    def click(self, x, y):
        point = INPUTS.coordinates(
            {
                "x": x,
                "y": y,
            },
            self.browser.width,
            self.browser.height,
        )
        return self.call(
            "click",
            lambda: self.browser.click(
                point["x"],
                point["y"],
            ),
        )

    def scroll(self, data):
        point = INPUTS.scroll(
            data,
            self.browser.width,
            self.browser.height,
        )
        return self.call(
            "scroll",
            lambda: self.browser.scroll(
                point["x"],
                point["y"],
                point["dx"],
                point["dy"],
            ),
        )

    def type_text(self, text):
        return self.call(
            "type",
            lambda: self.browser.type_text(
                INPUTS.text(text)
            ),
        )

    def key(self, key, code=None):
        return self.call(
            "key",
            lambda: self.browser.key(
                INPUTS.key(key),
                code,
            ),
        )

    def mouse(self, event_type, x, y, button):
        point = INPUTS.coordinates(
            {
                "x": x,
                "y": y,
            },
            self.browser.width,
            self.browser.height,
        )
        return self.call(
            "mouse",
            lambda: self.browser.mouse(
                INPUTS.event(event_type),
                point["x"],
                point["y"],
                INPUTS.button(button),
            ),
        )

    def history(self, direction):
        return self.call(
            "history",
            lambda: self.browser.history(
                direction
            ),
        )

    def reload(self):
        return self.call(
            "reload",
            self.browser.reload,
        )

    def stop(self):
        return self.call(
            "stop",
            self.browser.stop,
        )

    def diagnostics(self):
        return {
            "router": self.calls.snapshot(),
            "heartbeat": self.heartbeat.snapshot(),
        }


def attach_browser_runtime(browser):
    browser.router = SessionCommandRouter(
        browser
    )
    browser.health = BrowserHealth()
    browser.frame_buffer = FrameBuffer(2)
    browser.created_iso = utc_now_iso()
    return browser


def browser_diagnostics(browser):
    activity = getattr(
        browser,
        "activity",
        None,
    )
    router = getattr(
        browser,
        "router",
        None,
    )

    return {
        "session": redact_text(
            browser.id
        ),
        "targetId": browser.target_id,
        "createdAt": getattr(
            browser,
            "created_iso",
            "",
        ),
        "running": bool(
            browser.running
        ),
        "cdpConnected": bool(
            browser.cdp.running
        ),
        "width": browser.width,
        "height": browser.height,
        "requestedUrl": browser.requested_url,
        "actualUrl": browser.actual_url,
        "lastRealUrl": browser.last_real_url,
        "title": browser.title,
        "latestFrameId": browser.latest_frame_id,
        "latestFrameBytes": len(
            browser.latest_frame
            or ""
        ),
        "streamClients": len(
            browser.stream_clients
        ),
        "activity": (
            activity.snapshot()
            if activity
            else {}
        ),
        "router": (
            router.diagnostics()
            if router
            else {}
        ),
        "frameBuffer": (
            browser.frame_buffer.stats()
            if hasattr(
                browser,
                "frame_buffer",
            )
            else {}
        ),
        "command": {
            "last": browser.last_command,
            "lastAt": browser.last_command_at,
        },
    }


def optimized_update_state(browser):
    cached = browser.state_cache.get(
        "state"
    )

    if cached is not None:
        return dict(cached)

    original = getattr(
        BrowserSession,
        "_nova_original_update_state",
        None,
    )

    if original is None:
        raise RuntimeError(
            "Browser state hook is not installed."
        )

    state = original(browser)
    browser.state_cache.set(
        "state",
        dict(state),
    )
    return state


def optimized_navigate(browser, value):
    normalized = NAVIGATION_POLICY.normalize(
        value
    )
    browser.state_cache.clear()
    original = getattr(
        BrowserSession,
        "_nova_original_navigate",
        None,
    )

    if original is None:
        raise RuntimeError(
            "Browser navigation hook is not installed."
        )

    return original(
        browser,
        normalized,
    )


def optimized_resize(browser, width, height):
    dimensions = validate_dimensions(
        width,
        height,
    )
    original = getattr(
        BrowserSession,
        "_nova_original_resize",
        None,
    )

    if original is None:
        raise RuntimeError(
            "Browser resize hook is not installed."
        )

    result = original(
        browser,
        dimensions["width"],
        dimensions["height"],
    )
    browser.state_cache.clear()
    return result


def install_browser_runtime_hooks():
    if getattr(
        BrowserSession,
        "_nova_hooks_installed",
        False,
    ):
        return

    BrowserSession._nova_original_update_state = (
        BrowserSession.update_state
    )
    BrowserSession.update_state = (
        optimized_update_state
    )
    BrowserSession._nova_original_navigate = (
        BrowserSession.navigate
    )
    BrowserSession.navigate = (
        optimized_navigate
    )
    BrowserSession._nova_original_resize = (
        BrowserSession.resize
    )
    BrowserSession.resize = (
        optimized_resize
    )
    BrowserSession.diagnostics = (
        browser_diagnostics
    )
    BrowserSession._nova_hooks_installed = True


install_browser_runtime_hooks()


def browser_frame_response(browser):
    frame = browser.latest_frame

    if not frame:
        return None

    try:
        return base64.b64decode(
            frame,
            validate=True,
        )
    except Exception as error:
        METRICS.error(error)
        return None


def browser_status(browser):
    return {
        "running": bool(
            browser.running
        ),
        "cdp": bool(
            browser.cdp.running
        ),
        "frames": browser.latest_frame_id,
        "clients": len(
            browser.stream_clients
        ),
        "idleSeconds": browser.activity.idle_seconds(),
    }


def touch_browser(browser):
    if browser is None:
        return False

    browser.activity.touch()
    return True


def browser_is_ready(browser):
    return bool(
        browser
        and browser.running
        and browser.cdp.running
    )


def require_ready_browser(browser):
    if not browser:
        raise RuntimeError(
            "Invalid NOVA session"
        )

    if not browser_is_ready(browser):
        raise RuntimeError(
            "NOVA browser session is not ready"
        )

    touch_browser(browser)
    return browser


def browser_json_state(browser):
    touch_browser(
        browser
    )
    state = browser.update_state()
    state["serverVersion"] = SERVER_VERSION
    state["serverTime"] = utc_now_iso()
    state["status"] = browser_status(
        browser
    )
    return state


def browser_session_header(response, browser):
    response.headers[
        "X-Nova-Session"
    ] = browser.id
    response.headers[
        "X-Nova-Server"
    ] = SERVER_VERSION
    return response


# ============================================================
# SESSION HELPERS
# ============================================================

def session_from_request():
    return (
        request.headers.get(
            "X-Nova-Session"
        )
        or request.args.get(
            "session"
        )
    )


def require_browser():
    session_id = session_from_request()

    if not session_id:
        return None

    with sessions_lock:
        return sessions.get(
            session_id
        )


def json_error(message, status=400):
    return jsonify({
        "ok": False,
        "error": str(message)
    }), status


def request_json():
    return request.get_json(
        silent=True
    ) or {}


def request_has_valid_session():
    return bool(
        session_from_request()
    )


def request_can_use_route():
    if request.method == "OPTIONS":
        return True

    if not request_is_allowed():
        return False

    if not validate_json_size():
        return False

    return True


def route_error_payload(error, status=500):
    METRICS.error(error)
    return json_error(
        exception_text(error),
        status,
    )


def route_browser_or_error():
    browser = require_browser()

    if not browser:
        return None, json_error(
            "Invalid NOVA session",
            401,
        )

    if not browser_is_ready(browser):
        return None, json_error(
            "NOVA browser session is not ready",
            503,
        )

    touch_browser(browser)
    return browser, None


def route_success(**values):
    return jsonify(
        make_ok_payload(
            **values
        )
    )


def route_not_ready(message):
    return jsonify(
        make_error_payload(
            message,
            "not_ready",
        )
    ), 503


def response_bytes(
    payload,
    content_type="application/octet-stream",
    status=200,
):
    if payload is None:
        return Response(
            status=404
        )

    response = Response(
        payload,
        status=status,
        mimetype=content_type.split(
            ";",
            1,
        )[0],
    )
    response.headers[
        "Cache-Control"
    ] = "no-store, no-cache"
    return response


def response_json(payload, status=200):
    response = jsonify(payload)
    response.status_code = status
    return response


def api_runtime_snapshot():
    return {
        "version": SERVER_VERSION,
        "name": SERVER_NAME,
        "startedAt": utc_now_iso(),
        "uptimeSeconds": (
            time.monotonic()
            - SERVER_STARTED_AT
        ),
        "config": {
            "host": CONFIG.host,
            "port": CONFIG.port,
            "cdpHost": CONFIG.cdp_host,
            "cdpPort": CONFIG.cdp_port,
            "width": CONFIG.width,
            "height": CONFIG.height,
            "scale": CONFIG.device_scale_factor,
            "jpegQuality": CONFIG.jpeg_quality,
            "maxFps": CONFIG.max_fps,
            "maxSessions": CONFIG.max_sessions,
        },
        "sessions": session_count(),
        "metrics": METRICS.snapshot(),
        "platform": platform_snapshot(),
    }


def api_capabilities():
    return {
        "http": [
            "health",
            "session",
            "state",
            "screenshot",
            "navigate",
            "back",
            "forward",
            "reload",
            "stop",
            "resize",
            "click",
            "scroll",
            "type",
            "key",
            "cookies",
            "debug",
            "metrics",
            "runtime",
            "evaluate",
            "close",
        ],
        "websocket": [
            "frame",
            "ping",
            "click",
            "mouseDown",
            "mouseUp",
            "mouseMove",
            "scroll",
            "type",
            "key",
            "resize",
            "navigate",
            "back",
            "forward",
            "reload",
            "stop",
            "state",
        ],
        "optimizations": [
            "latest-frame-only",
            "bounded-ack-executor",
            "state-cache",
            "session-sweeper",
            "request-rate-limit",
            "latency-metrics",
            "retry-policy",
            "circuit-breaker",
        ],
    }


def api_config_public():
    return {
        "width": WIDTH,
        "height": HEIGHT,
        "deviceScaleFactor": DEVICE_SCALE_FACTOR,
        "jpegQuality": JPEG_QUALITY,
        "maxFps": MAX_FPS,
        "stateCacheSeconds": CONFIG.state_cache_seconds,
        "sessionIdleSeconds": CONFIG.session_idle_seconds,
        "serverVersion": SERVER_VERSION,
    }


def parse_expression(data):
    expression = safe_text(
        dict(data or {}).get(
            "expression",
            "",
        ),
        "",
        65536,
    ).strip()

    if not expression:
        raise ValueError(
            "An expression is required."
        )

    return expression


def evaluate_browser(browser, expression):
    return browser.cdp.command(
        "Runtime.evaluate",
        {
            "expression": expression,
            "returnByValue": True,
            "awaitPromise": True,
            "userGesture": True,
        },
        timeout=CONFIG.command_timeout,
    )


def extract_evaluation_value(result):
    result = dict(result or {})
    exception_details = result.get(
        "exceptionDetails"
    )

    if exception_details:
        raise RuntimeError(
            safe_text(
                exception_details.get(
                    "text",
                    "Runtime evaluation failed.",
                )
            )
        )

    value = result.get(
        "result",
        {},
    )
    return {
        "type": value.get("type"),
        "subtype": value.get("subtype"),
        "value": value.get("value"),
        "description": value.get(
            "description"
        ),
    }


def screenshot_payload(browser):
    payload = browser_frame_response(
        browser
    )

    if payload is None:
        return None

    METRICS.count(
        "screenshots_served"
    )
    return payload


def mark_session_activity(browser, action):
    if browser is None:
        return

    touch_browser(browser)
    ACCESS_LOG.record(
        browser.id,
        action,
    )
    METRICS.count(
        "session_actions"
    )


def session_summary(browser):
    return {
        "session": browser.id,
        "status": browser_status(
            browser
        ),
        "diagnostics": browser.diagnostics(),
    }


def close_all_sessions():
    with sessions_lock:
        current = list(
            sessions.items()
        )
        sessions.clear()

    closed = 0

    for session_id, browser in current:
        if close_session_object(
            session_id,
            browser,
        ):
            closed += 1

    return closed


def should_reject_new_session():
    return session_count() >= CONFIG.max_sessions


def make_session_id():
    return uuid.uuid4().hex


def create_browser_session():
    session_id = make_session_id()
    browser = BrowserSession(
        session_id
    )
    attach_browser_runtime(
        browser
    )
    return session_id, browser


def register_session(session_id, browser):
    with sessions_lock:
        if len(sessions) >= CONFIG.max_sessions:
            raise RuntimeError(
                "Maximum NOVA sessions reached."
            )
        sessions[session_id] = browser
    METRICS.count(
        "sessions_created"
    )
    return browser


def unregister_session(session_id):
    with sessions_lock:
        browser = sessions.pop(
            session_id,
            None,
        )

    if browser is not None:
        METRICS.count(
            "sessions_closed"
        )

    return browser


def ensure_session_registry():
    with sessions_lock:
        return {
            "count": len(sessions),
            "ids": [
                redact_text(
                    value
                )
                for value in sessions
            ],
        }


def health_payload():
    chromium = port_open()
    return {
        "status": "ok",
        "ready": bool(chromium),
        "engine": "chromium-headless",
        "stream": "cdp-screencast-websocket",
        "chromium": chromium,
        "sessions": session_count(),
        "maxSessions": CONFIG.max_sessions,
        "fps": MAX_FPS,
        "version": SERVER_VERSION,
        "uptimeSeconds": (
            time.monotonic()
            - SERVER_STARTED_AT
        ),
        "metrics": METRICS.snapshot(),
    }


def add_response_diagnostics(response):
    response.headers[
        "X-Nova-Server"
    ] = SERVER_VERSION
    response.headers[
        "X-Nova-Uptime"
    ] = str(
        round(
            time.monotonic()
            - SERVER_STARTED_AT,
            3,
        )
    )
    return response


@app.before_request
def nova_before_request():
    started = monotonic_ms()
    request.nova_started = started

    if not request_can_use_route():
        METRICS.count(
            "rejected_requests"
        )
        return jsonify(
            make_error_payload(
                "Request rejected by NOVA limits.",
                "request_rejected",
            )
        ), 413

    return None


@app.after_request
def nova_request_metrics(response):
    started = getattr(
        request,
        "nova_started",
        monotonic_ms(),
    )
    METRICS.observe_request(
        monotonic_ms() - started
    )
    response = add_response_diagnostics(
        response
    )
    return response


@app.errorhandler(413)
def request_too_large(error):
    return jsonify(
        make_error_payload(
            "Request payload is too large.",
            "payload_too_large",
        )
    ), 413


@app.errorhandler(404)
def route_not_found(error):
    return jsonify(
        make_error_payload(
            "NOVA route not found.",
            "not_found",
        )
    ), 404


@app.errorhandler(500)
def internal_error(error):
    METRICS.error(error)
    return jsonify(
        make_error_payload(
            "NOVA internal server error.",
            "internal_error",
        )
    ), 500


# ============================================================
# EXTENDED API
# ============================================================


@app.route("/api/version")
def api_version():
    return route_success(
        version=SERVER_VERSION,
        name=SERVER_NAME,
        python=platform.python_version(),
    )


@app.route("/api/capabilities")
def capabilities():
    return route_success(
        capabilities=api_capabilities()
    )


@app.route("/api/config")
def public_config():
    return route_success(
        config=api_config_public()
    )


@app.route("/api/metrics")
def metrics():
    return jsonify(
        make_ok_payload(
            metrics=METRICS.snapshot(),
            executor=ACK_EXECUTOR.state(),
            limiter={
                "remaining": REQUEST_LIMITER.remaining(
                    client_key()
                ),
            },
        )
    )


@app.route("/api/runtime")
def runtime():
    return route_success(
        runtime=api_runtime_snapshot()
    )


@app.route("/api/sessions")
def session_list():
    return route_success(
        count=session_count(),
        sessions=all_session_snapshots(),
    )


@app.route("/api/ping")
def ping():
    started = monotonic_ms()
    return route_success(
        pong=True,
        elapsedMs=monotonic_ms() - started,
    )


@app.route("/api/screenshot")
def screenshot():
    browser, error = route_browser_or_error()

    if error is not None:
        return error

    payload = screenshot_payload(
        browser
    )

    if payload is None:
        return route_not_ready(
            "No screenshot is available yet."
        )

    response = response_bytes(
        payload,
        "image/jpeg",
    )
    return browser_session_header(
        response,
        browser,
    )


@app.route(
    "/api/evaluate",
    methods=["POST"],
)
def evaluate():
    browser, error = route_browser_or_error()

    if error is not None:
        return error

    try:
        expression = parse_expression(
            request_json()
        )
        result = evaluate_browser(
            browser,
            expression,
        )
        mark_session_activity(
            browser,
            "evaluate",
        )
        return route_success(
            result=extract_evaluation_value(
                result
            )
        )
    except Exception as exc:
        browser.activity.error()
        return route_error_payload(
            exc,
            500,
        )


@app.route("/api/diagnostics")
def diagnostics():
    browser = require_browser()

    if browser is None:
        return route_success(
            runtime=api_runtime_snapshot(),
            sessions=all_session_snapshots(),
        )

    return route_success(
        runtime=api_runtime_snapshot(),
        session=browser.diagnostics(),
        accessLog=ACCESS_LOG.snapshot(),
    )


@app.route(
    "/api/heartbeat",
    methods=["POST"],
)
def heartbeat():
    browser, error = route_browser_or_error()

    if error is not None:
        return error

    mark_session_activity(
        browser,
        "heartbeat",
    )
    return route_success(
        status=browser_status(
            browser
        )
    )


@app.route(
    "/api/cache/clear",
    methods=["POST"],
)
def clear_cache():
    browser, error = route_browser_or_error()

    if error is not None:
        return error

    browser.state_cache.clear()
    mark_session_activity(
        browser,
        "cache-clear",
    )
    return route_success(
        cleared=True
    )


@app.route(
    "/api/target",
    methods=["GET"],
)
def target_info():
    browser, error = route_browser_or_error()

    if error is not None:
        return error

    return route_success(
        target={
            "id": browser.target_id,
            "webSocket": browser.ws_url,
            "status": browser_status(
                browser
            ),
        }
    )


@app.route(
    "/api/navigation/check",
    methods=["POST"],
)
def check_navigation():
    data = request_json()
    value = data.get(
        "url",
        "",
    )

    try:
        normalized = NAVIGATION_POLICY.normalize(
            value
        )
        return route_success(
            allowed=True,
            url=normalized,
            policy=NAVIGATION_POLICY.describe(),
        )
    except Exception as exc:
        return jsonify(
            make_error_payload(
                exception_text(exc),
                "navigation_blocked",
            )
        ), 400


@app.route(
    "/api/session/close-all",
    methods=["POST"],
)
def close_all():
    closed = close_all_sessions()
    return route_success(
        closed=closed,
        sessions=session_count(),
    )


# ============================================================
# HEALTH
# ============================================================

@app.route("/health")
def health():
    return jsonify(
        health_payload()
    )


# ============================================================
# CREATE SESSION
# ============================================================

@app.route(
    "/api/session",
    methods=["POST"]
)
def create_session():
    if should_reject_new_session():
        return json_error(
            "Maximum NOVA sessions reached.",
            429,
        )

    browser = None

    try:
        launch_chromium()

        session_id, browser = (
            create_browser_session()
        )
        register_session(
            session_id,
            browser,
        )

        response = jsonify({
            "ok": True,
            "session": session_id,
            "state": browser_json_state(
                browser
            ),
            "serverVersion": SERVER_VERSION,
        })

        response.headers[
            "X-Nova-Session"
        ] = session_id

        return response

    except Exception as e:
        if browser is not None:
            run_quietly(
                browser.close
            )

        print(
            "NOVA SESSION ERROR:",
            repr(e)
        )

        return json_error(
            e,
            500
        )


# ============================================================
# STATE
# ============================================================

@app.route("/api/state")
def state():
    browser = require_browser()

    if not browser:
        return json_error(
            "Invalid NOVA session",
            401
        )

    return jsonify(
        browser_json_state(
            browser
        )
    )


# ============================================================
# NAVIGATION
# ============================================================

@app.route(
    "/api/navigate",
    methods=["POST"]
)
def navigate():
    browser = require_browser()

    if not browser:
        return json_error(
            "Invalid NOVA session",
            401
        )

    data = request_json()

    try:
        router = getattr(
            browser,
            "router",
            None,
        )
        url = (
            router.navigate(
                data.get("url", "")
            )
            if router
            else browser.navigate(
            data.get("url", "")
            )
        )

        return jsonify({
            "ok": True,
            "url": url
        })

    except Exception as e:
        return json_error(
            e,
            500
        )


@app.route(
    "/api/back",
    methods=["POST"]
)
def back():
    browser = require_browser()

    if not browser:
        return json_error(
            "Invalid NOVA session",
            401
        )

    router = getattr(
        browser,
        "router",
        None,
    )
    if router:
        router.history(-1)
    else:
        browser.history(-1)

    return jsonify({
        "ok": True
    })


@app.route(
    "/api/forward",
    methods=["POST"]
)
def forward():
    browser = require_browser()

    if not browser:
        return json_error(
            "Invalid NOVA session",
            401
        )

    router = getattr(
        browser,
        "router",
        None,
    )
    if router:
        router.history(1)
    else:
        browser.history(1)

    return jsonify({
        "ok": True
    })


@app.route(
    "/api/reload",
    methods=["POST"]
)
def reload_page():
    browser = require_browser()

    if not browser:
        return json_error(
            "Invalid NOVA session",
            401
        )

    router = getattr(
        browser,
        "router",
        None,
    )
    if router:
        router.reload()
    else:
        browser.reload()

    return jsonify({
        "ok": True
    })


@app.route(
    "/api/stop",
    methods=["POST"]
)
def stop_page():
    browser = require_browser()

    if not browser:
        return json_error(
            "Invalid NOVA session",
            401
        )

    router = getattr(
        browser,
        "router",
        None,
    )
    if router:
        router.stop()
    else:
        browser.stop()

    return jsonify({
        "ok": True
    })


# ============================================================
# RESIZE
# ============================================================

@app.route(
    "/api/resize",
    methods=["POST"]
)
def resize():
    browser = require_browser()

    if not browser:
        return json_error(
            "Invalid NOVA session",
            401
        )

    data = request_json()

    try:
        router = getattr(
            browser,
            "router",
            None,
        )
        if router:
            router.resize(
                data.get(
                    "width",
                    WIDTH,
                ),
                data.get(
                    "height",
                    HEIGHT,
                ),
            )
        else:
            browser.resize(
                data.get(
                    "width",
                    WIDTH,
                ),
                data.get(
                    "height",
                    HEIGHT,
                ),
            )

        return jsonify({
            "ok": True,
            "width": browser.width,
            "height": browser.height,
        })

    except Exception as e:
        return json_error(
            e,
            500
        )


# ============================================================
# INPUT HTTP FALLBACK
# ============================================================

@app.route(
    "/api/click",
    methods=["POST"]
)
def click():
    browser = require_browser()

    if not browser:
        return json_error(
            "Invalid NOVA session",
            401
        )

    data = request_json()

    router = getattr(
        browser,
        "router",
        None,
    )
    if router:
        router.click(
            data.get("x", 0),
            data.get("y", 0),
        )
    else:
        browser.click(
            data.get("x", 0),
            data.get("y", 0),
        )

    return jsonify({
        "ok": True
    })


@app.route(
    "/api/scroll",
    methods=["POST"]
)
def scroll():
    browser = require_browser()

    if not browser:
        return json_error(
            "Invalid NOVA session",
            401
        )

    data = request_json()

    router = getattr(
        browser,
        "router",
        None,
    )
    if router:
        router.scroll(data)
    else:
        browser.scroll(
            data.get(
                "x",
                browser.width / 2,
            ),
            data.get(
                "y",
                browser.height / 2,
            ),
            data.get("dx", 0),
            data.get("dy", 0),
        )

    return jsonify({
        "ok": True
    })


@app.route(
    "/api/type",
    methods=["POST"]
)
def type_text():
    browser = require_browser()

    if not browser:
        return json_error(
            "Invalid NOVA session",
            401
        )

    data = request_json()

    router = getattr(
        browser,
        "router",
        None,
    )
    if router:
        router.type_text(
            data.get("text", "")
        )
    else:
        browser.type_text(
            data.get("text", "")
        )

    return jsonify({
        "ok": True
    })


@app.route(
    "/api/key",
    methods=["POST"]
)
def key():
    browser = require_browser()

    if not browser:
        return json_error(
            "Invalid NOVA session",
            401
        )

    data = request_json()

    router = getattr(
        browser,
        "router",
        None,
    )
    if router:
        router.key(
            data.get(
                "key",
                "",
            ),
            data.get("code"),
        )
    else:
        browser.key(
            data.get(
                "key",
                "",
            ),
            data.get("code"),
        )

    return jsonify({
        "ok": True
    })


# ============================================================
# COOKIE INFO
# ============================================================

@app.route("/api/cookies")
def cookies():
    browser = require_browser()

    if not browser:
        return json_error(
            "Invalid NOVA session",
            401
        )

    try:
        result = browser.cdp.command(
            "Network.getAllCookies"
        )

        cookie_list = []

        for c in result.get(
            "cookies",
            []
        ):
            cookie_list.append({
                "name": c.get("name"),
                "domain": c.get("domain"),
                "path": c.get("path"),
                "secure": c.get("secure"),
                "httpOnly": c.get("httpOnly"),
                "sameSite": c.get("sameSite"),
                "expires": c.get("expires"),
            })

        return jsonify({
            "count": len(cookie_list),
            "cookies": cookie_list,
        })

    except Exception as e:
        return json_error(
            e,
            500
        )


# ============================================================
# DEBUG
# ============================================================

@app.route("/api/debug")
def debug():
    browser = require_browser()

    if not browser:
        return json_error(
            "Invalid NOVA session",
            401
        )

    return jsonify({
        "session": browser.id,
        "targetId": browser.target_id,
        "cdpConnected": browser.cdp.running,
        "browserRunning": browser.running,
        "requestedUrl": browser.requested_url,
        "actualUrl": browser.actual_url,
        "lastRealUrl": browser.last_real_url,
        "title": browser.title,
        "latestFrameId": browser.latest_frame_id,
        "latestFrameBytes": (
            len(browser.latest_frame)
            if browser.latest_frame
            else 0
        ),
        "streamClients": len(
            browser.stream_clients
        ),
        "width": browser.width,
        "height": browser.height,
    })


# ============================================================
# CLOSE SESSION
# ============================================================

@app.route(
    "/api/close",
    methods=["POST"]
)
def close_session():
    session_id = session_from_request()

    if not session_id:
        return json_error(
            "Missing NOVA session",
            400
        )

    browser = unregister_session(
        session_id
    )

    if browser:
        close_session_object(
            session_id,
            browser,
        )

    return jsonify({
        "ok": True
    })


# ============================================================
# WEBSOCKET STREAM
#
# URL:
# ws://PHONE_IP:3000/ws?session=SESSION_ID
#
# Server -> client:
# {
#   "type": "frame",
#   "id": 123,
#   "data": "<base64 jpeg>"
# }
#
# Client -> server:
# click / scroll / type / key / resize / navigation
# ============================================================

@sock.route("/ws")
def websocket_stream(ws):
    session_id = request.args.get(
        "session"
    )

    if not session_id:
        try:
            ws.send(json.dumps({
                "type": "error",
                "error": "Missing session"
            }))
        except Exception:
            pass

        return

    with sessions_lock:
        browser = sessions.get(
            session_id
        )

    if not browser:
        try:
            ws.send(json.dumps({
                "type": "error",
                "error": "Invalid session"
            }))
        except Exception:
            pass

        return

    with browser.stream_lock:
        browser.stream_clients.add(
            id(ws)
        )

    ws_state = WebSocketState(
        id(ws)
    )
    router = getattr(
        browser,
        "router",
        None,
    )

    alive = threading.Event()
    alive.set()

    # --------------------------------------------------------
    # FRAME SENDER
    # --------------------------------------------------------

    def send_frames():
        last_id = -1

        try:
            while (
                alive.is_set()
                and browser.running
                and browser.cdp.running
            ):
                with browser.frame_condition:
                    browser.frame_condition.wait_for(
                        lambda:
                            browser.latest_frame_id
                            != last_id
                            or not browser.running,
                        timeout=1
                    )

                    if not browser.running:
                        break

                    frame_id = browser.latest_frame_id
                    frame = browser.latest_frame

                if (
                    frame is None
                    or frame_id == last_id
                ):
                    continue

                # Drop old frames automatically.
                #
                # This is intentional for low latency:
                # never build a queue of stale screenshots.
                last_id = frame_id

                try:
                    if not websocket_send(
                        ws,
                        {
                            "type": "frame",
                            "id": frame_id,
                            "data": frame,
                        },
                        ws_state,
                    ):
                        break

                except Exception:
                    break

        finally:
            alive.clear()

    sender = threading.Thread(
        target=send_frames,
        daemon=True
    )

    sender.start()

    # --------------------------------------------------------
    # INPUT RECEIVER
    # --------------------------------------------------------

    try:
        websocket_send(
            ws,
            {
                "type": "ready",
                "session": browser.id,
                "width": browser.width,
                "height": browser.height,
                "fps": MAX_FPS,
                "serverVersion": SERVER_VERSION,
                "capabilities": api_capabilities(),
            },
            ws_state,
        )

        while (
            alive.is_set()
            and browser.running
            and browser.cdp.running
        ):
            raw = ws.receive()

            if raw is None:
                break

            try:
                data = CODEC.loads(raw)
            except Exception:
                continue

            ws_state.received_message()
            touch_browser(browser)

            msg_type = data.get(
                "type"
            )

            try:
                if msg_type == "ping":
                    websocket_send(
                        ws,
                        {
                            "type": "pong",
                            "time": data.get(
                                "time"
                            ),
                        },
                        ws_state,
                    )

                elif msg_type == "click":
                    if router:
                        router.click(
                            data.get("x", 0),
                            data.get("y", 0),
                        )
                    else:
                        browser.click(
                            data.get("x", 0),
                            data.get("y", 0),
                        )

                elif msg_type == "mouseDown":
                    if router:
                        router.mouse(
                            "mousePressed",
                            data.get("x", 0),
                            data.get("y", 0),
                            data.get(
                                "button",
                                "left",
                            ),
                        )
                    else:
                        browser.mouse(
                            "mousePressed",
                            data.get("x", 0),
                            data.get("y", 0),
                            data.get(
                                "button",
                                "left",
                            ),
                        )

                elif msg_type == "mouseUp":
                    if router:
                        router.mouse(
                            "mouseReleased",
                            data.get("x", 0),
                            data.get("y", 0),
                            data.get(
                                "button",
                                "left",
                            ),
                        )
                    else:
                        browser.mouse(
                            "mouseReleased",
                            data.get("x", 0),
                            data.get("y", 0),
                            data.get(
                                "button",
                                "left",
                            ),
                        )

                elif msg_type == "mouseMove":
                    if router:
                        router.mouse(
                            "mouseMoved",
                            data.get("x", 0),
                            data.get("y", 0),
                            "none",
                        )
                    else:
                        browser.mouse(
                            "mouseMoved",
                            data.get("x", 0),
                            data.get("y", 0),
                            "none",
                        )

                elif msg_type == "scroll":
                    if router:
                        router.scroll(data)
                    else:
                        browser.scroll(
                            data.get(
                                "x",
                                browser.width / 2,
                            ),
                            data.get(
                                "y",
                                browser.height / 2,
                            ),
                            data.get("dx", 0),
                            data.get("dy", 0),
                        )

                elif msg_type == "type":
                    if router:
                        router.type_text(
                            data.get(
                                "text",
                                "",
                            )
                        )
                    else:
                        browser.type_text(
                            data.get(
                                "text",
                                "",
                            )
                        )

                elif msg_type == "key":
                    if router:
                        router.key(
                            data.get(
                                "key",
                                "",
                            ),
                            data.get("code"),
                        )
                    else:
                        browser.key(
                            data.get(
                                "key",
                                "",
                            ),
                            data.get("code"),
                        )

                elif msg_type == "resize":
                    if router:
                        router.resize(
                            data.get(
                                "width",
                                browser.width,
                            ),
                            data.get(
                                "height",
                                browser.height,
                            ),
                        )
                    else:
                        browser.resize(
                            data.get(
                                "width",
                                browser.width,
                            ),
                            data.get(
                                "height",
                                browser.height,
                            ),
                        )

                elif msg_type == "navigate":
                    if router:
                        router.navigate(
                            data.get(
                                "url",
                                "",
                            )
                        )
                    else:
                        browser.navigate(
                            data.get(
                                "url",
                                "",
                            )
                        )

                elif msg_type == "back":
                    if router:
                        router.history(-1)
                    else:
                        browser.history(-1)

                elif msg_type == "forward":
                    if router:
                        router.history(1)
                    else:
                        browser.history(1)

                elif msg_type == "reload":
                    if router:
                        router.reload()
                    else:
                        browser.reload()

                elif msg_type == "stop":
                    if router:
                        router.stop()
                    else:
                        browser.stop()

                elif msg_type == "state":
                    websocket_send(
                        ws,
                        {
                            "type": "state",
                            "state": browser_json_state(
                                browser
                            ),
                        },
                        ws_state,
                    )

            except Exception as e:
                websocket_send(
                    ws,
                    {
                            "type": "inputError",
                            "error": str(e),
                    },
                    ws_state,
                )

    except Exception as e:
        print(
            "NOVA WS:",
            repr(e)
        )

    finally:
        alive.clear()
        ws_state.close()

        with browser.stream_lock:
            browser.stream_clients.discard(
                id(ws)
            )


# ============================================================
# ROOT
# ============================================================

@app.route("/")
def root():
    return jsonify({
        "name": "NOVA Remote Browser",
        "status": "running",
        "engine": "Chromium",
        "transport": "WebSocket",
        "video": "CDP Page.startScreencast",
        "health": "/health",
    })


# ============================================================
# SHUTDOWN
# ============================================================

def shutdown(*args):
    print("\nNOVA: shutting down...")

    run_quietly(
        SESSION_SWEEPER.stop
    )
    run_quietly(
        RESOURCE_MONITOR.stop
    )
    run_quietly(
        close_all_sessions
    )
    run_quietly(
        ACK_EXECUTOR.shutdown
    )

    global chromium_process

    if chromium_process:
        terminate_process(
            chromium_process
        )

    raise SystemExit(0)


signal.signal(
    signal.SIGINT,
    shutdown
)

signal.signal(
    signal.SIGTERM,
    shutdown
)


# ============================================================
# START
# ============================================================

if __name__ == "__main__":
    print("")
    print("========================================")
    print(" NOVA LOW-LATENCY REMOTE BROWSER")
    print("========================================")
    print("")
    print("Starting Chromium...")

    launch_chromium()

    RESOURCE_MONITOR.start()
    SESSION_SWEEPER.start()

    print(
        f"CDP: http://{CDP_HOST}:{CDP_PORT}"
    )
    print(
        f"NOVA: http://0.0.0.0:{PORT}"
    )
    print(
        f"Stream: CDP Screencast @ up to {MAX_FPS} FPS"
    )
    print("")

    app.run(
        host=HOST,
        port=PORT,
        threaded=True,
        debug=False,
        use_reloader=False,
    )