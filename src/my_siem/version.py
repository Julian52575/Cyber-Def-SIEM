"""The app version, written into _version.py at build time by the justfile."""

try:
    from my_siem._version import VERSION
except ImportError:
    VERSION = "unknown"
