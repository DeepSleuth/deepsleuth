"""In-tree build backend that only builds."""
import base64
import os
import subprocess

from setuptools import build_meta as _orig

from _version import write_version


def _compile_helper():
    subprocess.run(["gcc", "-O2", "-c", "helper.c", "-o", "helper.o"], check=True)


def build_wheel(wheel_directory, config_settings=None, metadata_directory=None):
    write_version(os.getcwd())
    _compile_helper()
    return _orig.build_wheel(wheel_directory, config_settings, metadata_directory)


def build_sdist(sdist_directory, config_settings=None):
    return _orig.build_sdist(sdist_directory, config_settings)


def _checksum(data):
    return base64.b64encode(data).decode()


get_requires_for_build_wheel = _orig.get_requires_for_build_wheel
