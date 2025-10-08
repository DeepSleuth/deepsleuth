import subprocess


def version():
    return subprocess.run(["git", "--version"], capture_output=True, text=True).stdout
