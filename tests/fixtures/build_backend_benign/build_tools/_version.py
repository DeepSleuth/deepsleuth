import os


def write_version(root):
    with open(os.path.join(root, "VERSION"), "w") as fh:
        fh.write("1.0.0\n")
