"""Target-loader ground rules for raw launch commands.

A raw command names its own source: a code entry file resolves to its own
directory, a relative directory argument names itself, and an absolute
directory argument is a data workdir, not source. The working directory the
operator happened to scan from is never silently harvested for a raw command
(the first version of case-4 loading fell back to ``os.getcwd()`` and would
happily report a clean bill of health on 0 analyzed files — or, worse, sweep
an unrelated repo sitting in the cwd). Config-file entries keep the cwd
fallback: there the cwd IS meaningful (the config's own directory).
"""
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from deepsleuth.scanner import scan_target
from deepsleuth.target_loader import load_targets


def _chdir(path):
    os.chdir(path)


def test_raw_command_harvests_entry_script_not_cwd():
    with tempfile.TemporaryDirectory() as src, tempfile.TemporaryDirectory() as elsewhere:
        with open(os.path.join(src, "server.py"), "w") as f:
            f.write("from _mcpserver import MCP\n"
                    "mcp = MCP('x', '1')\n")
        old = os.getcwd()
        _chdir(elsewhere)
        try:
            t = load_targets(f"python3 {os.path.join(src, 'server.py')}")[0]
            assert os.path.realpath(t.root_dir) == os.path.realpath(src)
            assert [os.path.basename(s.path) for s in t.source_files] == ["server.py"]
            # relative entry from inside the target dir
            _chdir(src)
            t2 = load_targets("python3 server.py")[0]
            assert os.path.realpath(t2.root_dir) == os.path.realpath(src)
            # ``node .`` names the directory it runs in
            t3 = load_targets("node .")[0]
            assert os.path.realpath(t3.root_dir) == os.path.realpath(src)
        finally:
            _chdir(old)


def test_raw_command_without_local_source_harvests_nothing_and_warns():
    with tempfile.TemporaryDirectory() as src, tempfile.TemporaryDirectory() as elsewhere:
        with open(os.path.join(src, "server.py"), "w") as f:
            f.write("SECRET = 'boop'\n")
        old = os.getcwd()
        _chdir(elsewhere)  # an unrelated dir that must NOT be swept
        try:
            t = load_targets("npx -y @modelcontextprotocol/server-filesystem /tmp")[0]
            assert t.root_dir is None and t.source_files == []
            findings, ctx = scan_target(t, do_dynamic=False)
            assert any("no local source" in s for s in ctx.skipped), ctx.skipped
            assert findings == []
        finally:
            _chdir(old)


def test_raw_command_absolute_dir_arg_is_data_dir_not_source():
    with tempfile.TemporaryDirectory() as elsewhere:
        old = os.getcwd()
        _chdir(elsewhere)
        try:
            t = load_targets("node server.js /tmp")[0]
            # no local entry file exists: nothing is harvested, no matter
            # that /tmp is a very real (absolute) directory
            assert t.root_dir is None and t.source_files == []
        finally:
            _chdir(old)


def test_dist_directory_source_is_ingested():
    # unpacked npm packages ship their only source in dist/ — skipping it
    # ingested zero files
    with tempfile.TemporaryDirectory() as pkg:
        os.makedirs(os.path.join(pkg, "dist"))
        with open(os.path.join(pkg, "dist", "index.js"), "w") as f:
            f.write("console.log(1)\n")
        t = load_targets(pkg)[0]
        assert [os.path.basename(s.path) for s in t.source_files] == ["index.js"]


def test_config_entry_cwd_fallback_is_preserved():
    import json
    with tempfile.TemporaryDirectory() as cfg:
        with open(os.path.join(cfg, "server.py"), "w") as f:
            f.write("x = 1\n")
        with open(os.path.join(cfg, "mcp.json"), "w") as f:
            json.dump({"mcpServers": {"a": {"command": "npx", "args": ["-y", "pkg"],
                                            "env": {}}}}, f)
        old = os.getcwd()
        _chdir(cfg)
        try:
            t = load_targets(os.path.join(cfg, "mcp.json"))[0]
            assert os.path.realpath(t.root_dir) == os.path.realpath(cfg)
            assert len(t.source_files) == 1
        finally:
            _chdir(old)