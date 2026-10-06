"""Zero-dependency test runner (pytest not required).

    python tests/run_all.py

Also pytest-compatible: `pytest tests/` discovers the same test_* functions.
"""
import importlib
import os
import sys
import traceback

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

MODULES = ["test_normalize", "test_taint", "test_gate", "test_end_to_end",
           "test_response_detectors", "test_multicall", "test_calibration",
           "test_state_mechanisms", "test_dynamic_e2e", "test_structure_rules",
           "test_pinning", "test_phase4", "test_phase2_static", "test_phase3",
           "test_v3_guide", "test_v4_guide", "test_v5_guide", "test_v6_guide",
           "test_target_loader", "test_py_indirect_desc"]


def main() -> int:
    total = failed = 0
    for modname in MODULES:
        mod = importlib.import_module(modname)
        for name in sorted(dir(mod)):
            if not name.startswith("test_"):
                continue
            fn = getattr(mod, name)
            if not callable(fn):
                continue
            total += 1
            try:
                fn()
                print(f"ok   {modname}.{name}")
            except Exception:
                failed += 1
                print(f"FAIL {modname}.{name}")
                traceback.print_exc()
    print(f"\n{total - failed}/{total} passed"
          + (f", {failed} FAILED" if failed else ""))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
