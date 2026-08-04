# scripts/lab_scope.py
"""Write the lab scope file listing the saber-lab targets."""

from __future__ import annotations

from pathlib import Path

LAB_TARGETS = ["dvwa", "juiceshop", "metasploitable", "vulnbin"]


def main() -> None:
    out = Path("runs/lab_scope.yaml")
    out.parent.mkdir(parents=True, exist_ok=True)
    lines = ["mission_name: SABER lab", "targets:"]
    lines += [f"  - {t}" for t in LAB_TARGETS]
    out.write_text("\n".join(lines) + "\n")
    print(f"wrote {out}")


if __name__ == "__main__":
    main()
