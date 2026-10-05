"""Install a built wheel in a clean venv; exercise it without checkout imports."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


def main() -> None:
    dist = Path(sys.argv[1]).resolve()
    wheels = list(dist.glob("*.whl"))
    if len(wheels) != 1:
        raise SystemExit("smoke needs exactly one candidate wheel")
    dsn = os.environ.get("REGISTA_TEST_DSN")
    if not dsn:
        raise SystemExit("REGISTA_TEST_DSN is required; use disposable PostgreSQL")
    repo = Path(__file__).resolve().parents[1]
    with tempfile.TemporaryDirectory(prefix="regista-installed-") as directory:
        scratch = Path(directory)
        env = {k: v for k, v in os.environ.items() if k not in ("PYTHONPATH", "PYTHONHOME")}
        subprocess.run(
            ["uv", "venv", "--python", sys.executable, str(scratch / "venv")],
            check=True,
            cwd=scratch,
            env=env,
        )
        python = scratch / "venv/bin/python"
        subprocess.run(
            ["uv", "pip", "install", "--python", str(python), str(wheels[0])],
            check=True,
            cwd=scratch,
            env=env,
        )
        subprocess.run(
            [str(scratch / "venv/bin/regista"), "--help"], check=True, cwd=scratch, env=env
        )
        subprocess.run(
            [
                str(python),
                "-I",
                "-c",
                "import regista; from importlib.resources import files; "
                "print('installed:', regista.__file__); "
                "assert 'site-packages' in regista.__file__; "
                "assert files('regista').joinpath('schema.sql').is_file(); "
                "assert files('regista').joinpath('workflow.schema.json').is_file()",
            ],
            check=True,
            cwd=scratch,
            env=env,
        )
        shutil.copytree(repo / "examples", scratch / "examples")
        # The service DSN names a disposable test DB; create a fresh child database
        # so this smoke never depends on or resets a populated destination.
        probe = (
            "import psycopg, uuid; from psycopg.sql import SQL, Identifier; "
            "from psycopg.conninfo import make_conninfo; "
            "import subprocess, sys; "
            "dsn=sys.argv[1]; name='f1b_smoke_'+uuid.uuid4().hex; "
            "conn=psycopg.connect(dsn, autocommit=True); "
            "conn.execute(SQL('CREATE DATABASE {}').format(Identifier(name))); "
            "result=subprocess.run([sys.executable, '-I', "
            "'examples/example_documents.py', make_conninfo(dsn, dbname=name)]); "
            "conn.execute(SQL('DROP DATABASE {} WITH (FORCE)').format(Identifier(name))); "
            "conn.close(); sys.exit(result.returncode)"
        )
        subprocess.run([str(python), "-I", "-c", probe, dsn], check=True, cwd=scratch, env=env)
        print("Installed wheel smoke passed (clean venv, checkout absent from import path).")


if __name__ == "__main__":
    main()
