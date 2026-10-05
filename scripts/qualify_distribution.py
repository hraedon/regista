"""F3 installed-artifact qualification; only use a disposable PostgreSQL DSN.

Run: python scripts/qualify_distribution.py dist --dsn DISPOSABLE_DSN --output /tmp/f3
Creates its own child databases and removes them in a finally block. Installs wheel
and sdist in separate clean environments, exports old migration SQL from 84bb2ec,
and runs installed probes with no checkout import path or private configuration.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import shutil
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from importlib.resources import files
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]


def run(argv: list[str], cwd: Path, env: dict[str, str]) -> str:
    result = subprocess.run(argv, cwd=cwd, env=env, capture_output=True, text=True)
    print(result.stdout, end="")
    print(result.stderr, end="", file=sys.stderr)
    if result.returncode:
        raise RuntimeError(f"command {argv[0]} failed: exit {result.returncode}")
    return result.stdout


def probe(mode: str, dsn: str, directory: Path) -> None:
    # These imports occur ONLY in the isolated installed interpreter.
    import psycopg

    from regista import (
        ClaimContestedError,
        DatabaseOperationError,
        InvalidFieldError,
        Kernel,
        StaleAttemptError,
        UnsupportedSchemaError,
        Workflow,
    )

    if mode == "claim-child":
        k = Kernel.connect(dsn, require_existing=True)
        item_id = __import__("uuid").UUID((directory / "crash-item").read_text())
        held = k.claim(item_id, actor_id="crashed-worker", ttl_seconds=2)
        print(held.attempt, flush=True)
        time.sleep(300)
        return
    if mode == "legacy":
        for version, last in (("0.5-era", 44), ("0.6-0.7-era", 50)):
            # Each era has its OWN DB: old SQL includes public.projects.
            from psycopg.conninfo import conninfo_to_dict, make_conninfo

            target = make_conninfo(dsn, dbname=conninfo_to_dict(dsn)["dbname"] + f"_{last}")
            with psycopg.connect(target, autocommit=True) as conn:
                conn.execute("CREATE TABLE _regista_migrations "
                             "(version integer PRIMARY KEY, applied_at timestamptz DEFAULT now())")
                for path in sorted((directory / "migrations").glob("*.sql"))[:last]:
                    conn.execute(path.read_text())
                    conn.execute("INSERT INTO _regista_migrations(version) VALUES (%s)",
                                 (int(path.name[:3]),))
            before = subprocess.check_output(
                ["pg_dump", "--no-owner", "--no-acl", target], text=True)
            refusals = 0
            for require in (False, True):
                try:
                    k = Kernel.connect(target, require_existing=require)
                except UnsupportedSchemaError:
                    refusals += 1
                else:
                    k.close()
                    raise AssertionError("legacy open was accepted")
            result = subprocess.run([sys.executable, "-I", "-m", "regista.cli",
                                     "--dsn", target, "init"], capture_output=True, text=True)
            assert result.returncode == 2 and "Nothing was changed" in result.stderr
            after = subprocess.check_output(
                ["pg_dump", "--no-owner", "--no-acl", target], text=True)
            # PG17+ pg_dump emits a random restrict token; omit only that wrapper.
            def normalized(dump: str) -> str:
                return "\n".join(line for line in dump.splitlines()
                                 if not line.startswith(("\\restrict ", "\\unrestrict ")))
            assert normalized(before) == normalized(after)
            print(f"{version}: migrations 001-{last:03d}; {refusals} opens + init refused; "
                  "complete logical dump unchanged")
        return
    k = Kernel.connect(dsn, require_existing=True)
    try:
        if mode in ("restart", "recover"):
            items = k.list_items(limit=500)
            assert len(items) >= 4
            assert any(i.state == "done" for i in items)
            assert any(i.state == "archived" for i in items)
            assert any(k.links_from(i.id) for i in items)
            assert any(i.fields.get("source_uri") for i in items)
            reports = list(k.replay_all(batch_size=2))
            assert len(reports) == len(items) and all(not r.drift for r in reports)
            print(f"{mode}: new process/connection; {len(items)} persisted items, "
                  "fields/links read; whole-namespace replay clean")
            if mode == "recover":
                item = k.create_work_item(workflow="qualification", type="task",
                                          actor_id="restore-writer")
                lease = k.claim(item.id, actor_id="restore-writer")
                k.transition(item.id, transition="finish", actor_id="restore-writer",
                             attempt=lease.attempt, fields={"recovered": True})
                k.release(item.id, actor_id="restore-writer", attempt=lease.attempt)
                assert k.get(item.id).state == "done" and k.replay(item.id)[2] == []
                print("recover: another valid create/claim/transition/release persisted cleanly")
            return
        assert mode == "exercise"
        with psycopg.connect(dsn) as conn:
            server = conn.execute("SHOW server_version").fetchone()[0]
        print(json.dumps({"os": platform.platform(), "python": sys.version,
                          "postgresql": server,
                          "kernel_schema": k.health()["schema_version"],
                          "psycopg": psycopg.__version__}))
        for name in ("schema.sql", "workflow.schema.json"):
            assert files("regista").joinpath(name).read_bytes()
        assert "site-packages" in str(files("regista"))
        wf = Workflow(name="qualification", states=("new", "done"), initial="new",
                      types=("task",), transitions={"finish": (("new",), "done")},
                      terminal=("done",))
        k.register_workflow(wf)
        item = k.create_work_item(workflow=wf.name, type="task", actor_id="q",
                                  idempotency_key="qualification-create")
        assert k.create_work_item(workflow=wf.name, type="task", actor_id="q",
                                  idempotency_key="qualification-create") == item
        before = (k.get(item.id), k.history(item.id))
        try:
            k.transition(item.id, transition="finish", actor_id="q",
                         fields={"bad": float("nan")})
        except InvalidFieldError:
            pass
        else:
            raise AssertionError("invalid JSON committed")
        assert (k.get(item.id), k.history(item.id)) == before
        # Synthetic DB failure exercises rollback after SQL effects have begun.
        with psycopg.connect(dsn, autocommit=True) as conn:
            conn.execute("CREATE FUNCTION qualification_fail() RETURNS trigger "
                         "LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION "
                         "'qualification rollback'; END $$")
            conn.execute("CREATE TRIGGER qualification_fail AFTER INSERT ON events "
                         "FOR EACH ROW EXECUTE FUNCTION qualification_fail()")
        try:
            try:
                k.transition(item.id, transition="finish", actor_id="q")
            except DatabaseOperationError:
                pass
            else:
                raise AssertionError("injected SQL failure was ignored")
        finally:
            with psycopg.connect(dsn, autocommit=True) as conn:
                conn.execute("DROP TRIGGER qualification_fail ON events")
                conn.execute("DROP FUNCTION qualification_fail()")
        assert (k.get(item.id), k.history(item.id)) == before
        print("rollback: invalid input and injected SQL failure left state/history unchanged")

        def contend(n: int) -> tuple[str, Any]:
            independent = Kernel.connect(dsn, require_existing=True)
            try:
                held = independent.claim(item.id, actor_id=f"racer-{n}")
                return held.actor_id, held
            except ClaimContestedError:
                return "lost", None
            finally:
                independent.close()

        with ThreadPoolExecutor(max_workers=8) as executor:
            winners = [c for actor, c in executor.map(contend, range(8)) if actor != "lost"]
        assert len(winners) == 1
        held = winners[0]
        k.transition(item.id, transition="finish", actor_id=held.actor_id,
                     attempt=held.attempt)
        k.release(item.id, actor_id=held.actor_id, attempt=held.attempt)
        assert k.replay(item.id)[2] == []
        print("contention: 8 independent connections, exactly 1 claim winner; replay clean")
        crash = k.create_work_item(workflow=wf.name, type="task", actor_id="q")
        (directory / "crash-item").write_text(str(crash.id))
        child = subprocess.Popen([sys.executable, "-I", __file__, "--probe", "claim-child",
                                  "--dsn", dsn, "--output", str(directory)],
                                 stdout=subprocess.PIPE, text=True)
        try:
            assert child.stdout is not None
            old_attempt = int(child.stdout.readline())
            child.terminate()
            child.wait(timeout=10)
            assert child.returncode == -15
        finally:
            if child.poll() is None:
                child.kill()
                child.wait()
        time.sleep(2.2)
        takeover = k.claim(crash.id, actor_id="replacement")
        assert takeover.attempt > old_attempt
        try:
            k.transition(crash.id, transition="finish", actor_id="crashed-worker",
                         attempt=old_attempt)
        except StaleAttemptError:
            pass
        else:
            raise AssertionError("terminated worker's attempt committed")
        k.heartbeat(crash.id, actor_id="replacement", attempt=takeover.attempt)
        k.transition(crash.id, transition="finish", actor_id="replacement",
                     attempt=takeover.attempt)
        k.release(crash.id, actor_id="replacement", attempt=takeover.attempt)
        assert all(not r.drift for r in k.replay_all(batch_size=2))
        print("crash: lease-holding OS process terminated (SIGTERM); real expiry, "
              "takeover, stale refusal and valid replacement write passed")
    finally:
        k.close()


def qualify(dist: Path, dsn: str, out: Path) -> None:
    import psycopg
    from psycopg.conninfo import make_conninfo
    from psycopg.sql import SQL, Identifier

    out.mkdir(parents=True, exist_ok=False)
    shutil.copyfile(__file__, out / "probe.py")
    migrations = out / "migrations"
    migrations.mkdir()
    paths = subprocess.check_output(["git", "ls-tree", "-r", "--name-only", "84bb2ec",
                                     "migrations"], text=True).splitlines()
    assert len(paths) == 50
    for path in paths:
        data = subprocess.check_output(["git", "show", f"84bb2ec:{path}"])
        (migrations / Path(path).name).write_bytes(data)
    artifacts = sorted(dist.glob("*0.8.0*"))
    assert len(artifacts) == 2
    for index, artifact in enumerate(artifacts):
        scratch = out / ("wheel" if artifact.suffix == ".whl" else "sdist")
        scratch.mkdir()
        clean_home = scratch / "home"
        clean_home.mkdir()
        env = {"PATH": os.environ["PATH"], "HOME": str(clean_home), "LANG": "C.UTF-8",
               "UV_NO_CONFIG": "1", "PIP_CONFIG_FILE": "/dev/null",
               "PYTHONUTF8": "1"}
        run(["uv", "venv", "--python", sys.executable, str(scratch / "venv")], scratch, env)
        python = scratch / "venv/bin/python"
        run(["uv", "pip", "install", "--python", str(python), str(artifact)], scratch, env)
        run([str(scratch / "venv/bin/regista"), "--help"], scratch, env)
        run([str(python), "-I", "-c", "import regista; print(regista.__file__); "
             "from importlib.resources import files; from pathlib import Path; "
             "p=Path('examples'); p.mkdir(); "
             "names=('example_handoff.py','example_documents.py',"
             "'remediation.workflow.yaml','ingest.workflow.yaml'); "
             "[(p/n).write_bytes(files('regista').joinpath('examples',n).read_bytes()) "
             "for n in names]"], scratch, env)
        names = [f"f3_{out.name.replace('-', '_')}_{index}{suffix}"
                 for suffix in ("", "_restore", "_old", "_old_44", "_old_50")]
        with psycopg.connect(dsn, autocommit=True) as admin:
            for name in names:
                admin.execute(SQL("CREATE DATABASE {}").format(Identifier(name)))
        try:
            source = make_conninfo(dsn, dbname=names[0])
            restored = make_conninfo(dsn, dbname=names[1])
            old = make_conninfo(dsn, dbname=names[2])
            for scenario in ("example_handoff.py", "example_documents.py"):
                run([str(python), "-I", f"examples/{scenario}", source], scratch, env)
            for mode in ("exercise", "restart"):
                run([str(python), "-I", str(out / "probe.py"), "--probe", mode,
                     "--dsn", source, "--output", str(out)], scratch, env)
            dump = scratch / "populated.dump"
            run(["pg_dump", "--format=custom", "--no-owner", "--no-acl",
                 "--file", str(dump), source], scratch, env)
            run(["pg_restore", "--exit-on-error", "--no-owner", "--no-acl",
                 "--dbname", restored, str(dump)], scratch, env)
            run([str(python), "-I", str(out / "probe.py"), "--probe", "recover",
                 "--dsn", restored, "--output", str(out)], scratch, env)
            run([str(scratch / "venv/bin/regista"), "--dsn", restored,
                 "--json", "check-history"], scratch, env)
            run([str(python), "-I", str(out / "probe.py"), "--probe", "legacy",
                 "--dsn", old, "--output", str(out)], scratch, env)
            digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
            print(f"PASS {artifact.name} sha256={digest}")
        finally:
            with psycopg.connect(dsn, autocommit=True) as admin:
                for name in reversed(names):
                    admin.execute(SQL("DROP DATABASE {} WITH (FORCE)").format(Identifier(name)))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("dist", nargs="?", type=Path)
    parser.add_argument("--dsn", required=True)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--probe", choices=("exercise", "restart", "recover", "legacy",
                                          "claim-child"))
    args = parser.parse_args()
    if args.probe:
        probe(args.probe, args.dsn, args.output)
    else:
        qualify(args.dist.resolve(), args.dsn, args.output.resolve())


if __name__ == "__main__":
    main()
