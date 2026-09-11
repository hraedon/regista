from __future__ import annotations

import uuid

from regista import Regista
from regista._testing import drop_project_schema

DSN = "postgresql://regista_test:regista_test@localhost:5432/regista_test"


def test_worker_reviewer_example() -> None:
    from examples.worker_reviewer import main

    project = f"t_ex_worker_{uuid.uuid4().hex[:10]}"
    try:
        assert main(DSN, project) == 0
        sub = Regista(DSN, project)
        try:
            done = sub.query_work_items(current_states=["done"])
            assert len(done.items) == 1
            assert done.items[0].attempt_number == 2
            report = sub.replay()
            assert report.replayed_drift == 0
        finally:
            sub.close()
    finally:
        drop_project_schema(DSN, project)


def test_document_processing_example() -> None:
    from examples.document_processing import main

    project = f"t_ex_docs_{uuid.uuid4().hex[:10]}"
    try:
        assert main(DSN, project) == 0
        sub = Regista(DSN, project)
        try:
            committed = sub.query_work_items(current_states=["committed"])
            assert len(committed.items) == 1
            work_item = committed.items[0]
            assert work_item.work_item_type == "document"
            assert work_item.custom_fields["extracted"]["total"] == 1180.5
            report = sub.replay()
            assert report.replayed_drift == 0
        finally:
            sub.close()
    finally:
        drop_project_schema(DSN, project)
