import os

from regista import Kernel, Workflow

store = Kernel.connect(os.environ["REGISTA_DSN"], schema=os.getenv("REGISTA_SCHEMA", "tasks"))
try:
    store.initialize()  # empty destination, or the 0.8.0 baseline
    store.register_workflow(Workflow(
        name="tasks", types=("task",), states=("new", "review", "done"), initial="new",
        transitions={"submit": (("new",), "review"), "approve": (("review",), "done")},
        roles={"approve": ("reviewer",)}, role_names=("reviewer",), terminal=("done",),
    ))
    item = store.create_work_item(workflow="tasks", type="task", actor_id="worker")
    lease = store.claim(item.id, actor_id="worker")
    store.transition(item.id, transition="submit", actor_id="worker", attempt=lease.attempt)
    store.release(item.id, actor_id="worker", attempt=lease.attempt)  # explicit handoff
    store.transition(item.id, transition="approve", actor_id="alice", role="reviewer",
                     actor_kind="human")
    print(store.get(item.id).state)  # done
finally:
    store.close()
