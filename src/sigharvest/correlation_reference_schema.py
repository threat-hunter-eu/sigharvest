"""Version-1 disposable reference schema, shared by migration and loss recovery.

Keep this DDL contract compatible with migration 0042. No historical/user tables
are created or changed here. Publication is the caller's transaction.
"""

from typing import cast

from sqlalchemy import Connection, Table

from sigharvest.models import CorrelationReference, CorrelationReferenceDirty, CorrelationReferenceState

TABLES = tuple(cast(Table, model.__table__) for model in (CorrelationReference, CorrelationReferenceDirty, CorrelationReferenceState))
TRIGGERS = (
    *(f"correlation_ref_{kind}_{action}" for kind in ("input", "rows") for action in ("insert", "update", "delete")),
    "correlation_ref_queue_update",
    "correlation_ref_queue_delete",
)
OBJECTS = {table.name for table in TABLES} | set(TRIGGERS) | {"ix_correlation_references_content"}


def install(connection: Connection) -> None:
    """Create absent derived objects; existing rows and receipts remain intact."""
    for table in TABLES:
        table.create(connection, checkfirst=True)
    connection.exec_driver_sql("CREATE INDEX IF NOT EXISTS ix_correlation_references_content ON correlation_references(content_hash)")
    connection.exec_driver_sql(
        "INSERT OR IGNORE INTO correlation_reference_state(id,input_token,projection_token) VALUES(1,lower(hex(randomblob(16))),lower(hex(randomblob(16))))"
    )
    for action in ("insert", "update", "delete"):
        event = "UPDATE OF raw,content_hash,logic_hash" if action == "update" else action.upper()
        when = "WHEN old.raw IS NOT new.raw OR old.content_hash IS NOT new.content_hash OR old.logic_hash IS NOT new.logic_hash" if action == "update" else ""
        sides = ("old", "new") if action == "update" else ("old",) if action == "delete" else ("new",)
        queue = " ".join("INSERT OR IGNORE INTO correlation_reference_dirty(content_hash) VALUES(" + side + ".content_hash);" for side in sides)
        connection.exec_driver_sql(
            f"CREATE TRIGGER IF NOT EXISTS correlation_ref_input_{action} AFTER {event} ON rule_versions {when} "  # noqa: S608 - fixed DDL
            f"BEGIN {queue} UPDATE correlation_reference_state SET input_token=lower(hex(randomblob(16))) WHERE id=1; END"
        )
        connection.exec_driver_sql(
            f"CREATE TRIGGER IF NOT EXISTS correlation_ref_rows_{action} AFTER {action.upper()} ON correlation_references "  # noqa: S608 - fixed DDL
            "BEGIN UPDATE correlation_reference_state SET projection_token=lower(hex(randomblob(16))) WHERE id=1; END"
        )
    for action in ("update", "delete"):
        # A lost/rewritten queue row cannot be acknowledged as a complete delta.
        # Normal maintenance clears the queue then publishes its receipt atomically.
        connection.exec_driver_sql(
            f"CREATE TRIGGER IF NOT EXISTS correlation_ref_queue_{action} AFTER {action.upper()} ON correlation_reference_dirty "  # noqa: S608 - fixed DDL
            "BEGIN UPDATE correlation_reference_state SET fingerprint=NULL WHERE id=1; END"
        )
