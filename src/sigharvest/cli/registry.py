"""Import targets for CLI commands; help summaries live in help.py."""

GROUPS = {
    "sources": "sources.sources_app",
    "collection": "collection.collection_app",
    "release": "export.release_app",
    "site": "share.site_app",
    "runs": "health.runs_app",
    "quarantine": "quarantine.quarantine_app",
    "db": "database.db_app",
}

COMMANDS = {
    "init": ("pipeline.init", None),
    "update": ("pipeline.update", None),
    "sync": ("pipeline.sync", None),
    "index": ("pipeline.index_cmd", None),
    "test": ("pipeline.test_cmd", None),
    "stats": ("pipeline.stats", None),
    "search": ("browse.search_cmd", None),
    "list": ("browse.search_cmd", None),
    "show": ("browse.show", None),
    "diff": ("browse.diff", None),
    "dedupe": ("browse.dedupe", None),
    "export": ("export.export", None),
    "convert": ("export.convert", None),
    "coverage": ("reports.coverage", None),
    "changes": ("reports.changes_cmd", None),
    "report": ("reports.report", None),
    "discover": ("reports.discover", None),
    "lint": ("share.lint", None),
    "doctor": ("health.doctor", None),
    "serve": ("serve.serve", None),
    "version": ("health.version", None),
}

# Hidden aliases: not listed in help, same command. `web` is the name suriharvest used for `serve`.
ALIASES = {"web": "serve"}
