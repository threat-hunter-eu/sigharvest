"""Baseline schema of the public edition (squashed from the internal migration history).

Revision ID: 0001
Revises:

Creates every table, index, the FTS5 full-text table, the revision triggers that invalidate page caches and the
immutability triggers of the parse-error (quarantine) history. Later schema changes are new revisions on top of this one.
"""

from alembic import op

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None

TABLES = (
    """CREATE TABLE sources (
	id INTEGER NOT NULL, 
	name VARCHAR(200) NOT NULL, 
	type VARCHAR(10) NOT NULL, 
	url TEXT NOT NULL, 
	ref VARCHAR(200), 
	licence VARCHAR(100), 
	priority INTEGER NOT NULL, 
	enabled BOOLEAN NOT NULL, 
	last_commit VARCHAR(64), 
	last_sync_at DATETIME, 
	PRIMARY KEY (id), 
	UNIQUE (name)
)""",
    """CREATE TABLE rule_versions (
	id INTEGER NOT NULL, 
	content_hash VARCHAR(64) NOT NULL, 
	logic_hash VARCHAR(64) NOT NULL, 
	semantic_hash VARCHAR(64), 
	semantic_fingerprint VARCHAR(64), 
	rule_id VARCHAR(36) NOT NULL, 
	id_flag VARCHAR(20), 
	kind VARCHAR(12) NOT NULL, 
	title TEXT, 
	title_slug VARCHAR(300), 
	status VARCHAR(20), 
	level VARCHAR(20), 
	author TEXT, 
	date VARCHAR(20), 
	modified VARCHAR(20), 
	rule_license VARCHAR(100), 
	product VARCHAR(100), 
	category VARCHAR(100), 
	service VARCHAR(100), 
	tags JSON NOT NULL, 
	flags JSON NOT NULL, 
	raw TEXT NOT NULL, 
	original_raw BLOB, 
	context_digest VARCHAR(64), 
	first_seen DATETIME NOT NULL, 
	PRIMARY KEY (id), 
	UNIQUE (content_hash)
)""",
    """CREATE TABLE correlation_references (
	name VARCHAR(256) NOT NULL, 
	content_hash VARCHAR(64) NOT NULL, 
	logic_hash VARCHAR(64) NOT NULL, 
	PRIMARY KEY (name, content_hash)
)""",
    """CREATE TABLE correlation_reference_dirty (
	content_hash VARCHAR(64) NOT NULL, 
	PRIMARY KEY (content_hash)
)""",
    """CREATE TABLE correlation_reference_state (
	id INTEGER NOT NULL, 
	fingerprint VARCHAR(64), 
	input_token VARCHAR(32) NOT NULL, 
	built_input VARCHAR(32), 
	projection_token VARCHAR(32) NOT NULL, 
	built_projection VARCHAR(32), 
	PRIMARY KEY (id)
)""",
    """CREATE TABLE quarantine_blobs (
	hash VARCHAR(64) NOT NULL, 
	raw BLOB NOT NULL, 
	size INTEGER NOT NULL, 
	created_at DATETIME NOT NULL, 
	PRIMARY KEY (hash)
)""",
    """CREATE TABLE test_runs (
	id INTEGER NOT NULL, 
	stage VARCHAR(20) NOT NULL, 
	params JSON NOT NULL, 
	started_at DATETIME NOT NULL, 
	finished_at DATETIME, 
	status VARCHAR(20) NOT NULL, 
	PRIMARY KEY (id)
)""",
    """CREATE TABLE source_overlaps (
	name VARCHAR(200) NOT NULL, 
	other VARCHAR(200) NOT NULL, 
	exact INTEGER NOT NULL, 
	near INTEGER NOT NULL, 
	PRIMARY KEY (name, other)
)""",
    """CREATE TABLE source_summaries (
	name VARCHAR(200) NOT NULL, 
	documents INTEGER DEFAULT '0' NOT NULL, 
	logic INTEGER NOT NULL, 
	families INTEGER NOT NULL, 
	only INTEGER NOT NULL, 
	valid_pct INTEGER, 
	avg_score INTEGER NOT NULL, 
	PRIMARY KEY (name)
)""",
    """CREATE TABLE collections (
	id INTEGER NOT NULL, 
	name VARCHAR(80) NOT NULL, 
	description TEXT, 
	created_at DATETIME NOT NULL, 
	PRIMARY KEY (id), 
	UNIQUE (name)
)""",
    """CREATE TABLE source_roots (
	name VARCHAR(200) NOT NULL, 
	root VARCHAR(200) NOT NULL, 
	parent VARCHAR(200), 
	containment FLOAT NOT NULL, 
	logic INTEGER NOT NULL, 
	PRIMARY KEY (name)
)""",
    """CREATE TABLE near_duplicates (
	a VARCHAR(64) NOT NULL, 
	b VARCHAR(64) NOT NULL, 
	jaccard FLOAT NOT NULL, 
	PRIMARY KEY (a, b)
)""",
    """CREATE TABLE meta (
	"key" VARCHAR(60) NOT NULL, 
	value TEXT NOT NULL, 
	updated_at DATETIME NOT NULL, 
	PRIMARY KEY ("key")
)""",
    """CREATE TABLE update_runs (
	id INTEGER NOT NULL, 
	started_at DATETIME NOT NULL, 
	finished_at DATETIME, 
	status VARCHAR(20) NOT NULL, 
	reasons JSON NOT NULL, 
	durations JSON NOT NULL, 
	counts JSON NOT NULL, 
	gates JSON NOT NULL, 
	report TEXT, 
	PRIMARY KEY (id)
)""",
    """CREATE TABLE index_family_links (
	owner TEXT NOT NULL, 
	"key" TEXT NOT NULL, 
	logic_hash VARCHAR(64) NOT NULL, 
	PRIMARY KEY (owner, "key", logic_hash)
)""",
    """CREATE TABLE index_signatures (
	logic_hash VARCHAR(64) NOT NULL, 
	logsource TEXT NOT NULL, 
	items JSON NOT NULL, 
	signature JSON NOT NULL, 
	PRIMARY KEY (logic_hash)
)""",
    """CREATE TABLE index_buckets (
	bucket TEXT NOT NULL, 
	logic_hash VARCHAR(64) NOT NULL, 
	PRIMARY KEY (bucket, logic_hash)
)""",
    """CREATE TABLE index_near_pairs (
	a VARCHAR(64) NOT NULL, 
	b VARCHAR(64) NOT NULL, 
	jaccard FLOAT NOT NULL, 
	PRIMARY KEY (a, b)
)""",
    """CREATE TABLE cache_revisions (
	name VARCHAR(60) NOT NULL, 
	revision VARCHAR(32) NOT NULL, 
	PRIMARY KEY (name)
)""",
    """CREATE TABLE search_rank (
	id INTEGER NOT NULL, 
	family_id INTEGER NOT NULL, 
	score FLOAT NOT NULL, 
	status VARCHAR(30), 
	junk BOOLEAN NOT NULL, 
	PRIMARY KEY (id)
)""",
    """CREATE TABLE search_summaries (
	name VARCHAR(60) NOT NULL, 
	revision TEXT NOT NULL, 
	payload JSON NOT NULL, 
	PRIMARY KEY (name)
)""",
    """CREATE TABLE sync_log (
	id INTEGER NOT NULL, 
	source_id INTEGER NOT NULL, 
	started_at DATETIME NOT NULL, 
	finished_at DATETIME, 
	old_commit VARCHAR(64), 
	new_commit VARCHAR(64), 
	files_added INTEGER NOT NULL, 
	files_changed INTEGER NOT NULL, 
	files_removed INTEGER NOT NULL, 
	rules_new INTEGER NOT NULL, 
	versions_new INTEGER NOT NULL, 
	quarantined INTEGER NOT NULL, 
	status VARCHAR(20) NOT NULL, 
	error TEXT, 
	PRIMARY KEY (id), 
	FOREIGN KEY(source_id) REFERENCES sources (id)
)""",
    """CREATE TABLE semantic_results (
	fingerprint VARCHAR(64) NOT NULL, 
	version_id INTEGER NOT NULL, 
	semantic_hash VARCHAR(64) NOT NULL, 
	PRIMARY KEY (fingerprint, version_id), 
	FOREIGN KEY(version_id) REFERENCES rule_versions (id)
)""",
    """CREATE TABLE occurrences (
	id INTEGER NOT NULL, 
	version_id INTEGER NOT NULL, 
	source_id INTEGER NOT NULL, 
	path TEXT NOT NULL, 
	doc_index INTEGER NOT NULL, 
	file_hash VARCHAR(64) NOT NULL, 
	span_start INTEGER, 
	span_end INTEGER, 
	"commit" VARCHAR(64), 
	present BOOLEAN NOT NULL, 
	first_seen DATETIME NOT NULL, 
	last_seen DATETIME NOT NULL, 
	PRIMARY KEY (id), 
	UNIQUE (source_id, path, doc_index, version_id), 
	FOREIGN KEY(version_id) REFERENCES rule_versions (id), 
	FOREIGN KEY(source_id) REFERENCES sources (id)
)""",
    """CREATE TABLE quarantine (
	id INTEGER NOT NULL, 
	source_id INTEGER NOT NULL, 
	path TEXT NOT NULL, 
	doc_index INTEGER NOT NULL, 
	content_hash VARCHAR(64) NOT NULL, 
	error TEXT NOT NULL, 
	present BOOLEAN NOT NULL, 
	seen_at DATETIME NOT NULL, 
	reason_code VARCHAR(32) NOT NULL, 
	reason_version INTEGER NOT NULL, 
	parser_version VARCHAR(100), 
	snapshot_hash VARCHAR(64), 
	blob_hash VARCHAR(64), 
	source_commit VARCHAR(64), 
	span_start INTEGER, 
	span_end INTEGER, 
	retention VARCHAR(32) NOT NULL, 
	last_rejected_snapshot VARCHAR(64), 
	resolution VARCHAR(32), 
	resolved_at DATETIME, 
	PRIMARY KEY (id), 
	UNIQUE (source_id, path, doc_index, content_hash), 
	FOREIGN KEY(source_id) REFERENCES sources (id), 
	FOREIGN KEY(blob_hash) REFERENCES quarantine_blobs (hash)
)""",
    """CREATE TABLE test_results (
	id INTEGER NOT NULL, 
	version_id INTEGER NOT NULL, 
	stage VARCHAR(20) NOT NULL, 
	target VARCHAR(60) NOT NULL, 
	dataset VARCHAR(100) NOT NULL, 
	status VARCHAR(20) NOT NULL, 
	hits INTEGER, 
	duration FLOAT, 
	detail JSON NOT NULL, 
	fingerprint VARCHAR(64), 
	run_id INTEGER, 
	created_at DATETIME NOT NULL, 
	PRIMARY KEY (id), 
	UNIQUE (version_id, stage, target, dataset), 
	FOREIGN KEY(version_id) REFERENCES rule_versions (id), 
	FOREIGN KEY(run_id) REFERENCES test_runs (id)
)""",
    """CREATE TABLE logic_groups (
	id INTEGER NOT NULL, 
	logic_hash VARCHAR(64) NOT NULL, 
	family_id INTEGER NOT NULL, 
	family_size INTEGER NOT NULL, 
	canonical_version_id INTEGER NOT NULL, 
	canonical_source VARCHAR(200) NOT NULL, 
	rule_id VARCHAR(36) NOT NULL, 
	kind VARCHAR(12) NOT NULL, 
	title TEXT, 
	description TEXT, 
	product VARCHAR(100), 
	category VARCHAR(100), 
	service VARCHAR(100), 
	level VARCHAR(20), 
	status VARCHAR(20), 
	author TEXT, 
	tags JSON NOT NULL, 
	datasources JSON DEFAULT '[]' NOT NULL, 
	fields JSON NOT NULL, 
	copies INTEGER NOT NULL, 
	sources JSON NOT NULL, 
	n_sources INTEGER NOT NULL, 
	n_independent INTEGER NOT NULL, 
	n_rule_ids INTEGER NOT NULL, 
	validation VARCHAR(20), 
	converts JSON NOT NULL, 
	conversion JSON, 
	score FLOAT NOT NULL, 
	modified VARCHAR(20), 
	quality_flags JSON NOT NULL, 
	junk BOOLEAN NOT NULL, 
	PRIMARY KEY (id), 
	UNIQUE (logic_hash), 
	FOREIGN KEY(canonical_version_id) REFERENCES rule_versions (id)
)""",
    """CREATE TABLE collection_items (
	id INTEGER NOT NULL, 
	collection_id INTEGER NOT NULL, 
	logic_hash VARCHAR(64) NOT NULL, 
	rule_id VARCHAR(36), 
	title TEXT, 
	note TEXT, 
	added_at DATETIME NOT NULL, 
	PRIMARY KEY (id), 
	UNIQUE (collection_id, logic_hash), 
	FOREIGN KEY(collection_id) REFERENCES collections (id)
)""",
    """CREATE TABLE quarantine_attempts (
	id INTEGER NOT NULL, 
	quarantine_id INTEGER NOT NULL, 
	parser_version VARCHAR(100) NOT NULL, 
	snapshot_hash VARCHAR(64), 
	blob_hash VARCHAR(64), 
	outcome VARCHAR(32) NOT NULL, 
	reason_code VARCHAR(32) NOT NULL, 
	version_id INTEGER, 
	created_at DATETIME NOT NULL, 
	PRIMARY KEY (id), 
	FOREIGN KEY(quarantine_id) REFERENCES quarantine (id), 
	FOREIGN KEY(blob_hash) REFERENCES quarantine_blobs (hash), 
	FOREIGN KEY(version_id) REFERENCES rule_versions (id)
)""",
    """CREATE TABLE test_result_history (
	id INTEGER NOT NULL, 
	result_id INTEGER NOT NULL, 
	fingerprint VARCHAR(64), 
	snapshot JSON NOT NULL, 
	PRIMARY KEY (id), 
	FOREIGN KEY(result_id) REFERENCES test_results (id)
)""",
    """CREATE INDEX ix_rule_versions_category ON rule_versions (category)""",
    """CREATE INDEX ix_rule_versions_rule_id ON rule_versions (rule_id)""",
    """CREATE INDEX ix_rule_versions_semantic_hash ON rule_versions (semantic_hash)""",
    """CREATE INDEX ix_rule_versions_logic_hash ON rule_versions (logic_hash)""",
    """CREATE INDEX ix_rule_versions_service ON rule_versions (service)""",
    """CREATE INDEX ix_rule_versions_product ON rule_versions (product)""",
    """CREATE INDEX ix_versions_rule_logic ON rule_versions (rule_id, logic_hash)""",
    """CREATE INDEX ix_rule_versions_title_slug ON rule_versions (title_slug)""",
    """CREATE INDEX ix_correlation_references_content ON correlation_references (content_hash)""",
    """CREATE INDEX ix_source_overlaps_rank ON source_overlaps (name, exact, near)""",
    """CREATE INDEX ix_near_duplicates_b ON near_duplicates (b)""",
    """CREATE INDEX ix_update_runs_status ON update_runs (status)""",
    """CREATE INDEX ix_index_family_key ON index_family_links ("key")""",
    """CREATE INDEX ix_index_family_logic ON index_family_links (logic_hash)""",
    """CREATE INDEX ix_index_buckets_logic ON index_buckets (logic_hash)""",
    """CREATE INDEX ix_index_near_b ON index_near_pairs (b)""",
    """CREATE INDEX ix_occurrences_version_id ON occurrences (version_id)""",
    """CREATE INDEX ix_occurrences_source_version ON occurrences (source_id, version_id)""",
    """CREATE INDEX ix_occurrences_source_id ON occurrences (source_id)""",
    """CREATE INDEX ix_occurrences_source_path ON occurrences (source_id, path, present)""",
    """CREATE INDEX ix_occurrences_present ON occurrences (present)""",
    """CREATE INDEX ix_quarantine_source_id ON quarantine (source_id)""",
    """CREATE INDEX ix_quarantine_source_path ON quarantine (source_id, path)""",
    """CREATE INDEX ix_test_results_version_id ON test_results (version_id)""",
    """CREATE INDEX ix_telemetry_conversion_current ON test_results (version_id, target, json_extract(detail, '$.toolchain')) WHERE stage='convert' AND dataset='' AND status IN ('ok','partial','warning')""",
    """CREATE INDEX ix_results_stage_target ON test_results (stage, target)""",
    """CREATE INDEX ix_logic_groups_service ON logic_groups (service)""",
    """CREATE INDEX ix_logic_groups_product ON logic_groups (product)""",
    """CREATE INDEX ix_logic_groups_category ON logic_groups (category)""",
    """CREATE INDEX ix_logic_groups_junk ON logic_groups (junk)""",
    """CREATE INDEX ix_groups_search_rank ON logic_groups (-score, id, family_id) WHERE junk = 0 AND coalesce(status, '') NOT IN ('deprecated', 'unsupported')""",
    """CREATE INDEX ix_logic_groups_validation ON logic_groups (validation)""",
    """CREATE INDEX ix_logic_groups_rule_id ON logic_groups (rule_id)""",
    """CREATE INDEX ix_groups_family_logic ON logic_groups (family_id, logic_hash)""",
    """CREATE INDEX ix_logic_groups_family_id ON logic_groups (family_id)""",
    """CREATE INDEX ix_logic_groups_n_sources ON logic_groups (n_sources)""",
    """CREATE INDEX ix_logic_groups_score ON logic_groups (score)""",
    """CREATE INDEX ix_logic_groups_status ON logic_groups (status)""",
    """CREATE INDEX ix_logic_groups_n_independent ON logic_groups (n_independent)""",
    """CREATE INDEX ix_logic_groups_level ON logic_groups (level)""",
    """CREATE INDEX ix_collection_items_collection_id ON collection_items (collection_id)""",
    """CREATE INDEX ix_collection_items_logic_hash ON collection_items (logic_hash)""",
    """CREATE INDEX ix_collection_items_rule_id ON collection_items (rule_id)""",
    """CREATE INDEX ix_quarantine_attempts_quarantine_id ON quarantine_attempts (quarantine_id)""",
    """CREATE INDEX ix_quarantine_attempts_snapshot ON quarantine_attempts (snapshot_hash, outcome, quarantine_id)""",
    """CREATE INDEX ix_test_result_history_result_id ON test_result_history (result_id)""",
    """CREATE VIRTUAL TABLE rules_fts USING fts5(title, description, tags, logsource, fields, detection, author, tokenize = "unicode61 remove_diacritics 2 tokenchars '_'")""",
)

TRIGGERS = (
    """CREATE TRIGGER cache_collection_items_delete AFTER DELETE ON collection_items BEGIN UPDATE cache_revisions SET revision=lower(hex(randomblob(16))) WHERE name='collection_items'; END""",
    """CREATE TRIGGER cache_collection_items_insert AFTER INSERT ON collection_items BEGIN UPDATE cache_revisions SET revision=lower(hex(randomblob(16))) WHERE name='collection_items'; END""",
    """CREATE TRIGGER cache_collection_items_update AFTER UPDATE ON collection_items BEGIN UPDATE cache_revisions SET revision=lower(hex(randomblob(16))) WHERE name='collection_items'; END""",
    """CREATE TRIGGER cache_collections_delete AFTER DELETE ON collections BEGIN UPDATE cache_revisions SET revision=lower(hex(randomblob(16))) WHERE name='collections'; END""",
    """CREATE TRIGGER cache_collections_insert AFTER INSERT ON collections BEGIN UPDATE cache_revisions SET revision=lower(hex(randomblob(16))) WHERE name='collections'; END""",
    """CREATE TRIGGER cache_collections_update AFTER UPDATE ON collections BEGIN UPDATE cache_revisions SET revision=lower(hex(randomblob(16))) WHERE name='collections'; END""",
    """CREATE TRIGGER cache_logic_groups_delete AFTER DELETE ON logic_groups BEGIN UPDATE cache_revisions SET revision=lower(hex(randomblob(16))) WHERE name='logic_groups'; END""",
    """CREATE TRIGGER cache_logic_groups_insert AFTER INSERT ON logic_groups BEGIN UPDATE cache_revisions SET revision=lower(hex(randomblob(16))) WHERE name='logic_groups'; END""",
    """CREATE TRIGGER cache_logic_groups_update AFTER UPDATE ON logic_groups BEGIN UPDATE cache_revisions SET revision=lower(hex(randomblob(16))) WHERE name='logic_groups'; END""",
    """CREATE TRIGGER cache_meta_delete AFTER DELETE ON meta BEGIN UPDATE cache_revisions SET revision=lower(hex(randomblob(16))) WHERE name='meta'; END""",
    """CREATE TRIGGER cache_meta_insert AFTER INSERT ON meta BEGIN UPDATE cache_revisions SET revision=lower(hex(randomblob(16))) WHERE name='meta'; END""",
    """CREATE TRIGGER cache_meta_update AFTER UPDATE ON meta BEGIN UPDATE cache_revisions SET revision=lower(hex(randomblob(16))) WHERE name='meta'; END""",
    """CREATE TRIGGER cache_near_duplicates_delete AFTER DELETE ON near_duplicates BEGIN UPDATE cache_revisions SET revision=lower(hex(randomblob(16))) WHERE name='near_duplicates'; END""",
    """CREATE TRIGGER cache_near_duplicates_insert AFTER INSERT ON near_duplicates BEGIN UPDATE cache_revisions SET revision=lower(hex(randomblob(16))) WHERE name='near_duplicates'; END""",
    """CREATE TRIGGER cache_near_duplicates_update AFTER UPDATE ON near_duplicates BEGIN UPDATE cache_revisions SET revision=lower(hex(randomblob(16))) WHERE name='near_duplicates'; END""",
    """CREATE TRIGGER cache_occurrences_delete AFTER DELETE ON occurrences BEGIN UPDATE cache_revisions SET revision=lower(hex(randomblob(16))) WHERE name='occurrences'; END""",
    """CREATE TRIGGER cache_occurrences_insert AFTER INSERT ON occurrences BEGIN UPDATE cache_revisions SET revision=lower(hex(randomblob(16))) WHERE name='occurrences'; END""",
    """CREATE TRIGGER cache_occurrences_update AFTER UPDATE ON occurrences BEGIN UPDATE cache_revisions SET revision=lower(hex(randomblob(16))) WHERE name='occurrences'; END""",
    """CREATE TRIGGER cache_rule_versions_delete AFTER DELETE ON rule_versions BEGIN UPDATE cache_revisions SET revision=lower(hex(randomblob(16))) WHERE name='rule_versions'; END""",
    """CREATE TRIGGER cache_rule_versions_insert AFTER INSERT ON rule_versions BEGIN UPDATE cache_revisions SET revision=lower(hex(randomblob(16))) WHERE name='rule_versions'; END""",
    """CREATE TRIGGER cache_rule_versions_update AFTER UPDATE ON rule_versions BEGIN UPDATE cache_revisions SET revision=lower(hex(randomblob(16))) WHERE name='rule_versions'; END""",
    """CREATE TRIGGER cache_source_overlaps_delete AFTER DELETE ON source_overlaps BEGIN UPDATE cache_revisions SET revision=lower(hex(randomblob(16))) WHERE name='source_overlaps'; END""",
    """CREATE TRIGGER cache_source_overlaps_insert AFTER INSERT ON source_overlaps BEGIN UPDATE cache_revisions SET revision=lower(hex(randomblob(16))) WHERE name='source_overlaps'; END""",
    """CREATE TRIGGER cache_source_overlaps_update AFTER UPDATE ON source_overlaps BEGIN UPDATE cache_revisions SET revision=lower(hex(randomblob(16))) WHERE name='source_overlaps'; END""",
    """CREATE TRIGGER cache_source_summaries_delete AFTER DELETE ON source_summaries BEGIN UPDATE cache_revisions SET revision=lower(hex(randomblob(16))) WHERE name='source_summaries'; END""",
    """CREATE TRIGGER cache_source_summaries_insert AFTER INSERT ON source_summaries BEGIN UPDATE cache_revisions SET revision=lower(hex(randomblob(16))) WHERE name='source_summaries'; END""",
    """CREATE TRIGGER cache_source_summaries_update AFTER UPDATE ON source_summaries BEGIN UPDATE cache_revisions SET revision=lower(hex(randomblob(16))) WHERE name='source_summaries'; END""",
    """CREATE TRIGGER cache_sources_delete AFTER DELETE ON sources BEGIN UPDATE cache_revisions SET revision=lower(hex(randomblob(16))) WHERE name='sources'; END""",
    """CREATE TRIGGER cache_sources_insert AFTER INSERT ON sources BEGIN UPDATE cache_revisions SET revision=lower(hex(randomblob(16))) WHERE name='sources'; END""",
    """CREATE TRIGGER cache_sources_update AFTER UPDATE ON sources BEGIN UPDATE cache_revisions SET revision=lower(hex(randomblob(16))) WHERE name='sources'; END""",
    """CREATE TRIGGER cache_sync_log_delete AFTER DELETE ON sync_log BEGIN UPDATE cache_revisions SET revision=lower(hex(randomblob(16))) WHERE name='sync_log'; END""",
    """CREATE TRIGGER cache_sync_log_insert AFTER INSERT ON sync_log BEGIN UPDATE cache_revisions SET revision=lower(hex(randomblob(16))) WHERE name='sync_log'; END""",
    """CREATE TRIGGER cache_sync_log_update AFTER UPDATE ON sync_log BEGIN UPDATE cache_revisions SET revision=lower(hex(randomblob(16))) WHERE name='sync_log'; END""",
    """CREATE TRIGGER cache_test_results_delete AFTER DELETE ON test_results BEGIN UPDATE cache_revisions SET revision=lower(hex(randomblob(16))) WHERE name='test_results'; END""",
    """CREATE TRIGGER cache_test_results_insert AFTER INSERT ON test_results BEGIN UPDATE cache_revisions SET revision=lower(hex(randomblob(16))) WHERE name='test_results'; END""",
    """CREATE TRIGGER cache_test_results_update AFTER UPDATE ON test_results BEGIN UPDATE cache_revisions SET revision=lower(hex(randomblob(16))) WHERE name='test_results'; END""",
    """CREATE TRIGGER correlation_ref_input_delete AFTER DELETE ON rule_versions  BEGIN INSERT OR IGNORE INTO correlation_reference_dirty(content_hash) VALUES(old.content_hash); UPDATE correlation_reference_state SET input_token=lower(hex(randomblob(16))) WHERE id=1; END""",
    """CREATE TRIGGER correlation_ref_input_insert AFTER INSERT ON rule_versions  BEGIN INSERT OR IGNORE INTO correlation_reference_dirty(content_hash) VALUES(new.content_hash); UPDATE correlation_reference_state SET input_token=lower(hex(randomblob(16))) WHERE id=1; END""",
    """CREATE TRIGGER correlation_ref_input_update AFTER UPDATE OF raw,content_hash,logic_hash ON rule_versions WHEN old.raw IS NOT new.raw OR old.content_hash IS NOT new.content_hash OR old.logic_hash IS NOT new.logic_hash BEGIN INSERT OR IGNORE INTO correlation_reference_dirty(content_hash) VALUES(old.content_hash); INSERT OR IGNORE INTO correlation_reference_dirty(content_hash) VALUES(new.content_hash); UPDATE correlation_reference_state SET input_token=lower(hex(randomblob(16))) WHERE id=1; END""",
    """CREATE TRIGGER correlation_ref_queue_delete AFTER DELETE ON correlation_reference_dirty BEGIN UPDATE correlation_reference_state SET fingerprint=NULL WHERE id=1; END""",
    """CREATE TRIGGER correlation_ref_queue_update AFTER UPDATE ON correlation_reference_dirty BEGIN UPDATE correlation_reference_state SET fingerprint=NULL WHERE id=1; END""",
    """CREATE TRIGGER correlation_ref_rows_delete AFTER DELETE ON correlation_references BEGIN UPDATE correlation_reference_state SET projection_token=lower(hex(randomblob(16))) WHERE id=1; END""",
    """CREATE TRIGGER correlation_ref_rows_insert AFTER INSERT ON correlation_references BEGIN UPDATE correlation_reference_state SET projection_token=lower(hex(randomblob(16))) WHERE id=1; END""",
    """CREATE TRIGGER correlation_ref_rows_update AFTER UPDATE ON correlation_references BEGIN UPDATE correlation_reference_state SET projection_token=lower(hex(randomblob(16))) WHERE id=1; END""",
    """CREATE TRIGGER quarantine_attempts_delete BEFORE DELETE ON quarantine_attempts BEGIN SELECT RAISE(ABORT, 'immutable dead-letter history'); END""",
    """CREATE TRIGGER quarantine_attempts_update BEFORE UPDATE ON quarantine_attempts BEGIN SELECT RAISE(ABORT, 'immutable dead-letter history'); END""",
    """CREATE TRIGGER quarantine_blobs_delete BEFORE DELETE ON quarantine_blobs BEGIN SELECT RAISE(ABORT, 'immutable dead-letter history'); END""",
    """CREATE TRIGGER quarantine_blobs_update BEFORE UPDATE ON quarantine_blobs BEGIN SELECT RAISE(ABORT, 'immutable dead-letter history'); END""",
    """CREATE TRIGGER quarantine_provenance_update BEFORE UPDATE OF
        source_id, path, doc_index, content_hash, parser_version, snapshot_hash, blob_hash,
        source_commit, span_start, span_end, retention, reason_code, reason_version ON quarantine
        BEGIN SELECT RAISE(ABORT, 'immutable dead-letter provenance'); END""",
)

SEEDS = (
    """INSERT INTO cache_revisions(name, revision) VALUES ('logic_groups', '0'), ('rule_versions', '0'), ('occurrences', '0'), ('sources', '0'), ('collections', '0'), ('collection_items', '0'), ('test_results', '0'), ('meta', '0'), ('sync_log', '0'), ('source_summaries', '0'), ('source_overlaps', '0'), ('near_duplicates', '0')""",
    """INSERT INTO correlation_reference_state(id, fingerprint, input_token, built_input, projection_token, built_projection) VALUES (1, NULL, lower(hex(randomblob(16))), NULL, lower(hex(randomblob(16))), NULL)""",
)


def upgrade() -> None:
    for statement in (*TABLES, *TRIGGERS, *SEEDS):
        op.execute(statement)


def downgrade() -> None:
    raise NotImplementedError("the baseline cannot be downgraded")
