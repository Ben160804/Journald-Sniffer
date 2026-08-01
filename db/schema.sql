CREATE TABLE raw_logs (
    id              bigserial PRIMARY KEY,
    program         text NOT NULL,
    hostname        text,
    ingestion_time  timestamp NOT NULL,
    event_time      timestamp,
    pid             integer,
    raw_msg         jsonb NOT NULL,
    log_source      text NOT NULL,
    journal_cursor  text
);

CREATE TABLE auth_logs (
    id                  bigserial PRIMARY KEY,
    event_time          timestamp NOT NULL,
    program             text NOT NULL,
    pid                 bigint NOT NULL,
    action              text NOT NULL,
    outcome             text NOT NULL,
    username            text,
    uid                 text,
    src_ip              text,
    hostname            text,
    start_time          timestamp NOT NULL,
    end_time            timestamp NOT NULL,
    failure_count       integer NOT NULL DEFAULT 0,
    success_count       integer NOT NULL DEFAULT 0,
    neutral_count       integer NOT NULL DEFAULT 0,
    derived_from_raw_id bigint[] NOT NULL,
    jcursor             text[] NOT NULL
);

CREATE TABLE ingest_state (
    id              boolean PRIMARY KEY DEFAULT true,
    last_jcursor    text,
    CONSTRAINT single_row CHECK (id = true)
);

INSERT INTO ingest_state (id, last_jcursor) VALUES (TRUE, NULL);
