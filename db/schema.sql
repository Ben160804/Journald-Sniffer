--
-- PostgreSQL database dump
--

\restrict n7IbFxINuQonocOhmSV9ttr5Pq3lmJOH8fkZVEV4eBFLldzUOhaLp7UZSdGVbc9

-- Dumped from database version 18.1
-- Dumped by pg_dump version 18.1

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET transaction_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

SET default_tablespace = '';

SET default_table_access_method = heap;

--
-- Name: auth_logs; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.auth_logs (
    id bigint NOT NULL,
    event_time timestamp without time zone NOT NULL,
    pid bigint NOT NULL,
    program text NOT NULL,
    hostname text,
    outcome boolean NOT NULL,
    derived_from_raw_id bigint[] NOT NULL
);


--
-- Name: auth_logs_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.auth_logs_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: auth_logs_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.auth_logs_id_seq OWNED BY public.auth_logs.id;


--
-- Name: raw_logs; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.raw_logs (
    id bigint NOT NULL,
    program text NOT NULL,
    hostname text,
    ingestion_time timestamp without time zone NOT NULL,
    pid integer,
    raw_msg text NOT NULL,
    log_source text NOT NULL,
    journal_cursor text
);


--
-- Name: raw_logs_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.raw_logs_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: raw_logs_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.raw_logs_id_seq OWNED BY public.raw_logs.id;


--
-- Name: auth_logs id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.auth_logs ALTER COLUMN id SET DEFAULT nextval('public.auth_logs_id_seq'::regclass);


--
-- Name: raw_logs id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.raw_logs ALTER COLUMN id SET DEFAULT nextval('public.raw_logs_id_seq'::regclass);


--
-- Name: auth_logs auth_logs_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.auth_logs
    ADD CONSTRAINT auth_logs_pkey PRIMARY KEY (id);


--
-- Name: raw_logs raw_logs_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.raw_logs
    ADD CONSTRAINT raw_logs_pkey PRIMARY KEY (id);


--
-- PostgreSQL database dump complete
--

\unrestrict n7IbFxINuQonocOhmSV9ttr5Pq3lmJOH8fkZVEV4eBFLldzUOhaLp7UZSdGVbc9

