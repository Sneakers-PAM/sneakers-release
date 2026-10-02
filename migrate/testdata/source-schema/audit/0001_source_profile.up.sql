-- Copyright 2026 The Sneakers-PAM Authors
-- SPDX-License-Identifier: Apache-2.0

-- Test fixture: the audit database of the original system as sneakers-migrate
-- reads it (source profile original-v1, migration version 1). Built from
-- the Sneakers-PAM audit baseline plus the differences the migration maps;
-- used to stand up a synthetic source, never a real one.

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


CREATE TABLE public.audit_records (
    seq bigint NOT NULL,
    tier integer DEFAULT 0 NOT NULL,
    action text NOT NULL,
    actor_user_id text DEFAULT ''::text NOT NULL,
    subject text DEFAULT ''::text NOT NULL,
    group_id text DEFAULT ''::text NOT NULL,
    sensitive boolean DEFAULT false NOT NULL,
    attributes jsonb DEFAULT '{}'::jsonb NOT NULL,
    occurred_at text NOT NULL,
    prev_hash text DEFAULT ''::text NOT NULL,
    hash text NOT NULL
);



ALTER TABLE ONLY public.audit_records
    ADD CONSTRAINT audit_records_pkey PRIMARY KEY (seq);



CREATE INDEX audit_records_actor_idx ON public.audit_records USING btree (actor_user_id);



CREATE INDEX audit_records_subject_idx ON public.audit_records USING btree (subject);




