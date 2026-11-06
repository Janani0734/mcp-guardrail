-- db/security.sql
-- MCP-Guardrail: lock the database down to the backend (service_role) only.
-- Safe to re-run (idempotent). Run in the Supabase SQL Editor, or section by section.
-- Function signatures below match the ones currently deployed.

-- =====================================================================
-- 1. FUNCTIONS: backend-only
--    SECURITY DEFINER functions ignore RLS, so EXECUTE grants are the
--    only thing stopping anyone with the public anon key from calling
--    /rest/v1/rpc/audit_append_event and forging audit events.
-- =====================================================================
revoke execute on function public.audit_append_event(uuid, text, text, text, jsonb)
  from public, anon, authenticated;
revoke execute on function public.audit_get_chain_head()
  from public, anon, authenticated;
revoke execute on function public.audit_verify_chain()
  from public, anon, authenticated;
revoke execute on function public.audit_event_canonical_text(uuid, timestamptz, uuid, text, text, text, jsonb, text)
  from public, anon, authenticated;
revoke execute on function public.guardrail_finalize_request(uuid, text)
  from public, anon, authenticated;

grant execute on function public.audit_append_event(uuid, text, text, text, jsonb)
  to service_role;
grant execute on function public.audit_get_chain_head()
  to service_role;
grant execute on function public.audit_verify_chain()
  to service_role;
grant execute on function public.audit_event_canonical_text(uuid, timestamptz, uuid, text, text, text, jsonb, text)
  to service_role;
grant execute on function public.guardrail_finalize_request(uuid, text)
  to service_role;

-- =====================================================================
-- 2. TABLES: remove grants (second layer behind RLS)
-- =====================================================================
revoke all on table
  public.approval_requests,
  public.audit_events,
  public.audit_chain_anchors,
  public.policies,
  public.sandbox_tasks
from anon, authenticated;

-- Make sure the backend role keeps what it needs.
grant select, insert, update, delete on table
  public.approval_requests,
  public.audit_chain_anchors,
  public.policies,
  public.sandbox_tasks
to service_role;

-- Audit rows are only ever INSERTed by the SECURITY DEFINER function
-- (runs as the function owner), so the backend role only needs to read them.
grant select on table public.audit_events to service_role;
revoke insert, update, delete, truncate on table public.audit_events from service_role;

-- =====================================================================
-- 3. DEFAULTS: new tables/functions are not public by default
-- =====================================================================
alter default privileges for role postgres in schema public
  revoke all on tables from anon, authenticated;
alter default privileges for role postgres in schema public
  revoke execute on functions from anon, authenticated;
alter default privileges for role postgres
  revoke execute on functions from public;

-- =====================================================================
-- 4. ROW LEVEL SECURITY (already enabled; kept here so the repo is the
--    source of truth). RLS on + no policy = no access for anon/authenticated.
-- =====================================================================
alter table public.approval_requests   enable row level security;
alter table public.audit_events        enable row level security;
alter table public.audit_chain_anchors enable row level security;
alter table public.policies            enable row level security;
alter table public.sandbox_tasks       enable row level security;

drop policy if exists audit_events_no_delete on public.audit_events;
create policy audit_events_no_delete
  on public.audit_events for delete to public using (false);

drop policy if exists audit_events_no_update on public.audit_events;
create policy audit_events_no_update
  on public.audit_events for update to public using (false);

-- =====================================================================
-- 5. APPEND-ONLY TRIGGERS
--    RLS does not bind service_role or the table owner; triggers do.
--    A table owner can still drop these, so the audit log is
--    tamper-evident (hash chain + external anchors), not immutable.
-- =====================================================================
create or replace function public.audit_events_block_mutation()
  returns trigger
  language plpgsql
  set search_path to ''
as $$
begin
  raise exception 'audit_events is append-only';
end;
$$;

drop trigger if exists audit_events_no_update_delete on public.audit_events;
create trigger audit_events_no_update_delete
  before update or delete on public.audit_events
  for each row execute function public.audit_events_block_mutation();

drop trigger if exists audit_events_no_truncate on public.audit_events;
create trigger audit_events_no_truncate
  before truncate on public.audit_events
  for each statement execute function public.audit_events_block_mutation();

-- =====================================================================
-- 6. CONFIRM THE CHAIN STILL VERIFIES (run on its own; expect verified = true)
-- =====================================================================
-- select * from public.audit_verify_chain();
