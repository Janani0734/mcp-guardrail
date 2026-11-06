-- MCP-Guardrail policy engine table.
-- Run once in the Supabase SQL Editor before deploying the server.

create table if not exists public.policies (
  id uuid primary key default gen_random_uuid(),
  tool_name text not null,
  target_pattern text not null,
  action text not null check (action in ('DENY', 'REQUIRE_APPROVAL')),
  priority integer not null default 100,
  expiry_seconds integer check (expiry_seconds between 30 and 86400),
  reason text,
  created_at timestamptz not null default now()
);

-- The backend uses the service-role key, which bypasses row-level security.
-- Enabling it with no policies keeps the table closed to the public anon key.
alter table public.policies enable row level security;

-- Example rule: demo-task-2 can never be deleted.
insert into public.policies
  (tool_name, target_pattern, action, priority, reason)
values
  ('request_delete_task', 'demo-task-2', 'DENY', 10, 'Protected demo record');
