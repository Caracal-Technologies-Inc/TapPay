create table public.merchants (id uuid primary key default gen_random_uuid(), owner_id uuid not null references auth.users(id), name text not null check(char_length(name) between 1 and 160), created_at timestamptz not null default now());
create index merchants_owner_idx on public.merchants(owner_id);
create table public.merchant_sites (id uuid primary key default gen_random_uuid(), merchant_id uuid not null references public.merchants(id), origin text not null check(origin like 'https://%'), verified boolean not null default false, unique(merchant_id,origin));
create table public.provider_connections (id uuid primary key default gen_random_uuid(), merchant_id uuid not null references public.merchants(id), provider text not null, status text not null default 'pending' check(status in ('pending','disabled')), unique(merchant_id,provider));
create table public.checkout_sessions (id uuid primary key default gen_random_uuid(), merchant_id uuid not null references public.merchants(id), amount_minor bigint not null check(amount_minor>0), currency text not null check(currency ~ '^[A-Z]{3}$'), status text not null default 'created' check(status in ('created','simulated','cancelled','expired')), created_at timestamptz not null default now());
create table public.checkout_events (id uuid primary key default gen_random_uuid(), session_id uuid not null references public.checkout_sessions(id), event_type text not null check(event_type in ('created','simulated','cancelled','expired')), created_at timestamptz not null default now());
create index sites_merchant_idx on public.merchant_sites(merchant_id);
create index sessions_merchant_idx on public.checkout_sessions(merchant_id);
create index events_session_idx on public.checkout_events(session_id);

alter table public.merchants enable row level security;
revoke all on public.merchants from anon, authenticated;
grant select on public.merchants to authenticated;
grant select,insert,update,delete on public.merchants to service_role;
create policy owner_read on public.merchants for select to authenticated using (owner_id = (select auth.uid()));

alter table public.merchant_sites enable row level security;
revoke all on public.merchant_sites from anon, authenticated;
grant select on public.merchant_sites to authenticated;
grant select,insert,update,delete on public.merchant_sites to service_role;
create policy owner_read on public.merchant_sites for select to authenticated using (exists (select 1 from public.merchants m where m.id=merchant_sites.merchant_id and m.owner_id=(select auth.uid())));

alter table public.provider_connections enable row level security;
revoke all on public.provider_connections from anon, authenticated;
grant select on public.provider_connections to authenticated;
grant select,insert,update,delete on public.provider_connections to service_role;
create policy owner_read on public.provider_connections for select to authenticated using (exists (select 1 from public.merchants m where m.id=provider_connections.merchant_id and m.owner_id=(select auth.uid())));

alter table public.checkout_sessions enable row level security;
revoke all on public.checkout_sessions from anon, authenticated;
grant select on public.checkout_sessions to authenticated;
grant select,insert,update,delete on public.checkout_sessions to service_role;
create policy owner_read on public.checkout_sessions for select to authenticated using (exists (select 1 from public.merchants m where m.id=checkout_sessions.merchant_id and m.owner_id=(select auth.uid())));

alter table public.checkout_events enable row level security;
revoke all on public.checkout_events from anon, authenticated;
grant select on public.checkout_events to authenticated;
grant select,insert,update,delete on public.checkout_events to service_role;
create policy owner_read on public.checkout_events for select to authenticated using (exists (select 1 from public.checkout_sessions s join public.merchants m on m.id=s.merchant_id where s.id=checkout_events.session_id and m.owner_id=(select auth.uid())));
grant insert (owner_id,name), update (name) on public.merchants to authenticated;
create policy owner_create on public.merchants for insert to authenticated with check (owner_id=(select auth.uid()));
create policy owner_update on public.merchants for update to authenticated using (owner_id=(select auth.uid())) with check (owner_id=(select auth.uid()));