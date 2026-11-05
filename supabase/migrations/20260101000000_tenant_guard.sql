-- Tenant isolation foundation.
-- Every tenant-scoped row carries org_id and is protected by Row-Level Security.

set search_path = '';

create table public.organizations (
  id uuid primary key default gen_random_uuid(),
  name text not null,
  slug text not null,
  created_at timestamptz not null default now(),
  constraint organizations_name_length check (char_length(btrim(name)) between 1 and 120),
  constraint organizations_slug_format check (slug ~ '^[a-z0-9]+(-[a-z0-9]+)*$'),
  constraint organizations_slug_key unique (slug)
);

comment on table public.organizations is 'Tenants. Every other tenant-scoped table points here.';

create table public.memberships (
  id uuid primary key default gen_random_uuid(),
  org_id uuid not null references public.organizations (id) on delete cascade,
  user_id uuid not null references auth.users (id) on delete cascade,
  role text not null,
  created_at timestamptz not null default now(),
  constraint memberships_role_check check (role in ('owner', 'admin', 'member')),
  constraint memberships_org_user_key unique (org_id, user_id)
);

comment on table public.memberships is 'Which users belong to which tenant, and with which role.';

create table public.projects (
  id uuid primary key default gen_random_uuid(),
  org_id uuid not null references public.organizations (id) on delete cascade,
  name text not null,
  created_by uuid default auth.uid() references auth.users (id) on delete set null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  constraint projects_name_length check (char_length(btrim(name)) between 1 and 160)
);

comment on table public.projects is 'Example tenant-owned table. Replace or extend it with your own domain tables.';

-- ---------------------------------------------------------------------------
-- Helper functions used by the policies.
-- SECURITY DEFINER is required so a policy on memberships can read memberships
-- without recursing into itself. search_path is pinned and every name is
-- schema-qualified.
-- ---------------------------------------------------------------------------

create function public.is_member(org uuid)
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select exists (
    select 1
    from public.memberships as m
    where m.org_id = org
      and m.user_id = (select auth.uid())
  );
$$;

comment on function public.is_member(uuid) is 'True when the current user belongs to the given organization.';

create function public.has_role(org uuid, roles text[])
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select exists (
    select 1
    from public.memberships as m
    where m.org_id = org
      and m.user_id = (select auth.uid())
      and m.role = any (roles)
  );
$$;

comment on function public.has_role(uuid, text[]) is 'True when the current user has one of the given roles in the organization.';

-- ---------------------------------------------------------------------------
-- Invariants that a policy cannot express on its own (OLD row access).
-- ---------------------------------------------------------------------------

create function public.enforce_organization_invariants()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
  if new.id is distinct from old.id then
    raise exception 'organization id cannot be changed' using errcode = 'P0001';
  end if;
  return new;
end;
$$;

create function public.enforce_membership_invariants()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
  if new.org_id is distinct from old.org_id then
    raise exception 'org_id cannot be changed' using errcode = 'P0001';
  end if;

  if new.user_id is distinct from old.user_id then
    raise exception 'user_id cannot be changed' using errcode = 'P0001';
  end if;

  -- An admin may manage members, but only an owner may touch an owner row.
  if old.role = 'owner'
     and new.role <> 'owner'
     and auth.uid() is not null
     and not public.has_role(old.org_id, array['owner'])
  then
    raise exception 'only an owner can change an owner membership' using errcode = 'P0001';
  end if;

  return new;
end;
$$;

create function public.protect_last_owner()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
  -- Trusted contexts (service_role, direct SQL by an administrator) set no
  -- end-user identity. RLS is not a replacement for database backups.
  if auth.uid() is null then
    if tg_op = 'DELETE' then
      return old;
    end if;
    return new;
  end if;

  -- Cascading a whole organization delete already removed the parent row.
  if not exists (select 1 from public.organizations as o where o.id = old.org_id) then
    if tg_op = 'DELETE' then
      return old;
    end if;
    return new;
  end if;

  if old.role <> 'owner' then
    if tg_op = 'DELETE' then
      return old;
    end if;
    return new;
  end if;

  if tg_op = 'UPDATE' and new.role = 'owner' then
    return new;
  end if;

  if not public.has_role(old.org_id, array['owner']) then
    raise exception 'only an owner can remove an owner membership' using errcode = 'P0001';
  end if;

  -- serialize owner changes per organization so two owners cannot leave it ownerless at once
  perform pg_advisory_xact_lock(hashtext(old.org_id::text));

  if not exists (
    select 1
    from public.memberships as m
    where m.org_id = old.org_id
      and m.role = 'owner'
      and m.id <> old.id
  ) then
    raise exception 'cannot remove the last owner' using errcode = 'P0001';
  end if;

  if tg_op = 'DELETE' then
    return old;
  end if;
  return new;
end;
$$;

create function public.enforce_project_invariants()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
  if new.org_id is distinct from old.org_id then
    raise exception 'org_id cannot be changed' using errcode = 'P0001';
  end if;

  if new.created_by is distinct from old.created_by and new.created_by is not null then
    raise exception 'created_by cannot be changed' using errcode = 'P0001';
  end if;

  return new;
end;
$$;

create function public.set_updated_at()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
  new.updated_at = now();
  return new;
end;
$$;

-- The first member of a new organization is its owner. Creating the
-- organization and the owner membership in one round trip avoids a window
-- where a tenant exists with no administrator.
create function public.handle_new_organization()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
  if auth.uid() is not null then
    insert into public.memberships (org_id, user_id, role)
    values (new.id, auth.uid(), 'owner');
  end if;
  return new;
end;
$$;

create trigger organizations_enforce_invariants
before update on public.organizations
for each row execute function public.enforce_organization_invariants();

create trigger organizations_add_owner
after insert on public.organizations
for each row execute function public.handle_new_organization();

create trigger memberships_enforce_invariants
before update on public.memberships
for each row execute function public.enforce_membership_invariants();

create trigger memberships_protect_last_owner
before update or delete on public.memberships
for each row execute function public.protect_last_owner();

create trigger projects_enforce_invariants
before update on public.projects
for each row execute function public.enforce_project_invariants();

create trigger projects_set_updated_at
before update on public.projects
for each row execute function public.set_updated_at();

-- ---------------------------------------------------------------------------
-- Row-Level Security: one policy per operation, with WITH CHECK on writes.
-- ---------------------------------------------------------------------------

alter table public.organizations enable row level security;
alter table public.memberships enable row level security;
alter table public.projects enable row level security;

-- organizations -----------------------------------------------------------------

create policy organizations_select_members
on public.organizations
for select
to authenticated
using (public.is_member(id));

create policy organizations_insert_authenticated
on public.organizations
for insert
to authenticated
with check ((select auth.uid()) is not null);

create policy organizations_update_admins
on public.organizations
for update
to authenticated
using (public.has_role(id, array['owner', 'admin']))
with check (public.has_role(id, array['owner', 'admin']));

create policy organizations_delete_owners
on public.organizations
for delete
to authenticated
using (public.has_role(id, array['owner']));

-- memberships -------------------------------------------------------------------

create policy memberships_select_members
on public.memberships
for select
to authenticated
using (public.is_member(org_id));

create policy memberships_insert_admins
on public.memberships
for insert
to authenticated
with check (
  public.has_role(org_id, array['owner', 'admin'])
  and (public.has_role(org_id, array['owner']) or role <> 'owner')
);

create policy memberships_update_admins
on public.memberships
for update
to authenticated
using (public.has_role(org_id, array['owner', 'admin']))
with check (
  public.has_role(org_id, array['owner', 'admin'])
  and (public.has_role(org_id, array['owner']) or role <> 'owner')
);

create policy memberships_delete_admins_or_self
on public.memberships
for delete
to authenticated
using (
  public.has_role(org_id, array['owner', 'admin'])
  or user_id = (select auth.uid())
);

-- projects ----------------------------------------------------------------------

create policy projects_select_members
on public.projects
for select
to authenticated
using (public.is_member(org_id));

create policy projects_insert_members
on public.projects
for insert
to authenticated
with check (
  public.is_member(org_id)
  and created_by = (select auth.uid())
);

create policy projects_update_members
on public.projects
for update
to authenticated
using (public.is_member(org_id))
with check (public.is_member(org_id));

create policy projects_delete_admins
on public.projects
for delete
to authenticated
using (public.has_role(org_id, array['owner', 'admin']));

-- ---------------------------------------------------------------------------
-- Indexes used by the policies.
-- ---------------------------------------------------------------------------

create index memberships_user_id_idx on public.memberships (user_id);
create index memberships_org_id_role_idx on public.memberships (org_id, role);
create index projects_org_id_idx on public.projects (org_id);
create index projects_org_id_created_at_idx on public.projects (org_id, created_at desc);

-- ---------------------------------------------------------------------------
-- Privileges. RLS is not a grant system: anonymous visitors get no table
-- access at all, and authenticated users get only what the policies allow.
-- ---------------------------------------------------------------------------

revoke all on table public.organizations from public, anon;
revoke all on table public.memberships from public, anon;
revoke all on table public.projects from public, anon;

grant select, insert, update, delete on table public.organizations to authenticated;
grant select, insert, update, delete on table public.memberships to authenticated;
grant select, insert, update, delete on table public.projects to authenticated;

revoke all on function public.is_member(uuid) from public, anon;
revoke all on function public.has_role(uuid, text[]) from public, anon;
grant execute on function public.is_member(uuid) to authenticated, service_role;
grant execute on function public.has_role(uuid, text[]) to authenticated, service_role;

revoke all on function public.handle_new_organization() from public, anon, authenticated;
revoke all on function public.enforce_organization_invariants() from public, anon, authenticated;
revoke all on function public.enforce_membership_invariants() from public, anon, authenticated;
revoke all on function public.protect_last_owner() from public, anon, authenticated;
revoke all on function public.enforce_project_invariants() from public, anon, authenticated;
revoke all on function public.set_updated_at() from public, anon, authenticated;
