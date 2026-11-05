-- Tenant isolation proof.
-- Two fictional companies and three users, exercised through the same
-- authenticated role that PostgREST uses. Run with: supabase test db

begin;

create schema if not exists extensions;
create extension if not exists pgtap with schema extensions;

-- pgTAP lives in the extensions schema; the API roles must be able to call it
-- while the tests are running under SET ROLE.
grant usage on schema extensions to authenticated, anon;

set search_path = public, extensions;

select plan(71);

-- ---------------------------------------------------------------------------
-- Structure
-- ---------------------------------------------------------------------------

select has_table('public', 'organizations', 'organizations table exists');
select has_table('public', 'memberships', 'memberships table exists');
select has_table('public', 'projects', 'projects table exists');

select has_function('public', 'is_member', array['uuid'], 'is_member(org uuid) exists');
select has_function('public', 'has_role', array['uuid', 'text[]'], 'has_role(org uuid, roles text[]) exists');

select is(
  (select relrowsecurity from pg_class where oid = 'public.organizations'::regclass),
  true,
  'RLS is enabled on organizations'
);
select is(
  (select relrowsecurity from pg_class where oid = 'public.memberships'::regclass),
  true,
  'RLS is enabled on memberships'
);
select is(
  (select relrowsecurity from pg_class where oid = 'public.projects'::regclass),
  true,
  'RLS is enabled on projects'
);

select is(
  (select count(*)::int from pg_policies where schemaname = 'public' and tablename = 'organizations'),
  4,
  'organizations has one policy per operation'
);
select is(
  (select count(*)::int from pg_policies where schemaname = 'public' and tablename = 'memberships'),
  4,
  'memberships has one policy per operation'
);
select is(
  (select count(*)::int from pg_policies where schemaname = 'public' and tablename = 'projects'),
  4,
  'projects has one policy per operation'
);

select is(
  (select p.prosecdef from pg_proc p
   join pg_namespace n on n.oid = p.pronamespace
   where n.nspname = 'public' and p.proname = 'is_member'),
  true,
  'is_member is security definer'
);
select is(
  (select p.prosecdef from pg_proc p
   join pg_namespace n on n.oid = p.pronamespace
   where n.nspname = 'public' and p.proname = 'has_role'),
  true,
  'has_role is security definer'
);

select ok(
  (select array_to_string(p.proconfig, ',') like 'search_path=%'
   from pg_proc p
   join pg_namespace n on n.oid = p.pronamespace
   where n.nspname = 'public' and p.proname = 'is_member'),
  'is_member pins search_path'
);
select ok(
  (select array_to_string(p.proconfig, ',') like 'search_path=%'
   from pg_proc p
   join pg_namespace n on n.oid = p.pronamespace
   where n.nspname = 'public' and p.proname = 'has_role'),
  'has_role pins search_path'
);

select has_index('public', 'memberships', 'memberships_user_id_idx', array['user_id'], 'memberships are indexed by user');
select has_index('public', 'projects', 'projects_org_id_idx', array['org_id'], 'projects are indexed by organization');

-- ---------------------------------------------------------------------------
-- Fixtures: Alice owns Acme Corp, Carol owns Globex, Bob is a member of Acme.
-- ---------------------------------------------------------------------------

insert into auth.users (id, email, aud, role) values
  ('11111111-1111-1111-1111-111111111111', 'alice@example.test', 'authenticated', 'authenticated'),
  ('22222222-2222-2222-2222-222222222222', 'bob@example.test', 'authenticated', 'authenticated'),
  ('33333333-3333-3333-3333-333333333333', 'carol@example.test', 'authenticated', 'authenticated');

-- Alice creates Acme Corp. The insert trigger should enroll her as owner.
select set_config('request.jwt.claims', '{"sub":"11111111-1111-1111-1111-111111111111","role":"authenticated"}', true);
select set_config('request.jwt.claim.sub', '11111111-1111-1111-1111-111111111111', true);
set local role authenticated;

insert into organizations (id, name, slug)
values ('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa', 'Acme Corp', 'acme-corp');

insert into projects (id, org_id, name)
values ('a0000000-0000-0000-0000-000000000001', 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa', 'Website redesign');

select is(
  (select role from memberships
   where org_id = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
     and user_id = '11111111-1111-1111-1111-111111111111'),
  'owner',
  'creating an organization enrolls the creator as owner'
);
select ok(public.is_member('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'), 'Alice is a member of Acme');

-- Carol creates Globex.
reset role;
select set_config('request.jwt.claims', '{"sub":"33333333-3333-3333-3333-333333333333","role":"authenticated"}', true);
select set_config('request.jwt.claim.sub', '33333333-3333-3333-3333-333333333333', true);
set local role authenticated;

insert into organizations (id, name, slug)
values ('bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb', 'Globex', 'globex');

insert into projects (id, org_id, name)
values ('b0000000-0000-0000-0000-000000000001', 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb', 'Factory dashboard');

-- Alice is not a member of Globex.
reset role;
select set_config('request.jwt.claims', '{"sub":"11111111-1111-1111-1111-111111111111","role":"authenticated"}', true);
select set_config('request.jwt.claim.sub', '11111111-1111-1111-1111-111111111111', true);
set local role authenticated;

select ok(not public.is_member('bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb'), 'Alice is not a member of Globex');

-- Carol sees her own tenant only.
reset role;
select set_config('request.jwt.claims', '{"sub":"33333333-3333-3333-3333-333333333333","role":"authenticated"}', true);
select set_config('request.jwt.claim.sub', '33333333-3333-3333-3333-333333333333', true);
set local role authenticated;

select is((select count(*)::int from organizations), 1, 'Carol sees exactly one organization');
select is((select count(*)::int from projects), 1, 'Carol sees exactly one project');

-- Alice adds Bob to Acme as a member.
reset role;
select set_config('request.jwt.claims', '{"sub":"11111111-1111-1111-1111-111111111111","role":"authenticated"}', true);
select set_config('request.jwt.claim.sub', '11111111-1111-1111-1111-111111111111', true);
set local role authenticated;

insert into memberships (org_id, user_id, role)
values ('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa', '22222222-2222-2222-2222-222222222222', 'member');

select is(
  (select count(*)::int from memberships where org_id = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'),
  2,
  'Acme has two members after the owner adds Bob'
);

-- ---------------------------------------------------------------------------
-- Read isolation as Bob (member of Acme only)
-- ---------------------------------------------------------------------------

reset role;
select set_config('request.jwt.claims', '{"sub":"22222222-2222-2222-2222-222222222222","role":"authenticated"}', true);
select set_config('request.jwt.claim.sub', '22222222-2222-2222-2222-222222222222', true);
set local role authenticated;

select is((select count(*)::int from organizations), 1, 'Bob sees exactly one organization');
select is(
  (select count(*)::int from organizations where id = 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb'),
  0,
  'Bob cannot see the Globex organization'
);
select is((select count(*)::int from projects), 1, 'Bob sees only Acme projects');
select is(
  (select count(*)::int from projects where id = 'b0000000-0000-0000-0000-000000000001'),
  0,
  'Bob cannot read the Globex project by id'
);
select is(
  (select count(*)::int from memberships where org_id = 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb'),
  0,
  'Bob cannot see Globex memberships'
);
select ok(public.is_member('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'), 'is_member returns true for Bob in Acme');
select ok(not public.is_member('bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb'), 'is_member returns false for Bob in Globex');

-- Carol still cannot see Acme.
reset role;
select set_config('request.jwt.claims', '{"sub":"33333333-3333-3333-3333-333333333333","role":"authenticated"}', true);
select set_config('request.jwt.claim.sub', '33333333-3333-3333-3333-333333333333', true);
set local role authenticated;

select is((select count(*)::int from projects), 1, 'Carol still sees only Globex projects');
select is(
  (select count(*)::int from organizations where id = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'),
  0,
  'Carol cannot see the Acme organization'
);

-- ---------------------------------------------------------------------------
-- Write isolation as Bob (member)
-- ---------------------------------------------------------------------------

reset role;
select set_config('request.jwt.claims', '{"sub":"22222222-2222-2222-2222-222222222222","role":"authenticated"}', true);
select set_config('request.jwt.claim.sub', '22222222-2222-2222-2222-222222222222', true);
set local role authenticated;

select lives_ok(
  $$ insert into projects (id, org_id, name)
     values ('a0000000-0000-0000-0000-000000000002', 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa', 'Mobile app') $$,
  'a member can create a project in their own organization'
);

select throws_ok(
  $$ insert into projects (org_id, name)
     values ('bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb', 'Intrusion') $$,
  '42501',
  'a member cannot create a project in another organization'
);

select lives_ok(
  $$ update projects set name = 'Website redesign v2'
     where id = 'a0000000-0000-0000-0000-000000000001' $$,
  'a member can update a project in their own organization'
);

select is(
  (with changed as (
    update projects set name = 'Hijacked'
    where id = 'b0000000-0000-0000-0000-000000000001'
    returning 1
  ) select count(*)::int from changed),
  0,
  'a member cannot update a project in another organization'
);

select throws_ok(
  $$ update projects set org_id = 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb'
     where id = 'a0000000-0000-0000-0000-000000000001' $$,
  'P0001',
  'org_id cannot be changed',
  'moving a project to another organization is rejected'
);

select is(
  (with deleted as (
    delete from projects
    where id = 'b0000000-0000-0000-0000-000000000001'
    returning 1
  ) select count(*)::int from deleted),
  0,
  'a member cannot delete a project in another organization'
);

select is(
  (with deleted as (
    delete from projects
    where id = 'a0000000-0000-0000-0000-000000000001'
    returning 1
  ) select count(*)::int from deleted),
  0,
  'a member cannot delete a project in their own organization'
);

select throws_ok(
  $$ insert into projects (org_id, name, created_by)
     values ('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa', 'Forged', '33333333-3333-3333-3333-333333333333') $$,
  '42501',
  'a member cannot attribute a project to another user'
);

select is(
  (with changed as (
    update organizations set name = 'Bob Inc'
    where id = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
    returning 1
  ) select count(*)::int from changed),
  0,
  'a member cannot update the organization'
);

select is(
  (with deleted as (
    delete from organizations
    where id = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
    returning 1
  ) select count(*)::int from deleted),
  0,
  'a member cannot delete the organization'
);

-- ---------------------------------------------------------------------------
-- Organization administration as Alice (owner)
-- ---------------------------------------------------------------------------

reset role;
select set_config('request.jwt.claims', '{"sub":"11111111-1111-1111-1111-111111111111","role":"authenticated"}', true);
select set_config('request.jwt.claim.sub', '11111111-1111-1111-1111-111111111111', true);
set local role authenticated;

select throws_ok(
  $$ insert into projects (org_id, name)
     values ('bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb', 'Cross tenant') $$,
  '42501',
  'an owner cannot create a project in another organization'
);

select lives_ok(
  $$ update organizations set name = 'Acme Corporation'
     where id = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa' $$,
  'an owner can update the organization'
);

select lives_ok(
  $$ delete from projects where id = 'a0000000-0000-0000-0000-000000000002' $$,
  'an owner can delete a project in their organization'
);

-- ---------------------------------------------------------------------------
-- Membership management
-- ---------------------------------------------------------------------------

reset role;
select set_config('request.jwt.claims', '{"sub":"22222222-2222-2222-2222-222222222222","role":"authenticated"}', true);
select set_config('request.jwt.claim.sub', '22222222-2222-2222-2222-222222222222', true);
set local role authenticated;

select throws_ok(
  $$ insert into memberships (org_id, user_id, role)
     values ('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa', '33333333-3333-3333-3333-333333333333', 'member') $$,
  '42501',
  'a member cannot add other members'
);

select is(
  (with changed as (
    update memberships set role = 'owner'
    where org_id = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
      and user_id = '22222222-2222-2222-2222-222222222222'
    returning 1
  ) select count(*)::int from changed),
  0,
  'a member cannot promote themselves'
);

reset role;
select set_config('request.jwt.claims', '{"sub":"11111111-1111-1111-1111-111111111111","role":"authenticated"}', true);
select set_config('request.jwt.claim.sub', '11111111-1111-1111-1111-111111111111', true);
set local role authenticated;

select lives_ok(
  $$ update memberships set role = 'admin'
     where org_id = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
       and user_id = '22222222-2222-2222-2222-222222222222' $$,
  'an owner can promote a member to admin'
);

select is(
  (select role from memberships
   where org_id = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
     and user_id = '22222222-2222-2222-2222-222222222222'),
  'admin',
  'Bob is now an admin'
);

reset role;
select set_config('request.jwt.claims', '{"sub":"22222222-2222-2222-2222-222222222222","role":"authenticated"}', true);
select set_config('request.jwt.claim.sub', '22222222-2222-2222-2222-222222222222', true);
set local role authenticated;

select lives_ok(
  $$ insert into memberships (org_id, user_id, role)
     values ('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa', '33333333-3333-3333-3333-333333333333', 'member') $$,
  'an admin can add a member'
);

select throws_ok(
  $$ update memberships set role = 'owner'
     where org_id = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
       and user_id = '33333333-3333-3333-3333-333333333333' $$,
  '42501',
  'an admin cannot promote someone to owner'
);

select throws_ok(
  $$ update memberships set role = 'member'
     where org_id = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
       and user_id = '11111111-1111-1111-1111-111111111111' $$,
  'P0001',
  'only an owner can change an owner membership',
  'an admin cannot demote an owner'
);

select throws_ok(
  $$ delete from memberships
     where org_id = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
       and user_id = '11111111-1111-1111-1111-111111111111' $$,
  'P0001',
  'only an owner can remove an owner membership',
  'an admin cannot remove an owner'
);

select lives_ok(
  $$ delete from memberships
     where org_id = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
       and user_id = '33333333-3333-3333-3333-333333333333' $$,
  'an admin can remove a member'
);

select throws_ok(
  $$ insert into memberships (org_id, user_id, role)
     values ('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa', '33333333-3333-3333-3333-333333333333', 'owner') $$,
  '42501',
  'an admin cannot insert an owner'
);

reset role;
select set_config('request.jwt.claims', '{"sub":"11111111-1111-1111-1111-111111111111","role":"authenticated"}', true);
select set_config('request.jwt.claim.sub', '11111111-1111-1111-1111-111111111111', true);
set local role authenticated;

select throws_ok(
  $$ update memberships set org_id = 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb'
     where org_id = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
       and user_id = '22222222-2222-2222-2222-222222222222' $$,
  'P0001',
  'org_id cannot be changed',
  'moving a membership to another organization is rejected'
);

-- ---------------------------------------------------------------------------
-- Last-owner protection
-- ---------------------------------------------------------------------------

reset role;
select set_config('request.jwt.claims', '{"sub":"33333333-3333-3333-3333-333333333333","role":"authenticated"}', true);
select set_config('request.jwt.claim.sub', '33333333-3333-3333-3333-333333333333', true);
set local role authenticated;

select throws_ok(
  $$ delete from memberships
     where org_id = 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb'
       and user_id = '33333333-3333-3333-3333-333333333333' $$,
  'P0001',
  'cannot remove the last owner',
  'the sole owner of Globex cannot leave'
);

reset role;
select set_config('request.jwt.claims', '{"sub":"11111111-1111-1111-1111-111111111111","role":"authenticated"}', true);
select set_config('request.jwt.claim.sub', '11111111-1111-1111-1111-111111111111', true);
set local role authenticated;

select throws_ok(
  $$ delete from memberships
     where org_id = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
       and user_id = '11111111-1111-1111-1111-111111111111' $$,
  'P0001',
  'cannot remove the last owner',
  'the sole owner of Acme cannot leave'
);

select throws_ok(
  $$ update memberships set role = 'member'
     where org_id = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
       and user_id = '11111111-1111-1111-1111-111111111111' $$,
  'P0001',
  'cannot remove the last owner',
  'the sole owner of Acme cannot demote themselves'
);

select lives_ok(
  $$ update memberships set role = 'owner'
     where org_id = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
       and user_id = '22222222-2222-2222-2222-222222222222' $$,
  'an owner can promote an admin to owner'
);

select is(
  (select role from memberships
   where org_id = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
     and user_id = '22222222-2222-2222-2222-222222222222'),
  'owner',
  'Bob is now an owner of Acme'
);

select lives_ok(
  $$ delete from memberships
     where org_id = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
       and user_id = '11111111-1111-1111-1111-111111111111' $$,
  'an owner can leave when another owner remains'
);

select is((select count(*)::int from organizations), 0, 'Alice no longer sees Acme after leaving');

select throws_ok(
  $$ insert into memberships (org_id, user_id, role)
     values ('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa', '11111111-1111-1111-1111-111111111111', 'member') $$,
  '42501',
  'a former owner cannot add themselves back'
);

-- ---------------------------------------------------------------------------
-- Organization deletion (owner) with a disposable tenant
-- ---------------------------------------------------------------------------

reset role;
select set_config('request.jwt.claims', '{"sub":"22222222-2222-2222-2222-222222222222","role":"authenticated"}', true);
select set_config('request.jwt.claim.sub', '22222222-2222-2222-2222-222222222222', true);
set local role authenticated;

select lives_ok(
  $$ insert into organizations (id, name, slug)
     values ('cccccccc-cccc-cccc-cccc-cccccccccccc', 'Initech', 'initech') $$,
  'an authenticated user can create an organization'
);

select is(
  (select role from memberships
   where org_id = 'cccccccc-cccc-cccc-cccc-cccccccccccc'
     and user_id = '22222222-2222-2222-2222-222222222222'),
  'owner',
  'the creator owns the new organization'
);

select lives_ok(
  $$ delete from organizations where id = 'cccccccc-cccc-cccc-cccc-cccccccccccc' $$,
  'an owner can delete their organization'
);

select is(
  (select count(*)::int from organizations where id = 'cccccccc-cccc-cccc-cccc-cccccccccccc'),
  0,
  'the deleted organization is gone'
);

-- ---------------------------------------------------------------------------
-- Anonymous visitors
-- ---------------------------------------------------------------------------

reset role;
select set_config('request.jwt.claims', '', true);
select set_config('request.jwt.claim.sub', '', true);
set local role anon;

select throws_ok('select * from public.organizations', '42501', 'an anonymous visitor cannot read organizations');
select throws_ok(
  $$ insert into public.organizations (name, slug) values ('Anon Corp', 'anon-corp') $$,
  '42501',
  'an anonymous visitor cannot create organizations'
);
select throws_ok('select * from public.projects', '42501', 'an anonymous visitor cannot read projects');

reset role;
select * from finish();
rollback;
