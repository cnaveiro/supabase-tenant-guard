# 12 common RLS mistakes and how this template avoids them

Row-Level Security is easy to switch on and easy to get subtly wrong. The list
below is general and applies to any multi-tenant Postgres or Supabase schema.
Each item names the mistake, why it leaks or breaks data, and the convention
used in this template.

## 1. Forgetting `WITH CHECK`

**Mistake:** writing `CREATE POLICY ... FOR INSERT USING (...)` or an update
policy with `USING` but no `WITH CHECK`.

**Why it hurts:** `USING` filters which existing rows a user can see or touch.
It does not validate the row being written. Without `WITH CHECK`, a user can
insert a row for another tenant, or update their own row so that it points at
another tenant.

**This template:** every insert and update policy has an explicit `WITH CHECK`
(`supabase/migrations/20260101000000_tenant_guard.sql`). Inserts into member tables must belong to
an organization the caller is a member of (creating an organization only requires a signed-in user, who becomes its owner); updates must still belong to one
after the change. The tenant key is also protected by a trigger because a
policy cannot compare against the old row.

## 2. Helper functions without `SECURITY DEFINER` or with a mutable `search_path`

**Mistake:** a policy calls a helper that queries `memberships`, but the helper
runs as the caller. The policy on `memberships` then evaluates another policy
on `memberships`, and Postgres raises "infinite recursion detected in policy".

The opposite mistake is a `SECURITY DEFINER` function without
`SET search_path`, so a caller can shadow `memberships` or `auth.uid()` with
objects in a schema they control.

**This template:** `is_member()` and `has_role()` are `SECURITY DEFINER`,
`STABLE`, `SET search_path = ''`, and use fully qualified names such as
`public.memberships` and `auth.uid()`. Execute is granted only to
`authenticated` and `service_role`.

## 3. Storing authorization data in `user_metadata`

**Mistake:** putting a role or tenant id in `raw_user_meta_data` and trusting it
in policies.

**Why it hurts:** `user_metadata` is editable by the signed-in user through the
auth API. It is profile data, not a permission source.

**This template:** roles and tenant membership live in `public.memberships`,
which has no insert/update policy for ordinary members. `app_metadata` or
custom claims are not used for authorization either; the database is the source
of truth.

## 4. Blanket `FOR ALL` policies

**Mistake:** one policy with `FOR ALL` and a broad predicate, often copied
between tables.

**Why it hurts:** select, insert, update, and delete have different rules. A
predicate that is correct for reading is frequently too permissive for deleting
or for changing a role. It also hides which operation is missing a check.

**This template:** each table has four policies, one per operation, and each
write policy states its own `WITH CHECK`. Project deletes are owner/admin only
while project edits are open to members; that distinction would disappear
inside a single `FOR ALL` policy.

## 5. Enabling RLS but forgetting table privileges

**Mistake:** enabling RLS and assuming that is the whole security model. Or the
reverse: granting `ALL` to `anon` and relying on policies alone.

**Why it hurts:** RLS and grants are separate layers. A missing grant produces
confusing "permission denied" errors; an unnecessary grant widens the attack
surface if a policy is later weakened.

**This template:** RLS is enabled on all three tables, `anon` has no table
privileges at all, and `authenticated` receives only select/insert/update/delete
on the three tables. Anonymous access is proven to fail in the test suite.

## 6. Using a privileged connection for normal requests

**Mistake:** the application connects with the database owner, `postgres`, or
the `service_role` key "because RLS got in the way".

**Why it hurts:** table owners and roles with `BYPASSRLS` skip policies
entirely. One service-role query in a request path silently disables tenant
isolation for that request.

**This template:** the example client uses the `anon` key and a normal user
session. `service_role` is only mentioned as a server-only administrative tool.
The README calls this out explicitly.

## 7. Views and `SECURITY DEFINER` functions that bypass RLS

**Mistake:** exposing a view or an RPC that reads tenant tables. In Postgres 14
and earlier, views run with the owner's privileges by default. A
`SECURITY DEFINER` function can do the same.

**Why it hurts:** the caller never touches the table, so RLS is never applied,
and the view or function returns every tenant's rows.

**This template:** no views or tenant-reading RPCs are exposed. If you add one,
create it with `security_invoker = true` (Postgres 15 views) or make the
function `SECURITY INVOKER`, and add tests that call it as a tenant user.

## 8. Missing indexes on policy columns

**Mistake:** policies filter on `org_id` and `user_id`, but those columns have
no usable index.

**Why it hurts:** every request that touches a policy performs a sequential
scan, and performance degrades as tenants grow. Slow queries are often
"fixed" by bypassing RLS, which turns a performance bug into a data leak.

**This template:** `memberships (user_id)`, `memberships (org_id, role)`,
`projects (org_id)`, and `projects (org_id, created_at desc)` are indexed, in
addition to the unique `(org_id, user_id)` constraint.

## 9. Trusting a tenant id supplied by the client

**Mistake:** the API reads `org_id` from the request body or a query string and
uses it as proof of tenant membership.

**Why it hurts:** the client can send any UUID. Filtering by the supplied id is
not authorization; it is a hint.

**This template:** policies ignore client claims and resolve membership from
`auth.uid()` plus `public.memberships`. The `org_id` in the example client is
only a filter; the same query with another tenant's id returns zero rows.

## 10. Letting rows change tenant

**Mistake:** an update policy checks membership in the new `org_id` but not the
old one, or checks neither and relies on the client not to send `org_id`.

**Why it hurts:** a user can move a row they own into a tenant they also belong
to, or move another tenant's row out of view. Audit trails and foreign keys
become inconsistent.

**This template:** `org_id` is immutable on `projects` and `memberships`, and
`user_id`/`created_by` are immutable too. Triggers raise `P0001` before the
write commits. The test suite attempts a cross-tenant move and expects the
error.

## 11. Forgetting the last-owner rule

**Mistake:** allowing any owner to leave or demote themselves. The organization
is left with no owner: nobody can manage members, and recovery requires manual
SQL.

**Why it hurts:** it is not a confidentiality leak, but it is a reliable way to
lock a paying customer out of their own tenant.

**This template:** a `BEFORE UPDATE OR DELETE` trigger counts the remaining
owners and rejects removing or demoting the last one. Cascading deletes of a
whole organization are allowed because the parent row is already gone; trusted
administrative contexts with no end-user identity are also allowed, and that
trade-off is documented in the migration.

## 12. Testing only the happy path

**Mistake:** a test suite that signs in as one user, inserts a row, reads it
back, and stops. Negative cases are never exercised, so a missing `WITH CHECK`
or an over-broad policy ships unnoticed.

**Why it hurts:** RLS failures are silent. A leaked read returns `200 OK` with
extra rows; it does not raise an error.

**This template:** `supabase/tests/001_tenant_isolation.test.sql` runs 71
assertions with two organizations and three users. It fixes
`request.jwt.claims` and switches to the `authenticated` role, then checks
allowed and denied reads and writes, cross-tenant inserts and updates, tenant
key moves, role escalation, last-owner protection, and anonymous access.
