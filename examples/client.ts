/**
 * List the projects of the active organization.
 *
 * Install the client once:
 *   npm install @supabase/supabase-js
 *
 * Provide credentials through the environment (never hard-code them):
 *   SUPABASE_URL=https://your-project.supabase.co
 *   SUPABASE_ANON_KEY=your-anon-key
 *
 * The anon key is safe to ship in a browser app. Tenant isolation comes from
 * the RLS policies, not from hiding the key. Never ship the service_role key.
 */
import { createClient } from '@supabase/supabase-js'

const supabase = createClient(
  process.env.SUPABASE_URL ?? '',
  process.env.SUPABASE_ANON_KEY ?? '',
)

/**
 * @param orgId The organization selected in your app's org switcher.
 *              It is only a filter: RLS still decides what the user may read.
 */
export async function listProjects(orgId: string) {
  const { data, error } = await supabase
    .from('projects')
    .select('id, name, created_at')
    .eq('org_id', orgId)
    .order('created_at', { ascending: false })

  if (error) throw error
  return data ?? []
}

/**
 * The organizations the signed-in user belongs to. Useful for building the
 * org switcher; the memberships policy already filters this list.
 */
export async function listMyOrganizations() {
  const { data, error } = await supabase
    .from('memberships')
    .select('role, organizations (id, name, slug)')
    .order('created_at', { ascending: true })

  if (error) throw error
  return data ?? []
}
