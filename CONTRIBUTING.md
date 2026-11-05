# Contributing

Thanks for taking a look. This project is a template, so small, focused changes
are easier to review and safer to merge than large rewrites.

## Before you open a pull request

1. Read [`docs/rls-pitfalls.md`](docs/rls-pitfalls.md).
2. Add or update a pgTAP test for every policy change, including the negative
   case. A policy change without a test is considered incomplete.
3. Run the suite locally:

   ```bash
   supabase start
   supabase db reset
   supabase test db
   ```

4. Keep migrations append-only. Do not edit a migration that has already been
   published; add a new one.

## Pull requests

- One concern per pull request.
- Explain the threat model or bug the change addresses.
- Keep SQL, comments, and documentation in English.
- Do not include credentials, project URLs, customer data, or `.env` files.
- Update the README or the pitfalls guide if behavior or guidance changes.

Open an issue first for changes to the role model, the helper function
signatures, or the public table layout.

## Reporting a security issue

Please do not open a public issue for a vulnerability. Contact the maintainer
through [crisnaveiro.com](https://crisnaveiro.com) with a minimal reproduction.
