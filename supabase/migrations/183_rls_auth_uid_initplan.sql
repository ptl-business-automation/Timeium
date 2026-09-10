-- 183_rls_auth_uid_initplan.sql — evaluate auth.uid() once per query, not once
-- per row.
--
-- THE FINDING (Supabase performance advisor, "Auth RLS Initialization Plan",
-- severity 2 — a WARNING, not a security hole): a policy that calls auth.uid()
-- directly has it re-evaluated FOR EVERY ROW the query scans. Wrapped in a
-- scalar subquery it becomes an InitPlan: computed once, reused for the whole
-- scan. Same rows in, same rows out — this changes speed, not who can see what.
--
--     using (auth_user_id = auth.uid())            -- per row
--     using (auth_user_id = (select auth.uid()))   -- once
--
-- Measured on a snapshot of this database: 34 policies across 21 tables, and
-- NOT ONE was wrapped anywhere in 182 migrations. It is a habit, not a few
-- stragglers, so this fixes them together and future migrations should write
-- the wrapped form from the start.
--
-- IT MATTERS MOST WHERE IT IS LEAST VISIBLE. public.users and public.admins are
-- read on essentially every request by every module (current_org_id, guard),
-- and the leave and status tables are the ones that actually grow. A table with
-- fifty rows will never show the difference.
--
-- WHY IT IS GENERATED AND NOT TYPED. These policies ARE the security boundary
-- of the whole ERP — ten modules share this schema. Retyping 34 expressions by
-- hand is how a subtle change gets in. So this reads each policy's CURRENT
-- expression out of the catalogue, rewrites only the function call, and applies
-- it with ALTER POLICY.
--
-- ALTER POLICY, NEVER DROP AND RECREATE. ALTER changes the expression in place,
-- so there is no instant at which the table sits without that policy. A drop
-- and recreate inside a transaction would be safe from readers, but a failure
-- halfway through a 34-policy loop would leave the schema part-done; this
-- cannot.
--
-- SAFE TO RE-RUN: a policy that already reads `( SELECT auth.uid()` is skipped,
-- so a second run finds nothing to do. It also refuses to touch anything but
-- the auth.uid() call — see the assertion inside the loop.
--
-- Apply after 182.

DO $$
DECLARE
  r           record;
  v_qual      text;
  v_check     text;
  v_new_qual  text;
  v_new_check text;
  v_sql       text;
  v_done      int := 0;
BEGIN
  FOR r IN
    SELECT n.nspname          AS sch,
           c.relname          AS tbl,
           p.polname          AS pol,
           pg_get_expr(p.polqual,      p.polrelid) AS qual,
           pg_get_expr(p.polwithcheck, p.polrelid) AS wcheck
      FROM pg_policy p
      JOIN pg_class c ON c.oid = p.polrelid
      JOIN pg_namespace n ON n.oid = c.relnamespace
     WHERE n.nspname = 'public'
       AND (COALESCE(pg_get_expr(p.polqual, p.polrelid), '')
            || COALESCE(pg_get_expr(p.polwithcheck, p.polrelid), '')) ~ 'auth\.uid\(\)'
       -- Already an InitPlan. Postgres prints the wrapped form as
       -- "( SELECT auth.uid() AS uid)", which is what makes a re-run a no-op.
       AND (COALESCE(pg_get_expr(p.polqual, p.polrelid), '')
            || COALESCE(pg_get_expr(p.polwithcheck, p.polrelid), '')) !~ '\( SELECT auth\.uid\(\)'
     ORDER BY 1, 2, 3
  LOOP
    v_qual  := r.qual;
    v_check := r.wcheck;

    -- The ONLY edit. Nothing else in the expression is touched, and because the
    -- loop skips anything already wrapped, a plain global replace cannot
    -- double-wrap.
    v_new_qual  := regexp_replace(v_qual,  'auth\.uid\(\)', '(select auth.uid())', 'g');
    v_new_check := regexp_replace(v_check, 'auth\.uid\(\)', '(select auth.uid())', 'g');

    -- Prove the rewrite changed nothing but the wrapping: strip the wrapper
    -- back out of the new text and it must equal what we started with. A
    -- regexp that ever did more than intended stops the migration here rather
    -- than quietly loosening a policy.
    IF COALESCE(replace(v_new_qual,  '(select auth.uid())', 'auth.uid()'), '')
         IS DISTINCT FROM COALESCE(v_qual, '')
       OR COALESCE(replace(v_new_check, '(select auth.uid())', 'auth.uid()'), '')
         IS DISTINCT FROM COALESCE(v_check, '')
    THEN
      RAISE EXCEPTION 'STOP: rewriting policy %.% "%" changed more than the auth.uid() call',
        r.sch, r.tbl, r.pol;
    END IF;

    -- USING and WITH CHECK are set only where the policy has one. A policy with
    -- no USING clause (an INSERT policy) cannot be given one, and vice versa.
    v_sql := format('ALTER POLICY %I ON %I.%I', r.pol, r.sch, r.tbl);
    IF v_new_qual  IS NOT NULL THEN v_sql := v_sql || format(' USING (%s)', v_new_qual); END IF;
    IF v_new_check IS NOT NULL THEN v_sql := v_sql || format(' WITH CHECK (%s)', v_new_check); END IF;

    EXECUTE v_sql;
    v_done := v_done + 1;
    RAISE NOTICE 'rewrote %.% "%"', r.sch, r.tbl, r.pol;
  END LOOP;

  RAISE NOTICE '% policies now evaluate auth.uid() once per query.', v_done;
END $$;


-- ---------------------------------------------------------------- proof ----
-- Expect still_per_row = 0 and now_initplan = 34 (whatever the count was).
SELECT count(*) FILTER (WHERE e ~ 'auth\.uid\(\)' AND e !~ '\( SELECT auth\.uid\(\)')
         AS still_per_row,
       count(*) FILTER (WHERE e ~ '\( SELECT auth\.uid\(\)')
         AS now_initplan
  FROM (SELECT COALESCE(pg_get_expr(p.polqual, p.polrelid), '')
               || ' ' || COALESCE(pg_get_expr(p.polwithcheck, p.polrelid), '') AS e
          FROM pg_policy p
          JOIN pg_class c ON c.oid = p.polrelid
          JOIN pg_namespace n ON n.oid = c.relnamespace
         WHERE n.nspname = 'public') s;
