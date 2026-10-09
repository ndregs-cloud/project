CREATE TABLE media_key_revocations (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  media_id uuid NOT NULL REFERENCES media_assets(id),
  source_key text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  attempt_count integer NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
  retry_after timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX media_key_revocations_retry_idx ON media_key_revocations(retry_after, created_at);
