ALTER TABLE reports
  ADD COLUMN removal_pending boolean NOT NULL DEFAULT false;

ALTER TABLE media_key_revocations
  ADD COLUMN moderation_action_id uuid REFERENCES moderation_actions(id) ON DELETE SET NULL,
  ADD COLUMN escalated_at timestamptz;

-- Existing rows were created in the same database transaction as the corresponding moderation action.
UPDATE media_key_revocations revocation
SET moderation_action_id = (
  SELECT action.id
  FROM moderation_actions action
  WHERE action.created_at = revocation.created_at
    AND (
      (action.action='hide_story' AND action.target_type='story'
       AND EXISTS (SELECT 1 FROM stories story WHERE story.id=action.target_id AND story.cover_media_id=revocation.media_id))
      OR
      (action.action='suspend_user' AND action.target_type='user'
       AND EXISTS (SELECT 1 FROM media_assets media WHERE media.id=revocation.media_id AND media.owner_id=action.target_id))
    )
  ORDER BY action.id
  LIMIT 1
)
WHERE revocation.moderation_action_id IS NULL;

UPDATE reports report
SET status='reviewing', removal_pending=true, first_response_at=COALESCE(first_response_at,now()),
    closed_at=NULL, updated_at=now(),
    reopen_count=reopen_count + CASE WHEN report.status='closed' THEN 1 ELSE 0 END
WHERE EXISTS (
  SELECT 1 FROM media_key_revocations revocation
  JOIN moderation_actions action ON action.id=revocation.moderation_action_id
  WHERE action.target_type=report.target_type AND action.target_id=report.target_id
);

CREATE INDEX reports_removal_pending_idx ON reports(updated_at)
  WHERE removal_pending;
CREATE INDEX reports_target_idx ON reports(target_type,target_id,created_at DESC);
CREATE INDEX media_key_revocations_media_idx ON media_key_revocations(media_id);
CREATE INDEX media_key_revocations_action_idx ON media_key_revocations(moderation_action_id)
  WHERE moderation_action_id IS NOT NULL;
