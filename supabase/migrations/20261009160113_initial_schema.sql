CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TYPE user_status AS ENUM ('active', 'suspended', 'deleted');
CREATE TYPE user_role AS ENUM ('reader', 'moderator', 'support', 'security', 'admin');
CREATE TYPE story_status AS ENUM ('draft', 'published', 'removed');
CREATE TYPE story_visibility AS ENUM ('private', 'public');
CREATE TYPE media_status AS ENUM ('pending', 'processing', 'ready', 'rejected');
CREATE TYPE comment_status AS ENUM ('visible', 'removed');
CREATE TYPE report_target_type AS ENUM ('user', 'story', 'comment');
CREATE TYPE report_status AS ENUM ('received', 'reviewing', 'actioned', 'no_violation', 'closed');
CREATE TYPE feedback_category AS ENUM ('bug', 'usability', 'performance_reliability', 'content_safety', 'feature_request');
CREATE TYPE feedback_status AS ENUM ('received', 'triaged', 'in_progress', 'closed');
CREATE TYPE security_report_category AS ENUM ('security', 'privacy');
CREATE TYPE internal_report_status AS ENUM ('received', 'reviewing', 'actioned', 'closed');

CREATE TABLE users (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  auth_subject text NOT NULL UNIQUE,
  username varchar(32) NOT NULL,
  username_normalized varchar(32) NOT NULL UNIQUE,
  display_name varchar(80),
  bio varchar(500),
  avatar_media_id uuid,
  status user_status NOT NULL DEFAULT 'active',
  role user_role NOT NULL DEFAULT 'reader',
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT users_username_format CHECK (username_normalized ~ '^[a-z0-9_]{3,32}$')
);
CREATE INDEX users_status_idx ON users(status);

CREATE TABLE media_assets (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  owner_id uuid NOT NULL REFERENCES users(id),
  purpose text NOT NULL CHECK (purpose IN ('avatar', 'cover', 'feedback_screenshot')),
  object_key text NOT NULL UNIQUE,
  mime_type text NOT NULL CHECK (mime_type IN ('image/jpeg', 'image/png', 'image/webp')),
  size_bytes bigint NOT NULL CHECK (size_bytes > 0),
  checksum text,
  status media_status NOT NULL DEFAULT 'pending',
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  ready_at timestamptz
);
CREATE INDEX media_assets_owner_status_idx ON media_assets(owner_id, status);
ALTER TABLE users ADD CONSTRAINT users_avatar_media_fk FOREIGN KEY (avatar_media_id) REFERENCES media_assets(id);

CREATE TABLE tags (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name varchar(40) NOT NULL,
  normalized_name varchar(40) NOT NULL UNIQUE,
  created_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT tags_name_format CHECK (normalized_name ~ '^[a-z0-9-]{2,40}$')
);

CREATE TABLE stories (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  author_id uuid NOT NULL REFERENCES users(id),
  title varchar(160) NOT NULL DEFAULT '',
  slug varchar(180) NOT NULL,
  summary varchar(500) NOT NULL DEFAULT '',
  body text NOT NULL DEFAULT '',
  status story_status NOT NULL DEFAULT 'draft',
  visibility story_visibility NOT NULL DEFAULT 'private',
  version integer NOT NULL DEFAULT 1 CHECK (version >= 1),
  published_at timestamptz,
  cover_media_id uuid REFERENCES media_assets(id),
  comments_open boolean NOT NULL DEFAULT true,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  deleted_at timestamptz,
  CONSTRAINT stories_author_slug_unique UNIQUE (author_id, slug),
  CONSTRAINT stories_published_is_public CHECK (status <> 'published' OR (visibility = 'public' AND published_at IS NOT NULL)),
  CONSTRAINT stories_draft_is_private CHECK (status <> 'draft' OR visibility = 'private')
);
CREATE INDEX stories_public_feed_idx ON stories(published_at DESC, id DESC) WHERE status = 'published' AND deleted_at IS NULL;
CREATE INDEX stories_author_status_idx ON stories(author_id, status, created_at DESC);
CREATE INDEX stories_cover_media_idx ON stories(cover_media_id) WHERE cover_media_id IS NOT NULL;

CREATE TABLE story_tags (
  story_id uuid NOT NULL REFERENCES stories(id) ON DELETE CASCADE,
  tag_id uuid NOT NULL REFERENCES tags(id),
  PRIMARY KEY (story_id, tag_id)
);
CREATE INDEX story_tags_tag_story_idx ON story_tags(tag_id, story_id);

CREATE TABLE follows (
  follower_id uuid NOT NULL REFERENCES users(id),
  followed_id uuid NOT NULL REFERENCES users(id),
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (follower_id, followed_id),
  CONSTRAINT follows_no_self CHECK (follower_id <> followed_id)
);
CREATE INDEX follows_followed_idx ON follows(followed_id, created_at DESC);

CREATE TABLE bookmarks (
  user_id uuid NOT NULL REFERENCES users(id),
  story_id uuid NOT NULL REFERENCES stories(id),
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (user_id, story_id)
);
CREATE INDEX bookmarks_user_created_idx ON bookmarks(user_id, created_at DESC);

CREATE TABLE comments (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  story_id uuid NOT NULL REFERENCES stories(id),
  author_id uuid NOT NULL REFERENCES users(id),
  parent_id uuid REFERENCES comments(id),
  body varchar(2000) NOT NULL,
  status comment_status NOT NULL DEFAULT 'visible',
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  deleted_at timestamptz,
  CONSTRAINT comments_no_self_parent CHECK (parent_id IS NULL OR parent_id <> id)
);
CREATE INDEX comments_story_created_idx ON comments(story_id, created_at, id) WHERE deleted_at IS NULL;
CREATE INDEX comments_author_idx ON comments(author_id, created_at DESC);

CREATE TABLE reports (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  reporter_id uuid NOT NULL REFERENCES users(id),
  target_type report_target_type NOT NULL,
  target_id uuid NOT NULL,
  reason text NOT NULL CHECK (reason IN ('spam', 'harassment', 'copyright', 'sexual_or_harmful', 'other')),
  details varchar(2000),
  status report_status NOT NULL DEFAULT 'received',
  first_response_at timestamptz,
  closed_at timestamptz,
  reopen_count integer NOT NULL DEFAULT 0 CHECK (reopen_count >= 0),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX reports_one_open_per_target_idx ON reports(reporter_id, target_type, target_id) WHERE status IN ('received', 'reviewing');
CREATE INDEX reports_reporter_created_idx ON reports(reporter_id, created_at DESC, id DESC);
CREATE INDEX reports_review_queue_idx ON reports(status, created_at) WHERE status IN ('received', 'reviewing');

CREATE TABLE moderation_actions (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  moderator_id uuid NOT NULL REFERENCES users(id),
  target_type report_target_type NOT NULL,
  target_id uuid NOT NULL,
  action text NOT NULL,
  reason varchar(1000) NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  metadata jsonb NOT NULL DEFAULT '{}'::jsonb
);
CREATE INDEX moderation_actions_target_idx ON moderation_actions(target_type, target_id, created_at DESC);
CREATE INDEX moderation_actions_moderator_idx ON moderation_actions(moderator_id, created_at DESC);

-- Private beta feedback: never joined into community feeds or public analytics.
CREATE TABLE beta_feedback (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  reporter_id uuid NOT NULL REFERENCES users(id),
  category feedback_category NOT NULL,
  summary varchar(200) NOT NULL,
  affected_flow varchar(160),
  expected_behavior varchar(2000),
  actual_behavior varchar(2000),
  reproduction_steps varchar(4000),
  impact_frequency varchar(500),
  workaround varchar(500),
  device_info varchar(200),
  browser_info varchar(200),
  occurred_at timestamptz,
  screenshot_media_id uuid UNIQUE REFERENCES media_assets(id) ON DELETE SET NULL,
  status feedback_status NOT NULL DEFAULT 'received',
  first_response_at timestamptz,
  reopen_count integer NOT NULL DEFAULT 0 CHECK (reopen_count >= 0),
  recurrence_key varchar(120),
  resolution varchar(1000),
  reviewed_by uuid REFERENCES users(id),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL
);
CREATE INDEX beta_feedback_inbox_idx ON beta_feedback(status, created_at DESC, id DESC);
CREATE INDEX beta_feedback_expiry_idx ON beta_feedback(expires_at);

-- Separate, private escalation path; no screenshot or ordinary email notification fields.
CREATE TABLE security_reports (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  reporter_id uuid NOT NULL REFERENCES users(id),
  category security_report_category NOT NULL,
  summary varchar(200) NOT NULL,
  details varchar(5000) NOT NULL,
  affected_flow varchar(160),
  impact varchar(1000),
  status internal_report_status NOT NULL DEFAULT 'received',
  first_response_at timestamptz,
  reopen_count integer NOT NULL DEFAULT 0 CHECK (reopen_count >= 0),
  recurrence_key varchar(120),
  resolution varchar(1000),
  reviewed_by uuid REFERENCES users(id),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL
);
CREATE INDEX security_reports_inbox_idx ON security_reports(status, created_at DESC, id DESC);
CREATE INDEX security_reports_expiry_idx ON security_reports(expires_at);

-- Staff read/status events contain identifiers and event metadata only, not report details.
CREATE TABLE staff_access_audit (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  staff_id uuid NOT NULL REFERENCES users(id),
  event_type text NOT NULL CHECK (event_type IN (
    'content_report.read', 'content_report.status_changed',
    'feedback.read', 'feedback.screenshot_read', 'feedback.status_changed', 'feedback.metrics_read',
    'security_report.read', 'security_report.status_changed', 'security_report.metrics_read',
    'moderation_reports.metrics_read'
  )),
  resource_id uuid,
  metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL DEFAULT (now() + interval '365 days')
);
CREATE INDEX staff_access_audit_actor_idx ON staff_access_audit(staff_id, created_at DESC);
CREATE INDEX staff_access_audit_resource_idx ON staff_access_audit(resource_id, created_at DESC);
CREATE INDEX staff_access_audit_expiry_idx ON staff_access_audit(expires_at);

-- Fixed-window counters shared across API instances; keys are hashed before storage.
CREATE TABLE rate_limit_buckets (
  bucket_key text PRIMARY KEY,
  window_start timestamptz NOT NULL,
  hits integer NOT NULL CHECK (hits >= 1)
);
CREATE INDEX rate_limit_window_idx ON rate_limit_buckets(window_start);

-- A small, safe starter tag catalogue; teams can extend it through reviewed migrations.
INSERT INTO tags (name, normalized_name) VALUES
  ('Fantasy', 'fantasy'), ('Mystery', 'mystery'), ('Romance', 'romance'),
  ('Science Fiction', 'science-fiction'), ('Short Stories', 'short-stories')
ON CONFLICT (normalized_name) DO NOTHING;
