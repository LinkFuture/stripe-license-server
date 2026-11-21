export interface Env {
  DB: D1Database;
  ADMIN_TOKEN?: string;
  STRIPE_SECRET_KEY?: string;
  STRIPE_WEBHOOK_SECRET?: string;
  RESEND_API_KEY?: string;
  LICENSE_ENCRYPTION_KEY?: string;
  LICENSE_ISSUER?: string;
  MAIL_FROM?: string;
  MAIL_REPLY_TO?: string;
  RATE_LIMIT_IP_PER_MIN?: string;
  RATE_LIMIT_ACTIVATE_IP_PER_MIN?: string;
  RATE_LIMIT_ACTIVATE_KEY_PER_MIN?: string;
  RATE_LIMIT_VALIDATE_KEY_PER_MIN?: string;
  RATE_LIMIT_RECOVER_IP_PER_MIN?: string;
  RATE_LIMIT_RECOVER_EMAIL_PER_HOUR?: string;
  RATE_LIMIT_RESET_IP_PER_MIN?: string;
  CODE_TTL_SECONDS?: string;
  CODE_MAX_ATTEMPTS?: string;
  TEST_MIGRATIONS?: unknown;
}

export interface AppRow {
  id: number;
  slug: string;
  name: string;
  key_prefix: string;
  public_key: string;
  trial_days: number;
  offline_grace_days: number;
  inactive_release_days: number;
  reset_limit: number;
  reset_window_days: number;
  mail_from: string | null;
  status: "active" | "disabled";
  created_at: string;
}

export interface LicenseRow {
  id: number;
  app_id: number;
  key_hash: string;
  key_last4: string;
  key_enc: string;
  email: string;
  max_machines: number;
  stripe_session_id: string;
  stripe_payment_intent: string | null;
  status: "active" | "revoked";
  revoked_at: string | null;
  revoke_reason: "refund" | "dispute" | "admin" | null;
  email_sent_at: string | null;
  created_at: string;
}

export interface ActivationRow {
  id: number;
  license_id: number;
  machine_hash: string;
  machine_name: string | null;
  platform: string | null;
  app_version: string | null;
  activated_at: string;
  last_seen_at: string;
}

export interface TrialRow {
  id: number;
  app_id: number;
  machine_hash: string;
  started_at: string;
  expires_at: string;
  platform: string | null;
  app_version: string | null;
  created_at: string;
}

export interface EmailCodeRow {
  id: number;
  app_id: number;
  email: string;
  license_id: number | null;
  code_hash: string;
  purpose: "recover" | "reset_machines";
  attempts: number;
  expires_at: string;
  used_at: string | null;
  created_at: string;
}

export interface OutboundEmail {
  from: string;
  replyTo?: string | null;
  to: string;
  subject: string;
  text: string;
}

export type SendEmail = (env: Env, email: OutboundEmail) => Promise<void>;

export interface AppDeps {
  sendEmail?: SendEmail;
  now?: () => Date;
}
