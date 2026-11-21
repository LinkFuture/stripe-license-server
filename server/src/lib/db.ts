import type { ActivationRow, AppRow, LicenseRow } from "./types";

export async function logEvent(
  db: D1Database,
  event: {
    appId?: number | null;
    licenseId?: number | null;
    type: string;
    machineHash?: string | null;
    ip?: string | null;
    detail?: unknown;
    createdAt?: string;
  },
): Promise<void> {
  await db
    .prepare(
      `INSERT INTO events (app_id, license_id, type, machine_hash, ip, detail, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
    )
    .bind(
      event.appId ?? null,
      event.licenseId ?? null,
      event.type,
      event.machineHash ?? null,
      event.ip ?? null,
      event.detail === undefined ? null : JSON.stringify(event.detail),
      event.createdAt ?? new Date().toISOString(),
    )
    .run();
}

export async function getAppBySlug(db: D1Database, slug: string): Promise<AppRow | null> {
  return db.prepare(`SELECT * FROM apps WHERE slug = ?`).bind(slug).first<AppRow>();
}

export async function getLicenseByHash(db: D1Database, keyHash: string): Promise<LicenseRow | null> {
  return db.prepare(`SELECT * FROM licenses WHERE key_hash = ?`).bind(keyHash).first<LicenseRow>();
}

export async function getLicenseById(db: D1Database, id: number): Promise<LicenseRow | null> {
  return db.prepare(`SELECT * FROM licenses WHERE id = ?`).bind(id).first<LicenseRow>();
}

export async function listActivations(db: D1Database, licenseId: number): Promise<ActivationRow[]> {
  const res = await db
    .prepare(
      `SELECT * FROM activations WHERE license_id = ? ORDER BY activated_at ASC, id ASC`,
    )
    .bind(licenseId)
    .all<ActivationRow>();
  return res.results ?? [];
}

export function countsTowardLimit(row: ActivationRow, inactiveReleaseDays: number, now: Date): boolean {
  if (inactiveReleaseDays <= 0) return true;
  const cutoff = now.getTime() - inactiveReleaseDays * 86_400_000;
  return Date.parse(row.last_seen_at) >= cutoff;
}

export function machineView(row: ActivationRow, counts: boolean) {
  return {
    id: row.id,
    machine_hash: row.machine_hash,
    machine_name: row.machine_name,
    platform: row.platform,
    app_version: row.app_version,
    last_seen_at: row.last_seen_at,
    activated_at: row.activated_at,
    counts_toward_limit: counts,
  };
}
