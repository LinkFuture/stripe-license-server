import { config } from "../config/config";

export async function hitLimit(
  db: D1Database,
  bucket: string,
  limit: number,
  windowSeconds: number,
  now = new Date(),
): Promise<boolean> {
  if (limit <= 0) return false;
  const nowSec = Math.floor(now.getTime() / 1000);
  const windowStart = nowSec - (nowSec % windowSeconds);
  await db
    .prepare(
      `INSERT INTO rate_limits (bucket, window_start, count) VALUES (?, ?, 1)
       ON CONFLICT (bucket, window_start) DO UPDATE SET count = count + 1`,
    )
    .bind(bucket, windowStart)
    .run();
  const row = await db
    .prepare(`SELECT count AS count FROM rate_limits WHERE bucket = ? AND window_start = ?`)
    .bind(bucket, windowStart)
    .first<{ count: number }>();
  await db
    .prepare(`DELETE FROM rate_limits WHERE bucket = ? AND window_start < ?`)
    .bind(bucket, windowStart - windowSeconds)
    .run();
  return (row?.count ?? 1) > limit;
}

export function limits() {
  return config.rateLimits;
}
