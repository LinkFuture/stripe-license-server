import { intEnv } from "./util";
import type { Env } from "./types";

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

export function limits(env: Env) {
  return {
    ipPerMin: intEnv(env.RATE_LIMIT_IP_PER_MIN, 120),
    activateIpPerMin: intEnv(env.RATE_LIMIT_ACTIVATE_IP_PER_MIN, 20),
    activateKeyPerMin: intEnv(env.RATE_LIMIT_ACTIVATE_KEY_PER_MIN, 10),
    validateKeyPerMin: intEnv(env.RATE_LIMIT_VALIDATE_KEY_PER_MIN, 60),
    recoverIpPerMin: intEnv(env.RATE_LIMIT_RECOVER_IP_PER_MIN, 5),
    recoverEmailPerHour: intEnv(env.RATE_LIMIT_RECOVER_EMAIL_PER_HOUR, 5),
    resetIpPerMin: intEnv(env.RATE_LIMIT_RESET_IP_PER_MIN, 10),
    codeTtlSeconds: intEnv(env.CODE_TTL_SECONDS, 900),
    codeMaxAttempts: intEnv(env.CODE_MAX_ATTEMPTS, 5),
  };
}
