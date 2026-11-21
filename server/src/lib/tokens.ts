import { signToken } from "./crypto";
import type { AppRow, Env } from "./types";
import { licenseIssuer } from "./util";

export async function signLicenseJwt(
  env: Env,
  app: AppRow,
  privateKeyPem: string,
  licenseId: number,
  machineHash: string,
  maxMachines: number,
  now: Date,
): Promise<{ token: string; expiresAt: string }> {
  const iss = licenseIssuer(env);
  if (!iss) throw new Error("issuer_not_configured");
  const iat = Math.floor(now.getTime() / 1000);
  const exp = iat + app.offline_grace_days * 86_400;
  const token = await signToken({
    privateKeyPem,
    iss,
    aud: app.slug,
    sub: String(licenseId),
    mid: machineHash,
    iat,
    exp,
    extra: { max: maxMachines, kind: "license" },
  });
  return { token, expiresAt: new Date(exp * 1000).toISOString() };
}

export async function signTrialJwt(
  env: Env,
  app: AppRow,
  privateKeyPem: string,
  trialId: number,
  machineHash: string,
  expiresAtIso: string,
  now: Date,
): Promise<string> {
  const iss = licenseIssuer(env);
  if (!iss) throw new Error("issuer_not_configured");
  const iat = Math.floor(now.getTime() / 1000);
  const exp = Math.floor(Date.parse(expiresAtIso) / 1000);
  return signToken({
    privateKeyPem,
    iss,
    aud: app.slug,
    sub: `trial:${trialId}`,
    mid: machineHash,
    iat,
    exp,
    extra: { kind: "trial" },
  });
}
