/**
 * Dev-only numeric overrides.
 * Do not put emails, domains, URLs, database ids, or worker names here.
 * The public repo must not identify a real deployment.
 */
export const devOverrides = {
  rateLimits: {
    // Higher than production so a laptop session is less likely to trip the per-IP cap.
    ipPerMin: 240,
  },
} as const;
