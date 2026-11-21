/**
 * Production numeric overrides.
 * Do not put emails, domains, URLs, database ids, or worker names here.
 * Sender, issuer, and database id are Worker secrets or the deploy-time D1 binding.
 */
export const productionOverrides = {
  rateLimits: {
    ipPerMin: 120,
  },
} as const;
