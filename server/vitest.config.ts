import path from "node:path";
import { fileURLToPath } from "node:url";
import { defineWorkersConfig, readD1Migrations } from "@cloudflare/vitest-pool-workers/config";

const root = path.dirname(fileURLToPath(import.meta.url));

export default defineWorkersConfig(async () => {
  const migrations = await readD1Migrations(path.join(root, "migrations"));
  return {
    test: {
      setupFiles: ["./test/apply-migrations.ts"],
      testTimeout: 30000,
      poolOptions: {
        workers: {
          wrangler: { configPath: "./wrangler.toml" },
          miniflare: {
            bindings: {
              TEST_MIGRATIONS: migrations,
              ADMIN_TOKEN: "test-admin-token",
              STRIPE_WEBHOOK_SECRET: "whsec_test_secret",
              LICENSE_ENCRYPTION_KEY: "test-encryption-key",
              RESEND_API_KEY: "re_test",
              EMAIL_FROM: "info@linkfuture.net",
              JWT_ISS: "license.linkfuture.net",
            },
          },
        },
      },
    },
  };
});
