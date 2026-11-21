import path from "node:path";
import { fileURLToPath } from "node:url";
import { defineWorkersConfig, readD1Migrations } from "@cloudflare/vitest-pool-workers/config";

const root = path.dirname(fileURLToPath(import.meta.url));

export default defineWorkersConfig(async () => {
  const migrations = await readD1Migrations(path.join(root, "migrations"));
  return {
    test: {
      include: ["test/**/*.test.ts"],
      setupFiles: ["./test/helpers/apply-migrations.ts"],
      testTimeout: 30000,
      coverage: {
        provider: "istanbul",
        include: ["src/lib/**/*.ts"],
        exclude: ["src/lib/types.ts"],
        reporter: ["text", "json-summary"],
        thresholds: {
          lines: 100,
          functions: 100,
          statements: 98,
          branches: 91,
        },
      },
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
              MAIL_FROM: "My App <noreply@example.com>",
              MAIL_REPLY_TO: "support@example.com",
              LICENSE_ISSUER: "https://license.example.com",
            },
          },
        },
      },
    },
  };
});
