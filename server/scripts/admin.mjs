const base = (process.env.LICENSE_API_BASE ?? "").replace(/\/$/, "");
const token = process.env.ADMIN_TOKEN ?? "";

function usage() {
  console.error(`Usage:
  LICENSE_API_BASE=https://license.example.com ADMIN_TOKEN=... npm run admin -- apps
  npm run admin -- stats <app-slug>
  npm run admin -- licenses <app-slug>
  npm run admin -- activations <app-slug>
  npm run admin -- revoke <app-slug> <license-id>
  npm run admin -- unbind <app-slug> <activation-id>`);
  process.exit(1);
}

const [command, arg, extra] = process.argv.slice(2);
if (!command) usage();
if (!base || !token) {
  console.error("Set LICENSE_API_BASE and ADMIN_TOKEN.");
  process.exit(1);
}

const headers = { Authorization: `Bearer ${token}`, "Content-Type": "application/json" };
let path = "";
let method = "GET";
const app = arg ? encodeURIComponent(arg) : "";
if (command === "apps") path = "/api/admin/apps";
else if (command === "stats") {
  if (!arg) usage();
  path = `/api/${app}/admin/stats`;
} else if (command === "licenses") {
  if (!arg) usage();
  path = `/api/${app}/admin/licenses`;
} else if (command === "activations") {
  if (!arg) usage();
  path = `/api/${app}/admin/activations`;
} else if (command === "revoke") {
  if (!arg || !extra) usage();
  path = `/api/${app}/admin/licenses/${encodeURIComponent(extra)}/revoke`;
  method = "POST";
} else if (command === "unbind") {
  if (!arg || !extra) usage();
  path = `/api/${app}/admin/activations/${encodeURIComponent(extra)}`;
  method = "DELETE";
} else usage();

const res = await fetch(`${base}${path}`, { method, headers });
const text = await res.text();
console.log(text);
if (!res.ok) process.exit(1);
