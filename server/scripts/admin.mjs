const base = (process.env.LICENSE_API_BASE ?? "").replace(/\/$/, "");
const token = process.env.ADMIN_TOKEN ?? "";

function usage() {
  console.error(`Usage:
  LICENSE_API_BASE=https://license.example.com ADMIN_TOKEN=... npm run admin -- apps
  npm run admin -- stats [app-slug]
  npm run admin -- licenses [app-slug]
  npm run admin -- activations [app-slug]
  npm run admin -- revoke <license-id>
  npm run admin -- unbind <activation-id>`);
  process.exit(1);
}

const [command, arg] = process.argv.slice(2);
if (!command) usage();
if (!base || !token) {
  console.error("Set LICENSE_API_BASE and ADMIN_TOKEN.");
  process.exit(1);
}

const headers = { Authorization: `Bearer ${token}`, "Content-Type": "application/json" };
let path = "";
let method = "GET";
if (command === "apps") path = "/admin/apps";
else if (command === "stats") path = `/admin/stats${arg ? `?app=${encodeURIComponent(arg)}` : ""}`;
else if (command === "licenses") path = `/admin/licenses${arg ? `?app=${encodeURIComponent(arg)}` : ""}`;
else if (command === "activations") path = `/admin/activations${arg ? `?app=${encodeURIComponent(arg)}` : ""}`;
else if (command === "revoke") {
  if (!arg) usage();
  path = `/admin/licenses/${encodeURIComponent(arg)}/revoke`;
  method = "POST";
} else if (command === "unbind") {
  if (!arg) usage();
  path = `/admin/activations/${encodeURIComponent(arg)}`;
  method = "DELETE";
} else usage();

const res = await fetch(`${base}${path}`, { method, headers });
const text = await res.text();
console.log(text);
if (!res.ok) process.exit(1);
