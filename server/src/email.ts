import type { OutboundEmail, SendEmail } from "./types";
import { emailFrom } from "./util";

export const sendEmail: SendEmail = async (env, email) => {
  const from = emailFrom(env);
  if (!env.RESEND_API_KEY) {
    console.log(
      JSON.stringify({
        event: "email_skipped",
        to: email.to,
        subject: email.subject,
        reason: "RESEND_API_KEY unset",
      }),
    );
    return;
  }
  const res = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${env.RESEND_API_KEY}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      from,
      to: [email.to],
      subject: email.subject,
      text: email.text,
    }),
  });
  if (!res.ok) {
    const body = await res.text();
    throw new Error(`resend_${res.status}:${body.slice(0, 300)}`);
  }
};

export function licenseEmail(appName: string, keys: string[]): OutboundEmail["text"] {
  const lines = keys.map((k) => `  ${k}`).join("\n");
  return [
    `Your license key${keys.length > 1 ? "s" : ""} for ${appName}:`,
    "",
    lines,
    "",
    "Keep this key private. Activate it in the app while you are online.",
  ].join("\n");
}

export function resetCodeEmail(appName: string, code: string): string {
  return [
    `Your ${appName} device-reset code is ${code}.`,
    "",
    "It expires in 15 minutes. If you did not request this, you can ignore this email.",
  ].join("\n");
}
