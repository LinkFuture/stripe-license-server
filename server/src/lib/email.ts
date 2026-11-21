import type { OutboundEmail, SendEmail } from "./types";

export const sendEmail: SendEmail = async (env, email) => {
  if (!email.from) {
    console.log(JSON.stringify({ event: "email_failed", reason: "mail_from_unset", to: email.to }));
    throw new Error("mail_from_unset");
  }
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
  const body: Record<string, unknown> = {
    from: email.from,
    to: [email.to],
    subject: email.subject,
    text: email.text,
  };
  if (email.replyTo) body.reply_to = email.replyTo;
  const res = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${env.RESEND_API_KEY}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify(body),
  });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(`resend_${res.status}:${text.slice(0, 300)}`);
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
