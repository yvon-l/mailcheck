// Who is behind an SPF include, and who runs a mail server.
// Matching is by domain suffix: "spf.protection.outlook.com" matches
// "spf.protection.outlook.com" and anything ending in ".spf.protection.outlook.com".
// To add one, open a pull request with a link to the vendor's own setup docs.

export const SENDERS = [
  // Mailbox providers
  { match: "_spf.google.com", name: "Google Workspace", kind: "Mailbox provider" },
  { match: "spf.protection.outlook.com", name: "Microsoft 365", kind: "Mailbox provider" },
  { match: "spf.protection.outlook.de", name: "Microsoft 365 (Germany)", kind: "Mailbox provider" },
  { match: "outlook.com", name: "Microsoft Outlook.com", kind: "Mailbox provider" },
  { match: "_spf.protonmail.ch", name: "Proton Mail", kind: "Mailbox provider" },
  { match: "spf.migadu.com", name: "Migadu", kind: "Mailbox provider" },
  { match: "spf.messagingengine.com", name: "Fastmail", kind: "Mailbox provider" },
  { match: "icloud.com", name: "iCloud Mail", kind: "Mailbox provider" },
  { match: "zoho.com", name: "Zoho Mail", kind: "Mailbox provider" },
  { match: "zoho.eu", name: "Zoho Mail (EU)", kind: "Mailbox provider" },
  { match: "zohomail.com", name: "Zoho Mail", kind: "Mailbox provider" },
  { match: "_spf.yandex.net", name: "Yandex Mail", kind: "Mailbox provider" },
  { match: "mx.ovh.com", name: "OVHcloud mail", kind: "Mailbox provider" },
  { match: "secureserver.net", name: "GoDaddy mail", kind: "Mailbox provider" },
  { match: "_spf.mx.cloudflare.net", name: "Cloudflare Email Routing", kind: "Forwarding" },

  // Email security gateways
  { match: "_netblocks.mimecast.com", name: "Mimecast", kind: "Email security" },
  { match: "mimecast.com", name: "Mimecast", kind: "Email security" },
  { match: "_spf._d.mim.ec", name: "Mimecast", kind: "Hosted SPF" },
  { match: "pphosted.com", name: "Proofpoint", kind: "Email security" },
  { match: "spf.ess.barracudanetworks.com", name: "Barracuda", kind: "Email security" },

  // Sending services and marketing
  { match: "amazonses.com", name: "Amazon SES", kind: "Sending service" },
  { match: "sendgrid.net", name: "SendGrid", kind: "Sending service" },
  { match: "mailgun.org", name: "Mailgun", kind: "Sending service" },
  { match: "spf.mtasv.net", name: "Postmark", kind: "Sending service" },
  { match: "sparkpostmail.com", name: "SparkPost", kind: "Sending service" },
  { match: "spf.mailjet.com", name: "Mailjet", kind: "Sending service" },
  { match: "_spf.elasticemail.com", name: "Elastic Email", kind: "Sending service" },
  { match: "spf.sendinblue.com", name: "Brevo", kind: "Marketing email" },
  { match: "spf.brevo.com", name: "Brevo", kind: "Marketing email" },
  { match: "servers.mcsv.net", name: "Mailchimp", kind: "Marketing email" },
  { match: "spf.mandrillapp.com", name: "Mailchimp Transactional (Mandrill)", kind: "Sending service" },
  { match: "spf.constantcontact.com", name: "Constant Contact", kind: "Marketing email" },
  { match: "_spf.createsend.com", name: "Campaign Monitor", kind: "Marketing email" },
  { match: "_spf.mlsend.com", name: "MailerLite", kind: "Marketing email" },
  { match: "hubspotemail.net", name: "HubSpot", kind: "Marketing email" },
  { match: "mktomail.com", name: "Marketo", kind: "Marketing email" },

  // Business tools that send as you
  { match: "_spf.salesforce.com", name: "Salesforce", kind: "Business tool" },
  { match: "mail.zendesk.com", name: "Zendesk", kind: "Support tool" },
  { match: "email.freshdesk.com", name: "Freshdesk", kind: "Support tool" },
  { match: "helpscoutemail.com", name: "Help Scout", kind: "Support tool" },
  { match: "_spf.atlassian.net", name: "Atlassian (Jira, Confluence)", kind: "Business tool" },
  { match: "shops.shopify.com", name: "Shopify", kind: "Business tool" },
];

// Mail servers named in MX records, and the SPF include each provider asks for.
export const MAIL_PROVIDERS = [
  { match: "google.com", name: "Google Workspace", spf: "_spf.google.com" },
  { match: "googlemail.com", name: "Google Workspace", spf: "_spf.google.com" },
  { match: "mail.protection.outlook.com", name: "Microsoft 365", spf: "spf.protection.outlook.com" },
  { match: "protonmail.ch", name: "Proton Mail", spf: "_spf.protonmail.ch" },
  { match: "migadu.com", name: "Migadu", spf: "spf.migadu.com" },
  { match: "messagingengine.com", name: "Fastmail", spf: "spf.messagingengine.com" },
  { match: "icloud.com", name: "iCloud Mail", spf: "icloud.com" },
  { match: "zoho.com", name: "Zoho Mail", spf: "zoho.com" },
  { match: "zoho.eu", name: "Zoho Mail (EU)", spf: "zoho.eu" },
  { match: "yandex.net", name: "Yandex Mail", spf: "_spf.yandex.net" },
  { match: "mail.ovh.net", name: "OVHcloud mail", spf: "mx.ovh.com" },
  { match: "secureserver.net", name: "GoDaddy mail", spf: "secureserver.net" },
  { match: "mx.cloudflare.net", name: "Cloudflare Email Routing", spf: "_spf.mx.cloudflare.net", forwardingOnly: true },
  { match: "mimecast.com", name: "Mimecast", spf: null },
  { match: "pphosted.com", name: "Proofpoint", spf: null },
  { match: "barracudanetworks.com", name: "Barracuda", spf: null },
];

export function matchSuffix(host, pattern) {
  const h = String(host).toLowerCase().replace(/\.$/, "");
  const p = pattern.toLowerCase();
  return h === p || h.endsWith("." + p);
}

export function senderFor(domain) {
  return SENDERS.find((v) => matchSuffix(domain, v.match)) || null;
}

export function providerForMx(host) {
  return MAIL_PROVIDERS.find((v) => matchSuffix(host, v.match)) || null;
}
