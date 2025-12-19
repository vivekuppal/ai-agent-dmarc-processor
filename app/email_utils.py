import tldextract

# Map base domains → provider names
PROVIDER_BY_BASE_DOMAIN = {
    "google.com": "Google Workspace / GMail",
    "gmail.com": "Google Workspace / GMail",
    "outlook.com": "Microsoft",
    "office365.com": "Microsoft",
    "live.com": "Microsoft",
    "hotmail.com": "Microsoft",
    "yahoo.com": "Yahoo",
    "apple.com": "Apple",
    "icloud.com": "Apple",
    "me.com": "Apple",
    "mac.com": "Apple",
    "ppe-hosted.com": "Proofpoint",
    "pphosted.com": "Proofpoint",
    "zoho.com": "Zoho",
    "zoho.in": "Zoho",
    "trendmicro.com": "Trend Micro",
    "cloud-sec-av.com": "Avanan / Check Point Harmony",
    "amazonses.com": "Amazon SES",
    "sendgrid.net": "SendGrid",
    "mailgun.org": "Mailgun",
    "mailgun.net": "Mailgun",
    "sparkpostmail.com": "SparkPost",
    "mcsv.net": "Mailchimp",
    "secureserver.net": "GoDaddy",
    "onsecureserver.net": "GoDaddy",
    "inkyphishfence.com": "Inky Phish Fence",
    "perception-point.io": "Perception Point",
    "improvmx.com": "ImprovMx Email forwarding",
    "mailspamprotection.com": "SiteGround Email Service",
    "mimecast.com": "Mimecast",
    "forwardemail.net": "Forward Email",
    "iphmx.com": "Cisco Secure Email",
    "zendoff.com": "Zendoff Customer MTA",
    "dreamhost.com": "DreamHost Email Service",
    "v2soft.com": "V2Soft Custom MTA",
    "charter.net": "Spectrum / Charter Communications",
    "eigbox.met": "Custom MTA on Newfold Digital",
    # …add more here
}


def _extract_base_domain(hostname: str) -> str:
    """
    Extract the registrable/base domain from a hostname using the public suffix list.
    Examples:
        'email-connect-145.mjinn.com' -> 'mjinn.com'
        'ru1.netcore.co.in'           -> 'netcore.co.in'
        'flovrbmapp.kalyanicorp.com'  -> 'kalyanicorp.com'
    """
    ext = tldextract.extract(hostname)
    if not ext.domain:
        # Could be an IP address or something odd; just return what we got
        return hostname
    if ext.suffix:
        return f"{ext.domain}.{ext.suffix}"
    else:
        # No recognized public suffix (e.g. internal host); just return the domain part
        return ext.domain


def get_email_source(email_source_hostname: str) -> str:
    """
    Determine the email source/provider based on the hostname.

    If it matches a known provider, return the provider name.
    Otherwise, return a best-effort base domain (e.g. 'mjinn.com', 'netcore.co.in').
    """
    if not email_source_hostname:
        return ""

    hostname = email_source_hostname.strip().lower().rstrip(".")

    # 1. Normalize to base domain
    base_domain = _extract_base_domain(hostname)

    # 2. Look up provider by base domain (O(1))
    provider = PROVIDER_BY_BASE_DOMAIN.get(base_domain)

    if provider:
        return provider

    # 3. Fallback: use the base domain itself as a readable name
    #    (you can .title() it if you prefer 'Netcore.Co.In' etc.)
    return base_domain
