
import re
import ipaddress
from urllib.parse import urlsplit

# ==========================================
# PhishLens - Suspicious Email Analyser
# ==========================================

URL_PATTERN = r"https?://[^\s<>\"']+|www\.[^\s<>\"']+"

URGENT_PHRASES = [
    "verify your account",
    "immediately",
    "account suspended",
    "act now",
    "urgent action required",
    "within 24 hours",
    "your account will be closed",
    "confirm your password",
    "unusual activity detected",
]

SHORTENERS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "is.gd",
    "ow.ly",
}

RISKY_EXTENSIONS = {
    ".exe", ".scr", ".js", ".vbs",
    ".bat", ".cmd", ".ps1", ".msi",
}


def get_domain(url):
    """Extract the hostname from a URL."""
    if url.lower().startswith("www."):
        url = "http://" + url

    try:
        return (urlsplit(url).hostname or "").lower().rstrip(".")
    except ValueError:
        return ""


def analyse_email(sender, email_text):
    findings = []
    score = 0
    text = email_text.lower()

    # 1. Check the sender address
    sender_match = re.search(
        r"^[^@\s]+@([^@\s]+)$",
        sender.strip()
    )

    sender_domain = ""

    if sender_match:
        sender_domain = sender_match.group(1).lower()

        if sender_domain.startswith("xn--") or ".xn--" in sender_domain:
            findings.append((
                20,
                "Internationalised sender domain",
                "Some domains use encoded international "
                "characters that can resemble other characters."
            ))
            score += 20
    else:
        findings.append((
            10,
            "Unusual sender format",
            "The sender address does not match the expected "
            "name@domain format."
        ))
        score += 10

    # 2. Find and inspect links
    urls = re.findall(URL_PATTERN, email_text, re.IGNORECASE)
    link_domains = set()

    for url in urls:
        url = url.rstrip(".,!?;:)")
        domain = get_domain(url)

        if not domain:
            continue

        link_domains.add(domain)

        if domain in SHORTENERS:
            findings.append((
                15,
                "Shortened URL",
                f"{url} hides its final destination behind "
                "a URL-shortening service."
            ))
            score += 15

        try:
            ipaddress.ip_address(domain)
            findings.append((
                25,
                "IP address used as a link",
                f"{url} uses an IP address instead of a "
                "conventional domain name."
            ))
            score += 25
        except ValueError:
            pass

        if "@" in urlsplit(url).netloc:
            findings.append((
                25,
                "Potentially misleading URL",
                f"{url} contains an @ symbol in its "
                "network location. Check the actual hostname."
            ))
            score += 25

    # 3. Compare sender and link domains
    if sender_domain and link_domains:
        for domain in link_domains:
            if domain != sender_domain:
                findings.append((
                    10,
                    "Sender and link domains differ",
                    f"The sender uses {sender_domain}, but "
                    f"a link uses {domain}. Legitimate "
                    "services can also use different domains."
                ))
                score += 10

    # 4. Detect urgent or threatening wording
    for phrase in URGENT_PHRASES:
        if phrase in text:
            findings.append((
                10,
                "Urgent or threatening language",
                f'The phrase "{phrase}" appears in the email. '
                "Phishing messages may pressure recipients "
                "to act before checking the details."
            ))
            score += 10

    # 5. Detect potentially risky attachment names
    attachment_pattern = (
        r"\b[\w .()-]+\."
        r"(?:exe|scr|js|vbs|bat|cmd|ps1|msi)\b"
    )

    attachments = re.findall(
        attachment_pattern,
        email_text,
        re.IGNORECASE
    )

    for attachment in attachments:
        findings.append((
            20,
            "Potentially risky attachment",
            f'"{attachment.strip()}" has a file extension '
            "that can be associated with executable code."
        ))
        score += 20

    # 6. Calculate an indicative risk rating
    score = min(score, 100)

    if score >= 50:
        rating = "HIGH"
    elif score >= 20:
        rating = "MEDIUM"
    else:
        rating = "LOW"

    return score, rating, findings, urls


def main():
    print("=" * 45)
    print("       PHISHLENS EMAIL ANALYSER")
    print("=" * 45)

    sender = input("\nSender email address: ").strip()

    print(
        "\nPaste the email below. "
        "Press Enter on an empty line to finish:\n"
    )

    lines = []

    while True:
        try:
            line = input()

            if not line:
                break

            lines.append(line)

        except EOFError:
            break

    email_text = "\n".join(lines)

    if not email_text.strip():
        print("\nNo email text entered.")
        return

    score, rating, findings, urls = analyse_email(
        sender,
        email_text
    )

    print("\n" + "=" * 45)
    print("             ANALYSIS REPORT")
    print("=" * 45)

    print(f"\nRisk score: {score}/100")
    print(f"Risk rating: {rating}")
    print(f"Links found: {len(urls)}")
    print(f"Warnings found: {len(findings)}")

    if findings:
        print("\n--- WARNING DETAILS ---")

        for number, finding in enumerate(findings, 1):
            points, title, explanation = finding

            print(f"\n{number}. {title} (+{points} points)")
            print(f"   Why it matters: {explanation}")
    else:
        print("\nNo configured warning signs were detected.")

    print("\n--- LINKS FOUND ---")

    if urls:
        for url in urls:
            print(f"- {url}")
    else:
        print("No links found.")

    print("\nIMPORTANT:")
    print(
        "This tool identifies warning signs, not proof "
        "of phishing. A low score does not guarantee "
        "that an email is safe."
    )


if __name__ == "__main__":
    main()
