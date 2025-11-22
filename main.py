import requests
import json
import re
import csv
from collections import Counter, defaultdict
import smtplib
import ssl
from email.message import EmailMessage
import os

# Add your whitelisted domains here:
WHITELISTED_SELLER_DOMAINS = {
    "google.com",
    "ads.vk.com"
}

def extract_seller_domains_and_ids(domain):
    url = f"https://{domain}/app-ads.txt"
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
    except Exception as e:
        print(f"❌ Failed to fetch {url}: {e}")
        return [], []

    lines = response.text.splitlines()
    seller_domains = set()
    seller_ids = []

    for line in lines:
        line = line.strip()
        if not line or line.startswith("#") or "=" in line:
            continue
        parts = [p.strip() for p in line.split(",")]
        if len(parts) < 3:
            continue
        seller_domain = parts[0].lower()
        seller_id = parts[1].strip().lower()
        seller_type = parts[2].strip().upper()

        seller_domains.add(seller_domain)
        seller_ids.append((seller_id, seller_domain, seller_type))

    return sorted(seller_domains), seller_ids

def parse_json(response, domain):
    try:
        return response.json()
    except json.JSONDecodeError:
        try:
            cleaned_text = response.text.encode().decode('utf-8-sig')
            cleaned_text = re.sub(r',\s*([\]}])', r'\1', cleaned_text)
            cleaned_text = cleaned_text.replace('\x00', '')
            return json.loads(cleaned_text)
        except Exception as e2:
            print(f"❌ Failed to parse sellers.json from {domain}: {e2}")
            return None

def fetch_sellers_json(domain):
    paths = [
        f"https://{domain}/sellers.json",
        f"https://www.{domain}/sellers.json",
        f"http://{domain}/sellers.json",
        f"http://www.{domain}/sellers.json"
    ]

    headers = {
        "User-Agent": "Mozilla/5.0 (compatible; sellers-json-checker/1.0)",
        "Accept": "application/json",
    }

    for url in paths:
        try:
            response = requests.get(url, headers=headers, timeout=10, allow_redirects=True)
            if response.status_code == 200:
                print(f"✅ sellers.json found at {url}")
                parsed = parse_json(response, domain)
                if parsed:
                    return parsed.get("sellers", [])
        except Exception:
            continue
    print(f"❌ sellers.json not found for {domain}")
    return []

def relationship_match(app_ads_txt_type, seller_type):
    app_ads_txt_type = app_ads_txt_type.strip().upper()
    seller_type = (seller_type or "").strip().upper()
    if app_ads_txt_type == "RESELLER" and seller_type in ["INTERMEDIARY", "BOTH"]:
        return "✅", "OK"
    elif app_ads_txt_type == "DIRECT" and seller_type in ["PUBLISHER", "BOTH"]:
        return "✅", "OK"
    else:
        return "❌", f"Mismatch: {app_ads_txt_type} vs {seller_type or 'n/a'}"

def match_sellers(seller_domains, seller_ids, OUTPUT_CSV):
    print(f"\n🔍 Total seller IDs in app-ads.txt: {len(seller_ids)}")
    id_counter = Counter([(sid, sdomain) for sid, sdomain, _ in seller_ids])
    seen_ids = set()
    redundant_lines = sum(count - 1 for (sid, sdomain), count in id_counter.items() if count > 1)

    stats = {"total": len(seller_ids), "matched": 0, "mismatch": 0, "not_found": 0}
    csv_rows = []
    header = [
        "Status", "Seller Domain", "Seller ID", "Seller Type (app-ads.txt)",
        "Seller Name (JSON)", "Seller Type (JSON)", "JSON Domain",
        "Used Count (sellers.json)", "Comment", "Duplicate Entry"
    ]

    for domain in sorted(seller_domains):
        print(f"\n🌐 Checking domain: {domain}")

        if domain in WHITELISTED_SELLER_DOMAINS:
            for sid, seller_domain, seller_type in seller_ids:
                if seller_domain == domain:
                    count = id_counter[(sid, seller_domain)]
                    duplicate_flag = "Yes" if count > 1 else "No"
                    suffix = f" (x{count})" if count > 1 else ""
                    print(f"✅ {seller_domain}, {sid}{suffix}, {seller_type}, n/a, n/a, n/a, Part of whitelisted exchange domains")
                    stats["matched"] += 1
                    csv_rows.append(["✅", seller_domain, sid, seller_type, "n/a", "n/a", "n/a", count, "Part of whitelisted exchange domains", duplicate_flag])
            continue

        entries = fetch_sellers_json(domain)

        if not entries:
            for sid, seller_domain, seller_type in seller_ids:
                if seller_domain == domain:
                    count = id_counter[(sid, seller_domain)]
                    duplicate_flag = "Yes" if count > 1 else "No"
                    suffix = f" (x{count})" if count > 1 else ""
                    print(f"❌ {seller_domain}, {sid}{suffix}, {seller_type}, n/a, n/a, n/a, sellers.json not available or broken, used 0x")
                    stats["not_found"] += 1
                    csv_rows.append(["❌", seller_domain, sid, seller_type, "n/a", "n/a", "n/a", 0, "sellers.json not available or broken", duplicate_flag])
            continue

        json_id_counter = Counter()
        seller_id_occurrences = defaultdict(list)

        for entry in entries:
            sid_entry = entry.get("seller_id")
            if sid_entry is not None:
                sid_str = str(sid_entry).strip().lower()
                key = (sid_str, domain)
                json_id_counter[key] += 1
                seller_id_occurrences[sid_str].append(entry)

        for sid, seller_domain, seller_type in seller_ids:
            sid_clean = sid.strip().lower()
            if seller_domain == domain and (sid, domain) not in seen_ids:
                matched = False
                for entry in seller_id_occurrences.get(sid_clean, []):
                    seen_ids.add((sid, domain))
                    count_app_ads = id_counter[(sid, seller_domain)]
                    duplicate_flag = "Yes" if count_app_ads > 1 else "No"
                    suffix = f" (x{count_app_ads})" if count_app_ads > 1 else ""
                    count_json = json_id_counter.get((sid_clean, domain), 0)
                    relationship, comment = relationship_match(seller_type, entry.get("seller_type"))

                    if relationship == "✅":
                        stats["matched"] += 1
                    else:
                        stats["mismatch"] += 1

                    name = entry.get("name", "n/a")
                    s_type = entry.get("seller_type", "n/a")
                    s_domain = entry.get("domain", "n/a")

                    csv_rows.append([
                        relationship, seller_domain, sid, seller_type, name, s_type, s_domain, count_json, comment, duplicate_flag
                    ])
                    matched = True
                    break

                if not matched:
                    count_app_ads = id_counter[(sid, seller_domain)]
                    duplicate_flag = "Yes" if count_app_ads > 1 else "No"
                    suffix = f" (x{count_app_ads})" if count_app_ads > 1 else ""
                    count_json = json_id_counter.get((sid_clean, domain), 0)
                    stats["not_found"] += 1
                    csv_rows.append(["❌", seller_domain, sid, seller_type, "n/a", "n/a", "n/a", count_json, "ID not found in sellers.json", duplicate_flag])

    removable = stats["not_found"] + redundant_lines
    need_fixing = stats["mismatch"]
    percent_removable = (removable / stats["total"]) * 100 if stats["total"] > 0 else 0

    print("\n📊 Summary:")
    print(f"✔️ Matched: {stats['matched']} lines")
    print(f"⚠️ Mismatch: {stats['mismatch']} lines")
    print(f"❌ Not found: {stats['not_found']} lines")
    print(f"♻️ Redundant (duplicate) lines in app-ads.txt: {redundant_lines}")
    print(f"📉 Potentially removable lines (incl. duplicates): {removable} / {stats['total']} ({percent_removable:.2f}%)")
    print(f"🔧 Lines needs to be fixed: {need_fixing}")

    with open(OUTPUT_CSV, "w", newline='', encoding='utf-8') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(header)
        writer.writerows(csv_rows)
    print(f"\n📁 CSV report saved to: {OUTPUT_CSV}")

def send_email_with_csv(file_path, target_domain):
    sender = os.getenv("GMAIL_USER")
    password = os.getenv("GMAIL_APP_PASSWORD")
    recipient = "applytics2025@gmail.com"

    subject = f"app-ads.txt Cleanup Report ({target_domain})"
    body = f"Attached is the latest cleanup report for {target_domain}."

    msg = EmailMessage()
    msg["From"] = sender
    msg["To"] = recipient
    msg["Subject"] = subject
    msg.set_content(body)

    with open(file_path, "rb") as f:
        msg.add_attachment(
            f.read(),
            maintype="text",
            subtype="csv",
            filename=os.path.basename(file_path)
        )

    context = ssl.create_default_context()

    with smtplib.SMTP_SSL("smtp.gmail.com", 465, context=context) as smtp:
        smtp.login(sender, password)
        smtp.send_message(msg)

    print(f"📧 Email sent to {recipient} with attachment {file_path}")

if __name__ == "__main__":
    target_domain = "learnings.ai"  # Change as needed

    # Dynamic CSV filename based on domain
    domain_clean = target_domain.replace("https://", "").replace("http://", "").replace("www.", "").replace("/", "_")
    OUTPUT_CSV = f"app-ads-txt-cleanup-report-{domain_clean}.csv"

    domains, seller_ids = extract_seller_domains_and_ids(target_domain)

    if not seller_ids:
        print("No seller IDs found in app-ads.txt.")
    else:
        match_sellers(domains, seller_ids, OUTPUT_CSV)
        send_email_with_csv(OUTPUT_CSV, target_domain)
