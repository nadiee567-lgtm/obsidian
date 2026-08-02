#!/usr/bin/env python3
"""OBSIDIAN License Generator — Sebastian's Lab"""
import json, hashlib, os, sys, datetime

SECRET_SALT = "OBSIDIAN_SEBASTIAN_2025_X9K"

TIERS = {
    '1': ('lite',   'OBSIDIAN Investigator', 'Free'),
    '2': ('normal', 'OBSIDIAN Analyst',      '$5-10 USD'),
    '3': ('pro',    'OBSIDIAN Professional', '$20 USD'),
}

def generate_license(email, tier, days=365):
    email = email.strip().lower()
    expires = (datetime.datetime.now() + datetime.timedelta(days=days)).strftime('%Y-%m-%d')
    raw = SECRET_SALT + email + tier + expires
    sig = hashlib.sha256(raw.encode()).hexdigest()[:16]
    return {
        'email':   email,
        'tier':    tier,
        'expira':  expires,
        'sig':     sig,
        'version': '1.0'
    }

def verify_license(key_data):
    email   = key_data.get('email', '')
    tier    = key_data.get('tier', '')
    expires = key_data.get('expira', '')
    sig     = key_data.get('sig', '')
    raw     = SECRET_SALT + email + tier + expires
    expected = hashlib.sha256(raw.encode()).hexdigest()[:16]
    if sig != expected:
        return False, "Invalid signature"
    try:
        exp = datetime.datetime.strptime(expires, '%Y-%m-%d')
        if exp < datetime.datetime.now():
            return False, "License expired"
    except Exception:
        return False, "Invalid date"
    return True, "OK"

def main():
    print("\n⬛ OBSIDIAN License Generator")
    print("─" * 40)

    if len(sys.argv) == 4:
        email = sys.argv[1]
        tier  = sys.argv[2]
        days  = int(sys.argv[3])
    else:
        email = input("Customer email: ").strip()
        print("\nAvailable tiers:")
        for k, (t, name, price) in TIERS.items():
            print(f"  {k}. {name} ({price})")
        option = input("\nTier (1/2/3): ").strip()
        if option not in TIERS:
            print("Invalid option"); sys.exit(1)
        tier = TIERS[option][0]
        days_str = input("Validity in days [365]: ").strip()
        days = int(days_str) if days_str else 365

    if tier not in ('lite', 'normal', 'pro'):
        print("Invalid tier"); sys.exit(1)

    key_data = generate_license(email, tier, days)
    ok, msg  = verify_license(key_data)

    tier_names = {'lite': 'Investigator', 'normal': 'Analyst', 'pro': 'Professional'}

    print("\n✅ LICENSE GENERATED")
    print("─" * 40)
    print(f"  Product: OBSIDIAN {tier_names[tier]}")
    print(f"  Email:   {key_data['email']}")
    print(f"  Tier:    {key_data['tier']}")
    print(f"  Expires: {key_data['expira']}")
    print(f"  Sig:     {key_data['sig']}")
    print(f"  Valid:   {ok} — {msg}")
    print("─" * 40)

    key_json = json.dumps(key_data, indent=2)
    print("\nobsidian.key contents:")
    print(key_json)

    filename = f"obsidian_{email.replace('@','_').replace('.','_')}_{tier}.key"
    with open(filename, 'w') as f:
        f.write(key_json)

    print(f"\n💾 Saved to: {filename}")
    print("   Send this file to the customer.")
    print("   They place it in: ~/.obsidian/obsidian.key\n")

if __name__ == '__main__':
    main()
