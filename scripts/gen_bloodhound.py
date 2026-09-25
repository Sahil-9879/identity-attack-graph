import json, zipfile
from pathlib import Path

DOMAIN = "CORP.LOCAL"
BASE = "S-1-5-21-1000-2000-3000"
def sid(rid): return f"{BASE}-{rid}"

users = [
    {"ObjectIdentifier": sid(1101), "Properties": {"name": "DAVE@CORP.LOCAL",
        "samaccountname": "dave", "domain": DOMAIN, "enabled": True,
        "admincount": False, "hasspn": False, "highvalue": False}, "Aces": []},
    {"ObjectIdentifier": sid(1102), "Properties": {"name": "ALICE@CORP.LOCAL",
        "samaccountname": "alice", "domain": DOMAIN, "enabled": True,
        "admincount": False, "hasspn": False, "highvalue": False}, "Aces": []},
    {"ObjectIdentifier": sid(1103), "Properties": {"name": "FRANK@CORP.LOCAL",
        "samaccountname": "frank", "domain": DOMAIN, "enabled": True,
        "admincount": True, "hasspn": False, "highvalue": False}, "Aces": []},
    {"ObjectIdentifier": sid(500), "Properties": {"name": "ADMINISTRATOR@CORP.LOCAL",
        "samaccountname": "administrator", "domain": DOMAIN, "enabled": True,
        "admincount": True, "hasspn": False, "highvalue": True}, "Aces": []},
    {"ObjectIdentifier": sid(1106), "Properties": {"name": "SVC_BACKUP@CORP.LOCAL",
        "samaccountname": "svc_backup", "domain": DOMAIN, "enabled": True,
        "admincount": True, "hasspn": True, "highvalue": False}, "Aces": []},
]

groups = [
    {"ObjectIdentifier": sid(512),
     "Properties": {"name": "DOMAIN ADMINS@CORP.LOCAL",
        "samaccountname": "Domain Admins", "domain": DOMAIN, "highvalue": True},
     "Members": [sid(500), sid(1103)],
     "Aces": []},
    {"ObjectIdentifier": sid(551),
     "Properties": {"name": "BACKUP OPERATORS@CORP.LOCAL",
        "samaccountname": "Backup Operators", "domain": DOMAIN, "highvalue": True},
     "Members": [sid(1106)],
     "Aces": []},
    {"ObjectIdentifier": sid(1200),
     "Properties": {"name": "HELPDESK@CORP.LOCAL",
        "samaccountname": "GG-Helpdesk", "domain": DOMAIN, "highvalue": False},
     "Members": [sid(1102), sid(1103)],
     "Aces": []},
]

computers = [
    {"ObjectIdentifier": sid(2001),
     "Properties": {"name": "DC01.CORP.LOCAL", "samaccountname": "DC01$",
        "operatingsystem": "Windows Server 2022", "domain": DOMAIN,
        "highvalue": True},
     "Sessions": {"Results": [{"UserSID": sid(500), "UserName": "Administrator"}]},
     "LocalAdmins": {"Results": [{"ObjectIdentifier": sid(512), "ObjectType": "Group"}]},
     "Aces": []},
    {"ObjectIdentifier": sid(2002),
     "Properties": {"name": "SRV-WEB01.CORP.LOCAL", "samaccountname": "SRV-WEB01$",
        "operatingsystem": "Windows Server 2022", "domain": DOMAIN,
        "highvalue": False},
     "Sessions": {"Results": [{"UserSID": sid(1102), "UserName": "alice"}]},
     "LocalAdmins": {"Results": [{"ObjectIdentifier": sid(1200), "ObjectType": "Group"}]},
     "Aces": []},
    {"ObjectIdentifier": sid(2003),
     "Properties": {"name": "SRV-SQL01.CORP.LOCAL", "samaccountname": "SRV-SQL01$",
        "operatingsystem": "Windows Server 2022", "domain": DOMAIN,
        "highvalue": False},
     "Sessions": {"Results": [{"UserSID": sid(1106), "UserName": "svc_backup"}]},
     "LocalAdmins": {"Results": [{"ObjectIdentifier": sid(512), "ObjectType": "Group"}]},
     "Aces": []},
    {"ObjectIdentifier": sid(2101),
     "Properties": {"name": "WKS-DAVE01.CORP.LOCAL", "samaccountname": "WKS-DAVE01$",
        "operatingsystem": "Windows 10", "domain": DOMAIN, "highvalue": False},
     "Sessions": {"Results": [{"UserSID": sid(1101), "UserName": "dave"}]},
     "LocalAdmins": {"Results": [{"ObjectIdentifier": sid(1200), "ObjectType": "Group"}]},
     "Aces": []},
]

# Real ACLs — the interesting part
groups[1]["Aces"].append({
    "PrincipalSID": sid(1103), "PrincipalType": "User",
    "RightName": "GenericAll", "IsInherited": False,
})
users[1]["Aces"].append({
    "PrincipalSID": sid(1101), "PrincipalType": "User",
    "RightName": "ForceChangePassword", "IsInherited": False,
})

BASE2 = "S-1-5-21-4000-5000-6000"
def sid2(rid): return f"{BASE2}-{rid}"

# ---- Forest 2: PROD.LOCAL — a partner domain with a bidirectional trust
prod_users = [
    {"ObjectIdentifier": sid2(1101),
     "Properties": {"name": "PROD_APP@PROD.LOCAL",
                    "samaccountname": "prod_app",
                    "domain": "PROD.LOCAL", "enabled": True,
                    "admincount": False, "hasspn": True, "highvalue": False},
     "Aces": []},
    {"ObjectIdentifier": sid2(500),
     "Properties": {"name": "PROD_ADMIN@PROD.LOCAL",
                    "samaccountname": "prod_admin",
                    "domain": "PROD.LOCAL", "enabled": True,
                    "admincount": True, "hasspn": False, "highvalue": True},
     "Aces": []},
]
prod_groups = [
    {"ObjectIdentifier": sid2(512),
     "Properties": {"name": "PROD ENTERPRISE ADMINS@PROD.LOCAL",
                    "samaccountname": "Enterprise Admins",
                    "domain": "PROD.LOCAL", "highvalue": True},
     "Members": [sid2(500)], "Aces": []},
]
prod_computers = [
    {"ObjectIdentifier": sid2(3001),
     "Properties": {"name": "PROD-DB01.PROD.LOCAL",
                    "samaccountname": "PROD-DB01$",
                    "operatingsystem": "Windows Server 2022",
                    "domain": "PROD.LOCAL", "highvalue": True},
     "Sessions": {"Results": [{"UserSID": sid2(500), "UserName": "prod_admin"}]},
     "LocalAdmins": {"Results": [{"ObjectIdentifier": sid2(512),
                                   "ObjectType": "Group"}]},
     "Aces": []},
]

domains = [
    {
        "ObjectIdentifier": BASE,
        "Properties": {"name": DOMAIN, "domain": DOMAIN, "highvalue": True},
        "Aces": [{"PrincipalSID": sid(512), "PrincipalType": "Group",
                  "RightName": "DCSync", "IsInherited": False}],
        "Trusts": [{
            "TargetDomainSid": BASE2,
            "TargetDomainName": "PROD.LOCAL",
            "TrustDirection": 3,       # bidirectional
            "TrustType": "External",
            "IsTransitive": True,
        }],
    },
    {
        "ObjectIdentifier": BASE2,
        "Properties": {"name": "PROD.LOCAL", "domain": "PROD.LOCAL",
                       "highvalue": True},
        "Aces": [{"PrincipalSID": sid2(512), "PrincipalType": "Group",
                  "RightName": "DCSync", "IsInherited": False}],
        "Trusts": [{
            "TargetDomainSid": BASE,
            "TargetDomainName": DOMAIN,
            "TrustDirection": 3,
            "TrustType": "External",
            "IsTransitive": True,
        }],
    },
]

users = users + prod_users
groups = groups + prod_groups
computers = computers + prod_computers

out = Path("/tmp/bloodhound_demo.zip")
with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as zf:
    zf.writestr("users.json", json.dumps(users, indent=2))
    zf.writestr("groups.json", json.dumps(groups, indent=2))
    zf.writestr("computers.json", json.dumps(computers, indent=2))
    zf.writestr("domains.json", json.dumps(domains, indent=2))

print(f"wrote {out}")
print(f"  users: {len(users)}  groups: {len(groups)}  computers: {len(computers)}  domains: {len(domains)}")
