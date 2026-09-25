"""Synthetic BloodHound export for the ACME.LOCAL domain."""

DOMAIN = "ACME.LOCAL"
BASE_SID = "S-1-5-21-1111111111-2222222222-3333333333"


def _sid(rid: int) -> str:
    return f"{BASE_SID}-{rid}"


def _user(rid, sam, display, title=None, spn=False, admincount=False, highvalue=False):
    return {
        "ObjectIdentifier": _sid(rid),
        "Properties": {
            "name": f"{sam.upper()}@{DOMAIN}",
            "samaccountname": sam,
            "displayname": display,
            "domain": DOMAIN,
            "domainsid": BASE_SID,
            "title": title,
            "enabled": True,
            "hasspn": spn,
            "admincount": admincount,
            "highvalue": highvalue,
            "serviceprincipalnames": [f"http/{sam}.{DOMAIN.lower()}"] if spn else None,
        },
    }


def _group(rid, sam, display, members, highvalue=False):
    return {
        "ObjectIdentifier": _sid(rid),
        "Properties": {
            "name": f"{sam.upper()}@{DOMAIN}",
            "samaccountname": sam,
            "displayname": display,
            "domain": DOMAIN,
            "highvalue": highvalue,
        },
        "Members": [_sid(m) for m in members],
    }


def _computer(rid, sam, os_, sessions=None, admins=None, highvalue=False):
    return {
        "ObjectIdentifier": _sid(rid),
        "Properties": {
            "name": f"{sam.upper()}.{DOMAIN}",
            "samaccountname": f"{sam.upper()}$",
            "operatingsystem": os_,
            "domain": DOMAIN,
            "highvalue": highvalue,
            "enabled": True,
        },
        "Sessions": {"Results": [{"UserSID": _sid(s), "UserName": ""} for s in (sessions or [])]},
        "LocalAdmins": {"Results": [
            {"ObjectIdentifier": _sid(a), "ObjectType": "User"} for a in (admins or [])
        ]},
    }


DAVE, CAROL, BOB, ALICE, FRANK = 1101, 1102, 1103, 1104, 1105
SVCBK, SVCWEB, SVCCI = 1106, 1107, 1108
ADMIN = 500

DOMAIN_ADMINS, DOMAIN_USERS, BACKUP_OPS = 512, 513, 551
HELPDESK, DEVELOPERS, FINANCE = 1101, 1102, 1103

DC01, SRV_WEB, SRV_SQL, SRV_BACKUP = 2001, 2002, 2003, 2004
WKS_ALICE, WKS_BOB, WKS_CAROL, WKS_DAVE = 2101, 2102, 2103, 2104


USERS = [
    _user(DAVE,  "dave",  "Dave Kumar",   "Contractor"),
    _user(CAROL, "carol", "Carol Nunez",  "Finance Analyst"),
    _user(BOB,   "bob",   "Bob Reyes",    "Developer"),
    _user(ALICE, "alice", "Alice Chen",   "Helpdesk L1"),
    _user(FRANK, "frank", "Frank Ortiz",  "IT Manager", admincount=True),
    _user(SVCBK,  "svc_backup", "svc_backup", "Backup Agent", spn=True, admincount=True),
    _user(SVCWEB, "svc_web",    "svc_web",    "IIS App Pool", spn=True),
    _user(SVCCI,  "svc_ci",     "svc_ci",     "CI Runner",    spn=True),
    _user(ADMIN, "administrator", "Administrator", highvalue=True),
]


GROUPS = [
    _group(DOMAIN_ADMINS, "Domain Admins", "Domain Admins", [ADMIN, FRANK], highvalue=True),
    _group(DOMAIN_USERS,  "Domain Users",  "Domain Users",  [DAVE, CAROL, BOB, ALICE, FRANK]),
    _group(BACKUP_OPS,    "Backup Operators", "Backup Operators", [SVCBK], highvalue=True),
    _group(HELPDESK,      "GG-Helpdesk",  "Helpdesk Team", [ALICE, FRANK]),
    _group(DEVELOPERS,    "GG-Developers", "Developers",   [BOB]),
    _group(FINANCE,       "GG-Finance",    "Finance",      [CAROL]),
]


COMPUTERS = [
    _computer(DC01, "DC01", "Windows Server 2019",
              sessions=[ADMIN, SVCBK], admins=[DOMAIN_ADMINS], highvalue=True),
    _computer(SRV_WEB, "SRV-WEB01", "Windows Server 2019",
              sessions=[SVCWEB], admins=[DOMAIN_ADMINS, HELPDESK]),
    _computer(SRV_SQL, "SRV-SQL01", "Windows Server 2019",
              sessions=[SVCBK, ALICE], admins=[DOMAIN_ADMINS]),
    _computer(SRV_BACKUP, "SRV-BACKUP01", "Windows Server 2019",
              sessions=[SVCBK], admins=[DOMAIN_ADMINS, BACKUP_OPS]),
    _computer(WKS_ALICE, "WKS-ALICE01", "Windows 10",
              sessions=[ALICE], admins=[HELPDESK, FRANK]),
    _computer(WKS_BOB, "WKS-BOB01", "Windows 10",
              sessions=[BOB], admins=[HELPDESK, FRANK]),
    _computer(WKS_CAROL, "WKS-CAROL01", "Windows 10",
              sessions=[CAROL, ALICE], admins=[HELPDESK, FRANK]),
    _computer(WKS_DAVE, "WKS-DAVE01", "Windows 10",
              sessions=[DAVE, ALICE], admins=[HELPDESK, FRANK]),
]
