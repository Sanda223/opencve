"""
Provision OpenCVE projects, subscriptions and email alerts from a JSON file.

Usage (from the docker/ folder, stack running):
    docker compose exec -T \
        -e OPENCVE_PROVISION_CONFIG="$(cat conf/subscriptions.json)" \
        webserver python manage.py shell < provision_subscriptions.py

See conf/subscriptions.json.example for the config format. The real
conf/subscriptions.json is gitignored as it describes private projects.

For each project the script:
  - sets its subscriptions (each entry lists alternative "vendor:product" or
    "vendor" names; the first one present in the CVE database wins),
  - creates an enabled email notification to `email`,
  - creates an alert automation for high/critical (CVSS v3.1 or v4.0 >= 7)
    or CISA KEV-listed CVEs that enter the project, are added to KEV, or
    get a CVSS increase.

Idempotent: re-running updates subscriptions and descriptions and leaves
existing notifications/automations untouched.
"""

import json
import os
import secrets

from django.db import transaction
from django.utils.timezone import now

from cves.constants import PRODUCT_SEPARATOR
from cves.models import Product, Vendor
from organizations.models import Membership, Organization
from projects.models import Automation, Notification, Project
from users.models import User

CONFIG = json.loads(os.environ["OPENCVE_PROVISION_CONFIG"])

AUTOMATION_NAME = "High severity or exploited CVEs"
AUTOMATION_TRIGGERS = ["cve_enters_project", "kev_added", "cvss_increased"]
AUTOMATION_CONDITIONS = {
    "operator": "OR",
    "children": [
        {"type": "cvss_gte", "value": {"version": "v3.1", "value": 7}},
        {"type": "cvss_gte", "value": {"version": "v4.0", "value": 7}},
        {"type": "kev_present", "value": True},
    ],
}


def resolve(alternatives):
    for name in alternatives:
        if ":" in name:
            vendor, product = name.split(":", 1)
            if Product.objects.filter(vendor__name=vendor, name=product).exists():
                return f"{vendor}{PRODUCT_SEPARATOR}{product}"
        elif Vendor.objects.filter(name=name).exists():
            return name
    return None


@transaction.atomic
def main():
    user = User.objects.get(username=CONFIG["owner_username"])
    email = CONFIG["email"]

    org, created = Organization.objects.get_or_create(name=CONFIG["organization"])
    if created:
        Membership.objects.create(
            user=user,
            organization=org,
            role=Membership.OWNER,
            date_invited=now(),
            date_joined=now(),
        )

    for project_name, spec in CONFIG["projects"].items():
        subs = {"vendors": [], "products": []}
        found, missing = [], []
        for alternatives in spec["subscriptions"]:
            key = resolve(alternatives)
            if key is None:
                missing.append(alternatives[0])
                continue
            bucket = "products" if PRODUCT_SEPARATOR in key else "vendors"
            if key not in subs[bucket]:
                subs[bucket].append(key)
            found.append(key.replace(PRODUCT_SEPARATOR, ":"))

        project, _ = Project.objects.get_or_create(name=project_name, organization=org)
        project.description = spec.get("description", "")
        project.subscriptions = subs
        project.save()

        notification, _ = Notification.objects.get_or_create(
            project=project,
            name="Email alerts",
            defaults={
                "type": "email",
                "is_enabled": True,
                "configuration": {
                    "extras": {
                        "email": email,
                        "created_by_email": user.email,
                        # Same state the UI leaves once the address is confirmed
                        "unsubscribe_token": secrets.token_urlsafe(32),
                    }
                },
            },
        )

        Automation.objects.get_or_create(
            project=project,
            name=AUTOMATION_NAME,
            defaults={
                "trigger_type": Automation.TRIGGER_ALERT,
                "is_enabled": True,
                "configuration": {
                    "triggers": AUTOMATION_TRIGGERS,
                    "conditions": AUTOMATION_CONDITIONS,
                    "actions": [
                        {"type": "send_notification", "value": str(notification.id)}
                    ],
                },
            },
        )

        print(f"\n== {project_name}")
        print("  subscribed:", ", ".join(found) or "-")
        print("  not in CVE database:", ", ".join(missing) or "-")


main()
