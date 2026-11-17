"""Reviewed collection routes, not field mappings or executable conversion pipelines.

Each default names a concrete export or a required bundle of logs. Explicit services
must be allowlisted and never fall back to a product default. See the research report
for references and the distinction between collection candidates and usable rules.
"""

from __future__ import annotations

from dataclasses import dataclass

from sigma.pipelines.common import windows_logsource_mapping
from sigma.pipelines.sysmon.sysmon import sysmon_generic_logsource_eventid_mapping


@dataclass(frozen=True)
class CollectionRoute:
    product: str
    scope: str
    label: str
    services: tuple[str, ...] = ()
    categories: tuple[str, ...] = ()
    default: bool = False
    note: str = "Enable the named logs and normalize vendor fields; collection alone does not establish field coverage."

    @property
    def key(self) -> str:
        return f"{self.product}:{self.scope}"


# Use the installed, fingerprinted pySigma taxonomy instead of maintaining a second
# partial Sysmon/channel table. Extra channels below are in the Sigma appendix.
SYSMON_EVENTS = {
    category: "+".join(str(e) for e in (events if isinstance(events, list) else [events]))
    for category, events in sysmon_generic_logsource_eventid_mapping.items()
}
# Reviewed spelling aliases stay within services; never turn a service into a category.
WINDOWS_SERVICE_ALIASES = {"bits": "bits-client", "vhd": "vhdmp", "windows-defender": "windefend"}
WINDOWS_AMBIGUOUS_SERVICES = frozenset({"process", "registry_event", "firewall"})
WINDOWS_CHANNELS: dict[str, str | list[str]] = {
    service: channels if isinstance(channels, str) else list(channels) for service, channels in windows_logsource_mapping.items()
} | {
    "setup": "Setup",
    "application-experience": [
        "Microsoft-Windows-Application-Experience/Program-Telemetry",
        "Microsoft-Windows-Application-Experience/Program-Compatibility-Assistant",
    ],
    "hyper-v-worker": "Microsoft-Windows-Hyper-V-Worker",
    "iis-configuration": "Microsoft-IIS-Configuration/Operational",
    "msexchange": "MSExchange Management",
    "kernel-event-tracing": "Microsoft-Windows-Kernel-EventTracing",
    "kernel-shimengine": ["Microsoft-Windows-Kernel-ShimEngine/Operational", "Microsoft-Windows-Kernel-ShimEngine/Diagnostic"],
    "ntfs": "Microsoft-Windows-Ntfs/Operational",
    "sense": "Microsoft-Windows-SENSE/Operational",
    "servicebus-client": ["Microsoft-ServiceBus-Client/Operational", "Microsoft-ServiceBus-Client/Admin"],
    "smbserver-security": "Microsoft-Windows-SMBServer/Security",
    "smbclient-connectivity": "Microsoft-Windows-SMBClient/Connectivity",
}
WINDOWS_CHANNELS.update({alias: WINDOWS_CHANNELS[canonical] for alias, canonical in WINDOWS_SERVICE_ALIASES.items()})

ROUTES = (
    CollectionRoute("aws", "waf", "AWS WAF request logs", ("waf",)),
    CollectionRoute(
        "aws",
        "cloudwatch",
        "Amazon CloudWatch Logs",
        ("cloudwatch",),
        note="Select the originating log group and producer; CloudWatch is a transport, not a common event schema.",
    ),
    CollectionRoute("azure", "nsg_flow_logs", "Azure Network Security Group flow logs", ("nsg_flow_logs",)),
    CollectionRoute("azure", "security_alerts", "Microsoft Defender for Cloud security alerts", ("security_alerts",)),
    CollectionRoute("azure", "m365", "Microsoft 365 Unified Audit Log", ("m365", "office365")),
    CollectionRoute("gcp", "firewall_logs", "Google Cloud VPC firewall rule logs", ("firewall_logs",)),
    CollectionRoute("gcp", "workspace-audit", "Google Workspace Reports API audit activities", ("google_workspace.admin", "google_workspace.login")),
    CollectionRoute("m365", "entra-audit", "Microsoft Entra audit logs", ("audit.azuread", "azureactivedirectory")),
    CollectionRoute("m365", "defender-alerts", "Microsoft Defender XDR alerts", ("windefend", "threat_management", "threat_detection")),
    CollectionRoute("m365", "cloud_app_security", "Microsoft Defender for Cloud Apps activity log", ("cloud_app_security",)),
    CollectionRoute("cisco", "duo", "Cisco Duo authentication log", ("duo",)),
    CollectionRoute("fortigate", "utm", "FortiGate UTM security logs", ("utm",)),
    CollectionRoute("paloalto", "globalprotect", "PAN-OS GlobalProtect logs", ("globalprotect",)),
    CollectionRoute("apache", "httpd", "Apache HTTP Server access and error log bundle", ("httpd",)),
    CollectionRoute("gitlab", "audit", "GitLab audit events", ("audit", "audit_events")),
    CollectionRoute("gitlab", "application", "GitLab production_json.log", ("production_json.log",)),
    CollectionRoute("jenkins", "audit", "Jenkins Audit Trail plugin logs", ("audit",)),
    CollectionRoute(
        "barracuda",
        "logs",
        "Barracuda appliance security, access and audit syslog bundle",
        ("syslog", "waf"),
        default=True,
        note="Identify the Barracuda appliance family; WAF and CloudGen Firewall require different parsers and logging policies.",
    ),
    CollectionRoute("cyberark", "audit", "CyberArk Vault audit syslog", ("audit", "syslog"), default=True),
    CollectionRoute("aws", "cloudtrail", "AWS CloudTrail", ("cloudtrail",), ("cloudtrail",)),
    CollectionRoute("aws", "guardduty", "AWS GuardDuty findings", ("guardduty",)),
    CollectionRoute("aws", "vpcflowlogs", "AWS VPC Flow Logs", ("vpcflowlogs", "vpcflow")),
    CollectionRoute("aws", "s3-access", "Amazon S3 server access logs", ("s3", "s3_access")),
    CollectionRoute("aws", "cloudfront", "Amazon CloudFront access logs", ("cloudfront",)),
    CollectionRoute("aws", "elb", "AWS load balancer access logs", ("elb", "alb")),
    CollectionRoute("aws", "route53", "Amazon Route 53 Resolver query logs", ("route53",)),
    CollectionRoute("azure", "activitylogs", "Azure Activity Log", ("activitylogs", "activity", "activitylog")),
    CollectionRoute("azure", "auditlogs", "Microsoft Entra audit logs", ("auditlogs", "audit", "azure.aad", "entra_id")),
    CollectionRoute("azure", "signinlogs", "Microsoft Entra sign-in logs", ("signinlogs", "sign_ins")),
    CollectionRoute("azure", "riskdetection", "Microsoft Entra risk detections", ("riskdetection", "riskdetections")),
    CollectionRoute("azure", "pim", "Microsoft Entra PIM audit logs", ("pim",)),
    CollectionRoute("gcp", "gcp.audit", "Google Cloud Audit Logs", ("gcp.audit", "audit", "auditlogs", "gke_audit_logs", "iam"), ("gcp", "audit")),
    CollectionRoute(
        "m365",
        "audit",
        "Microsoft 365 Unified Audit Log",
        ("audit", "auditlogs", "unified_audit_log", "management", "management_activity", "m365", "securitycompliancecenter"),
        ("audit",),
    ),
    CollectionRoute("m365", "exchange", "Microsoft 365 Exchange audit logs", ("exchange", "audit.exchange")),
    CollectionRoute("m365", "sharepoint", "Microsoft 365 SharePoint audit logs", ("sharepoint", "audit.sharepoint")),
    CollectionRoute("m365", "teams", "Microsoft 365 Teams audit logs", ("teams", "audit.teams")),
    CollectionRoute("m365", "messagetrace", "Exchange Online message trace", ("messagetrace",)),
    CollectionRoute("okta", "okta", "Okta System Log", ("okta", "system", "systemlog", "system_log", "audit"), default=True),
    CollectionRoute("github", "audit", "GitHub organization audit log", ("audit", "auditlogs"), ("audit",), True),
    CollectionRoute(
        "google_workspace",
        "audit",
        "Google Workspace Reports API audit activities",
        (
            "audit",
            "admin",
            "login",
            "drive",
            "reports",
            "token",
            "google_workspace.admin",
            "google_workspace.login",
            "google_workspace.user_accounts",
        ),
    ),
    CollectionRoute("oci", "audit", "Oracle Cloud Infrastructure Audit", ("audit",)),
    CollectionRoute("kubernetes", "audit", "Kubernetes API audit log", ("audit", "api_server"), ("kubernetes_audit",)),
    CollectionRoute("docker", "events", "Docker daemon events", ("events", "docker", "daemon")),
    CollectionRoute(
        "linux",
        "auditd",
        "Linux auditd",
        ("auditd", "audit"),
        ("process_creation", "file_event", "file_delete", "file_change", "network_connection"),
        note="Configure audit rules and normalize process/file fields; not a native Sigma field guarantee.",
    ),
    CollectionRoute("linux", "journald/syslog", "Linux journald/syslog", ("syslog", "journald", "auth", "sshd", "ssh", "cron", "sudo", "su", "systemd")),
    CollectionRoute(
        "linux",
        "shell-history",
        "Linux shell history",
        ("bash", "shell"),
        note="Collect shell history explicitly; it can be disabled, altered or incomplete.",
    ),
    CollectionRoute("linux", "sysmon", "Sysmon for Linux", ("sysmon",)),
    CollectionRoute("macos", "unifiedlog", "macOS Unified Log", ("unifiedlog",)),
    CollectionRoute("macos", "auditd", "macOS OpenBSM audit trail", ("auditd",)),
    CollectionRoute(
        "macos",
        "endpointsecurity",
        "macOS Endpoint Security events",
        ("endpointsecurity", "esf"),
        ("process_creation", "process_termination", "file_event", "file_delete", "file_rename", "file_access"),
        note="Deploy an entitled Endpoint Security client, subscribe to the required events and normalize its schema.",
    ),
    CollectionRoute("suricata", "eve", "Suricata EVE JSON", ("eve", "alert", "dns", "http", "tls", "flow", "fileinfo", "ids"), default=True),
    CollectionRoute("snort", "alert", "Snort alert logs", ("alert", "alerts"), default=True),
    CollectionRoute("paloalto", "logs", "PAN-OS traffic, threat, system and configuration log bundle", ("syslog", "firewall"), default=True),
    CollectionRoute("paloalto", "traffic", "PAN-OS traffic logs", ("traffic",)),
    CollectionRoute("paloalto", "threat", "PAN-OS threat logs", ("threat",)),
    CollectionRoute("paloalto", "system", "PAN-OS system logs", ("system",)),
    CollectionRoute("paloalto", "config", "PAN-OS configuration logs", ("config",)),
    CollectionRoute(
        "cisco",
        "syslog",
        "Cisco device syslog",
        ("syslog", "asa", "ios", "firewall", "secure_firewall", "aaa"),
        default=True,
        note="Identify the Cisco device family and enable its message catalog; ASA, IOS and other families are not interchangeable.",
    ),
    CollectionRoute("fortigate", "logs", "FortiGate traffic, event and security log bundle", ("syslog", "fortigate"), default=True),
    CollectionRoute("fortigate", "traffic", "FortiGate traffic logs", ("traffic",)),
    CollectionRoute("fortigate", "event", "FortiGate event logs", ("event",)),
    CollectionRoute("sonicwall", "syslog", "SonicWall firewall syslog", ("syslog", "firewall"), default=True),
    CollectionRoute("checkpoint", "logs", "Check Point security and audit logs", ("firewall", "audit", "syslog"), default=True),
    CollectionRoute("watchguard", "syslog", "WatchGuard Firebox syslog", ("syslog", "firewall"), default=True),
    CollectionRoute("juniper", "syslog", "Juniper Junos system/security syslog", ("syslog", "srx"), default=True),
    CollectionRoute("zscaler", "nss", "Zscaler NSS web and firewall log bundle", ("nss", "proxy", "firewall"), default=True),
    CollectionRoute(
        "syslog",
        "messages",
        "Syslog messages with application identity",
        ("syslog",),
        default=True,
        note="Retain the originating application and raw message; configure the named application's forwarding and any enrichments.",
    ),
    CollectionRoute(
        "crowdstrike",
        "falcon",
        "CrowdStrike Falcon event/alert export",
        ("falcon", "event_streams", "fdr"),
        default=True,
        note="Select Falcon Event Streams for detections or FDR for endpoint events; normalize the required fields and retain enrichments.",
    ),
    CollectionRoute("carbonblack", "events", "Carbon Black endpoint event export", ("events", "edr"), default=True),
    CollectionRoute(
        "wazuh",
        "archives",
        "Wazuh decoded event archives",
        ("archives", "audit"),
        default=True,
        note="Enable logall_json and required decoders/integrations; alerts.json alone excludes non-alerting events.",
    ),
    CollectionRoute("sophos", "central", "Sophos Central event and alert exports", ("central", "events", "alerts")),
    CollectionRoute("sophos", "firewall", "Sophos Firewall syslog", ("syslog", "firewall")),
    CollectionRoute(
        "sophos",
        "logs",
        "Sophos Firewall syslog and Central event/alert bundle",
        default=True,
        note="Identify the Sophos product family; Firewall syslog and Central endpoint exports use different schemas.",
    ),
    CollectionRoute("exchange", "management", "Exchange management event log and admin audit log", ("management", "audit"), default=True),
    CollectionRoute("apache", "access", "Apache HTTP Server access log", ("access", "http", "webserver"), ("webserver",)),
    CollectionRoute("apache", "error", "Apache HTTP Server error log", ("error",)),
    CollectionRoute("nginx", "access", "NGINX access log", ("access", "http", "webserver"), ("webserver",)),
    CollectionRoute("nginx", "error", "NGINX error log", ("error",)),
    CollectionRoute("iis", "access", "IIS W3C access log", ("access", "iis", "w3svc"), ("webserver",)),
    CollectionRoute("tomcat", "access", "Apache Tomcat AccessLogValve", ("access",), ("webserver",)),
    CollectionRoute("sqlserver", "audit", "SQL Server Audit", ("audit", "application")),
    CollectionRoute("postgresql", "audit", "PostgreSQL pgAudit log", ("audit", "pgaudit")),
    CollectionRoute("postgresql", "server", "PostgreSQL server log", ("postgresql", "server")),
    CollectionRoute("mysql", "audit", "MySQL Enterprise Audit log", ("audit",)),
    CollectionRoute("mysql", "general", "MySQL general query log", ("general",)),
    CollectionRoute("mysql", "error", "MySQL error log", ("error",)),
    CollectionRoute("snowflake", "query_history", "Snowflake ACCOUNT_USAGE.QUERY_HISTORY", ("query_history",)),
    CollectionRoute("snowflake", "login_history", "Snowflake ACCOUNT_USAGE.LOGIN_HISTORY", ("login_history",)),
    CollectionRoute("bind", "queries", "BIND query log", ("queries", "dns", "named"), ("dns",), True),
)
ZEEK_SERVICES = frozenset(
    {
        "conn",
        "dns",
        "http",
        "ssl",
        "x509",
        "files",
        "notice",
        "weird",
        "ssh",
        "smtp",
        "ftp",
        "rdp",
        "smb_files",
        "smb_mapping",
        "dce_rpc",
        "kerberos",
        "ntlm",
        "dhcp",
    }
)
SERVICE_ROUTES = {(r.product, service): r for r in ROUTES for service in r.services}
CATEGORY_ROUTES = {(r.product, category): r for r in ROUTES for category in r.categories}
DEFAULT_ROUTES = {r.product: r for r in ROUTES if r.default}
GENERIC_STREAMS = {
    "webserver": ("Web server access logs", {"access", "access_log", "access-log", "http", "webserver", "nginx", "apache", "iis", "w3svc"}),
    "proxy": ("Proxy request logs", {"proxy", "http", "access", "access_log"}),
    "dns": ("DNS query logs", {"dns", "query", "queries", "named"}),
    "firewall": ("Firewall traffic logs", {"firewall", "traffic", "filterlog"}),
}


def collection_route(product: str | None, category: str | None, service: str | None) -> CollectionRoute | None:
    """Resolve a reviewed route without guessing through an explicit unknown service."""
    if product == "zeek" and service in ZEEK_SERVICES:
        return CollectionRoute("zeek", str(service), f"Zeek {service}.log")
    category = "webserver" if category == "web" else category
    route = SERVICE_ROUTES.get((product or "", service or "")) if service else CATEGORY_ROUTES.get((product or "", category or ""))
    if route:
        return route
    if product not in {"windows", "linux", "macos"} and category in GENERIC_STREAMS:
        label, services = GENERIC_STREAMS[category]
        if service is None or service in services:
            return CollectionRoute(
                product or "generic",
                category,
                label,
                note="Retain request/query details and normalize vendor fields; preserve the rule's explicit service constraint.",
            )
    if product is None:
        return None
    if service:
        return None
    if category:
        return None
    return DEFAULT_ROUTES.get(product)
