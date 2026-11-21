"""AWS account: read-only posture checks using an access key for a read-only IAM user or role."""

from __future__ import annotations

import csv
import io
import re
import time
from datetime import datetime, timedelta, timezone

from .base import CheckDef, ConfigField, Outcome, PermissionReport, Provider, SetupStep

AUDIT_POLICIES = frozenset({"arn:aws:iam::aws:policy/SecurityAudit", "arn:aws:iam::aws:policy/job-function/ViewOnlyAccess"})
KEY_MAX_DAYS = 90  # access keys older than this should have been rotated
UNUSED_DAYS = 90  # users with no sign-in or key use for this long
REGION = re.compile(r"[a-z]{2}(?:-[a-z]+)+-\d{1,2}")


class AwsProvider(Provider):
    key = "aws"
    name = "Amazon Web Services"
    description = ("Checks root MFA, CloudTrail, the IAM password policy, S3 account-level public access block, GuardDuty, access key age, "
                   "unused users, default EBS encryption, RDS encryption, VPC flow logs and AWS Config.")
    fields = (
        ConfigField("region", "Home region", help="e.g. eu-west-1", example="eu-west-1"),
        ConfigField("access_key_id", "Access key ID", secret=True, help="For an IAM identity with the AWS managed SecurityAudit policy only."),
        ConfigField("secret_access_key", "Secret access key", secret=True),
    )
    checks = (
        CheckDef("root_mfa", "Root account has MFA", ("KC-TEC-05", "KC-TEC-02")),
        CheckDef("cloudtrail", "CloudTrail is logging", ("KC-TEC-15", "KC-TEC-16")),
        CheckDef("password_policy", "IAM password policy is strong", ("KC-ORG-17",)),
        CheckDef("s3_public_block", "S3 account public access blocked", ("KC-TEC-03", "KC-TEC-12")),
        CheckDef("guardduty", "GuardDuty is enabled", ("KC-TEC-16", "KC-ORG-25")),
        CheckDef("access_key_age", f"Access keys rotated within {KEY_MAX_DAYS} days", ("KC-ORG-17",)),
        CheckDef("unused_users", f"No IAM users unused for {UNUSED_DAYS} days", ("KC-ORG-18", "KC-ORG-16")),
        CheckDef("ebs_default_encryption", "New EBS volumes encrypted by default", ("KC-TEC-24", "KC-TEC-01")),
        CheckDef("rds_encrypted", "RDS databases encrypted", ("KC-TEC-24",)),
        CheckDef("vpc_flow_logs", "VPC flow logs on for every VPC", ("KC-TEC-15", "KC-TEC-16")),
        CheckDef("config_recording", "AWS Config recording", ("KC-TEC-09", "KC-ORG-09")),
    )
    setup = (
        SetupStep(
            "Create a read-only IAM user",
            "Run in AWS CloudShell (or with an administrator profile) in the account to check. The AWS managed "
            "SecurityAudit policy only allows reading configuration (Get, List, Describe). Copy the AccessKeyId "
            "and SecretAccessKey from the last command into the settings.",
            code="aws iam create-user --user-name keystone-readonly\n"
                 "aws iam attach-user-policy --user-name keystone-readonly --policy-arn arn:aws:iam::aws:policy/SecurityAudit\n"
                 "aws iam create-access-key --user-name keystone-readonly",
            link="https://console.aws.amazon.com/cloudshell/home?region={region}", link_label="Open CloudShell",
        ),
        SetupStep(
            "Check the user has nothing else attached",
            "Expect SecurityAudit as the only attached policy, and empty lists for inline policies and groups.",
            kind="verify",
            code="aws iam list-attached-user-policies --user-name keystone-readonly --query 'AttachedPolicies[].PolicyName'\n"
                 "aws iam list-user-policies --user-name keystone-readonly --query 'PolicyNames'\n"
                 "aws iam list-groups-for-user --user-name keystone-readonly --query 'Groups[].GroupName'",
        ),
        SetupStep(
            "Prove it cannot change anything",
            "The IAM policy simulator evaluates the user's permissions without performing any action. Every row "
            "must say implicitDeny.",
            kind="verify",
            code='aws iam simulate-principal-policy \\\n'
                 '  --policy-source-arn "arn:aws:iam::$(aws sts get-caller-identity --query Account --output text):user/keystone-readonly" \\\n'
                 '  --action-names iam:CreateUser iam:AttachUserPolicy s3:PutObject s3:DeleteBucket ec2:TerminateInstances cloudtrail:StopLogging guardduty:DeleteDetector \\\n'
                 "  --query 'EvaluationResults[].[EvalActionName,EvalDecision]' --output table",
        ),
    )

    def __init__(self, session_factory=None, sleep=time.sleep):
        self.session_factory = session_factory
        self.sleep = sleep

    def _session(self, config: dict, secrets: dict):
        if self.session_factory:
            return self.session_factory()
        import boto3

        region = (config.get("region") or "us-east-1").strip()
        if not REGION.fullmatch(region):  # boto3 builds endpoint host names from the region (SC-SSRF-001)
            raise ValueError("Enter an AWS region such as eu-west-1.")
        return boto3.session.Session(aws_access_key_id=secrets["access_key_id"], aws_secret_access_key=secrets["secret_access_key"], region_name=region)

    def _clients(self, config: dict, secrets: dict):
        s = self._session(config, secrets)
        if self.session_factory:
            return s.client
        from botocore.config import Config  # SC-ERR-004: explicit timeouts and bounded retries on every AWS call

        boto_config = Config(connect_timeout=10, read_timeout=20, retries={"max_attempts": 3, "mode": "standard"})

        def client(name: str, _s=s, _c=boto_config):
            return _s.client(name, config=_c)
        return client

    def permissions(self, config: dict, secrets: dict) -> PermissionReport:
        """For an IAM user: every policy and group attached, compared with SecurityAudit (or ViewOnlyAccess). SecurityAudit
        itself allows these reads."""
        from botocore.exceptions import BotoCoreError, ClientError

        client = self._clients(config, secrets)
        try:
            arn = client("sts").get_caller_identity()["Arn"]
            if arn.endswith(":root"):
                return PermissionReport("fail", "These are the account's root keys. Delete them and use a read-only IAM user.", ["root account"])
            if ":user/" not in arn:
                return PermissionReport("unknown", "Keystone checks IAM users' policies; for a role, check in the IAM console that only SecurityAudit is attached.")
            user = arn.split(":user/", 1)[1].split("/")[-1]
            iam = client("iam")
            attached = [x["PolicyArn"] for x in iam.list_attached_user_policies(UserName=user)["AttachedPolicies"]]
            inline = iam.list_user_policies(UserName=user)["PolicyNames"]
            groups = [g["GroupName"] for g in iam.list_groups_for_user(UserName=user)["Groups"]]
        except ClientError as e:
            return PermissionReport("unknown", f"AWS: {e.response.get('Error', {}).get('Code', 'error')} while reading the user's policies")
        except BotoCoreError as e:
            return PermissionReport("unknown", f"AWS: {type(e).__name__}")
        extra = [a.rsplit("/", 1)[-1] for a in attached if a not in AUDIT_POLICIES] + [f"inline policy {n}" for n in inline] + [f"group {g}" for g in groups]
        if extra:
            return PermissionReport("fail", f"The user {user} has more than SecurityAudit: {', '.join(extra)}.", extra)
        return PermissionReport("pass", f"The user {user} has SecurityAudit only.")

    def run(self, config: dict, secrets: dict, session=None) -> list[Outcome]:
        from botocore.exceptions import BotoCoreError, ClientError

        client = self._clients(config, secrets)
        out = []

        def attempt(key: str, fn):
            try:
                out.append(fn())
            except ClientError as e:
                code = e.response.get("Error", {}).get("Code", "")
                out.append(Outcome(key, "error" if code not in ("NoSuchEntity", "NoSuchPublicAccessBlockConfiguration") else "fail", f"AWS: {code}"))
            except BotoCoreError as e:
                out.append(Outcome(key, "error", f"AWS: {type(e).__name__}"))

        iam = client("iam")
        attempt("root_mfa", lambda: (lambda v: Outcome("root_mfa", "pass" if v == 1 else "fail", "Enabled" if v == 1 else "Not enabled"))(iam.get_account_summary()["SummaryMap"].get("AccountMFAEnabled")))

        def trail():
            ct = client("cloudtrail")
            trails = ct.describe_trails()["trailList"]
            logging = [t["Name"] for t in trails if ct.get_trail_status(Name=t["TrailARN"])["IsLogging"]]
            multi = any(t.get("IsMultiRegionTrail") for t in trails if t["Name"] in logging)
            return Outcome("cloudtrail", "pass" if logging and multi else "fail", f"{len(logging)} logging trail(s){'' if multi else ', none multi-region'}")
        attempt("cloudtrail", trail)

        def pw():
            p = iam.get_account_password_policy()["PasswordPolicy"]
            ok = p.get("MinimumPasswordLength", 0) >= 12 and p.get("RequireSymbols") and p.get("RequireNumbers")
            return Outcome("password_policy", "pass" if ok else "fail", f"Minimum length {p.get('MinimumPasswordLength')}")
        attempt("password_policy", pw)

        def s3():
            account = client("sts").get_caller_identity()["Account"]
            cfg = client("s3control").get_public_access_block(AccountId=account)["PublicAccessBlockConfiguration"]
            ok = all(cfg.get(k) for k in ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets"))
            return Outcome("s3_public_block", "pass" if ok else "fail", "All four settings on" if ok else "Not all settings on", cfg)
        attempt("s3_public_block", s3)

        def gd():
            ids = client("guardduty").list_detectors()["DetectorIds"]
            return Outcome("guardduty", "pass" if ids else "fail", f"{len(ids)} detector(s) in {config.get('region')}")
        attempt("guardduty", gd)

        report: list[dict] = []

        def credential_report() -> list[dict]:
            if not report:
                iam.generate_credential_report()
                for _ in range(10):  # AWS builds it in a few seconds
                    try:
                        raw = iam.get_credential_report()["Content"]
                        break
                    except ClientError as e:
                        if e.response.get("Error", {}).get("Code") not in ("ReportInProgress", "ReportNotPresent"):
                            raise
                        self.sleep(2)
                else:
                    raise ValueError("The IAM credential report wasn't ready in time; it is checked again on the next run.")
                text = raw.decode() if isinstance(raw, bytes) else str(raw)
                report.extend(r for r in csv.DictReader(io.StringIO(text)) if r.get("user") != "<root_account>")
            return report

        now = datetime.now(timezone.utc)

        def when(v: str | None) -> datetime | None:
            if not v or v in ("N/A", "no_information", "not_supported"):
                return None
            try:
                return datetime.fromisoformat(v.replace("Z", "+00:00"))
            except ValueError:
                return None

        def keys():
            old = []
            for r in credential_report():
                for n in ("1", "2"):
                    rotated = when(r.get(f"access_key_{n}_last_rotated"))
                    if r.get(f"access_key_{n}_active") == "true" and rotated and now - rotated > timedelta(days=KEY_MAX_DAYS):
                        old.append(f"{r['user']} (key {n}, {(now - rotated).days} days)")
            return Outcome("access_key_age", "fail" if old else "pass", f"{len(old)} active key(s) older than {KEY_MAX_DAYS} days: {', '.join(old[:8])}" if old else "No active key is older than "
                           f"{KEY_MAX_DAYS} days", {"old_keys": old[:500]})
        attempt("access_key_age", keys)

        def unused():
            idle = []
            for r in credential_report():
                created = when(r.get("user_creation_time"))
                used = [d for d in (when(r.get("password_last_used")), when(r.get("access_key_1_last_used_date")), when(r.get("access_key_2_last_used_date"))) if d]
                last = max(used) if used else created
                if created and now - created > timedelta(days=UNUSED_DAYS) and last and now - last > timedelta(days=UNUSED_DAYS):
                    idle.append(r["user"])
            return Outcome("unused_users", "fail" if idle else "pass", f"{len(idle)} user(s) unused for {UNUSED_DAYS} days: {', '.join(idle[:8])}" if idle else "Every IAM user was used recently",
                           {"unused": idle[:500]})
        attempt("unused_users", unused)

        def ebs():
            on = client("ec2").get_ebs_encryption_by_default()["EbsEncryptionByDefault"]
            return Outcome("ebs_default_encryption", "pass" if on else "fail", f"{'On' if on else 'Off'} in {config.get('region')}")
        attempt("ebs_default_encryption", ebs)

        def rds():
            dbs = client("rds").describe_db_instances().get("DBInstances", [])
            plain = [d["DBInstanceIdentifier"] for d in dbs if not d.get("StorageEncrypted")]
            if not dbs:
                return Outcome("rds_encrypted", "pass", f"No RDS databases in {config.get('region')}")
            return Outcome("rds_encrypted", "fail" if plain else "pass", f"{len(plain)} of {len(dbs)} not encrypted: {', '.join(plain[:8])}" if plain else f"All {len(dbs)} encrypted", {"unencrypted": plain})
        attempt("rds_encrypted", rds)

        def flow():
            ec2 = client("ec2")
            vpcs = [v["VpcId"] for v in ec2.describe_vpcs().get("Vpcs", [])]
            logged = {f.get("ResourceId") for f in ec2.describe_flow_logs().get("FlowLogs", []) if f.get("FlowLogStatus") == "ACTIVE"}
            missing = [v for v in vpcs if v not in logged]
            return Outcome("vpc_flow_logs", "fail" if missing else "pass", f"{len(missing)} of {len(vpcs)} VPC(s) without flow logs: {', '.join(missing[:8])}" if missing else f"All {len(vpcs)} VPC(s) log flows",
                           {"without_flow_logs": missing})
        attempt("vpc_flow_logs", flow)

        def config_rec():
            st = client("config").describe_configuration_recorder_status().get("ConfigurationRecordersStatus", [])
            on = [x["name"] for x in st if x.get("recording")]
            return Outcome("config_recording", "pass" if on else "fail", f"Recording ({', '.join(on)})" if on else f"No recorder is recording in {config.get('region')}")
        attempt("config_recording", config_rec)
        return out
