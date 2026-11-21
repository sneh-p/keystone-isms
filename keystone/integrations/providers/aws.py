"""AWS account: read-only posture checks using an access key for a read-only IAM user or role."""

from __future__ import annotations

import re

from .base import CheckDef, ConfigField, Outcome, PermissionReport, Provider, SetupStep

AUDIT_POLICIES = frozenset({"arn:aws:iam::aws:policy/SecurityAudit", "arn:aws:iam::aws:policy/job-function/ViewOnlyAccess"})
REGION = re.compile(r"[a-z]{2}(?:-[a-z]+)+-\d{1,2}")


class AwsProvider(Provider):
    key = "aws"
    name = "Amazon Web Services"
    description = "Checks root MFA, CloudTrail, the IAM password policy, S3 account-level public access block and GuardDuty."
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

    def __init__(self, session_factory=None):
        self.session_factory = session_factory

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
        return out
