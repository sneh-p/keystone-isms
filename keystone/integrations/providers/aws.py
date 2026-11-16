"""AWS account: read-only posture checks using an access key for a read-only IAM user or role."""

from __future__ import annotations

import re

from .base import CheckDef, ConfigField, Outcome, Provider, SetupStep

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

    def run(self, config: dict, secrets: dict, session=None) -> list[Outcome]:
        from botocore.exceptions import BotoCoreError, ClientError

        s = self._session(config, secrets)
        if self.session_factory:
            client = s.client
        else:  # SC-ERR-004: explicit timeouts and bounded retries on every AWS call
            from botocore.config import Config

            boto_config = Config(connect_timeout=10, read_timeout=20, retries={"max_attempts": 3, "mode": "standard"})

            def client(name: str, _s=s, _c=boto_config):
                return _s.client(name, config=_c)
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
