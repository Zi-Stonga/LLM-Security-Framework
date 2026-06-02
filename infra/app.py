"""CDK app entry point for the LLM Security Testing Framework."""
import aws_cdk as cdk
from cdk_stack import SecurityTestingStack

app = cdk.App()

account = app.node.try_get_context("account")
region = app.node.try_get_context("region")

if not account or account == "REPLACE_WITH_YOUR_AWS_ACCOUNT_ID":
    raise ValueError(
        "Set your AWS account ID in infra/cdk.json under context.account"
    )

SecurityTestingStack(
    app,
    "SecurityTestingStack",
    env=cdk.Environment(account=account, region=region or "us-east-1"),
    tags={"Project": "llm-security-testing", "ManagedBy": "CDK"},
)

app.synth()
