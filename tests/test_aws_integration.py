"""Integration tests for AWS helper functions using moto mocks.

All tests use the @mock_aws decorator to intercept boto3 calls.
No real AWS account or credentials are needed.

Structure: Arrange / Act / Assert throughout.
"""
import json
import os

import boto3
import pytest
from moto import mock_aws


@pytest.fixture(autouse=True)
def aws_credentials():
    """Set fake AWS credentials required by moto for all tests.

    Moto intercepts all boto3 calls, but the library still requires
    credential env vars to be present even though they are never used.
    """
    for key, value in [
        ("AWS_ACCESS_KEY_ID", "testing"),
        ("AWS_SECRET_ACCESS_KEY", "testing"),
        ("AWS_SECURITY_TOKEN", "testing"),
        ("AWS_SESSION_TOKEN", "testing"),
        ("AWS_DEFAULT_REGION", "us-east-1"),
    ]:
        os.environ.setdefault(key, value)


class TestSecretsManager:
    """Tests for get_secret and get_api_key."""

    @mock_aws
    def test_get_secret_returns_parsed_json(self):
        # Arrange
        boto3.client("secretsmanager", region_name="us-east-1").create_secret(
            Name="test/key",
            SecretString=json.dumps({"ANTHROPIC_API_KEY": "sk-test"}),
        )
        from src.aws.aws_helpers import get_secret

        # Act
        result = get_secret("test/key")

        # Assert
        assert result["ANTHROPIC_API_KEY"] == "sk-test"

    @mock_aws
    def test_get_api_key_falls_back_to_env_var(self):
        # Arrange: no secret exists in moto; env var is set
        os.environ["ANTHROPIC_API_KEY"] = "env-key"
        import src.aws.aws_helpers as helpers

        helpers._api_key_cache.clear()

        # Act
        key = helpers.get_api_key("nonexistent/secret")

        # Assert
        assert key == "env-key"


class TestS3Integration:
    """Tests for upload_to_s3, download_from_s3, and list_s3_objects."""

    @mock_aws
    def test_upload_and_download_roundtrip(self):
        # Arrange
        boto3.client("s3", region_name="us-east-1").create_bucket(Bucket="test-bucket")
        from src.aws.aws_helpers import download_from_s3
        from src.aws.aws_helpers import upload_to_s3

        # Act
        uri = upload_to_s3('{"value":42}', "test-bucket", "test/file.json")
        content = download_from_s3("test-bucket", "test/file.json")

        # Assert
        assert uri == "s3://test-bucket/test/file.json"
        assert json.loads(content)["value"] == 42

    @mock_aws
    def test_list_s3_objects_filters_by_prefix(self):
        # Arrange
        client = boto3.client("s3", region_name="us-east-1")
        client.create_bucket(Bucket="test-bucket")
        for i in range(5):
            client.put_object(Bucket="test-bucket", Key=f"data/f{i}.json", Body=b"{}")
        for i in range(3):
            client.put_object(Bucket="test-bucket", Key=f"other/f{i}.json", Body=b"{}")
        from src.aws.aws_helpers import list_s3_objects

        # Act
        data_keys = list_s3_objects("test-bucket", prefix="data/")
        all_keys = list_s3_objects("test-bucket")

        # Assert
        assert len(data_keys) == 5
        assert len(all_keys) == 8


class TestDynamoDB:
    """Tests for dynamo_put and dynamo_get."""

    @mock_aws
    def test_put_and_get_roundtrip(self):
        # Arrange
        boto3.resource("dynamodb", region_name="us-east-1").create_table(
            TableName="test-table",
            KeySchema=[{"AttributeName": "id", "KeyType": "HASH"}],
            AttributeDefinitions=[{"AttributeName": "id", "AttributeType": "S"}],
            BillingMode="PAY_PER_REQUEST",
        )
        from src.aws.aws_helpers import dynamo_get
        from src.aws.aws_helpers import dynamo_put

        # Act
        dynamo_put("test-table", {"id": "001", "status": "done"})
        item = dynamo_get("test-table", {"id": "001"})

        # Assert
        assert item["status"] == "done"

    @mock_aws
    def test_get_missing_key_returns_none(self):
        # Arrange
        boto3.resource("dynamodb", region_name="us-east-1").create_table(
            TableName="test-table",
            KeySchema=[{"AttributeName": "id", "KeyType": "HASH"}],
            AttributeDefinitions=[{"AttributeName": "id", "AttributeType": "S"}],
            BillingMode="PAY_PER_REQUEST",
        )
        from src.aws.aws_helpers import dynamo_get

        # Act
        result = dynamo_get("test-table", {"id": "does-not-exist"})

        # Assert
        assert result is None


class TestSQS:
    """Tests for send_sqs_message, receive_sqs_messages, and delete_sqs_message."""

    @mock_aws
    def test_send_receive_delete_full_cycle(self):
        # Arrange
        url = boto3.client("sqs", region_name="us-east-1").create_queue(
            QueueName="test-q"
        )["QueueUrl"]
        from src.aws.aws_helpers import delete_sqs_message
        from src.aws.aws_helpers import receive_sqs_messages
        from src.aws.aws_helpers import send_sqs_message

        # Act
        send_sqs_message(url, {"job": "001"})
        messages = receive_sqs_messages(url, max_messages=1, wait_seconds=0)
        delete_sqs_message(url, messages[0]["ReceiptHandle"])
        remaining = receive_sqs_messages(url, max_messages=10, wait_seconds=0)

        # Assert
        assert json.loads(messages[0]["Body"])["job"] == "001"
        assert len(remaining) == 0


class TestSNS:
    """Tests for publish_sns."""

    @mock_aws
    def test_publish_returns_non_empty_message_id(self):
        # Arrange
        arn = boto3.client("sns", region_name="us-east-1").create_topic(
            Name="test-topic"
        )["TopicArn"]
        from src.aws.aws_helpers import publish_sns

        # Act
        message_id = publish_sns(arn, "Subject", "Body")

        # Assert
        assert message_id and len(message_id) > 0


class TestCloudWatch:
    """Tests for put_metric."""

    @mock_aws
    def test_put_metric_does_not_raise(self):
        # Arrange
        from src.aws.aws_helpers import put_metric

        # Act / Assert: no exception raised
        put_metric("LLMSecurity", "TestMetric", 1.0, "Count", {"Env": "test"})
