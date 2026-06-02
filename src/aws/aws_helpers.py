"""AWS utility functions for the LLM Security Testing Framework.

Covers Secrets Manager, S3, DynamoDB, SQS, SNS, CloudWatch, SSM, and Lambda.
All functions are module-level with no shared mutable state except the
API key TTL cache, which is keyed on (secret_name, region) and expires
after API_KEY_TTL_SECONDS.
"""
from __future__ import annotations

import json
import logging
import os
import time
from typing import Any
from typing import Dict
from typing import List
from typing import Optional
from typing import Tuple

import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)

_DEFAULT_REGION: str = os.environ.get("AWS_DEFAULT_REGION", "us-east-1")
_API_KEY_TTL_SECONDS: int = 300
_api_key_cache: Dict[Tuple[str, str], Tuple[str, float]] = {}


def get_secret(secret_name: str, region: str = _DEFAULT_REGION) -> Dict[str, Any]:
    """Retrieve and JSON-parse a secret from AWS Secrets Manager.

    Args:
        secret_name: The name or ARN of the secret.
        region: AWS region. Defaults to AWS_DEFAULT_REGION env var.

    Returns:
        Parsed JSON contents of the secret as a dict.

    Raises:
        ClientError: If the secret does not exist or access is denied.
        json.JSONDecodeError: If the secret value is not valid JSON.
    """
    client = boto3.client("secretsmanager", region_name=region)
    response = client.get_secret_value(SecretId=secret_name)
    return json.loads(response["SecretString"])


def get_api_key(secret_name: str, region: str = _DEFAULT_REGION) -> str:
    """Return the ANTHROPIC_API_KEY with a 5-minute in-process TTL cache.

    Falls back to the ANTHROPIC_API_KEY environment variable when Secrets
    Manager is unavailable (for example, during local development).

    Args:
        secret_name: Secrets Manager path for the API key secret.
        region: AWS region. Defaults to AWS_DEFAULT_REGION env var.

    Returns:
        The API key string, or an empty string if not found anywhere.
    """
    cache_key = (secret_name, region)
    cached_value, cached_at = _api_key_cache.get(cache_key, ("", 0.0))
    if cached_value and (time.monotonic() - cached_at) < _API_KEY_TTL_SECONDS:
        return cached_value
    try:
        key = get_secret(secret_name, region)["ANTHROPIC_API_KEY"]
        _api_key_cache[cache_key] = (key, time.monotonic())
        return key
    except ClientError:
        fallback = os.environ.get("ANTHROPIC_API_KEY", "")
        if not fallback:
            logger.warning(
                "ANTHROPIC_API_KEY not found in Secrets Manager (%r) or environment",
                secret_name,
            )
        return fallback


def upload_to_s3(
    content: str,
    bucket: str,
    key: str,
    region: str = _DEFAULT_REGION,
    content_type: str = "application/json",
    kms_key_id: str = "",
) -> str:
    """Upload a UTF-8 string to S3 with explicit SSE-KMS encryption.

    Encryption is declared at the call level, not relied on as a bucket
    default, so a misconfigured bucket policy cannot silently fall back
    to unencrypted storage.

    Args:
        content: String content to upload.
        bucket: S3 bucket name.
        key: S3 object key.
        region: AWS region.
        content_type: MIME type for the object. Defaults to application/json.
        kms_key_id: Optional specific KMS key ID. Uses bucket default if empty.

    Returns:
        S3 URI in the format s3://bucket/key.
    """
    put_kwargs: Dict[str, Any] = {
        "Bucket": bucket,
        "Key": key,
        "Body": content.encode("utf-8"),
        "ContentType": content_type,
        "ServerSideEncryption": "aws:kms",
    }
    if kms_key_id:
        put_kwargs["SSEKMSKeyId"] = kms_key_id
    boto3.client("s3", region_name=region).put_object(**put_kwargs)
    return f"s3://{bucket}/{key}"


def download_from_s3(bucket: str, key: str, region: str = _DEFAULT_REGION) -> str:
    """Download an S3 object and return its content as a UTF-8 string.

    Args:
        bucket: S3 bucket name.
        key: S3 object key.
        region: AWS region.

    Returns:
        Object content decoded as UTF-8.

    Raises:
        ClientError: If the object does not exist or access is denied.
    """
    resp = boto3.client("s3", region_name=region).get_object(Bucket=bucket, Key=key)
    return resp["Body"].read().decode("utf-8")


def list_s3_objects(
    bucket: str,
    prefix: str = "",
    region: str = _DEFAULT_REGION,
) -> List[str]:
    """Return all object keys in a bucket under the given prefix.

    Uses paginated list_objects_v2 to handle buckets with more than 1000 objects.

    Args:
        bucket: S3 bucket name.
        prefix: Key prefix to filter by. Empty string returns all objects.
        region: AWS region.

    Returns:
        List of S3 object keys.
    """
    client = boto3.client("s3", region_name=region)
    paginator = client.get_paginator("list_objects_v2")
    keys: List[str] = []
    for page in paginator.paginate(Bucket=bucket, Prefix=prefix):
        keys.extend(obj["Key"] for obj in page.get("Contents", []))
    return keys


def dynamo_put(
    table_name: str,
    item: Dict[str, Any],
    region: str = _DEFAULT_REGION,
) -> None:
    """Write a single item to a DynamoDB table.

    Args:
        table_name: DynamoDB table name.
        item: Dict representing the full item, including all key attributes.
        region: AWS region.

    Raises:
        ClientError: If the write fails due to permissions or validation errors.
    """
    boto3.resource("dynamodb", region_name=region).Table(table_name).put_item(Item=item)


def dynamo_get(
    table_name: str,
    key: Dict[str, Any],
    region: str = _DEFAULT_REGION,
) -> Optional[Dict[str, Any]]:
    """Retrieve a single item from DynamoDB by its key.

    Args:
        table_name: DynamoDB table name.
        key: Dict containing the partition key and, if applicable, sort key.
        region: AWS region.

    Returns:
        The item dict if found, or None if the key does not exist.
    """
    resp = (
        boto3.resource("dynamodb", region_name=region)
        .Table(table_name)
        .get_item(Key=key)
    )
    return resp.get("Item")


def send_sqs_message(
    queue_url: str,
    payload: Dict[str, Any],
    region: str = _DEFAULT_REGION,
) -> str:
    """Serialise a dict to JSON and send it to an SQS queue.

    Args:
        queue_url: Full SQS queue URL.
        payload: Dict to serialise and send.
        region: AWS region.

    Returns:
        SQS MessageId string.

    Raises:
        ClientError: If the send fails.
    """
    resp = boto3.client("sqs", region_name=region).send_message(
        QueueUrl=queue_url, MessageBody=json.dumps(payload)
    )
    return resp["MessageId"]


def receive_sqs_messages(
    queue_url: str,
    max_messages: int = 10,
    wait_seconds: int = 20,
    region: str = _DEFAULT_REGION,
) -> List[Dict[str, Any]]:
    """Long-poll an SQS queue for messages.

    Args:
        queue_url: Full SQS queue URL.
        max_messages: Max messages to receive. Capped at 10 (SQS API limit).
        wait_seconds: Long-poll wait time in seconds. Capped at 20.
        region: AWS region.

    Returns:
        List of raw SQS message dicts (may be empty).
    """
    resp = boto3.client("sqs", region_name=region).receive_message(
        QueueUrl=queue_url,
        MaxNumberOfMessages=min(max_messages, 10),
        WaitTimeSeconds=min(wait_seconds, 20),
    )
    return resp.get("Messages", [])


def delete_sqs_message(
    queue_url: str,
    receipt_handle: str,
    region: str = _DEFAULT_REGION,
) -> None:
    """Delete a processed SQS message by its receipt handle.

    Args:
        queue_url: Full SQS queue URL.
        receipt_handle: Receipt handle from the received message.
        region: AWS region.
    """
    boto3.client("sqs", region_name=region).delete_message(
        QueueUrl=queue_url, ReceiptHandle=receipt_handle
    )


def publish_sns(
    topic_arn: str,
    subject: str,
    message: str,
    attributes: Optional[Dict[str, str]] = None,
    region: str = _DEFAULT_REGION,
) -> str:
    """Publish a message to an SNS topic.

    Args:
        topic_arn: Full SNS topic ARN.
        subject: Message subject (used for email subscriptions).
        message: Message body.
        attributes: Optional string message attributes.
        region: AWS region.

    Returns:
        SNS MessageId string.
    """
    kwargs: Dict[str, Any] = {
        "TopicArn": topic_arn,
        "Subject": subject,
        "Message": message,
    }
    if attributes:
        kwargs["MessageAttributes"] = {
            k: {"DataType": "String", "StringValue": v}
            for k, v in attributes.items()
        }
    return boto3.client("sns", region_name=region).publish(**kwargs)["MessageId"]


def put_metric(
    namespace: str,
    metric_name: str,
    value: float,
    unit: str = "None",
    dimensions: Optional[Dict[str, str]] = None,
    region: str = _DEFAULT_REGION,
) -> None:
    """Publish a single custom CloudWatch metric.

    Args:
        namespace: CloudWatch metric namespace.
        metric_name: Metric name within the namespace.
        value: Numeric metric value.
        unit: CloudWatch unit string. Defaults to "None".
        dimensions: Optional dict of dimension name/value pairs.
        region: AWS region.
    """
    metric_data: Dict[str, Any] = {
        "MetricName": metric_name,
        "Value": value,
        "Unit": unit,
    }
    if dimensions:
        metric_data["Dimensions"] = [
            {"Name": k, "Value": v} for k, v in dimensions.items()
        ]
    boto3.client("cloudwatch", region_name=region).put_metric_data(
        Namespace=namespace, MetricData=[metric_data]
    )


def put_log_event(
    log_group: str,
    log_stream: str,
    message: str,
    region: str = _DEFAULT_REGION,
) -> None:
    """Append a single event to a CloudWatch Logs stream.

    Creates the log group and stream if they do not already exist.
    The CloudWatch Logs API no longer requires sequence tokens as of 2023.

    Args:
        log_group: CloudWatch log group name.
        log_stream: CloudWatch log stream name.
        message: Log message string.
        region: AWS region.
    """
    client = boto3.client("logs", region_name=region)
    for create_fn, kwargs in [
        (client.create_log_group, {"logGroupName": log_group}),
        (
            client.create_log_stream,
            {"logGroupName": log_group, "logStreamName": log_stream},
        ),
    ]:
        try:
            create_fn(**kwargs)
        except client.exceptions.ResourceAlreadyExistsException:
            pass
    client.put_log_events(
        logGroupName=log_group,
        logStreamName=log_stream,
        logEvents=[{"timestamp": int(time.time() * 1000), "message": message}],
    )


def ssm_get(
    param_name: str,
    decrypt: bool = True,
    region: str = _DEFAULT_REGION,
) -> str:
    """Retrieve a parameter value from SSM Parameter Store.

    Args:
        param_name: SSM parameter name or path.
        decrypt: Whether to decrypt SecureString values. Defaults to True.
        region: AWS region.

    Returns:
        Parameter value as a string.

    Raises:
        ClientError: If the parameter does not exist or access is denied.
    """
    return boto3.client("ssm", region_name=region).get_parameter(
        Name=param_name, WithDecryption=decrypt
    )["Parameter"]["Value"]


def ssm_put(
    param_name: str,
    value: str,
    param_type: str = "SecureString",
    region: str = _DEFAULT_REGION,
) -> None:
    """Write a value to SSM Parameter Store.

    Refuses to write an empty string to prevent accidentally blanking a secret.

    Args:
        param_name: SSM parameter name or path.
        value: Parameter value. Must not be empty.
        param_type: SSM parameter type. Defaults to SecureString.
        region: AWS region.

    Raises:
        ValueError: If value is empty.
        ClientError: If the write fails.
    """
    if not value:
        raise ValueError("ssm_put: value must not be empty -- refusing to write blank secret")
    boto3.client("ssm", region_name=region).put_parameter(
        Name=param_name, Value=value, Type=param_type, Overwrite=True
    )


def lambda_invoke(
    function_name: str,
    payload: Any,
    async_: bool = False,
    region: str = _DEFAULT_REGION,
) -> Any:
    """Invoke an AWS Lambda function synchronously or asynchronously.

    Raises RuntimeError if the function returns a FunctionError, which
    indicates an unhandled exception in the Lambda handler.

    Args:
        function_name: Lambda function name or ARN.
        payload: JSON-serialisable payload.
        async_: If True, invokes with Event type (fire and forget).
        region: AWS region.

    Returns:
        Parsed JSON response payload for synchronous invocations,
        or {"status": "async_invoked"} for asynchronous.

    Raises:
        RuntimeError: If the Lambda function returns a FunctionError.
    """
    inv_type = "Event" if async_ else "RequestResponse"
    resp = boto3.client("lambda", region_name=region).invoke(
        FunctionName=function_name,
        InvocationType=inv_type,
        Payload=json.dumps(payload, default=str).encode(),
    )
    if not async_:
        if resp.get("FunctionError"):
            error_payload = json.loads(resp["Payload"].read())
            raise RuntimeError(
                f"Lambda {function_name!r} returned FunctionError: {error_payload}"
            )
        return json.loads(resp["Payload"].read())
    return {"status": "async_invoked"}
