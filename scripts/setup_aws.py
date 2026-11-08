#!/usr/bin/env python3
"""Idempotent AWS setup: DynamoDB audit table + Bedrock Guardrail."""
from __future__ import annotations

import json
import os
import sys
import time

import boto3
from botocore.exceptions import ClientError

REGION = os.environ.get("AWS_REGION", "us-east-1")
TABLE = os.environ.get("AUDIT_TABLE", "AgentGuardAuditLogs")
GUARDRAIL_NAME = os.environ.get("GUARDRAIL_NAME", "AgentGuardPromptAttack")


def main() -> int:
    ddb = boto3.client("dynamodb", region_name=REGION)
    bedrock = boto3.client("bedrock", region_name=REGION)

    # --- DynamoDB table ---
    try:
        ddb.describe_table(TableName=TABLE)
        print(f"DynamoDB table exists: {TABLE}")
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
        print(f"Creating DynamoDB table: {TABLE}")
        ddb.create_table(
            TableName=TABLE,
            AttributeDefinitions=[
                {"AttributeName": "session_id", "AttributeType": "S"},
                {"AttributeName": "ts_seq", "AttributeType": "S"},
            ],
            KeySchema=[
                {"AttributeName": "session_id", "KeyType": "HASH"},
                {"AttributeName": "ts_seq", "KeyType": "RANGE"},
            ],
            BillingMode="PAY_PER_REQUEST",
        )
        waiter = ddb.get_waiter("table_exists")
        waiter.wait(TableName=TABLE)

    # --- Bedrock guardrail ---
    guardrail_id = None
    try:
        listed = bedrock.list_guardrails()
        for g in listed.get("guardrails", []):
            if g.get("name") == GUARDRAIL_NAME:
                guardrail_id = g["id"]
                print(f"Guardrail exists: {GUARDRAIL_NAME} ({guardrail_id})")
                break
    except ClientError:
        pass

    if not guardrail_id:
        print(f"Creating guardrail: {GUARDRAIL_NAME}")
        created = bedrock.create_guardrail(
            name=GUARDRAIL_NAME,
            description="Prompt-attack filter for AgentGuard",
            contentPolicyConfig={
                "filtersConfig": [
                    {
                        "type": "PROMPT_ATTACK",
                        "inputStrength": "HIGH",
                        "outputStrength": "NONE",
                    }
                ]
            },
            blockedInputMessaging="Blocked by AgentGuard guardrail.",
            blockedOutputsMessaging="Blocked by AgentGuard guardrail.",
        )
        guardrail_id = created["guardrailId"]
        # Brief pause so version create is accepted
        time.sleep(1)

    versioned = bedrock.create_guardrail_version(
        guardrailIdentifier=guardrail_id,
        description="AgentGuard PROMPT_ATTACK v",
    )
    guardrail_version = versioned["version"]

    print()
    print(f"GUARDRAIL_ID={guardrail_id}")
    print(f"GUARDRAIL_VERSION={guardrail_version}")
    print()
    print("Least-privilege IAM policy (attach to the app role/user):")
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AuditPutItem",
                "Effect": "Allow",
                "Action": ["dynamodb:PutItem"],
                "Resource": f"arn:aws:dynamodb:{REGION}:*:table/{TABLE}",
            },
            {
                "Sid": "ApplyGuardrail",
                "Effect": "Allow",
                "Action": ["bedrock:ApplyGuardrail"],
                "Resource": f"arn:aws:bedrock:{REGION}:*:guardrail/{guardrail_id}",
            },
        ],
    }
    print(json.dumps(policy, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
