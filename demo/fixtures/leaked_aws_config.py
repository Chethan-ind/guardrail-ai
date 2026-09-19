# WARNING: demo fixture only. These are fake, non-functional example
# credentials in AWS's documented dummy format — used to prove GuardRail's
# detector works, never real infrastructure secrets.

import boto3

session = boto3.Session(
    aws_access_key_id="AKIAIOSFODNN7EXAMPLE",
    aws_secret_access_key="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    region_name="ap-south-1",
)

DATABASE_URL = "postgres://admin:Sup3rSecretPass!@prod-db.cluster-example.ap-south-1.rds.amazonaws.com:5432/orders"
