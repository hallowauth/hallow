# Hallow Terraform Module

This is a Terraform module which provisions KMS, Lambda, and API Gateway
resources for running Hallow.

## Variables

- `lambda_s3_bucket`: Name of an S3 bucket containing the Hallow Lambda `.zip`
- `lambda_s3_key`: Name of the key in the S3 bucket containing the Hallow
  Lambda `.zip`

## Outputs

- `request_certificate_policy_arn`: An IAM policy which may be granted to users
  or roles, giving them the ability to request certificates from Hallow
- `hallow_endpoint`: URL to make requests to in order to obtain certificates
- `ssh_ca_key_arn`: ARN for the KMS key for the SSH CA