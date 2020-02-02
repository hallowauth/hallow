output "request_certificate_policy_arn" {
  value = aws_iam_policy.request_certificate_policy.arn
}

output "hallow_endpoint" {
  value = "${aws_api_gateway_deployment.prod.invoke_url}${aws_api_gateway_resource.hallow_resource.path}"
}

output "ssh_ca_key_arn" {
  value = aws_kms_key.ssh_ca_key.arn
}