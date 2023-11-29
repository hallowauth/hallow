resource "aws_kms_key" "ssh_ca_key" {
  description              = "SSH CA key"
  key_usage                = "SIGN_VERIFY"
  customer_master_key_spec = "ECC_NIST_P256"
}

resource "aws_iam_role" "lambda_role" {
  name               = "hallow-lambda"
  description        = "IAM role for Hallow Lambda to run as"
  assume_role_policy = data.aws_iam_policy_document.assume_role_policy.json
}

data "aws_iam_policy_document" "assume_role_policy" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

resource "aws_iam_role_policy" "lambda_role_policy" {
  name   = "hallow-lambda"
  role   = aws_iam_role.lambda_role.id
  policy = data.aws_iam_policy_document.lambda_policy.json
}

data "aws_iam_policy_document" "lambda_policy" {
  statement {
    actions = [
      "logs:CreateLogStream",
      "logs:PutLogEvents"
    ]
    resources = ["arn:aws:logs:*:*:log-group:${aws_cloudwatch_log_group.log_group.name}:*"]
  }

  statement {
    actions = [
      "kms:Sign",
      "kms:GetPublicKey",
    ]
    resources = [aws_kms_key.ssh_ca_key.arn]
  }

  statement {
    actions   = ["iam:GetRole"]
    resources = ["*"]
  }
}

resource "aws_cloudwatch_log_group" "log_group" {
  // Magic name! Lambda is hard coded to which group it logs to, we pre-create
  // that to be able to reference in the IAM policy.
  name = "/aws/lambda/hallow"
}

resource "aws_lambda_function" "hallow_lambda" {
  s3_bucket     = var.lambda_s3_bucket
  s3_key        = var.lambda_s3_key
  function_name = "hallow"
  handler       = "hallow"
  role          = aws_iam_role.lambda_role.arn
  runtime       = "go1.x"

  environment {
    variables = {
      HALLOW_KMS_KEY_ARN = aws_kms_key.ssh_ca_key.arn,
    }
  }

  depends_on = [aws_cloudwatch_log_group.log_group]
}

resource "aws_api_gateway_rest_api" "hallow_api_gateway" {
  name = "Hallow API"

  endpoint_configuration {
    types = ["REGIONAL"]
  }
}

resource "aws_api_gateway_resource" "hallow_resource" {
  rest_api_id = aws_api_gateway_rest_api.hallow_api_gateway.id
  parent_id   = aws_api_gateway_rest_api.hallow_api_gateway.root_resource_id
  path_part   = "hallow"
}

resource "aws_api_gateway_method" "hallow_gateway_method" {
  rest_api_id   = aws_api_gateway_rest_api.hallow_api_gateway.id
  resource_id   = aws_api_gateway_resource.hallow_resource.id
  http_method   = "PUT"
  authorization = "AWS_IAM"
}

resource "aws_api_gateway_integration" "hallow_lambda_integration" {
  rest_api_id             = aws_api_gateway_rest_api.hallow_api_gateway.id
  resource_id             = aws_api_gateway_resource.hallow_resource.id
  http_method             = aws_api_gateway_method.hallow_gateway_method.http_method
  integration_http_method = "POST"
  type                    = "AWS_PROXY"
  uri                     = aws_lambda_function.hallow_lambda.invoke_arn
}

resource "aws_api_gateway_deployment" "prod" {
  depends_on  = [aws_api_gateway_integration.hallow_lambda_integration]
  rest_api_id = aws_api_gateway_rest_api.hallow_api_gateway.id
  stage_name  = "prod"
}

resource "aws_lambda_permission" "allow_api_gateway" {
  function_name = aws_lambda_function.hallow_lambda.arn
  action        = "lambda:InvokeFunction"
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_api_gateway_deployment.prod.execution_arn}/*/*"
}

resource "aws_iam_policy" "request_certificate_policy" {
  name        = "hallow-request-certificate"
  description = "Policy which allows requesting certificates from Hallow"
  policy      = data.aws_iam_policy_document.request_certificate_policy.json
}

data "aws_iam_policy_document" "request_certificate_policy" {
  statement {
    actions   = ["execute-api:Invoke"]
    resources = ["${aws_api_gateway_rest_api.hallow_api_gateway.execution_arn}/*/*/*"]
  }
}

resource "aws_api_gateway_domain_name" "hallow_api_gateway" {
  count = (var.dns == null) ? 0 : 1

  domain_name              = var.dns.domain
  regional_certificate_arn = aws_acm_certificate.hallow_api_gateway[0].arn

  endpoint_configuration {
    types = ["REGIONAL"]
  }

  depends_on = [aws_acm_certificate_validation.hallow_api_gateway]
}

resource "aws_api_gateway_base_path_mapping" "hallow_api_gateway" {
  count = (var.dns == null) ? 0 : 1

  api_id      = aws_api_gateway_rest_api.hallow_api_gateway.id
  domain_name = aws_api_gateway_domain_name.hallow_api_gateway[0].domain_name
}

resource "aws_route53_record" "hallow_api_gateway" {
  count = (var.dns == null) ? 0 : 1

  zone_id = var.dns.zone_id
  name    = aws_api_gateway_domain_name.hallow_api_gateway[0].domain_name
  type    = "A"

  alias {
    zone_id                = aws_api_gateway_domain_name.hallow_api_gateway[0].regional_zone_id
    name                   = aws_api_gateway_domain_name.hallow_api_gateway[0].regional_domain_name
    evaluate_target_health = true
  }
}

resource "aws_acm_certificate" "hallow_api_gateway" {
  count = (var.dns == null) ? 0 : 1

  domain_name       = var.dns.domain
  validation_method = "DNS"

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_acm_certificate_validation" "hallow_api_gateway" {
  count = (var.dns == null) ? 0 : 1

  certificate_arn         = aws_acm_certificate.hallow_api_gateway[0].arn
  validation_record_fqdns = [for record in aws_route53_record.certificate_validation : record.fqdn]
}

resource "aws_route53_record" "certificate_validation" {
  for_each = (var.dns == null) ? {} : {
    for option in aws_acm_certificate.hallow_api_gateway[0].domain_validation_options :
    option.domain_name => {
      name  = option.resource_record_name
      type  = option.resource_record_type
      value = option.resource_record_value
    }
  }

  zone_id = var.dns.zone_id
  name    = each.value.name
  type    = each.value.type
  records = [each.value.value]
  ttl     = 300
}
