data "aws_iam_policy_document" "lambda_assume_role" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

data "aws_iam_policy_document" "ca_policy" {
  statement {
    sid    = "AccessCASecret"
    effect = "Allow"

    actions = ["secretsmanager:GetSecretValue"]

    // Restrict this to a specific secret
    resources = ["*"]
  }

  statement {
    sid = "DecryptSecret"
    effect = "Allow"

    actions = [
      "kms:Decrypt",
      "kms:DescribeKey",
    ]

    // Restrict this to a specific key
    resources = ["*"]
  }
}

resource "aws_iam_policy" "ca_policy" {
  name        = "ca_policy"
  description = "This policy allows to read the CA secrets"

  policy = data.aws_iam_policy_document.ca_policy.json
}

resource "aws_iam_role" "ca" {
  name                = "serverless-ca"
  assume_role_policy  = data.aws_iam_policy_document.lambda_assume_role.json
  managed_policy_arns = [
    aws_iam_policy.ca_policy.arn,
    "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
  ]
}

resource "aws_lambda_function" "ca" {
  function_name = "vault-bootstrap-tls"
  runtime       = "go1.x"
  architectures = ["x86_64"]
  handler       = "main"
  role          = aws_iam_role.ca.arn

  filename         = "function.zip"
  source_code_hash = filebase64sha256("function.zip")

  environment {
    variables = {
      // Set this to the CA secret name (see README)
      CA_SM_SECRET_NAME = "vault-bootstrap-certificate-authority"
    }
  }
}