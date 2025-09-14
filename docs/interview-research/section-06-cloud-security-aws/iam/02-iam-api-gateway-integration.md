# IAM API Gateway Integration

## Question
**How does IAM integrate with API Gateway for securing REST APIs? Describe the flow.**

*Complexity: High | Focus Area: API authentication flows*

## Core Answer

IAM integrates with API Gateway through multiple authentication mechanisms, providing flexible security options for REST APIs. The integration enables fine-grained access control, request signing, and seamless AWS service integration.

### Primary Integration Methods

**1. AWS_IAM Authorization**
- Direct IAM user/role authentication
- Signature Version 4 (SigV4) request signing
- AWS SDK automatic credential management
- Cross-account access support

**2. IAM Roles and Policies**
- Resource-based access control
- Method-level permissions
- Integration with other AWS services
- Temporary credential support via STS

**3. Lambda Authorizers with IAM**
- Custom authorization logic
- IAM role assumption
- Token-based authentication
- Policy document generation

## Technical Implementation

### 1. Basic IAM Authentication Setup

```python
# Python boto3 - API Gateway with IAM authentication
import boto3
import json
from datetime import datetime

def create_iam_secured_api():
    """Create API Gateway with IAM authentication"""

    # Initialize clients
    apigateway = boto3.client('apigateway')
    iam = boto3.client('iam')

    # Create API Gateway
    api_response = apigateway.create_rest_api(
        name='secure-web-api',
        description='IAM-secured REST API for web application',
        endpointConfiguration={
            'types': ['REGIONAL']
        }
    )
    api_id = api_response['id']

    # Get root resource
    resources = apigateway.get_resources(restApiId=api_id)
    root_id = resources['items'][0]['id']

    # Create resource
    resource_response = apigateway.create_resource(
        restApiId=api_id,
        parentId=root_id,
        pathPart='users'
    )
    resource_id = resource_response['id']

    # Create method with IAM authorization
    apigateway.put_method(
        restApiId=api_id,
        resourceId=resource_id,
        httpMethod='GET',
        authorizationType='AWS_IAM',
        requestParameters={
            'method.request.header.Authorization': True
        }
    )

    # Create IAM policy for API access
    policy_document = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "execute-api:Invoke",
                "Resource": f"arn:aws:execute-api:*:*:{api_id}/*/GET/users"
            }
        ]
    }

    # Create IAM role for API consumers
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {
                    "Service": "lambda.amazonaws.com"
                },
                "Action": "sts:AssumeRole"
            },
            {
                "Effect": "Allow",
                "Principal": {
                    "AWS": "arn:aws:iam::ACCOUNT-ID:root"
                },
                "Action": "sts:AssumeRole"
            }
        ]
    }

    iam.create_role(
        RoleName='APIGatewayConsumerRole',
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Description='Role for consuming IAM-secured API Gateway'
    )

    iam.put_role_policy(
        RoleName='APIGatewayConsumerRole',
        PolicyName='APIGatewayInvokePolicy',
        PolicyDocument=json.dumps(policy_document)
    )

    return api_id, resource_id

# Client-side authenticated request
def make_authenticated_request(api_url, region='us-east-1'):
    """Make SigV4 signed request to API Gateway"""
    import requests
    from botocore.auth import SigV4Auth
    from botocore.awsrequest import AWSRequest
    from boto3 import Session

    # Get AWS credentials
    session = Session()
    credentials = session.get_credentials()

    # Create request
    request = AWSRequest(method='GET', url=api_url)

    # Sign request with SigV4
    SigV4Auth(credentials, 'execute-api', region).add_auth(request)

    # Send request
    response = requests.get(api_url, headers=dict(request.headers))
    return response

# Usage example
if __name__ == "__main__":
    api_id, resource_id = create_iam_secured_api()

    # Construct API URL
    api_url = f"https://{api_id}.execute-api.us-east-1.amazonaws.com/prod/users"

    # Make authenticated request
    response = make_authenticated_request(api_url)
    print(f"Response: {response.status_code}")
```

### 2. Lambda Authorizer with IAM Integration

```python
# Lambda Authorizer Function
import json
import boto3
import jwt
from typing import Dict, Any

def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """Custom authorizer with IAM role assumption"""

    try:
        # Extract authorization token
        token = event['authorizationToken']
        method_arn = event['methodArn']

        # Validate token (example with JWT)
        if not validate_token(token):
            raise Exception('Unauthorized')

        # Extract user information from token
        user_info = jwt.decode(token, verify=False)
        user_id = user_info.get('sub')
        user_role = user_info.get('role', 'user')

        # Generate IAM policy based on user role
        policy = generate_iam_policy(user_id, user_role, method_arn)

        # Return authorization response
        return {
            'principalId': user_id,
            'policyDocument': policy,
            'context': {
                'userId': user_id,
                'userRole': user_role,
                'tokenExpiry': str(user_info.get('exp', ''))
            }
        }

    except Exception as e:
        print(f"Authorization failed: {str(e)}")
        raise Exception('Unauthorized')

def validate_token(token: str) -> bool:
    """Validate JWT token"""
    try:
        # In production, use proper JWT validation
        # with secret key and expiration checking
        decoded = jwt.decode(token, verify=False)
        return 'sub' in decoded
    except:
        return False

def generate_iam_policy(user_id: str, user_role: str, method_arn: str) -> Dict[str, Any]:
    """Generate IAM policy based on user role"""

    # Parse method ARN to get resource components
    arn_parts = method_arn.split(':')
    api_gateway_arn = ':'.join(arn_parts[:-1])

    # Base policy structure
    policy = {
        "Version": "2012-10-17",
        "Statement": []
    }

    # Role-based permissions
    if user_role == 'admin':
        # Admin can access all methods
        policy['Statement'].append({
            "Effect": "Allow",
            "Action": "execute-api:Invoke",
            "Resource": f"{api_gateway_arn}/*"
        })
    elif user_role == 'user':
        # Regular users can only access specific methods
        policy['Statement'].extend([
            {
                "Effect": "Allow",
                "Action": "execute-api:Invoke",
                "Resource": f"{api_gateway_arn}/*/GET/users/{user_id}"
            },
            {
                "Effect": "Allow",
                "Action": "execute-api:Invoke",
                "Resource": f"{api_gateway_arn}/*/PUT/users/{user_id}"
            }
        ])
    else:
        # Deny access for unknown roles
        policy['Statement'].append({
            "Effect": "Deny",
            "Action": "execute-api:Invoke",
            "Resource": f"{api_gateway_arn}/*"
        })

    return policy

# API Gateway setup with Lambda Authorizer
def setup_lambda_authorizer_api():
    """Setup API Gateway with Lambda Authorizer"""

    apigateway = boto3.client('apigateway')
    lambda_client = boto3.client('lambda')

    # Create API
    api_response = apigateway.create_rest_api(
        name='lambda-auth-api',
        description='API with Lambda Authorizer and IAM integration'
    )
    api_id = api_response['id']

    # Create Lambda Authorizer
    authorizer_response = apigateway.create_authorizer(
        restApiId=api_id,
        name='custom-lambda-authorizer',
        type='TOKEN',
        authorizerUri=f'arn:aws:apigateway:us-east-1:lambda:path/2015-03-31/functions/arn:aws:lambda:us-east-1:ACCOUNT-ID:function:api-authorizer/invocations',
        authorizerCredentials='arn:aws:iam::ACCOUNT-ID:role/APIGatewayAuthorizerRole',
        identitySource='method.request.header.Authorization',
        authorizerResultTtlInSeconds=300
    )
    authorizer_id = authorizer_response['id']

    return api_id, authorizer_id
```

### 3. Cross-Account API Access

```python
# Cross-account IAM role setup
def setup_cross_account_api_access():
    """Setup cross-account access for API Gateway"""

    iam = boto3.client('iam')

    # Cross-account trust policy
    cross_account_trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {
                    "AWS": [
                        "arn:aws:iam::TRUSTED-ACCOUNT-1:root",
                        "arn:aws:iam::TRUSTED-ACCOUNT-2:root"
                    ]
                },
                "Action": "sts:AssumeRole",
                "Condition": {
                    "StringEquals": {
                        "sts:ExternalId": "unique-external-id-123"
                    }
                }
            }
        ]
    }

    # API access policy
    api_access_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "execute-api:Invoke"
                ],
                "Resource": [
                    "arn:aws:execute-api:*:*:*/*/GET/*",
                    "arn:aws:execute-api:*:*:*/*/POST/*"
                ]
            }
        ]
    }

    # Create cross-account role
    iam.create_role(
        RoleName='CrossAccountAPIAccess',
        AssumeRolePolicyDocument=json.dumps(cross_account_trust_policy),
        Description='Cross-account access to API Gateway'
    )

    iam.put_role_policy(
        RoleName='CrossAccountAPIAccess',
        PolicyName='APIGatewayInvokePolicy',
        PolicyDocument=json.dumps(api_access_policy)
    )

# Client code for cross-account access
def assume_cross_account_role_and_call_api():
    """Assume cross-account role and call API"""

    sts = boto3.client('sts')

    # Assume cross-account role
    response = sts.assume_role(
        RoleArn='arn:aws:iam::TARGET-ACCOUNT:role/CrossAccountAPIAccess',
        RoleSessionName='api-access-session',
        ExternalId='unique-external-id-123',
        DurationSeconds=3600
    )

    credentials = response['Credentials']

    # Create session with assumed role credentials
    session = boto3.Session(
        aws_access_key_id=credentials['AccessKeyId'],
        aws_secret_access_key=credentials['SecretAccessKey'],
        aws_session_token=credentials['SessionToken']
    )

    # Make API call using assumed role credentials
    # (Implementation similar to make_authenticated_request above)
```

## Terraform Infrastructure as Code

```hcl
# Terraform configuration for IAM-API Gateway integration
terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

# API Gateway REST API
resource "aws_api_gateway_rest_api" "secure_api" {
  name        = "secure-web-api"
  description = "IAM-secured REST API"

  endpoint_configuration {
    types = ["REGIONAL"]
  }
}

# API Gateway Resource
resource "aws_api_gateway_resource" "users_resource" {
  rest_api_id = aws_api_gateway_rest_api.secure_api.id
  parent_id   = aws_api_gateway_rest_api.secure_api.root_resource_id
  path_part   = "users"
}

# API Gateway Method with IAM Authorization
resource "aws_api_gateway_method" "users_get" {
  rest_api_id   = aws_api_gateway_rest_api.secure_api.id
  resource_id   = aws_api_gateway_resource.users_resource.id
  http_method   = "GET"
  authorization = "AWS_IAM"

  request_parameters = {
    "method.request.header.Authorization" = true
  }
}

# Lambda function for backend
resource "aws_lambda_function" "users_handler" {
  filename         = "users_handler.zip"
  function_name    = "users-handler"
  role            = aws_iam_role.lambda_exec_role.arn
  handler         = "index.handler"
  runtime         = "python3.9"

  source_code_hash = filebase64sha256("users_handler.zip")
}

# IAM role for Lambda execution
resource "aws_iam_role" "lambda_exec_role" {
  name = "lambda-exec-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
      }
    ]
  })
}

# Lambda basic execution policy
resource "aws_iam_role_policy_attachment" "lambda_basic_execution" {
  role       = aws_iam_role.lambda_exec_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

# API Gateway Integration
resource "aws_api_gateway_integration" "users_integration" {
  rest_api_id = aws_api_gateway_rest_api.secure_api.id
  resource_id = aws_api_gateway_resource.users_resource.id
  http_method = aws_api_gateway_method.users_get.http_method

  integration_http_method = "POST"
  type                   = "AWS_PROXY"
  uri                    = aws_lambda_function.users_handler.invoke_arn
}

# Lambda permission for API Gateway
resource "aws_lambda_permission" "api_gateway_invoke" {
  statement_id  = "AllowAPIGatewayInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.users_handler.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_api_gateway_rest_api.secure_api.execution_arn}/*/*"
}

# IAM role for API consumers
resource "aws_iam_role" "api_consumer_role" {
  name = "api-consumer-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
      }
    ]
  })
}

# IAM policy for API access
resource "aws_iam_role_policy" "api_invoke_policy" {
  name = "api-invoke-policy"
  role = aws_iam_role.api_consumer_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = "execute-api:Invoke"
        Resource = "${aws_api_gateway_rest_api.secure_api.execution_arn}/*/GET/users"
      }
    ]
  })
}

# Lambda Authorizer
resource "aws_lambda_function" "authorizer" {
  filename         = "authorizer.zip"
  function_name    = "api-authorizer"
  role            = aws_iam_role.authorizer_exec_role.arn
  handler         = "index.lambda_handler"
  runtime         = "python3.9"

  source_code_hash = filebase64sha256("authorizer.zip")
}

# IAM role for Lambda Authorizer
resource "aws_iam_role" "authorizer_exec_role" {
  name = "authorizer-exec-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
      }
    ]
  })
}

# API Gateway Authorizer
resource "aws_api_gateway_authorizer" "lambda_authorizer" {
  name                   = "lambda-authorizer"
  rest_api_id           = aws_api_gateway_rest_api.secure_api.id
  authorizer_uri        = aws_lambda_function.authorizer.invoke_arn
  authorizer_credentials = aws_iam_role.authorizer_invocation_role.arn
  type                  = "TOKEN"
  identity_source       = "method.request.header.Authorization"
  authorizer_result_ttl_in_seconds = 300
}

# IAM role for authorizer invocation
resource "aws_iam_role" "authorizer_invocation_role" {
  name = "authorizer-invocation-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "apigateway.amazonaws.com"
        }
      }
    ]
  })
}

# Policy for authorizer invocation
resource "aws_iam_role_policy" "authorizer_invocation_policy" {
  name = "authorizer-invocation-policy"
  role = aws_iam_role.authorizer_invocation_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = "lambda:InvokeFunction"
        Resource = aws_lambda_function.authorizer.arn
      }
    ]
  })
}

# API Gateway Deployment
resource "aws_api_gateway_deployment" "api_deployment" {
  rest_api_id = aws_api_gateway_rest_api.secure_api.id
  stage_name  = "prod"

  depends_on = [
    aws_api_gateway_method.users_get,
    aws_api_gateway_integration.users_integration
  ]
}

# Data source for current AWS account
data "aws_caller_identity" "current" {}

# Outputs
output "api_gateway_url" {
  value = "https://${aws_api_gateway_rest_api.secure_api.id}.execute-api.${data.aws_region.current.name}.amazonaws.com/prod"
}

output "api_consumer_role_arn" {
  value = aws_iam_role.api_consumer_role.arn
}

data "aws_region" "current" {}
```

## Authentication Flow Diagram

```
Client Application
        │
        │ 1. Obtain AWS Credentials
        ├─── STS AssumeRole (if cross-account)
        │    └── Temporary credentials
        │
        │ 2. Create SigV4 Signed Request
        ├─── AWS SDK automatically signs
        │    └── Authorization header added
        │
        │ 3. HTTP Request to API Gateway
        ▼
API Gateway
        │
        │ 4. Validate IAM Authorization
        ├─── Check signature validity
        ├─── Verify credentials are not expired
        └─── Extract principal identity
        │
        │ 5. Policy Evaluation
        ├─── Check resource-based policies
        ├─── Check identity-based policies
        └─── Apply conditions and constraints
        │
        │ 6. Authorization Decision
        ├─── ALLOW: Continue to backend
        └─── DENY: Return 403 Forbidden
        │
        │ 7. Backend Integration
        ▼
Lambda Function / Backend Service
        │
        │ 8. Process Request
        ├─── Access user context from event
        └─── Execute business logic
        │
        │ 9. Return Response
        ▼
Client Application
```

## Real-World Implementation Examples

### 1. Multi-Tenant SaaS Platform

```python
# Multi-tenant API with tenant-based IAM policies
class MultiTenantAPIHandler:
    def __init__(self):
        self.iam = boto3.client('iam')
        self.apigateway = boto3.client('apigateway')

    def create_tenant_specific_role(self, tenant_id: str, permissions: list):
        """Create IAM role with tenant-specific permissions"""

        role_name = f"tenant-{tenant_id}-api-role"

        # Trust policy allowing the tenant to assume the role
        trust_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {
                        "AWS": f"arn:aws:iam::ACCOUNT-ID:user/tenant-{tenant_id}-user"
                    },
                    "Action": "sts:AssumeRole",
                    "Condition": {
                        "StringEquals": {
                            "sts:ExternalId": f"tenant-{tenant_id}-external-id"
                        }
                    }
                }
            ]
        }

        # Create role
        self.iam.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=json.dumps(trust_policy),
            Description=f'API access role for tenant {tenant_id}'
        )

        # Create tenant-specific policy
        tenant_policy = {
            "Version": "2012-10-17",
            "Statement": []
        }

        for permission in permissions:
            tenant_policy['Statement'].append({
                "Effect": "Allow",
                "Action": "execute-api:Invoke",
                "Resource": f"arn:aws:execute-api:*:*:*/*/{permission}/tenants/{tenant_id}/*"
            })

        self.iam.put_role_policy(
            RoleName=role_name,
            PolicyName=f'tenant-{tenant_id}-api-policy',
            PolicyDocument=json.dumps(tenant_policy)
        )

        return role_name

    def setup_tenant_api_resources(self, api_id: str, tenant_permissions: dict):
        """Setup API resources with tenant-based access"""

        for tenant_id, permissions in tenant_permissions.items():
            # Create tenant-specific resources
            tenant_resource = self.apigateway.create_resource(
                restApiId=api_id,
                parentId=self.get_root_resource_id(api_id),
                pathPart=f'tenants'
            )

            tenant_id_resource = self.apigateway.create_resource(
                restApiId=api_id,
                parentId=tenant_resource['id'],
                pathPart=f'{tenant_id}'
            )

            # Create methods for each permission
            for method in permissions:
                self.apigateway.put_method(
                    restApiId=api_id,
                    resourceId=tenant_id_resource['id'],
                    httpMethod=method.upper(),
                    authorizationType='AWS_IAM'
                )
```

### 2. Healthcare Data API (HIPAA Compliant)

```python
# HIPAA-compliant API with strict IAM controls
class HealthcareAPISetup:
    def __init__(self):
        self.iam = boto3.client('iam')
        self.kms = boto3.client('kms')

    def create_healthcare_api_roles(self):
        """Create HIPAA-compliant IAM roles"""

        roles = {
            'healthcare-physician-role': {
                'permissions': ['GET', 'POST', 'PUT'],
                'resources': [
                    '/patients/*',
                    '/medical-records/*',
                    '/prescriptions/*'
                ]
            },
            'healthcare-nurse-role': {
                'permissions': ['GET', 'POST'],
                'resources': [
                    '/patients/*/vitals',
                    '/patients/*/notes'
                ]
            },
            'healthcare-admin-role': {
                'permissions': ['GET'],
                'resources': [
                    '/patients/*/demographics',
                    '/reports/*'
                ]
            }
        }

        for role_name, config in roles.items():
            # Create role with MFA requirement
            trust_policy = {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {
                            "AWS": f"arn:aws:iam::ACCOUNT-ID:root"
                        },
                        "Action": "sts:AssumeRole",
                        "Condition": {
                            "Bool": {
                                "aws:MultiFactorAuthPresent": "true"
                            },
                            "NumericLessThan": {
                                "aws:MultiFactorAuthAge": "3600"
                            }
                        }
                    }
                ]
            }

            self.iam.create_role(
                RoleName=role_name,
                AssumeRolePolicyDocument=json.dumps(trust_policy),
                Description=f'HIPAA-compliant role: {role_name}'
            )

            # Create restrictive policy
            policy = {
                "Version": "2012-10-17",
                "Statement": []
            }

            for resource in config['resources']:
                for permission in config['permissions']:
                    policy['Statement'].append({
                        "Effect": "Allow",
                        "Action": "execute-api:Invoke",
                        "Resource": f"arn:aws:execute-api:*:*:*/*/{permission}{resource}",
                        "Condition": {
                            "IpAddress": {
                                "aws:SourceIp": [
                                    "192.168.1.0/24",  # Hospital network
                                    "10.0.0.0/16"      # VPN network
                                ]
                            },
                            "DateGreaterThan": {
                                "aws:CurrentTime": "2024-01-01T00:00:00Z"
                            },
                            "DateLessThan": {
                                "aws:CurrentTime": "2025-01-01T00:00:00Z"
                            }
                        }
                    })

            self.iam.put_role_policy(
                RoleName=role_name,
                PolicyName=f'{role_name}-policy',
                PolicyDocument=json.dumps(policy)
            )
```

## Common Integration Patterns

### 1. Mobile Application Backend
- Cognito User Pools for user authentication
- IAM roles for AWS service access
- API Gateway with Cognito authorizer
- Fine-grained resource permissions

### 2. Enterprise API Gateway
- SAML/OIDC federation with corporate identity
- Cross-account role assumption
- VPC endpoint integration
- CloudTrail audit logging

### 3. Partner API Access
- External ID for secure cross-account access
- Time-bounded sessions with STS
- API key + IAM dual authentication
- Rate limiting and throttling

## Security Best Practices

**1. Principle of Least Privilege**
- Grant minimum required permissions
- Use resource-level restrictions
- Implement time-based access controls

**2. Defense in Depth**
- Combine IAM with other security measures
- Use VPC endpoints for internal APIs
- Implement request/response validation

**3. Monitoring and Auditing**
- Enable CloudTrail for API calls
- Monitor failed authentication attempts
- Set up CloudWatch alarms for suspicious activity

## Common Pitfalls

**1. Overly Broad Policies**
- Avoid wildcard resources in production
- Limit cross-account access scope
- Regularly audit and rotate policies

**2. Incorrect Trust Relationships**
- Validate AssumeRole policies
- Use external IDs for cross-account access
- Implement proper condition blocks

**3. SigV4 Implementation Issues**
- Ensure correct regional endpoints
- Handle credential refresh properly
- Validate request signing process

## Follow-Up Questions

**Technical Deep Dive:**
- "How would you implement API versioning with IAM policies?"
- "Describe handling IAM role chaining in API Gateway"
- "How do you manage API Gateway resource policies at scale?"

**Security Focus:**
- "What IAM conditions would you use for mobile API access?"
- "How would you implement API Gateway access logging for compliance?"
- "Describe your approach to IAM policy testing and validation"

**Architecture Design:**
- "Design API Gateway authentication for a multi-region application"
- "How would you handle API Gateway integration with on-premises identity systems?"
- "What's your strategy for IAM governance in a microservices architecture?"

## Related Topics
- [IAM Core Components](./01-iam-core-components.md)
- [IAM Best Practices](./03-iam-best-practices.md)
- [AWS Cognito Integration](../api-gateway-security/03-cognito-integration.md)
- [API Authentication Mechanisms](../api-gateway-security/02-auth-mechanisms.md)