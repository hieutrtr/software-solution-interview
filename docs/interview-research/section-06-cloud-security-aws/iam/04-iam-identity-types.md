# IAM Identity Types

## Question
**When would you use IAM users vs roles vs federated identities? Explain the differences.**

*Complexity: Medium | Focus Area: Users vs roles vs federated identities*

## Core Answer

IAM provides three primary identity types, each serving different use cases: **IAM Users** for long-term individuals/services, **IAM Roles** for temporary access and service-to-service authentication, and **Federated Identities** for external identity integration. The choice depends on access duration, security requirements, and integration needs.

### Identity Type Comparison

| Identity Type | Use Case | Credentials | Duration | Best For |
|---------------|----------|-------------|----------|----------|
| **IAM Users** | Individual people, CI/CD systems | Access keys, passwords | Permanent | Human users, legacy systems |
| **IAM Roles** | Applications, temporary access | Temporary tokens | Time-limited | AWS services, applications, cross-account |
| **Federated Identities** | External identity systems | External tokens | Variable | Enterprise SSO, web/mobile apps |

## Technical Implementation

### 1. IAM Users - Implementation and Use Cases

```python
# IAM Users management implementation
import boto3
import json
import secrets
import string
from datetime import datetime, timedelta

class IAMUserManager:
    def __init__(self):
        self.iam = boto3.client('iam')

    def create_human_user(self, username: str, department: str, job_function: str):
        """Create IAM user for human employee"""

        # Create user with tags
        user_tags = [
            {'Key': 'UserType', 'Value': 'Human'},
            {'Key': 'Department', 'Value': department},
            {'Key': 'JobFunction', 'Value': job_function},
            {'Key': 'CreatedBy', 'Value': 'IAMUserManager'},
            {'Key': 'CreatedDate', 'Value': datetime.utcnow().isoformat()}
        ]

        user_response = self.iam.create_user(
            UserName=username,
            Tags=user_tags
        )

        # Create login profile (console access)
        temporary_password = self._generate_temporary_password()

        self.iam.create_login_profile(
            UserName=username,
            Password=temporary_password,
            PasswordResetRequired=True
        )

        # Add to appropriate groups based on job function
        self._assign_to_groups(username, job_function, department)

        return {
            'user_arn': user_response['User']['Arn'],
            'temporary_password': temporary_password,
            'console_url': f"https://{self._get_account_alias()}.signin.aws.amazon.com/console"
        }

    def create_service_user(self, service_name: str, purpose: str):
        """Create IAM user for service account (legacy systems)"""

        username = f"service-{service_name}"

        service_tags = [
            {'Key': 'UserType', 'Value': 'Service'},
            {'Key': 'ServiceName', 'Value': service_name},
            {'Key': 'Purpose', 'Value': purpose},
            {'Key': 'CreatedBy', 'Value': 'IAMUserManager'}
        ]

        # Create user without console access
        user_response = self.iam.create_user(
            UserName=username,
            Tags=service_tags
        )

        # Create access key for programmatic access
        access_key_response = self.iam.create_access_key(UserName=username)

        # Create minimal policy for the service
        policy_name = f"{service_name}-service-policy"
        service_policy = self._create_service_policy(service_name, purpose)

        policy_response = self.iam.create_policy(
            PolicyName=policy_name,
            PolicyDocument=json.dumps(service_policy),
            Description=f"Service policy for {service_name}"
        )

        # Attach policy to user
        self.iam.attach_user_policy(
            UserName=username,
            PolicyArn=policy_response['Policy']['Arn']
        )

        return {
            'username': username,
            'access_key_id': access_key_response['AccessKey']['AccessKeyId'],
            'secret_access_key': access_key_response['AccessKey']['SecretAccessKey'],
            'policy_arn': policy_response['Policy']['Arn']
        }

    def _generate_temporary_password(self) -> str:
        """Generate secure temporary password"""
        length = 16
        characters = string.ascii_letters + string.digits + "!@#$%^&*"
        return ''.join(secrets.choice(characters) for _ in range(length))

    def _assign_to_groups(self, username: str, job_function: str, department: str):
        """Assign user to appropriate groups"""

        # Job function groups
        job_function_groups = {
            'developer': ['Developers', 'RequireMFA'],
            'admin': ['Administrators', 'RequireMFA', 'EmergencyAccess'],
            'analyst': ['DataAnalysts', 'RequireMFA'],
            'security': ['SecurityTeam', 'RequireMFA', 'AuditAccess']
        }

        # Department groups
        department_groups = {
            'engineering': ['EngineeringTeam'],
            'finance': ['FinanceTeam'],
            'hr': ['HRTeam'],
            'security': ['SecurityTeam']
        }

        # Add to job function groups
        if job_function.lower() in job_function_groups:
            for group_name in job_function_groups[job_function.lower()]:
                try:
                    self.iam.add_user_to_group(
                        GroupName=group_name,
                        UserName=username
                    )
                except Exception as e:
                    print(f"Failed to add user to group {group_name}: {str(e)}")

        # Add to department groups
        if department.lower() in department_groups:
            for group_name in department_groups[department.lower()]:
                try:
                    self.iam.add_user_to_group(
                        GroupName=group_name,
                        UserName=username
                    )
                except Exception as e:
                    print(f"Failed to add user to group {group_name}: {str(e)}")

    def _create_service_policy(self, service_name: str, purpose: str) -> dict:
        """Create minimal policy for service user"""

        base_policy = {
            "Version": "2012-10-17",
            "Statement": []
        }

        # Common service policies based on purpose
        if purpose == 'ci-cd':
            base_policy['Statement'] = [
                {
                    "Effect": "Allow",
                    "Action": [
                        "s3:GetObject",
                        "s3:PutObject",
                        "lambda:UpdateFunctionCode",
                        "cloudformation:DescribeStacks",
                        "cloudformation:UpdateStack"
                    ],
                    "Resource": [
                        f"arn:aws:s3:::deployment-{service_name}/*",
                        f"arn:aws:lambda:*:*:function:{service_name}-*",
                        f"arn:aws:cloudformation:*:*:stack/{service_name}-*"
                    ]
                }
            ]
        elif purpose == 'monitoring':
            base_policy['Statement'] = [
                {
                    "Effect": "Allow",
                    "Action": [
                        "cloudwatch:GetMetricStatistics",
                        "cloudwatch:ListMetrics",
                        "logs:DescribeLogGroups",
                        "logs:DescribeLogStreams",
                        "logs:GetLogEvents"
                    ],
                    "Resource": "*"
                }
            ]
        elif purpose == 'backup':
            base_policy['Statement'] = [
                {
                    "Effect": "Allow",
                    "Action": [
                        "s3:GetObject",
                        "s3:PutObject",
                        "s3:ListBucket",
                        "rds:DescribeDBInstances",
                        "rds:CreateDBSnapshot"
                    ],
                    "Resource": [
                        f"arn:aws:s3:::backup-{service_name}",
                        f"arn:aws:s3:::backup-{service_name}/*",
                        "arn:aws:rds:*:*:db:*"
                    ]
                }
            ]

        return base_policy

    def _get_account_alias(self) -> str:
        """Get AWS account alias"""
        try:
            response = self.iam.list_account_aliases()
            if response['AccountAliases']:
                return response['AccountAliases'][0]
            else:
                # Return account ID if no alias set
                sts = boto3.client('sts')
                account_id = sts.get_caller_identity()['Account']
                return account_id
        except:
            return 'aws-account'

# Example usage
def setup_development_team():
    """Setup IAM users for development team"""

    manager = IAMUserManager()

    team_members = [
        {'username': 'john.developer', 'department': 'engineering', 'job_function': 'developer'},
        {'username': 'sarah.admin', 'department': 'engineering', 'job_function': 'admin'},
        {'username': 'mike.analyst', 'department': 'finance', 'job_function': 'analyst'}
    ]

    created_users = []
    for member in team_members:
        user_info = manager.create_human_user(
            member['username'],
            member['department'],
            member['job_function']
        )
        created_users.append(user_info)

    # Create service user for CI/CD
    service_user = manager.create_service_user('webapp-ci', 'ci-cd')

    return created_users, service_user
```

### 2. IAM Roles - Implementation and Use Cases

```python
# IAM Roles comprehensive implementation
class IAMRoleManager:
    def __init__(self):
        self.iam = boto3.client('iam')
        self.sts = boto3.client('sts')

    def create_service_role(self, service_name: str, aws_service: str, permissions: list):
        """Create role for AWS services (EC2, Lambda, etc.)"""

        role_name = f"{service_name}-{aws_service}-role"

        # Trust policy for AWS service
        trust_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {
                        "Service": f"{aws_service}.amazonaws.com"
                    },
                    "Action": "sts:AssumeRole"
                }
            ]
        }

        # Create role
        role_response = self.iam.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=json.dumps(trust_policy),
            Description=f"Service role for {service_name} {aws_service}",
            Tags=[
                {'Key': 'ServiceName', 'Value': service_name},
                {'Key': 'AWSService', 'Value': aws_service},
                {'Key': 'RoleType', 'Value': 'ServiceRole'}
            ]
        )

        # Create and attach custom policy
        if permissions:
            policy_name = f"{role_name}-policy"
            custom_policy = {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": permissions,
                        "Resource": "*"
                    }
                ]
            }

            policy_response = self.iam.create_policy(
                PolicyName=policy_name,
                PolicyDocument=json.dumps(custom_policy)
            )

            self.iam.attach_role_policy(
                RoleName=role_name,
                PolicyArn=policy_response['Policy']['Arn']
            )

        return role_response['Role']['Arn']

    def create_cross_account_role(self, role_name: str, trusted_accounts: list,
                                  policies: list, external_id: str = None):
        """Create role for cross-account access"""

        # Trust policy for cross-account access
        principals = [f"arn:aws:iam::{account}:root" for account in trusted_accounts]

        trust_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {
                        "AWS": principals
                    },
                    "Action": "sts:AssumeRole"
                }
            ]
        }

        # Add external ID condition if provided
        if external_id:
            trust_policy["Statement"][0]["Condition"] = {
                "StringEquals": {
                    "sts:ExternalId": external_id
                }
            }

        # Create role
        role_response = self.iam.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=json.dumps(trust_policy),
            Description=f"Cross-account access role",
            MaxSessionDuration=3600,  # 1 hour
            Tags=[
                {'Key': 'RoleType', 'Value': 'CrossAccount'},
                {'Key': 'TrustedAccounts', 'Value': ','.join(trusted_accounts)}
            ]
        )

        # Attach policies
        for policy_arn in policies:
            self.iam.attach_role_policy(
                RoleName=role_name,
                PolicyArn=policy_arn
            )

        return role_response['Role']['Arn']

    def create_application_role(self, app_name: str, resources: list,
                               required_actions: list):
        """Create role for application with least privilege"""

        role_name = f"{app_name}-application-role"

        # Trust policy allowing EC2 instances to assume role
        trust_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {
                        "Service": "ec2.amazonaws.com"
                    },
                    "Action": "sts:AssumeRole"
                },
                {
                    "Effect": "Allow",
                    "Principal": {
                        "Service": "lambda.amazonaws.com"
                    },
                    "Action": "sts:AssumeRole"
                }
            ]
        }

        # Create role
        role_response = self.iam.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=json.dumps(trust_policy),
            Description=f"Application role for {app_name}"
        )

        # Create least privilege policy
        app_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": required_actions,
                    "Resource": resources
                }
            ]
        }

        policy_name = f"{app_name}-app-policy"
        policy_response = self.iam.create_policy(
            PolicyName=policy_name,
            PolicyDocument=json.dumps(app_policy)
        )

        self.iam.attach_role_policy(
            RoleName=role_name,
            PolicyArn=policy_response['Policy']['Arn']
        )

        # Create instance profile for EC2
        self.iam.create_instance_profile(InstanceProfileName=role_name)
        self.iam.add_role_to_instance_profile(
            InstanceProfileName=role_name,
            RoleName=role_name
        )

        return {
            'role_arn': role_response['Role']['Arn'],
            'instance_profile_arn': f"arn:aws:iam::{self._get_account_id()}:instance-profile/{role_name}"
        }

    def assume_role_with_mfa(self, role_arn: str, session_name: str,
                            mfa_serial: str, token_code: str, duration: int = 3600):
        """Assume role with MFA requirement"""

        try:
            response = self.sts.assume_role(
                RoleArn=role_arn,
                RoleSessionName=session_name,
                DurationSeconds=duration,
                SerialNumber=mfa_serial,
                TokenCode=token_code
            )

            credentials = response['Credentials']

            return {
                'access_key_id': credentials['AccessKeyId'],
                'secret_access_key': credentials['SecretAccessKey'],
                'session_token': credentials['SessionToken'],
                'expiration': credentials['Expiration']
            }

        except Exception as e:
            print(f"Error assuming role: {str(e)}")
            return None

    def _get_account_id(self) -> str:
        """Get current AWS account ID"""
        return self.sts.get_caller_identity()['Account']

# Example role implementations
def setup_microservices_roles():
    """Setup roles for microservices architecture"""

    role_manager = IAMRoleManager()

    # API Gateway Lambda role
    api_role = role_manager.create_service_role(
        'user-api',
        'lambda',
        [
            'dynamodb:GetItem',
            'dynamodb:PutItem',
            'dynamodb:Query',
            'logs:CreateLogGroup',
            'logs:CreateLogStream',
            'logs:PutLogEvents'
        ]
    )

    # Data processing Lambda role
    processor_role = role_manager.create_service_role(
        'data-processor',
        'lambda',
        [
            's3:GetObject',
            's3:PutObject',
            'dynamodb:BatchWriteItem',
            'sns:Publish'
        ]
    )

    # Cross-account analytics role
    analytics_role = role_manager.create_cross_account_role(
        'analytics-cross-account',
        ['123456789012'],  # Analytics account ID
        ['arn:aws:iam::aws:policy/ReadOnlyAccess'],
        'analytics-external-id-2024'
    )

    return {
        'api_role': api_role,
        'processor_role': processor_role,
        'analytics_role': analytics_role
    }
```

### 3. Federated Identities - Implementation and Use Cases

```python
# Federated Identities implementation
class FederatedIdentityManager:
    def __init__(self):
        self.iam = boto3.client('iam')
        self.cognito_idp = boto3.client('cognito-idp')
        self.cognito_identity = boto3.client('cognito-identity')

    def setup_saml_federation(self, idp_name: str, metadata_document: str):
        """Setup SAML 2.0 federation with corporate IdP"""

        # Create SAML identity provider
        saml_provider_response = self.iam.create_saml_provider(
            SAMLMetadataDocument=metadata_document,
            Name=idp_name
        )

        provider_arn = saml_provider_response['SAMLProviderArn']

        # Create role for SAML users
        saml_role_name = f"{idp_name}-federated-role"

        # Trust policy for SAML federation
        trust_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {
                        "Federated": provider_arn
                    },
                    "Action": "sts:AssumeRoleWithSAML",
                    "Condition": {
                        "StringEquals": {
                            "SAML:aud": "https://signin.aws.amazon.com/saml"
                        }
                    }
                }
            ]
        }

        # Create federated role
        role_response = self.iam.create_role(
            RoleName=saml_role_name,
            AssumeRolePolicyDocument=json.dumps(trust_policy),
            Description=f"SAML federated role for {idp_name}",
            MaxSessionDuration=28800  # 8 hours
        )

        # Create policy with attribute-based access control
        abac_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": [
                        "s3:GetObject",
                        "s3:ListBucket"
                    ],
                    "Resource": "*",
                    "Condition": {
                        "StringEquals": {
                            "s3:ExistingObjectTag/Department": "${saml:department}"
                        }
                    }
                },
                {
                    "Effect": "Allow",
                    "Action": [
                        "ec2:DescribeInstances",
                        "ec2:StartInstances",
                        "ec2:StopInstances"
                    ],
                    "Resource": "*",
                    "Condition": {
                        "StringEquals": {
                            "ec2:ResourceTag/Team": "${saml:team}"
                        }
                    }
                }
            ]
        }

        policy_response = self.iam.create_policy(
            PolicyName=f"{saml_role_name}-policy",
            PolicyDocument=json.dumps(abac_policy)
        )

        self.iam.attach_role_policy(
            RoleName=saml_role_name,
            PolicyArn=policy_response['Policy']['Arn']
        )

        return {
            'provider_arn': provider_arn,
            'role_arn': role_response['Role']['Arn']
        }

    def setup_cognito_identity_pool(self, pool_name: str, user_pool_id: str,
                                   user_pool_client_id: str):
        """Setup Cognito Identity Pool for mobile/web apps"""

        # Create identity pool
        identity_pool_response = self.cognito_identity.create_identity_pool(
            IdentityPoolName=pool_name,
            AllowUnauthenticatedIdentities=False,
            CognitoIdentityProviders=[
                {
                    'ProviderName': f'cognito-idp.us-east-1.amazonaws.com/{user_pool_id}',
                    'ClientId': user_pool_client_id,
                    'ServerSideTokenCheck': True
                }
            ]
        )

        identity_pool_id = identity_pool_response['IdentityPoolId']

        # Create authenticated role
        auth_role_name = f"{pool_name.replace('-', '_')}_authenticated_role"

        auth_trust_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {
                        "Federated": "cognito-identity.amazonaws.com"
                    },
                    "Action": "sts:AssumeRoleWithWebIdentity",
                    "Condition": {
                        "StringEquals": {
                            "cognito-identity.amazonaws.com:aud": identity_pool_id
                        },
                        "ForAnyValue:StringLike": {
                            "cognito-identity.amazonaws.com:amr": "authenticated"
                        }
                    }
                }
            ]
        }

        auth_role_response = self.iam.create_role(
            RoleName=auth_role_name,
            AssumeRolePolicyDocument=json.dumps(auth_trust_policy)
        )

        # Create authenticated user policy
        auth_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": [
                        "s3:GetObject",
                        "s3:PutObject"
                    ],
                    "Resource": [
                        f"arn:aws:s3:::user-data/${{cognito-identity.amazonaws.com:sub}}/*"
                    ]
                },
                {
                    "Effect": "Allow",
                    "Action": [
                        "lambda:InvokeFunction"
                    ],
                    "Resource": [
                        "arn:aws:lambda:*:*:function:user-*"
                    ]
                }
            ]
        }

        auth_policy_response = self.iam.create_policy(
            PolicyName=f"{auth_role_name}-policy",
            PolicyDocument=json.dumps(auth_policy)
        )

        self.iam.attach_role_policy(
            RoleName=auth_role_name,
            PolicyArn=auth_policy_response['Policy']['Arn']
        )

        # Set identity pool roles
        self.cognito_identity.set_identity_pool_roles(
            IdentityPoolId=identity_pool_id,
            Roles={
                'authenticated': auth_role_response['Role']['Arn']
            }
        )

        return {
            'identity_pool_id': identity_pool_id,
            'authenticated_role_arn': auth_role_response['Role']['Arn']
        }

    def setup_oidc_provider(self, provider_url: str, client_ids: list):
        """Setup OpenID Connect provider"""

        # Get thumbprint for OIDC provider
        import ssl
        import socket
        from urllib.parse import urlparse

        parsed_url = urlparse(provider_url)
        hostname = parsed_url.hostname
        port = parsed_url.port or 443

        # Get certificate thumbprint
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port)) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert(binary_form=True)
                thumbprint = ssl.DER_cert_to_PEM_cert(cert)

        import hashlib
        thumbprint_sha1 = hashlib.sha1(cert).hexdigest().upper()

        # Create OIDC provider
        oidc_provider_response = self.iam.create_open_id_connect_provider(
            Url=provider_url,
            ClientIDList=client_ids,
            ThumbprintList=[thumbprint_sha1]
        )

        provider_arn = oidc_provider_response['OpenIDConnectProviderArn']

        # Create role for OIDC users
        oidc_role_name = "github-actions-role"

        oidc_trust_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {
                        "Federated": provider_arn
                    },
                    "Action": "sts:AssumeRoleWithWebIdentity",
                    "Condition": {
                        "StringLike": {
                            "token.actions.githubusercontent.com:sub": "repo:myorg/myrepo:*"
                        },
                        "StringEquals": {
                            "token.actions.githubusercontent.com:aud": "sts.amazonaws.com"
                        }
                    }
                }
            ]
        }

        oidc_role_response = self.iam.create_role(
            RoleName=oidc_role_name,
            AssumeRolePolicyDocument=json.dumps(oidc_trust_policy)
        )

        return {
            'provider_arn': provider_arn,
            'role_arn': oidc_role_response['Role']['Arn']
        }
```

## Terraform Infrastructure as Code

```hcl
# Terraform configuration for all identity types
terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

# IAM Users for human employees
resource "aws_iam_user" "developers" {
  for_each = toset(["john.doe", "jane.smith", "bob.wilson"])
  name     = each.value

  tags = {
    UserType   = "Human"
    Department = "Engineering"
    JobFunction = "Developer"
  }
}

# IAM Group for developers
resource "aws_iam_group" "developers" {
  name = "developers"
}

# Developer policy
resource "aws_iam_policy" "developer_policy" {
  name        = "DeveloperPolicy"
  description = "Policy for development team"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "ec2:Describe*",
          "ec2:RunInstances",
          "ec2:StopInstances",
          "s3:GetObject",
          "s3:PutObject",
          "lambda:*"
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "aws:RequestedRegion" = ["us-east-1", "us-west-2"]
          }
          StringNotLike = {
            "aws:PrincipalTag/Environment" = "production"
          }
        }
      }
    ]
  })
}

# Attach policy to group
resource "aws_iam_group_policy_attachment" "developer_policy_attachment" {
  group      = aws_iam_group.developers.name
  policy_arn = aws_iam_policy.developer_policy.arn
}

# Add users to group
resource "aws_iam_group_membership" "developers_membership" {
  name = "developers-membership"
  users = [for user in aws_iam_user.developers : user.name]
  group = aws_iam_group.developers.name
}

# Service user for CI/CD
resource "aws_iam_user" "cicd_user" {
  name = "service-cicd"

  tags = {
    UserType = "Service"
    Purpose  = "CI/CD Pipeline"
  }
}

# Access key for service user
resource "aws_iam_access_key" "cicd_key" {
  user = aws_iam_user.cicd_user.name
}

# Lambda execution role
resource "aws_iam_role" "lambda_execution_role" {
  name = "lambda-execution-role"

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

  tags = {
    RoleType = "ServiceRole"
    Service  = "Lambda"
  }
}

# Lambda execution policy
resource "aws_iam_role_policy_attachment" "lambda_basic_execution" {
  role       = aws_iam_role.lambda_execution_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

# Cross-account role
resource "aws_iam_role" "cross_account_role" {
  name = "cross-account-analytics"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          AWS = [
            "arn:aws:iam::123456789012:root"  # Analytics account
          ]
        }
        Condition = {
          StringEquals = {
            "sts:ExternalId" = "analytics-external-id-2024"
          }
          Bool = {
            "aws:MultiFactorAuthPresent" = "true"
          }
        }
      }
    ]
  })

  max_session_duration = 3600  # 1 hour

  tags = {
    RoleType = "CrossAccount"
    Purpose  = "Analytics"
  }
}

# Attach ReadOnly policy to cross-account role
resource "aws_iam_role_policy_attachment" "cross_account_readonly" {
  role       = aws_iam_role.cross_account_role.name
  policy_arn = "arn:aws:iam::aws:policy/ReadOnlyAccess"
}

# SAML Identity Provider
resource "aws_iam_saml_provider" "corporate_saml" {
  name                   = "CorporateAD"
  saml_metadata_document = file("corporate-metadata.xml")
}

# SAML federated role
resource "aws_iam_role" "saml_federated_role" {
  name = "corporate-saml-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRoleWithSAML"
        Effect = "Allow"
        Principal = {
          Federated = aws_iam_saml_provider.corporate_saml.arn
        }
        Condition = {
          StringEquals = {
            "SAML:aud" = "https://signin.aws.amazon.com/saml"
          }
        }
      }
    ]
  })

  max_session_duration = 28800  # 8 hours
}

# OIDC Provider for GitHub Actions
resource "aws_iam_openid_connect_provider" "github_actions" {
  url = "https://token.actions.githubusercontent.com"

  client_id_list = [
    "sts.amazonaws.com"
  ]

  thumbprint_list = [
    "6938fd4d98bab03faadb97b34396831e3780aea1"
  ]
}

# GitHub Actions role
resource "aws_iam_role" "github_actions_role" {
  name = "github-actions-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRoleWithWebIdentity"
        Effect = "Allow"
        Principal = {
          Federated = aws_iam_openid_connect_provider.github_actions.arn
        }
        Condition = {
          StringLike = {
            "token.actions.githubusercontent.com:sub" = "repo:myorg/myrepo:*"
          }
          StringEquals = {
            "token.actions.githubusercontent.com:aud" = "sts.amazonaws.com"
          }
        }
      }
    ]
  })
}

# GitHub Actions deployment policy
resource "aws_iam_policy" "github_actions_policy" {
  name = "GitHubActionsDeploymentPolicy"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject",
          "lambda:UpdateFunctionCode",
          "cloudformation:DescribeStacks",
          "cloudformation:UpdateStack"
        ]
        Resource = [
          "arn:aws:s3:::deployment-bucket/*",
          "arn:aws:lambda:*:*:function:webapp-*",
          "arn:aws:cloudformation:*:*:stack/webapp-*"
        ]
      }
    ]
  })
}

# Attach policy to GitHub Actions role
resource "aws_iam_role_policy_attachment" "github_actions_policy_attachment" {
  role       = aws_iam_role.github_actions_role.name
  policy_arn = aws_iam_policy.github_actions_policy.arn
}

# Cognito User Pool
resource "aws_cognito_user_pool" "main" {
  name = "webapp-user-pool"

  password_policy {
    minimum_length    = 12
    require_lowercase = true
    require_numbers   = true
    require_symbols   = true
    require_uppercase = true
  }

  mfa_configuration = "OPTIONAL"
}

# Cognito User Pool Client
resource "aws_cognito_user_pool_client" "webapp_client" {
  name         = "webapp-client"
  user_pool_id = aws_cognito_user_pool.main.id

  generate_secret = false

  explicit_auth_flows = [
    "ADMIN_NO_SRP_AUTH",
    "USER_PASSWORD_AUTH"
  ]
}

# Cognito Identity Pool
resource "aws_cognito_identity_pool" "main" {
  identity_pool_name      = "webapp_identity_pool"
  allow_unauthenticated_identities = false

  cognito_identity_providers {
    provider_name = aws_cognito_user_pool.main.endpoint
    client_id     = aws_cognito_user_pool_client.webapp_client.id
  }
}

# Cognito authenticated role
resource "aws_iam_role" "cognito_authenticated" {
  name = "cognito_authenticated_role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRoleWithWebIdentity"
        Effect = "Allow"
        Principal = {
          Federated = "cognito-identity.amazonaws.com"
        }
        Condition = {
          StringEquals = {
            "cognito-identity.amazonaws.com:aud" = aws_cognito_identity_pool.main.id
          }
          "ForAnyValue:StringLike" = {
            "cognito-identity.amazonaws.com:amr" = "authenticated"
          }
        }
      }
    ]
  })
}

# Cognito authenticated user policy
resource "aws_iam_policy" "cognito_authenticated_policy" {
  name = "CognitoAuthenticatedPolicy"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject"
        ]
        Resource = [
          "arn:aws:s3:::user-data/$${cognito-identity.amazonaws.com:sub}/*"
        ]
      }
    ]
  })
}

# Attach policy to authenticated role
resource "aws_iam_role_policy_attachment" "cognito_authenticated_policy_attachment" {
  role       = aws_iam_role.cognito_authenticated.name
  policy_arn = aws_iam_policy.cognito_authenticated_policy.arn
}

# Set Identity Pool roles
resource "aws_cognito_identity_pool_roles_attachment" "main" {
  identity_pool_id = aws_cognito_identity_pool.main.id

  roles = {
    "authenticated" = aws_iam_role.cognito_authenticated.arn
  }
}

# Data sources
data "aws_caller_identity" "current" {}

# Outputs
output "iam_users" {
  value = { for user in aws_iam_user.developers : user.name => user.arn }
}

output "service_role_arns" {
  value = {
    lambda_execution = aws_iam_role.lambda_execution_role.arn
    cross_account    = aws_iam_role.cross_account_role.arn
    github_actions   = aws_iam_role.github_actions_role.arn
    cognito_auth     = aws_iam_role.cognito_authenticated.arn
  }
}

output "identity_providers" {
  value = {
    saml_provider_arn = aws_iam_saml_provider.corporate_saml.arn
    oidc_provider_arn = aws_iam_openid_connect_provider.github_actions.arn
    cognito_pool_id   = aws_cognito_identity_pool.main.id
  }
}
```

## Decision Matrix: When to Use Each Identity Type

### IAM Users
**✅ Use When:**
- Individual human employees need AWS access
- Legacy applications requiring long-term credentials
- CI/CD systems that can't use roles
- Third-party services requiring access keys
- Emergency break-glass access scenarios

**❌ Avoid When:**
- Applications running on AWS services (use roles instead)
- Temporary access needs (use roles with STS)
- Large number of external users (use federation)
- Cross-account access (use roles)

### IAM Roles
**✅ Use When:**
- AWS services need permissions (Lambda, EC2, etc.)
- Applications running on AWS infrastructure
- Cross-account access scenarios
- Temporary elevated permissions
- Service-to-service authentication

**❌ Avoid When:**
- Individual human users (use IAM users)
- Long-term external service integration
- Simple legacy system integration
- When external identity integration is needed

### Federated Identities
**✅ Use When:**
- Integrating with existing corporate identity systems
- Web/mobile applications with external users
- Single Sign-On (SSO) requirements
- Large scale user management
- Compliance requirements for identity management

**❌ Avoid When:**
- Simple internal applications
- Direct AWS service access
- Legacy systems without federation support
- When you need permanent credentials

## Real-World Implementation Scenarios

### 1. Enterprise Web Application

```python
# Complete identity architecture for enterprise web app
class EnterpriseIdentityArchitecture:
    def __init__(self):
        self.iam = boto3.client('iam')
        self.cognito_idp = boto3.client('cognito-idp')
        self.federated_manager = FederatedIdentityManager()
        self.role_manager = IAMRoleManager()

    def setup_complete_architecture(self):
        """Setup complete identity architecture"""

        architecture = {}

        # 1. Human Users (Employees)
        # Use SAML federation with corporate AD
        saml_config = self.federated_manager.setup_saml_federation(
            'CorporateAD',
            self._load_saml_metadata()
        )
        architecture['employee_access'] = saml_config

        # 2. Application Roles
        # Lambda functions for API
        api_role = self.role_manager.create_service_role(
            'webapp-api', 'lambda',
            ['dynamodb:*', 'logs:*', 's3:GetObject']
        )

        # Data processing roles
        processor_role = self.role_manager.create_service_role(
            'data-processor', 'lambda',
            ['s3:*', 'dynamodb:*', 'sns:*']
        )

        architecture['application_roles'] = {
            'api_role': api_role,
            'processor_role': processor_role
        }

        # 3. Customer Access (External Users)
        # Cognito for customer authentication
        cognito_config = self.federated_manager.setup_cognito_identity_pool(
            'customer-identity-pool',
            'us-east-1_XXXXXXXXX',  # User Pool ID
            'xxxxxxxxxxxxxxxxxx'     # Client ID
        )
        architecture['customer_access'] = cognito_config

        # 4. Cross-Account Analytics
        analytics_role = self.role_manager.create_cross_account_role(
            'analytics-access',
            ['123456789012'],  # Analytics account
            ['arn:aws:iam::aws:policy/ReadOnlyAccess'],
            'analytics-2024-external-id'
        )
        architecture['cross_account'] = analytics_role

        # 5. CI/CD Pipeline
        # GitHub Actions OIDC
        cicd_config = self.federated_manager.setup_oidc_provider(
            'https://token.actions.githubusercontent.com',
            ['sts.amazonaws.com']
        )
        architecture['cicd_access'] = cicd_config

        return architecture

    def _load_saml_metadata(self) -> str:
        """Load SAML metadata from corporate IdP"""
        # In real implementation, fetch from IdP
        return """<?xml version="1.0"?>
        <EntityDescriptor>
            <!-- SAML metadata content -->
        </EntityDescriptor>"""
```

### 2. Microservices Platform

```python
# Microservices identity patterns
class MicroservicesIdentityPlatform:
    def setup_service_mesh_identity(self):
        """Setup identity for microservices platform"""

        services = [
            {'name': 'user-service', 'permissions': ['dynamodb:*']},
            {'name': 'order-service', 'permissions': ['dynamodb:*', 'sns:*']},
            {'name': 'payment-service', 'permissions': ['dynamodb:*', 'kms:*']},
            {'name': 'notification-service', 'permissions': ['sns:*', 'ses:*']},
            {'name': 'analytics-service', 'permissions': ['s3:*', 'athena:*']}
        ]

        role_manager = IAMRoleManager()
        service_roles = {}

        for service in services:
            # Create service-specific role
            role_arn = role_manager.create_application_role(
                service['name'],
                [f"arn:aws:dynamodb:*:*:table/{service['name']}-*"],
                service['permissions']
            )
            service_roles[service['name']] = role_arn

        return service_roles
```

## Security Comparison

| Security Aspect | IAM Users | IAM Roles | Federated Identities |
|-----------------|-----------|-----------|---------------------|
| **Credential Rotation** | Manual/Automated | Automatic (STS) | Automatic (External IdP) |
| **Session Duration** | Permanent | Time-limited | Configurable |
| **MFA Support** | ✅ Native | ✅ Conditional | ✅ External IdP |
| **Audit Trail** | CloudTrail | CloudTrail | CloudTrail + External |
| **Scalability** | Limited | High | Very High |
| **Complexity** | Low | Medium | High |

## Best Practice Recommendations

### Identity Type Selection Framework

1. **Start with the Questions:**
   - Is this for a human or application?
   - Is this temporary or permanent access?
   - Do you have external identity systems?
   - What's the scale requirement?

2. **Decision Tree:**
   ```
   Human User?
   ├── Yes → Enterprise SSO available?
   │   ├── Yes → Federated Identity (SAML/OIDC)
   │   └── No → IAM User (with MFA)
   └── No → Application?
       ├── AWS Service → IAM Role
       ├── External App → Federated Identity
       └── Legacy System → IAM User (service account)
   ```

3. **Migration Path:**
   - Phase 1: Secure existing IAM users
   - Phase 2: Convert applications to roles
   - Phase 3: Implement federation for humans
   - Phase 4: Remove unnecessary IAM users

## Follow-Up Questions

**Technical Deep Dive:**
- "How would you migrate from IAM users to federated identities?"
- "Describe implementing attribute-based access control (ABAC) with federation"
- "How do you handle identity lifecycle management across all three types?"

**Security Focus:**
- "What are the security implications of each identity type?"
- "How would you implement zero-trust principles with these identity types?"
- "Describe your approach to credential compromise incident response"

**Architecture Design:**
- "Design identity architecture for a multi-tenant SaaS platform"
- "How would you handle identity in a hybrid cloud environment?"
- "What's your strategy for identity governance at enterprise scale?"

## Related Topics
- [IAM Core Components](./01-iam-core-components.md)
- [IAM API Gateway Integration](./02-iam-api-gateway-integration.md)
- [IAM Best Practices](./03-iam-best-practices.md)
- [MFA Implementation](./05-mfa-implementation.md)