# IAM Best Practices

## Question
**What are IAM best practices for permission management and security? Provide examples.**

*Complexity: Medium | Focus Area: Permission management, security*

## Core Answer

IAM best practices focus on implementing the principle of least privilege, securing root accounts, using roles over users for applications, enabling strong authentication, and maintaining proper governance through monitoring and regular audits.

### Key Best Practice Categories

**1. Access Management**
- Principle of least privilege
- Role-based access control (RBAC)
- Just-in-time access patterns
- Regular access reviews and cleanup

**2. Authentication & Authorization**
- Multi-factor authentication (MFA)
- Strong password policies
- Temporary credentials via STS
- Federated access where appropriate

**3. Monitoring & Governance**
- CloudTrail logging
- Access Analyzer findings
- Policy simulation and testing
- Automated compliance checks

## Technical Implementation

### 1. Least Privilege Implementation

```python
# Python implementation of least privilege IAM policies
import boto3
import json
from datetime import datetime, timedelta

class LeastPrivilegeIAM:
    def __init__(self):
        self.iam = boto3.client('iam')
        self.sts = boto3.client('sts')

    def create_least_privilege_policy(self, user_role: str, required_actions: list, resources: list):
        """Create policy with minimal required permissions"""

        policy_document = {
            "Version": "2012-10-17",
            "Statement": []
        }

        # Group actions by service for better organization
        actions_by_service = {}
        for action in required_actions:
            service = action.split(':')[0]
            if service not in actions_by_service:
                actions_by_service[service] = []
            actions_by_service[service].append(action)

        # Create separate statements for each service
        for service, actions in actions_by_service.items():
            # Filter resources relevant to this service
            service_resources = [r for r in resources if f":{service}:" in r or r == "*"]

            statement = {
                "Effect": "Allow",
                "Action": actions,
                "Resource": service_resources if service_resources else f"arn:aws:{service}:*:*:*"
            }

            # Add conditions based on role requirements
            conditions = self._get_role_conditions(user_role)
            if conditions:
                statement["Condition"] = conditions

            policy_document["Statement"].append(statement)

        return policy_document

    def _get_role_conditions(self, role: str) -> dict:
        """Get appropriate conditions based on role"""

        conditions = {}

        if role == 'developer':
            conditions = {
                # Restrict to development resources
                "StringEquals": {
                    "aws:RequestedRegion": ["us-east-1", "us-west-2"]
                },
                "StringLike": {
                    "aws:userid": "*:${aws:username}"
                },
                # Prevent production resource access
                "ForAllValues:StringNotLike": {
                    "aws:PrincipalTag/Environment": "production"
                }
            }
        elif role == 'analyst':
            conditions = {
                # Read-only access during business hours
                "DateGreaterThan": {
                    "aws:CurrentTime": "08:00Z"
                },
                "DateLessThan": {
                    "aws:CurrentTime": "18:00Z"
                },
                "IpAddress": {
                    "aws:SourceIp": "203.0.113.0/24"  # Office IP range
                }
            }
        elif role == 'admin':
            conditions = {
                # Require MFA for admin actions
                "Bool": {
                    "aws:MultiFactorAuthPresent": "true"
                },
                "NumericLessThan": {
                    "aws:MultiFactorAuthAge": "3600"
                }
            }

        return conditions

    def implement_resource_tagging_strategy(self, resource_arn: str, environment: str, owner: str, project: str):
        """Implement comprehensive resource tagging for access control"""

        tags = [
            {'Key': 'Environment', 'Value': environment},
            {'Key': 'Owner', 'Value': owner},
            {'Key': 'Project', 'Value': project},
            {'Key': 'CreatedBy', 'Value': 'IAMBestPractices'},
            {'Key': 'CreatedDate', 'Value': datetime.utcnow().isoformat()}
        ]

        # Tag-based access control policy
        tag_based_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "*",
                    "Resource": "*",
                    "Condition": {
                        "StringEquals": {
                            "aws:PrincipalTag/Department": "${aws:ResourceTag/Department}",
                            "aws:PrincipalTag/Environment": "${aws:ResourceTag/Environment}"
                        }
                    }
                },
                {
                    "Effect": "Deny",
                    "Action": [
                        "ec2:TerminateInstances",
                        "rds:DeleteDBInstance",
                        "s3:DeleteBucket"
                    ],
                    "Resource": "*",
                    "Condition": {
                        "StringEquals": {
                            "aws:ResourceTag/Environment": "production"
                        },
                        "StringNotEquals": {
                            "aws:PrincipalTag/Role": "admin"
                        }
                    }
                }
            ]
        }

        return tags, tag_based_policy

# Usage example
def setup_developer_environment():
    """Setup IAM for development team with best practices"""

    iam_manager = LeastPrivilegeIAM()

    # Define minimal required actions for developers
    developer_actions = [
        'ec2:DescribeInstances',
        'ec2:RunInstances',
        'ec2:StopInstances',
        's3:GetObject',
        's3:PutObject',
        'lambda:CreateFunction',
        'lambda:UpdateFunctionCode',
        'lambda:InvokeFunction',
        'logs:CreateLogGroup',
        'logs:PutLogEvents'
    ]

    # Define development resources
    dev_resources = [
        'arn:aws:ec2:*:*:instance/*',
        'arn:aws:s3:::dev-*/*',
        'arn:aws:lambda:*:*:function:dev-*',
        'arn:aws:logs:*:*:log-group:dev-*'
    ]

    # Create least privilege policy
    policy = iam_manager.create_least_privilege_policy(
        'developer', developer_actions, dev_resources
    )

    print(json.dumps(policy, indent=2))
```

### 2. MFA and Strong Authentication

```python
# Comprehensive MFA implementation
class MFABestPractices:
    def __init__(self):
        self.iam = boto3.client('iam')

    def enforce_mfa_policy(self):
        """Create policy requiring MFA for sensitive operations"""

        mfa_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "AllowViewAccountInfo",
                    "Effect": "Allow",
                    "Action": [
                        "iam:GetAccountPasswordPolicy",
                        "iam:GetAccountSummary",
                        "iam:ListVirtualMFADevices"
                    ],
                    "Resource": "*"
                },
                {
                    "Sid": "AllowManageOwnPasswords",
                    "Effect": "Allow",
                    "Action": [
                        "iam:ChangePassword",
                        "iam:GetUser"
                    ],
                    "Resource": "arn:aws:iam::*:user/${aws:username}"
                },
                {
                    "Sid": "AllowManageOwnMFA",
                    "Effect": "Allow",
                    "Action": [
                        "iam:CreateVirtualMFADevice",
                        "iam:DeleteVirtualMFADevice",
                        "iam:EnableMFADevice",
                        "iam:ListMFADevices",
                        "iam:ResyncMFADevice"
                    ],
                    "Resource": [
                        "arn:aws:iam::*:mfa/${aws:username}",
                        "arn:aws:iam::*:user/${aws:username}"
                    ]
                },
                {
                    "Sid": "DenyAllExceptUnlessSignedInWithMFA",
                    "Effect": "Deny",
                    "NotAction": [
                        "iam:CreateVirtualMFADevice",
                        "iam:EnableMFADevice",
                        "iam:GetUser",
                        "iam:ListMFADevices",
                        "iam:ListVirtualMFADevices",
                        "iam:ResyncMFADevice",
                        "sts:GetSessionToken"
                    ],
                    "Resource": "*",
                    "Condition": {
                        "BoolIfExists": {
                            "aws:MultiFactorAuthPresent": "false"
                        }
                    }
                }
            ]
        }

        return mfa_policy

    def setup_virtual_mfa_device(self, username: str):
        """Setup virtual MFA device for user"""

        try:
            # Create virtual MFA device
            response = self.iam.create_virtual_mfa_device(
                VirtualMFADeviceName=f"{username}-mfa"
            )

            # Return QR code data for user setup
            return {
                'serial_number': response['VirtualMFADevice']['SerialNumber'],
                'qr_code_png': response['VirtualMFADevice']['QRCodePNG'],
                'seed': response['VirtualMFADevice']['Base32StringSeed']
            }

        except Exception as e:
            print(f"Error creating MFA device: {str(e)}")
            return None

    def enable_mfa_device(self, username: str, serial_number: str, auth_code1: str, auth_code2: str):
        """Enable MFA device with authentication codes"""

        try:
            self.iam.enable_mfa_device(
                UserName=username,
                SerialNumber=serial_number,
                AuthenticationCode1=auth_code1,
                AuthenticationCode2=auth_code2
            )
            return True
        except Exception as e:
            print(f"Error enabling MFA device: {str(e)}")
            return False
```

### 3. Role-Based Access Control (RBAC)

```python
# Advanced RBAC implementation
class RBACImplementation:
    def __init__(self):
        self.iam = boto3.client('iam')

    def create_rbac_structure(self):
        """Create comprehensive RBAC structure"""

        roles_config = {
            'SecurityAdmin': {
                'description': 'Security administration role',
                'max_duration': 3600,  # 1 hour
                'policies': ['security-admin-policy'],
                'trusted_entities': ['arn:aws:iam::ACCOUNT-ID:group/security-team']
            },
            'DatabaseAdmin': {
                'description': 'Database administration role',
                'max_duration': 7200,  # 2 hours
                'policies': ['database-admin-policy'],
                'trusted_entities': ['arn:aws:iam::ACCOUNT-ID:group/database-team']
            },
            'ReadOnlyAnalyst': {
                'description': 'Read-only access for analysts',
                'max_duration': 28800,  # 8 hours
                'policies': ['analyst-readonly-policy'],
                'trusted_entities': ['arn:aws:iam::ACCOUNT-ID:group/analyst-team']
            },
            'IncidentResponder': {
                'description': 'Emergency incident response role',
                'max_duration': 1800,  # 30 minutes
                'policies': ['incident-response-policy'],
                'trusted_entities': ['arn:aws:iam::ACCOUNT-ID:group/security-team']
            }
        }

        created_roles = {}

        for role_name, config in roles_config.items():
            # Create trust policy
            trust_policy = {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {
                            "AWS": config['trusted_entities']
                        },
                        "Action": "sts:AssumeRole",
                        "Condition": {
                            "Bool": {
                                "aws:MultiFactorAuthPresent": "true"
                            },
                            "NumericLessThan": {
                                "aws:MultiFactorAuthAge": "300"  # MFA within 5 minutes
                            }
                        }
                    }
                ]
            }

            # Create role
            role_response = self.iam.create_role(
                RoleName=role_name,
                AssumeRolePolicyDocument=json.dumps(trust_policy),
                Description=config['description'],
                MaxSessionDuration=config['max_duration']
            )

            created_roles[role_name] = role_response['Role']['Arn']

            # Attach policies
            for policy_name in config['policies']:
                self._create_and_attach_policy(role_name, policy_name)

        return created_roles

    def _create_and_attach_policy(self, role_name: str, policy_name: str):
        """Create and attach role-specific policies"""

        policies = {
            'security-admin-policy': {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": [
                            "iam:*",
                            "organizations:*",
                            "account:*"
                        ],
                        "Resource": "*"
                    },
                    {
                        "Effect": "Deny",
                        "Action": [
                            "iam:DeleteRole",
                            "iam:DeleteUser"
                        ],
                        "Resource": "*",
                        "Condition": {
                            "StringNotEquals": {
                                "aws:RequestedRegion": "us-east-1"
                            }
                        }
                    }
                ]
            },
            'database-admin-policy': {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": [
                            "rds:*",
                            "dynamodb:*",
                            "elasticache:*"
                        ],
                        "Resource": "*"
                    },
                    {
                        "Effect": "Deny",
                        "Action": [
                            "rds:DeleteDBInstance",
                            "dynamodb:DeleteTable"
                        ],
                        "Resource": "*",
                        "Condition": {
                            "StringEquals": {
                                "aws:ResourceTag/Environment": "production"
                            }
                        }
                    }
                ]
            },
            'analyst-readonly-policy': {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": [
                            "s3:GetObject",
                            "s3:ListBucket",
                            "athena:*",
                            "quicksight:*",
                            "cloudwatch:Get*",
                            "cloudwatch:List*",
                            "cloudwatch:Describe*"
                        ],
                        "Resource": "*"
                    }
                ]
            },
            'incident-response-policy': {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": [
                            "ec2:DescribeInstances",
                            "ec2:StopInstances",
                            "ec2:TerminateInstances",
                            "s3:GetObject",
                            "s3:PutObject",
                            "logs:*",
                            "cloudtrail:*"
                        ],
                        "Resource": "*"
                    }
                ]
            }
        }

        if policy_name in policies:
            # Create policy
            policy_response = self.iam.create_policy(
                PolicyName=policy_name,
                PolicyDocument=json.dumps(policies[policy_name]),
                Description=f'Policy for {role_name}'
            )

            # Attach policy to role
            self.iam.attach_role_policy(
                RoleName=role_name,
                PolicyArn=policy_response['Policy']['Arn']
            )
```

### 4. Access Review and Compliance Automation

```python
# Automated compliance and access review system
class IAMComplianceMonitor:
    def __init__(self):
        self.iam = boto3.client('iam')
        self.accessanalyzer = boto3.client('accessanalyzer')
        self.organizations = boto3.client('organizations')

    def perform_access_review(self) -> dict:
        """Comprehensive IAM access review"""

        review_results = {
            'unused_credentials': [],
            'overprivileged_users': [],
            'missing_mfa': [],
            'old_access_keys': [],
            'external_access': []
        }

        # Check for unused credentials
        review_results['unused_credentials'] = self._find_unused_credentials()

        # Check for overprivileged users
        review_results['overprivileged_users'] = self._find_overprivileged_users()

        # Check for users without MFA
        review_results['missing_mfa'] = self._find_users_without_mfa()

        # Check for old access keys
        review_results['old_access_keys'] = self._find_old_access_keys()

        # Check for external access using Access Analyzer
        review_results['external_access'] = self._find_external_access()

        return review_results

    def _find_unused_credentials(self, days_threshold: int = 90) -> list:
        """Find credentials not used in specified days"""

        unused_credentials = []
        threshold_date = datetime.utcnow() - timedelta(days=days_threshold)

        # Get credential report
        try:
            self.iam.generate_credential_report()
            # Wait for report generation
            import time
            time.sleep(10)

            response = self.iam.get_credential_report()
            report_content = response['Content'].decode('utf-8')

            for line in report_content.split('\n')[1:]:  # Skip header
                if not line:
                    continue

                fields = line.split(',')
                username = fields[0]
                password_last_used = fields[4]
                access_key_1_last_used = fields[10]
                access_key_2_last_used = fields[15]

                # Check password usage
                if password_last_used and password_last_used != 'N/A':
                    last_used = datetime.strptime(password_last_used, '%Y-%m-%dT%H:%M:%S+00:00')
                    if last_used < threshold_date:
                        unused_credentials.append({
                            'username': username,
                            'credential_type': 'password',
                            'last_used': password_last_used
                        })

                # Check access keys
                for key_field, key_name in [(access_key_1_last_used, 'access_key_1'),
                                           (access_key_2_last_used, 'access_key_2')]:
                    if key_field and key_field != 'N/A':
                        last_used = datetime.strptime(key_field, '%Y-%m-%dT%H:%M:%S+00:00')
                        if last_used < threshold_date:
                            unused_credentials.append({
                                'username': username,
                                'credential_type': key_name,
                                'last_used': key_field
                            })

        except Exception as e:
            print(f"Error generating credential report: {str(e)}")

        return unused_credentials

    def _find_overprivileged_users(self) -> list:
        """Find users with excessive privileges"""

        overprivileged_users = []

        # Get all users
        paginator = self.iam.get_paginator('list_users')

        for page in paginator.paginate():
            for user in page['Users']:
                username = user['UserName']

                # Get user policies
                user_policies = self.iam.list_attached_user_policies(UserName=username)
                inline_policies = self.iam.list_user_policies(UserName=username)

                # Check for administrative policies
                admin_policies = ['AdministratorAccess', 'PowerUserAccess']
                for policy in user_policies['AttachedPolicies']:
                    if policy['PolicyName'] in admin_policies:
                        overprivileged_users.append({
                            'username': username,
                            'policy': policy['PolicyName'],
                            'type': 'managed'
                        })

                # Check inline policies for wildcard permissions
                for policy_name in inline_policies['PolicyNames']:
                    policy_doc = self.iam.get_user_policy(
                        UserName=username,
                        PolicyName=policy_name
                    )

                    if self._has_wildcard_permissions(policy_doc['PolicyDocument']):
                        overprivileged_users.append({
                            'username': username,
                            'policy': policy_name,
                            'type': 'inline',
                            'issue': 'wildcard_permissions'
                        })

        return overprivileged_users

    def _has_wildcard_permissions(self, policy_document: dict) -> bool:
        """Check if policy has wildcard permissions"""

        for statement in policy_document.get('Statement', []):
            if statement.get('Effect') == 'Allow':
                actions = statement.get('Action', [])
                resources = statement.get('Resource', [])

                if isinstance(actions, str):
                    actions = [actions]
                if isinstance(resources, str):
                    resources = [resources]

                # Check for wildcard actions or resources
                if '*' in actions or '*' in resources:
                    return True

        return False

    def _find_users_without_mfa(self) -> list:
        """Find users without MFA enabled"""

        users_without_mfa = []
        paginator = self.iam.get_paginator('list_users')

        for page in paginator.paginate():
            for user in page['Users']:
                username = user['UserName']

                # Check MFA devices
                mfa_devices = self.iam.list_mfa_devices(UserName=username)

                if not mfa_devices['MFADevices']:
                    users_without_mfa.append({
                        'username': username,
                        'created_date': user['CreateDate'].isoformat()
                    })

        return users_without_mfa

    def _find_old_access_keys(self, days_threshold: int = 90) -> list:
        """Find access keys older than threshold"""

        old_access_keys = []
        threshold_date = datetime.utcnow() - timedelta(days=days_threshold)

        paginator = self.iam.get_paginator('list_users')

        for page in paginator.paginate():
            for user in page['Users']:
                username = user['UserName']

                # Get access keys
                access_keys = self.iam.list_access_keys(UserName=username)

                for key in access_keys['AccessKeyMetadata']:
                    if key['CreateDate'].replace(tzinfo=None) < threshold_date:
                        old_access_keys.append({
                            'username': username,
                            'access_key_id': key['AccessKeyId'],
                            'created_date': key['CreateDate'].isoformat(),
                            'status': key['Status']
                        })

        return old_access_keys

    def _find_external_access(self) -> list:
        """Find resources with external access using Access Analyzer"""

        external_access = []

        try:
            # List analyzers
            analyzers = self.accessanalyzer.list_analyzers()

            for analyzer in analyzers['analyzers']:
                if analyzer['status'] == 'ACTIVE':
                    # Get findings
                    findings = self.accessanalyzer.list_findings(
                        analyzerArn=analyzer['arn']
                    )

                    for finding in findings['findings']:
                        if finding['status'] == 'ACTIVE':
                            external_access.append({
                                'resource': finding['resource'],
                                'resource_type': finding['resourceType'],
                                'principal': finding.get('principal', {}),
                                'action': finding.get('action', []),
                                'condition': finding.get('condition', {}),
                                'created_at': finding['createdAt'].isoformat()
                            })

        except Exception as e:
            print(f"Error getting Access Analyzer findings: {str(e)}")

        return external_access

    def generate_compliance_report(self, review_results: dict) -> str:
        """Generate comprehensive compliance report"""

        report = f"""
# IAM Compliance Review Report
Generated: {datetime.utcnow().isoformat()}

## Executive Summary
- Unused Credentials: {len(review_results['unused_credentials'])}
- Overprivileged Users: {len(review_results['overprivileged_users'])}
- Users without MFA: {len(review_results['missing_mfa'])}
- Old Access Keys: {len(review_results['old_access_keys'])}
- External Access Findings: {len(review_results['external_access'])}

## Detailed Findings

### Unused Credentials ({len(review_results['unused_credentials'])})
"""

        for cred in review_results['unused_credentials']:
            report += f"- {cred['username']}: {cred['credential_type']} last used {cred['last_used']}\n"

        report += f"\n### Overprivileged Users ({len(review_results['overprivileged_users'])})\n"
        for user in review_results['overprivileged_users']:
            report += f"- {user['username']}: {user['policy']} ({user['type']})\n"

        report += f"\n### Users without MFA ({len(review_results['missing_mfa'])})\n"
        for user in review_results['missing_mfa']:
            report += f"- {user['username']}: Created {user['created_date']}\n"

        report += "\n## Recommendations\n"
        report += "1. Remove or rotate unused credentials\n"
        report += "2. Review and reduce overprivileged user permissions\n"
        report += "3. Enforce MFA for all users\n"
        report += "4. Implement regular access key rotation\n"
        report += "5. Review external access findings\n"

        return report
```

## Terraform Infrastructure as Code

```hcl
# Terraform configuration for IAM best practices
terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

# Password policy enforcement
resource "aws_iam_account_password_policy" "strict_password_policy" {
  minimum_password_length        = 14
  require_lowercase_characters   = true
  require_uppercase_characters   = true
  require_numbers               = true
  require_symbols              = true
  allow_users_to_change_password = true
  max_password_age             = 90
  password_reuse_prevention    = 12
  hard_expiry                  = false
}

# Security group for MFA enforcement
resource "aws_iam_group" "require_mfa_group" {
  name = "require-mfa"
  path = "/"
}

# MFA enforcement policy
resource "aws_iam_policy" "require_mfa_policy" {
  name        = "RequireMFAPolicy"
  description = "Policy that requires MFA for all actions"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowViewAccountInfo"
        Effect = "Allow"
        Action = [
          "iam:GetAccountPasswordPolicy",
          "iam:GetAccountSummary",
          "iam:ListVirtualMFADevices"
        ]
        Resource = "*"
      },
      {
        Sid    = "AllowManageOwnPasswords"
        Effect = "Allow"
        Action = [
          "iam:ChangePassword",
          "iam:GetUser"
        ]
        Resource = "arn:aws:iam::*:user/$${aws:username}"
      },
      {
        Sid    = "AllowManageOwnMFA"
        Effect = "Allow"
        Action = [
          "iam:CreateVirtualMFADevice",
          "iam:DeleteVirtualMFADevice",
          "iam:EnableMFADevice",
          "iam:ListMFADevices",
          "iam:ResyncMFADevice"
        ]
        Resource = [
          "arn:aws:iam::*:mfa/$${aws:username}",
          "arn:aws:iam::*:user/$${aws:username}"
        ]
      },
      {
        Sid       = "DenyAllExceptUnlessSignedInWithMFA"
        Effect    = "Deny"
        NotAction = [
          "iam:CreateVirtualMFADevice",
          "iam:EnableMFADevice",
          "iam:GetUser",
          "iam:ListMFADevices",
          "iam:ListVirtualMFADevices",
          "iam:ResyncMFADevice",
          "sts:GetSessionToken"
        ]
        Resource = "*"
        Condition = {
          BoolIfExists = {
            "aws:MultiFactorAuthPresent" = "false"
          }
        }
      }
    ]
  })
}

# Attach MFA policy to group
resource "aws_iam_group_policy_attachment" "require_mfa_attachment" {
  group      = aws_iam_group.require_mfa_group.name
  policy_arn = aws_iam_policy.require_mfa_policy.arn
}

# Role for emergency access (break-glass)
resource "aws_iam_role" "emergency_access_role" {
  name = "EmergencyAccess"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          AWS = [
            "arn:aws:iam::${data.aws_caller_identity.current.account_id}:user/emergency-user-1",
            "arn:aws:iam::${data.aws_caller_identity.current.account_id}:user/emergency-user-2"
          ]
        }
        Condition = {
          Bool = {
            "aws:MultiFactorAuthPresent" = "true"
          }
          NumericLessThan = {
            "aws:MultiFactorAuthAge" = "300"
          }
        }
      }
    ]
  })

  max_session_duration = 3600  # 1 hour
}

# Emergency access policy
resource "aws_iam_policy" "emergency_access_policy" {
  name        = "EmergencyAccessPolicy"
  description = "Emergency access policy with time restrictions"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = "*"
        Resource = "*"
        Condition = {
          DateGreaterThan = {
            "aws:CurrentTime" = "2024-01-01T00:00:00Z"
          }
          DateLessThan = {
            "aws:CurrentTime" = "2025-12-31T23:59:59Z"
          }
        }
      }
    ]
  })
}

# Attach emergency policy to role
resource "aws_iam_role_policy_attachment" "emergency_access_attachment" {
  role       = aws_iam_role.emergency_access_role.name
  policy_arn = aws_iam_policy.emergency_access_policy.arn
}

# Access Analyzer for external access detection
resource "aws_accessanalyzer_analyzer" "account_analyzer" {
  analyzer_name = "account-analyzer"
  type         = "ACCOUNT"

  tags = {
    Name        = "Account Access Analyzer"
    Purpose     = "External access detection"
    Environment = "security"
  }
}

# CloudTrail for IAM monitoring
resource "aws_cloudtrail" "iam_monitoring" {
  name           = "iam-monitoring-trail"
  s3_bucket_name = aws_s3_bucket.cloudtrail_bucket.bucket

  event_selector {
    read_write_type                 = "All"
    include_management_events       = true
    exclude_management_event_sources = []

    data_resource {
      type   = "AWS::S3::Object"
      values = ["arn:aws:s3:::iam-policy-*/*"]
    }
  }

  depends_on = [aws_s3_bucket_policy.cloudtrail_bucket_policy]
}

# S3 bucket for CloudTrail logs
resource "aws_s3_bucket" "cloudtrail_bucket" {
  bucket        = "iam-monitoring-cloudtrail-${random_string.bucket_suffix.result}"
  force_destroy = true
}

resource "aws_s3_bucket_policy" "cloudtrail_bucket_policy" {
  bucket = aws_s3_bucket.cloudtrail_bucket.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AWSCloudTrailAclCheck"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action   = "s3:GetBucketAcl"
        Resource = aws_s3_bucket.cloudtrail_bucket.arn
      },
      {
        Sid    = "AWSCloudTrailWrite"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action   = "s3:PutObject"
        Resource = "${aws_s3_bucket.cloudtrail_bucket.arn}/*"
        Condition = {
          StringEquals = {
            "s3:x-amz-acl" = "bucket-owner-full-control"
          }
        }
      }
    ]
  })
}

# Random string for unique bucket names
resource "random_string" "bucket_suffix" {
  length  = 8
  special = false
  upper   = false
}

# Data sources
data "aws_caller_identity" "current" {}

# Outputs
output "mfa_group_name" {
  value = aws_iam_group.require_mfa_group.name
}

output "emergency_role_arn" {
  value = aws_iam_role.emergency_access_role.arn
}

output "access_analyzer_arn" {
  value = aws_accessanalyzer_analyzer.account_analyzer.arn
}
```

## Real-World Implementation Examples

### 1. Enterprise Multi-Account Setup

```python
# Multi-account IAM best practices implementation
class MultiAccountIAM:
    def __init__(self):
        self.organizations = boto3.client('organizations')
        self.iam = boto3.client('iam')

    def setup_organization_scp(self):
        """Implement Service Control Policies for organization"""

        # Deny policy for production account protection
        production_deny_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "DenyProductionTermination",
                    "Effect": "Deny",
                    "Action": [
                        "ec2:TerminateInstances",
                        "rds:DeleteDBInstance",
                        "s3:DeleteBucket"
                    ],
                    "Resource": "*",
                    "Condition": {
                        "StringNotEquals": {
                            "aws:PrincipalTag/Role": "admin"
                        }
                    }
                },
                {
                    "Sid": "DenyRootUserActions",
                    "Effect": "Deny",
                    "Action": "*",
                    "Resource": "*",
                    "Condition": {
                        "StringEquals": {
                            "aws:PrincipalType": "Root"
                        }
                    }
                }
            ]
        }

        # Create SCP
        scp_response = self.organizations.create_policy(
            Name='ProductionAccountProtection',
            Description='Protect production resources from accidental deletion',
            Type='SERVICE_CONTROL_POLICY',
            Content=json.dumps(production_deny_policy)
        )

        return scp_response['Policy']['PolicyId']

    def create_cross_account_roles(self, trusted_accounts: list):
        """Create cross-account access roles"""

        roles = {
            'ReadOnlyAccess': {
                'policy_arn': 'arn:aws:iam::aws:policy/ReadOnlyAccess',
                'max_duration': 3600
            },
            'PowerUserAccess': {
                'policy_arn': 'arn:aws:iam::aws:policy/PowerUserAccess',
                'max_duration': 7200
            },
            'SecurityAudit': {
                'policy_arn': 'arn:aws:iam::aws:policy/SecurityAudit',
                'max_duration': 3600
            }
        }

        for role_name, config in roles.items():
            trust_policy = {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {
                            "AWS": [f"arn:aws:iam::{account}:root" for account in trusted_accounts]
                        },
                        "Action": "sts:AssumeRole",
                        "Condition": {
                            "Bool": {
                                "aws:MultiFactorAuthPresent": "true"
                            },
                            "StringEquals": {
                                "sts:ExternalId": f"{role_name}-external-id"
                            }
                        }
                    }
                ]
            }

            self.iam.create_role(
                RoleName=f"CrossAccount{role_name}",
                AssumeRolePolicyDocument=json.dumps(trust_policy),
                MaxSessionDuration=config['max_duration']
            )

            self.iam.attach_role_policy(
                RoleName=f"CrossAccount{role_name}",
                PolicyArn=config['policy_arn']
            )
```

### 2. DevOps Team Permissions

```python
# DevOps team IAM setup with time-based restrictions
class DevOpsTeamIAM:
    def __init__(self):
        self.iam = boto3.client('iam')

    def create_devops_structure(self):
        """Create DevOps team IAM structure"""

        # Create DevOps group
        self.iam.create_group(GroupName='DevOps')

        # Time-restricted deployment policy
        deployment_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": [
                        "ec2:*",
                        "ecs:*",
                        "lambda:*",
                        "apigateway:*",
                        "cloudformation:*"
                    ],
                    "Resource": "*",
                    "Condition": {
                        "DateGreaterThan": {
                            "aws:CurrentTime": "08:00Z"
                        },
                        "DateLessThan": {
                            "aws:CurrentTime": "18:00Z"
                        },
                        "StringEquals": {
                            "aws:RequestedRegion": ["us-east-1", "us-west-2"]
                        }
                    }
                },
                {
                    "Effect": "Deny",
                    "Action": [
                        "ec2:TerminateInstances",
                        "rds:DeleteDBInstance"
                    ],
                    "Resource": "*",
                    "Condition": {
                        "StringEquals": {
                            "aws:ResourceTag/Environment": "production"
                        }
                    }
                }
            ]
        }

        # Create and attach policy
        policy_response = self.iam.create_policy(
            PolicyName='DevOpsDeploymentPolicy',
            PolicyDocument=json.dumps(deployment_policy)
        )

        self.iam.attach_group_policy(
            GroupName='DevOps',
            PolicyArn=policy_response['Policy']['Arn']
        )
```

## Security Best Practice Checklist

### Access Management
- ✅ Implement least privilege access
- ✅ Use roles instead of users for applications
- ✅ Regular access reviews (quarterly)
- ✅ Automated unused credential detection
- ✅ Time-bounded sessions for sensitive operations

### Authentication & Authorization
- ✅ Enforce MFA for all users
- ✅ Strong password policies
- ✅ Regular credential rotation
- ✅ Use temporary credentials via STS
- ✅ Implement role-based access control

### Monitoring & Governance
- ✅ Enable CloudTrail for all accounts
- ✅ Use Access Analyzer for external access detection
- ✅ Monitor failed authentication attempts
- ✅ Automated policy compliance checks
- ✅ Regular penetration testing

## Common Pitfalls and Solutions

### 1. Over-Permissive Policies
**Problem:** Granting `*` permissions for convenience
**Solution:** Use AWS Policy Simulator to test minimal permissions

### 2. Shared Credentials
**Problem:** Multiple users sharing access keys
**Solution:** Individual IAM users with unique credentials

### 3. Hardcoded Credentials
**Problem:** Access keys in application code
**Solution:** Use IAM roles and instance profiles

### 4. Missing MFA
**Problem:** Administrative access without MFA
**Solution:** Conditional policies requiring MFA

### 5. Stale Permissions
**Problem:** Accumulating unused permissions over time
**Solution:** Regular access reviews and automated cleanup

## Follow-Up Questions

**Technical Deep Dive:**
- "How would you implement just-in-time access for AWS resources?"
- "Describe your approach to IAM policy testing and validation"
- "How do you handle IAM at scale across multiple AWS accounts?"

**Security Focus:**
- "What IAM controls would you implement for SOC 2 compliance?"
- "How would you detect and respond to privilege escalation attempts?"
- "Describe your strategy for emergency access (break-glass) procedures"

**Architecture Design:**
- "Design IAM structure for a microservices architecture"
- "How would you integrate IAM with existing identity providers?"
- "What's your approach to IAM governance in a multi-cloud environment?"

## Related Topics
- [IAM Core Components](./01-iam-core-components.md)
- [IAM API Gateway Integration](./02-iam-api-gateway-integration.md)
- [IAM Identity Types](./04-iam-identity-types.md)
- [MFA Implementation](./05-mfa-implementation.md)