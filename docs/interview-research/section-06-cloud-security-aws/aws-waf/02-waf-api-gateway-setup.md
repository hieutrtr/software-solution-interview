# Setting Up AWS WAF for API Gateway or CloudFront

## Original Question
> **How do you set up WAF for API Gateway or CloudFront?**

## Core Concepts

### Key Definitions
- **Web ACL (Web Access Control List)**: The fundamental WAF resource. It's a container for a collection of rules that you want to apply to your protected AWS resource.
- **Rule**: A specific condition that WAF inspects for in web requests. Examples include checking for malicious SQL code, matching an IP address, or checking the request's country of origin.
- **Rule Group**: A reusable set of rules. AWS provides and maintains **Managed Rule Groups** for common threats, which is the easiest way to get started.
- **Association**: The action of linking a Web ACL to a specific AWS resource, such as a CloudFront distribution, an Application Load Balancer, or an API Gateway stage.

### Fundamental Principles
- **Scope is Critical**: The most important concept to understand is the **scope** of the Web ACL. 
    - **`CLOUDFRONT`**: For protecting CloudFront distributions. These Web ACLs must be created in the **US East (N. Virginia) `us-east-1`** region, regardless of where your other resources are.
    - **`REGIONAL`**: For protecting regional resources like ALBs and API Gateways. These Web ACLs must be created in the **same region** as the resource you want to protect.
- **Layered Protection**: For maximum security, it is a best practice to associate a WAF with a CloudFront distribution that sits in front of your API Gateway. This blocks malicious traffic at the AWS edge, closest to the user.

## Best Practices & Industry Standards

Setting up WAF involves creating a Web ACL, adding rules to it, and then associating it with your resource.

### Step-by-Step Setup Process

#### Step 1: Create a Web ACL
1.  Navigate to the **WAF & Shield** console in AWS.
2.  Click **Create web ACL**.
3.  **Choose the Scope**: Select `CLOUDFRONT` if you are protecting a CloudFront distribution, or `REGIONAL` for an API Gateway stage.
4.  **Name the Web ACL**: Give it a descriptive name (e.g., `my-app-cloudfront-acl`).

#### Step 2: Add Rules and Rule Groups
This is where you define your security logic.

1.  **Add Managed Rule Groups (Recommended)**: This is the most effective way to start.
    -   Click **Add rules** -> **Add managed rule groups**.
    -   Expand the **AWS managed rule groups** section.
    -   Add essential rules like:
        -   `AWSManagedRulesCommonRuleSet`: Protects against a wide range of common threats (OWASP Top 10).
        -   `AWSManagedRulesSQLiRuleSet`: Specifically targets SQL injection attacks.
        -   `AWSManagedRulesKnownBadInputsRuleSet`: Blocks request patterns known to be malicious.
2.  **Add Custom Rules (Optional but Powerful)**:
    -   Click **Add rules** -> **Add my own rules and rule groups**.
    -   You can create rules based on various criteria:
        -   **IP set**: To block or allow traffic from specific IP addresses.
        -   **Geo match**: To block traffic from specific countries.
        -   **Rate-based rule**: To automatically block IPs that send an excessive number of requests (e.g., more than 2000 requests in 5 minutes), which is crucial for mitigating DDoS and brute-force attacks.

#### Step 3: Set Rule Actions and Default Action
-   For each rule, you can set the action to **Block** or **Count**. It is a best practice to initially set new or aggressive rules to **Count** mode. This allows you to monitor how many requests would be blocked without actually blocking them, helping you identify and prevent false positives.
-   Set the **Default action** for the Web ACL. This determines what happens if a request does not match any of the rules. For most public applications, the default action is **Allow**.

#### Step 4: Associate the Web ACL with the Resource
1.  In the Web ACL settings, go to the **Associated AWS resources** tab.
2.  Click **Add AWS resources**.
3.  Select the specific CloudFront distribution or API Gateway stage you want to protect.

### Implementation Guidelines

-   **Start with Managed Rules**: Always begin by implementing the core AWS Managed Rule Groups. They provide excellent baseline protection with minimal effort.
-   **Use Count Mode First**: Never deploy a new, untested rule directly into Block mode in production. Use Count mode to evaluate its impact on legitimate traffic.
-   **Enable Logging**: Configure WAF logging to send detailed logs to an Amazon Kinesis Data Firehose, which can then deliver them to S3. This is essential for troubleshooting, analyzing threats, and tuning rules.

## Real-World Examples

### Example 1: Setting up WAF for a CloudFront Distribution
**Context**: A global web application is served via CloudFront, which pulls content from an S3 bucket and an Application Load Balancer.
**Challenge**: Protect the application at the edge from common web attacks.
**Solution**:
1.  In the AWS WAF console, with the region set to **US East (N. Virginia)**, a new Web ACL was created with the `CLOUDFRONT` scope.
2.  The `AWSManagedRulesCommonRuleSet` and `AWSManagedRulesAmazonIpReputationList` were added to the ACL in **Block** mode.
3.  A custom **rate-based rule** was added to block IPs making more than 1000 requests in 5 minutes.
4.  The Web ACL was then associated with the CloudFront distribution ID.
**Outcome**: Malicious traffic is now blocked at the AWS edge, reducing risk and lowering the load on the origin servers. Latency for legitimate users is improved due to CloudFront's caching.
**Technologies**: AWS WAF, CloudFront, AWS Managed Rules.

### Example 2: Securing a Regional API Gateway
**Context**: A regional REST API on API Gateway is used by internal services and needs protection from internal threats or misconfigurations.
**Challenge**: Apply firewall rules directly to the API Gateway stage.
**Solution**:
1.  In the AWS WAF console, with the region set to the **same region as the API Gateway** (e.g., `us-west-2`), a new Web ACL was created with the `REGIONAL` scope.
2.  A custom **IP set** rule was created to only allow requests from the company's known IP ranges.
3.  The default action for the Web ACL was set to **Block**.
4.  The Web ACL was then associated with the specific stage of the API Gateway (e.g., `v1-prod`).
**Outcome**: The API is now only accessible from trusted corporate IP addresses, effectively creating a network boundary at the application layer.
**Technologies**: AWS WAF, API Gateway, IP Set Rules.

## Common Pitfalls & Solutions

### Pitfall 1: Choosing the Wrong Scope/Region
**Problem**: Creating a `REGIONAL` Web ACL and being unable to find it in the CloudFront console, or vice-versa.
**Why it happens**: A fundamental misunderstanding of WAF scopes.
**Solution**: Remember the golden rule: **CloudFront WAFs are global and must be in `us-east-1`**. All other WAFs are regional and must be in the same region as the resource they protect.
**Prevention**: Clearly name your Web ACLs to indicate their scope (e.g., `my-app-regional-acl`, `my-app-cloudfront-acl`).

### Pitfall 2: Overlooking Logging
**Problem**: A legitimate user is blocked, but there are no logs to determine which rule caused it.
**Why it happens**: Forgetting to enable logging during setup to save costs or time.
**Solution**: Always enable WAF logging during setup. The cost is minimal compared to the operational blindness of not having logs. Stream logs to S3 via Kinesis Data Firehose and use Amazon Athena to easily query them when needed.
**Prevention**: Make WAF logging a mandatory part of your IaC templates for any new Web ACL.

## Follow-up Questions Preparation

### Likely Deep-Dive Questions
1.  **"How would you add an exception to an AWS Managed Rule? For example, if it's blocking a legitimate request?"**
    - You can't edit the managed rule itself, but you can override its behavior. You would set the managed rule to `Count` mode instead of `Block`. This adds a *label* to requests that match the rule. Then, you create a new custom rule with a lower priority that looks for this label. Your custom rule can then use more specific logic (e.g., `if label exists AND IP is NOT in my-allow-list THEN block`), giving you fine-grained control.
2.  **"How does WAF pricing work?"**
    - It has three components: a monthly fee per Web ACL, a per-rule fee, and a per-request fee. This is why it's more cost-effective to use managed rule groups (which count as a single rule for pricing) than to create dozens of individual custom rules.

### Related Topics to Be Ready For
- **AWS Shield**: How it works with WAF for DDoS protection.
- **Kinesis Data Firehose and Amazon Athena**: The standard services used for WAF log storage and analysis.

### Connection Points to Other Sections
- **Section 6 (API Gateway Security)**: WAF is a key component of the defense-in-depth strategy for securing APIs.
- **Section 5 (Security & Encryption)**: WAF is a practical tool for mitigating many of the threats described in the OWASP Top 10.

## Sample Answer Framework

### Opening Statement
"Setting up AWS WAF involves three main steps: creating a Web ACL with the correct scope, adding rules to define your security logic, and associating that ACL with the resource you want to protect, like an API Gateway stage or a CloudFront distribution."

### Core Answer Structure
1.  **Choose the Scope**: Start by explaining the critical difference between a `CLOUDFRONT` scope (which must be in `us-east-1`) and a `REGIONAL` scope (which must be in the same region as the resource).
2.  **Add Rules**: Describe the process of adding rules, emphasizing the best practice of starting with AWS Managed Rule Groups for baseline protection against common threats like the OWASP Top 10.
3.  **Add Custom/Rate-Based Rules**: Mention adding custom rules for application-specific logic and rate-based rules for DDoS protection.
4.  **Associate with Resource**: Explain the final step of linking the Web ACL to the specific API Gateway stage or CloudFront distribution.
5.  **Mention Testing**: Conclude by highlighting the importance of using `Count` mode to test rules before enabling `Block` mode in production.

### Closing Statement
"By following this process, you can deploy a powerful, scalable firewall at the edge of your application. The best practice for most applications is to associate the WAF with a CloudFront distribution to block malicious traffic as early as possible, which also improves performance and reduces load on the origin."

## Technical Deep-Dive Points

### Implementation Details

**Terraform for WAF and CloudFront Association:**
```hcl
provider "aws" {
  alias  = "virginia"
  region = "us-east-1"
}

# WAF must be in us-east-1 for CloudFront
resource "aws_wafv2_web_acl" "cloudfront_acl" {
  provider = aws.virginia

  name  = "my-cloudfront-acl"
  scope = "CLOUDFRONT"

  default_action {
    allow {}
  }

  rule {
    name     = "AWS-Managed-Common-Rules"
    priority = 1
    override_action {
      none {}
    }
    statement {
      managed_rule_group_statement {
        vendor_name = "AWS"
        name        = "AWSManagedRulesCommonRuleSet"
      }
    }
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "aws-common-rules"
      sampled_requests_enabled   = true
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "cloudfront-acl"
    sampled_requests_enabled   = true
  }
}

# CloudFront Distribution
resource "aws_cloudfront_distribution" "my_distribution" {
  # ... other configuration ...

  # Associate the WAF Web ACL
  web_acl_id = aws_wafv2_web_acl.cloudfront_acl.arn
}
```

### Metrics and Measurement
- **WAF Logs**: The most critical tool for setup and tuning. They provide full details on every request WAF inspects, which rules it matched, and what action was taken.
- **CloudWatch Metrics**: `BlockedRequests` and `CountedRequests` are essential for validating that your rules are working as expected and not causing false positives.

## Recommended Reading

### Official Documentation
- [Tutorial: Getting started with AWS WAF](https://docs.aws.amazon.com/waf/latest/developerguide/getting-started.html)
- [Associating a Web ACL with an AWS resource](https://docs.aws.amazon.com/waf/latest/developerguide/web-acl-associating.html)

### Industry Resources
- [AWS Blog: How to set up AWS WAF for Amazon API Gateway](https://aws.amazon.com/blogs/networking-and-content-delivery/how-to-set-up-aws-waf-for-amazon-api-gateway/)
