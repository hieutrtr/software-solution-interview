# AWS WAF and Application Protection

## Original Question
> **What is AWS WAF and how does it protect apps?**

## Core Concepts

### Key Definitions
- **AWS WAF (Web Application Firewall)**: A firewall that helps protect your web applications or APIs against common web exploits and bots that may affect availability, compromise security, or consume excessive resources.
- **Web ACL (Web Access Control List)**: The core resource in AWS WAF. It is a collection of rules that you define to inspect and control HTTP/HTTPS requests to your application.
- **Rule**: A single condition that WAF inspects for in web requests. Rules can be simple (like checking an IP address) or complex (like matching a regex pattern in the request body).
- **Managed Rule Group**: A pre-configured set of rules curated by AWS or AWS Marketplace sellers to provide protection against common threats like the OWASP Top 10, known bad bots, or application-specific vulnerabilities (e.g., for WordPress).

### Fundamental Principles
- **Layer 7 Filtering**: Unlike a traditional network firewall that operates at lower network layers (like IP addresses and ports), a WAF operates at the Application Layer (Layer 7). This allows it to inspect the actual content of HTTP requests, including headers, body, and URI.
- **Protection at the Edge**: WAF is most effective when deployed at the edge of the AWS network, integrated with services like Amazon CloudFront or Application Load Balancer. This allows it to block malicious traffic before it ever reaches your application servers.
- **Default Deny vs. Default Allow**: A Web ACL can be configured in two modes: it can either block all requests except the ones that match an `Allow` rule, or allow all requests except the ones that match a `Block` rule. The latter is more common.

## Best Practices & Industry Standards

AWS WAF protects applications by inspecting incoming web traffic and applying a set of rules to filter out malicious requests. Here’s how it works:

### 1. **Integration with AWS Services**
WAF is not a standalone service; it must be associated with one of the following AWS resources:
-   **Amazon CloudFront**: The recommended integration point for most web applications. It provides protection at the AWS network edge, blocking bad traffic closest to the source and improving performance.
-   **Application Load Balancer (ALB)**: Protects all applications behind the load balancer.
-   **Amazon API Gateway**: Protects your REST and HTTP APIs.
-   **AWS AppSync**: Protects your GraphQL APIs.

### 2. **Rule-Based Traffic Inspection**
WAF rules inspect various parts of an HTTP request:
-   Originating IP address (supports IPv4 and IPv6)
-   Country of origin
-   HTTP headers (e.g., `User-Agent`, `Referer`)
-   HTTP method (e.g., `GET`, `POST`)
-   Query string and URI path
-   Request body (including JSON)

Based on these inspections, you can configure rules to **Allow**, **Block**, or **Count** (monitor) the request.

### 3. **Protection Mechanisms**

-   **Against Common Exploits (OWASP Top 10)**: By using the **AWS Managed Rule Groups** (e.g., `AWSManagedRulesCommonRuleSet`, `AWSManagedRulesSQLiRuleSet`), you get instant protection against common vulnerabilities like:
    -   **SQL Injection (SQLi)**: WAF detects and blocks request patterns that look like attempts to inject malicious SQL code.
    -   **Cross-Site Scripting (XSS)**: WAF inspects for and blocks scripts embedded in request parameters that could be executed in a user's browser.

-   **Against Automated Bots**: The **AWS Managed Bot Control** rule group can identify and block or rate-limit common and sophisticated bots, such as scrapers, scanners, and crawlers, reducing load and preventing content theft.

-   **Against DDoS Attacks**: WAF provides application-layer DDoS mitigation. **Rate-based rules** are particularly effective here. You can configure a rule to automatically block any IP address that sends more than a specified number of requests (e.g., 2000) in a 5-minute period.

-   **Custom Protection**: You can write your own custom rules to protect against application-specific threats. For example, you could block requests to a `/admin` login page that do not come from your corporate IP range.

## Real-World Examples

### Example 1: Protecting a Public E-commerce Website
**Context**: An e-commerce website hosted on EC2 behind an Application Load Balancer is experiencing high traffic from scraper bots and probes for common vulnerabilities.
**Challenge**: Block malicious traffic without impacting legitimate customers.
**Solution**:
1.  An AWS WAF Web ACL was created and associated with the Application Load Balancer.
2.  The following AWS Managed Rule Groups were enabled:
    -   `AWSManagedRulesCommonRuleSet` (for general OWASP Top 10 protection).
    -   `AWSManagedRulesAmazonIpReputationList` (to block IPs with poor reputations).
    -   `AWSManagedRulesKnownBadInputsRuleSet` (to block patterns known to be malicious).
3.  A custom **rate-based rule** was added to block any IP making more than 5,000 requests in 5 minutes to mitigate application-layer DDoS attacks.
**Outcome**: The site's error rate dropped significantly, and server load was reduced by 30% due to the blocking of scraper and scanner traffic. Several SQL injection attempts were blocked in the first day.
**Technologies**: AWS WAF, Application Load Balancer, AWS Managed Rules.

### Example 2: Securing a REST API for a Mobile App
**Context**: A REST API built on API Gateway and Lambda serves a popular mobile application.
**Challenge**: The API was being abused by users trying to exploit business logic by sending malformed JSON in the request body.
**Solution**:
1.  A WAF Web ACL was associated with the API Gateway stage.
2.  In addition to standard managed rules, a **custom rule** was created to inspect the JSON body of `POST` requests to `/api/submit-order`.
3.  The rule was configured with a regex to ensure that the `price` field in the JSON was a valid positive number and not a negative value or a string, which had been used in previous abuse attempts.
**Outcome**: The business logic exploit was completely mitigated at the edge. The backend Lambda function no longer had to handle malformed price data, simplifying its code and making it more secure.
**Technologies**: AWS WAF, API Gateway, Custom WAF Rules.

## Common Pitfalls & Solutions

### Pitfall 1: Using WAF in Count-Only Mode
**Problem**: Admins enable rules in "Count" mode to evaluate them but forget to switch them to "Block" mode, leaving the application unprotected.
**Why it happens**: Fear of blocking legitimate traffic (false positives).
**Solution**: Have a clear process. Run in Count mode for a defined period (e.g., 24-48 hours), analyze the logs for false positives, tune the rules by creating exceptions if necessary, and then switch to Block mode.
**Prevention**: Use automated reminders or CI/CD processes that enforce a transition from Count to Block mode after a review period.

### Pitfall 2: Not Monitoring WAF Logs
**Problem**: Setting up WAF and never looking at the logs. This means you miss new attack patterns and don't know if your rules are effective or are causing false positives.
**Why it happens**: It's a "set it and forget it" mentality.
**Solution**: Stream WAF logs to a central location like an S3 bucket or CloudWatch Logs. Use Amazon Athena to query the logs or set up CloudWatch Dashboards and Alarms to get visibility into what WAF is blocking.
**Prevention**: Integrate WAF monitoring into your regular security operations and review dashboards weekly.

## Follow-up Questions Preparation

### Likely Deep-Dive Questions
1.  **"How would you handle a false positive, where WAF is blocking a legitimate user?"**
    - First, analyze the WAF logs to identify which rule is blocking the request. If it's a managed rule, you can add a label to it. Then, create a subsequent custom rule with a lower priority that allows requests containing that specific label, but only if they meet other narrow criteria (e.g., coming from a specific IP or containing a certain header), to avoid opening a security hole.
2.  **"What is the difference between AWS WAF and AWS Shield?"**
    - AWS WAF is a **Web Application Firewall** that operates at Layer 7 to protect against application-level attacks (like XSS, SQLi). **AWS Shield** is a **DDoS protection service**. Shield Standard (free) protects against common network and transport layer (Layer 3/4) DDoS attacks. Shield Advanced provides enhanced protection against larger and more sophisticated DDoS attacks and includes features like 24/7 DDoS response team support and cost protection.
3.  **"Can you use WAF to protect non-web traffic?"**
    - No. WAF is specifically designed for inspecting HTTP and HTTPS traffic. It cannot be used to protect other protocols like SSH, RDP, or raw TCP/UDP traffic.

### Related Topics to Be Ready For
- **OWASP Top 10**: A deep understanding of these vulnerabilities is key to understanding what WAF is protecting against.
- **Regular Expressions (Regex)**: Writing effective custom rules often requires knowledge of regex.

### Connection Points to Other Sections
- **Section 6 (API Gateway Security)**: WAF is a primary layer of defense for any API Gateway endpoint.
- **Section 5 (Security & Encryption)**: WAF is a practical implementation of the defense-in-depth principle.

## Sample Answer Framework

### Opening Statement
"AWS WAF is a managed web application firewall that acts as a critical security layer for applications and APIs. Its primary role is to protect against common web exploits and malicious bots by filtering HTTP/S traffic *before* it reaches the application. It operates at Layer 7, allowing it to inspect the actual content of requests."

### Core Answer Structure
1.  **What it is**: Define WAF as a Layer 7 firewall that inspects HTTP/S requests.
2.  **How it Integrates**: Explain that it's not standalone and must be attached to an AWS resource like CloudFront, an ALB, or API Gateway.
3.  **How it Protects**: Describe the two main protection mechanisms:
    -   Using **AWS Managed Rules** for out-of-the-box protection against common threats like the OWASP Top 10.
    -   Creating **Custom Rules** (including rate-based rules) to block application-specific threats or mitigate DDoS attacks.
4.  **Give a Concrete Example**: Briefly describe a scenario, such as using WAF to block SQL injection attempts against an API.

### Closing Statement
"By integrating WAF at the edge of the application delivery network—ideally with CloudFront—you create a powerful, scalable first line of defense, significantly reducing the application's attack surface and filtering out a large volume of malicious traffic before it can do any harm."

## Technical Deep-Dive Points

### Implementation Details

**Terraform for a Basic WAF Setup:**
```hcl
resource "aws_wafv2_web_acl" "main" {
  name        = "my-app-web-acl"
  scope       = "REGIONAL" # Use "CLOUDFRONT" for CloudFront distributions
  description = "WAF Web ACL for my application"

  default_action {
    allow {}
  }

  # Rule 1: Use AWS Managed Rule for common threats
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

  # Rule 2: Rate-based rule to block IPs making too many requests
  rule {
    name     = "Rate-Limit-5-Min"
    priority = 2

    action {
      block {}
    }

    statement {
      rate_based_statement {
        limit              = 2000 # Requests per 5 minutes per IP
        aggregate_key_type = "IP"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "rate-limit"
      sampled_requests_enabled   = true
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "main-web-acl"
    sampled_requests_enabled   = true
  }
}

# Associate the Web ACL with an Application Load Balancer
resource "aws_wafv2_web_acl_association" "alb_assoc" {
  resource_arn = aws_lb.my_alb.arn
  web_acl_arn  = aws_wafv2_web_acl.main.arn
}
```

### Metrics and Measurement
- **BlockedRequests**: The number of requests blocked by WAF. A sudden spike can indicate an attack.
- **CountedRequests**: The number of requests that matched a rule in "Count" mode. Useful for testing new rules.
- **AllowedRequests**: The total number of requests that were not blocked.
- **WAF Logs**: Provide detailed, request-level information about every request inspected by WAF, including which rule it matched. Essential for forensics and tuning.

## Recommended Reading

### Official Documentation
- [What Is AWS WAF?](https://docs.aws.amazon.com/waf/latest/developerguide/what-is-aws-waf.html) (AWS Developer Guide)
- [AWS Managed Rule groups](https://docs.aws.amazon.com/waf/latest/developerguide/aws-managed-rule-groups.html)

### Industry Resources
- [OWASP Top Ten Project](https://owasp.org/www-project-top-ten/): Understanding the threats WAF helps protect against.
- [AWS Security Blog: WAF](https://aws.amazon.com/blogs/security/category/security-identity-compliance/aws-waf/): Best practices and new feature announcements.
