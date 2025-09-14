# AWS WAF Rule Types and Custom Rule Enhancement

## Original Question
> **What rule types exist, and how do custom rules enhance protection?**

## Core Concepts

### Key Definitions
- **Rule**: The basic building block of a Web ACL. A rule contains a statement that defines the inspection criteria and an action to take if a request matches the criteria (e.g., Block, Allow, Count).
- **Rule Group**: A collection of rules that are managed as a single entity. This is the primary way rules are deployed in a Web ACL.
- **AWS Managed Rule Group**: A curated, pre-configured rule group managed by AWS or AWS Marketplace sellers. These provide broad protection against common threats with minimal setup.
- **Custom Rule**: A rule that you define yourself to target specific patterns, business logic, or threats unique to your application.
- **Web ACL Capacity Units (WCU)**: A metric used by WAF to measure the operating resources required to run your rules. Each Web ACL has a WCU limit, and each rule consumes a certain number of WCUs.

### Fundamental Principles
- **Layered Logic**: WAF protection is built by layering different types of rules. You typically start with broad, managed rules and then add more specific custom rules to refine the protection.
- **Specificity and Granularity**: The power of WAF comes from its ability to move beyond generic protection and apply highly specific, granular logic that is tailored to your application's traffic patterns and vulnerabilities.

## Best Practices & Industry Standards

AWS WAF provides two main categories of rule types: **Managed Rule Groups** and **Custom Rules**.

### 1. Managed Rule Groups
These are the first line of defense and provide immediate, broad protection. They are created and maintained by security experts at AWS or third-party vendors.

-   **Core Protection**: Groups like `AWSManagedRulesCommonRuleSet` provide baseline protection against the OWASP Top 10 and other common vulnerabilities.
-   **Use-Case Specific**: There are specialized groups for different needs, such as:
    -   `AWSManagedRulesSQLiRuleSet`: Focuses specifically on SQL injection attacks.
    -   `AWSManagedRulesBotControl`: Identifies and blocks or challenges automated bots.
    -   `AWSManagedRulesAmazonIpReputationList`: Blocks traffic from IP addresses known to be associated with malicious activity.
-   **Benefit**: They offer a low-effort way to implement robust, up-to-date security without needing to be a security expert.

### 2. Custom Rules
Custom rules are where you tailor WAF's protection to your application's specific needs. They enhance protection by addressing threats that managed rules might not cover.

-   **Rule Statements**: A custom rule is built from one or more statements that define what to inspect in a request. These can be combined with logical operators (`AND`, `OR`, `NOT`).
-   **Inspection Criteria**: You can inspect almost any part of an HTTP request:
    -   **IP sets**: Match against a list of IP addresses you define.
    -   **Geo match**: Match against the request's country of origin.
    -   **String match / Regex match**: Match a string or regular expression in the URI, query string, headers, or body.
    -   **Size constraint**: Match requests where a component (e.g., the body) is larger or smaller than a specified size.

#### How Custom Rules Enhance Protection:

-   **Virtual Patching**: If a new vulnerability is discovered in your application (e.g., a specific URL is vulnerable to parameter tampering), you can immediately deploy a custom WAF rule to block requests matching that attack pattern. This protects the application while your developers work on a permanent code fix.
-   **Business Logic Abuse**: Protect against abuse that isn't a technical vulnerability. For example, you can block users from submitting a negative value in a `price` field in a JSON body.
-   **Reducing False Positives**: If a managed rule is too aggressive and blocks legitimate traffic, you can create a more specific custom `Allow` rule with a higher priority to create a targeted exception.
-   **Targeted Blocking**: Block traffic from a specific malicious user-agent or a geography you don't do business in.

### 3. Rate-Based Rules (A Special Type of Custom Rule)
This is one of the most powerful custom rule types. It tracks the rate of requests from individual source IP addresses over a rolling 5-minute period.

-   **How it Enhances Protection**: It is the primary tool for mitigating application-layer DDoS attacks, web scraping, and brute-force login attempts. By setting a threshold (e.g., 2000 requests per 5 minutes), you can automatically block IPs that are trying to overwhelm your application.

## Real-World Examples

### Example 1: Virtual Patching a Vulnerability
**Context**: A security scan reveals that the URL ` /legacy/getUser.php?id=...` is vulnerable to SQL injection.
**Challenge**: Protect the application immediately while developers work on a fix.
**Solution**: A **custom rule** was created with the following logic:
-   **IF** the URI path exactly matches `/legacy/getUser.php`
-   **AND** the query string contains patterns that look like SQL injection (e.g., using a regex like `(?i)union|select|--`)
-   **THEN** `Block` the request.
**Outcome**: The specific vulnerability was patched at the edge within minutes, preventing exploitation. The managed SQLi rule group might also have caught this, but the custom rule provides guaranteed, targeted protection.

### Example 2: Preventing Brute-Force Login Attacks
**Context**: An application's login page (`/login`) is being targeted by a distributed brute-force attack from thousands of different IPs.
**Challenge**: Block the attack without impacting legitimate users who may be trying to log in.
**Solution**: A **rate-based rule** was created with the following logic:
-   **IF** the URI path exactly matches `/login`
-   **AND** the HTTP method is `POST`
-   **THEN** track the rate of requests from each source IP.
-   **Action**: If any single IP exceeds 100 requests in 5 minutes, block all subsequent requests from that IP for a configured duration.
**Outcome**: The brute-force attack was immediately mitigated. The attacker's IPs were automatically blocked as they exceeded the rate limit, while legitimate users were unaffected.

## Common Pitfalls & Solutions

### Pitfall 1: Writing Inefficient Regex Patterns
**Problem**: A poorly written or overly complex regular expression in a custom rule can increase WAF processing latency.
**Why it happens**: Lack of regex optimization knowledge.
**Solution**: Use simple `string match` conditions where possible. If regex is necessary, write it to be as efficient as possible (e.g., avoid excessive backtracking) and test its performance.
**Prevention**: Have regex patterns peer-reviewed. Use tools to analyze regex performance before deploying.

### Pitfall 2: Rule Order and Priority
**Problem**: An `Allow` rule is placed with a higher priority (lower number) than a `Block` rule, causing a malicious request to be allowed before the block rule is ever evaluated.
**Why it happens**: Misunderstanding how WAF processes rules.
**Solution**: WAF processes rules in order of priority, from lowest number to highest. Always place your most specific `Allow` rules (exceptions) at the top (lowest priority number), followed by your broad `Block` rules.
**Prevention**: Regularly review the priority order of your Web ACL rules to ensure the logic is sound.

## Follow-up Questions Preparation

### Likely Deep-Dive Questions
1.  **"How do you combine multiple rule statements in a custom rule?"**
    - You use logical operators. You can nest statements inside an `AND`, `OR`, or `NOT` statement to create complex logic, such as `Block if (A AND B) OR C`.
2.  **"What are WAF labels and how are they used?"**
    - Labels are metadata that rules can add to a request as they are processed. They are extremely useful for creating exceptions to managed rules. For example, a managed rule can be set to `Count` mode, which adds a label like `awswaf:managed:aws:core-rule-set:CrossSiteScripting_QueryArguments`. A subsequent custom rule can then match on this label to decide whether to block the request or allow it based on other criteria.

### Related Topics to Be Ready For
- **JSON**: WAF rules are ultimately defined as JSON documents. Understanding the structure is helpful for advanced configurations and IaC.
- **Application Security**: A solid understanding of web vulnerabilities is necessary to write effective custom rules.

### Connection Points to Other Sections
- **Section 6 (WAF Setup)**: This topic provides the details on the "what" you are configuring in the setup process.
- **Section 5 (Input Validation)**: WAF rules are a form of centralized, edge-based input validation.

## Sample Answer Framework

### Opening Statement
"AWS WAF has two main types of rules: Managed Rule Groups, which are pre-packaged by AWS for broad protection, and Custom Rules, which you create for specific needs. The best practice is to use both, layering them to create a comprehensive defense. Custom rules are what truly enhance protection by allowing you to tailor the firewall to your application's unique logic and vulnerabilities."

### Core Answer Structure
1.  **Managed Rules First**: Explain that you always start with AWS Managed Rules for a strong baseline against common threats like the OWASP Top 10.
2.  **Introduce Custom Rules**: Describe custom rules as the mechanism for granular control. Give a clear example of how they enhance protection, such as for **virtual patching**.
3.  **Explain Rate-Based Rules**: Specifically call out rate-based rules as a powerful type of custom rule used to mitigate DDoS and brute-force attacks.
4.  **Provide a Scenario**: Walk through a simple scenario, like blocking traffic from a specific country you don't serve, which is a classic custom rule use case.

### Closing Statement
"In summary, while managed rules provide an essential foundation, custom rules are what elevate WAF from a generic firewall to a highly effective, application-aware security control. They allow an organization to respond immediately to new threats and protect against business logic abuse, creating a much stronger and more tailored security posture."

## Technical Deep-Dive Points

### Implementation Details

**Terraform for a Custom Rule to Block a Malicious User-Agent:**
```hcl
resource "aws_wafv2_web_acl" "main" {
  # ... other config ...

  # Custom Rule
  rule {
    name     = "Block-Bad-Scanner"
    priority = 10

    action {
      block {}
    }

    statement {
      string_match_statement {
        search_string = "BadScanner/1.0"
        field_to_match {
          single_header {
            name = "user-agent"
          }
        }
        text_transformation {
          priority = 0
          type     = "NONE"
        }
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "bad-scanner-rule"
      sampled_requests_enabled   = true
    }
  }
}
```

### Metrics and Measurement
- **Custom Rule Metrics**: Each custom rule gets its own CloudWatch metric. Monitoring the `BlockedRequests` for a specific custom rule is the best way to see if it is working as intended.
- **Sampled Requests**: When a custom rule is matched, looking at the sampled requests in the WAF console is crucial for verifying it's not causing false positives.

## Recommended Reading

### Official Documentation
- [AWS WAF rules](https://docs.aws.amazon.com/waf/latest/developerguide/waf-rules.html)
- [AWS Managed Rule groups](https://docs.aws.amazon.com/waf/latest/developerguide/aws-managed-rule-groups.html)
- [Rate-based rules](https://docs.aws.amazon.com/waf/latest/developerguide/waf-rule-statement-type-rate-based.html)

### Industry Resources
- [AWS Blog: How to create custom rules and rule groups in AWS WAF](https://aws.amazon.com/blogs/security/how-to-create-custom-rules-and-rule-groups-in-aws-waf/)
