# Common API Authentication Mechanisms (IAM, Cognito, JWT)

## Original Question
> **What auth mechanisms are common for public APIs (IAM, Cognito, JWT)?**

## Core Concepts

### Key Definitions
- **IAM (Identity and Access Management)**: An AWS service for securely controlling access to AWS resources. For APIs, this involves signing requests with AWS credentials (Signature Version 4).
- **Amazon Cognito**: A managed service providing user sign-up, sign-in, and access control for web and mobile apps. It acts as an Identity Provider (IdP) and issues JSON Web Tokens (JWTs).
- **JWT (JSON Web Token)**: An open standard (RFC 7519) that defines a compact and self-contained way for securely transmitting information between parties as a JSON object. It's the foundation for modern token-based authentication.
- **Lambda Authorizer**: A feature of API Gateway that uses a Lambda function to perform custom authentication and authorization logic, often by validating a bearer token like a JWT.

### Fundamental Principles
- **Authentication (AuthN)**: The process of verifying who a user or service is. In the context of APIs, this is typically done by validating a credential, signature, or token.
- **Authorization (AuthZ)**: The process of determining what an authenticated user or service is allowed to do. This happens *after* successful authentication.
- **Token-Based Flow**: The standard for public APIs. A client first authenticates with an Identity Provider to get a token, then includes that token in API requests to prove its identity and permissions.

## Best Practices & Industry Standards

This table provides a high-level comparison of the three primary mechanisms for securing public APIs in AWS.

| Feature | AWS IAM Authentication | Amazon Cognito Authorizer | Custom JWT (Lambda Authorizer) |
| :--- | :--- | :--- | :--- |
| **Primary Use Case** | Service-to-service communication within AWS. | Authenticating end-users for web/mobile apps. | Integrating with any third-party or custom IdP. |
| **Credential Type** | AWS Access Keys (SigV4 Signature) | JWT (from Cognito User Pool) | Any bearer token (typically JWT) |
| **AuthZ Model** | IAM Policies | JWT Scopes & Groups | Custom logic in Lambda returning an IAM policy |
| **Complexity** | High for public clients, simple for AWS SDKs. | Low (fully managed user directory). | High (requires custom Lambda code). |
| **Flexibility** | Low (tied to IAM identities). | Medium (tied to Cognito features). | Very High (fully customizable logic). |

### 1. **AWS IAM Authentication**
- **How it Works**: Every API request must be cryptographically signed using an IAM user's or role's access keys. API Gateway validates this `Signature Version 4` (SigV4) signature to authenticate the request.
- **When to Use**: Excellent for **service-to-service** communication within the AWS ecosystem (e.g., a Lambda function calling an API, an EC2 instance calling an API). It is generally **not suitable** for authenticating end-users from a public frontend, as it would require distributing long-term AWS credentials to clients, which is a major security risk.

### 2. **Amazon Cognito User Pool Authorizer**
- **How it Works**: This is the standard, best-practice approach for public web/mobile apps. The frontend application uses Cognito to handle user sign-in. Cognito issues a JWT to the client. The client then passes this JWT in the `Authorization` header of every API request. API Gateway has a built-in authorizer that validates the token against the Cognito User Pool automatically.
- **When to Use**: The default choice for securing APIs that will be consumed by end-users of your application. It provides a complete, managed solution for identity, authentication, and token issuance.

### 3. **Custom JWT with a Lambda Authorizer**
- **How it Works**: For ultimate flexibility, you can write your own Lambda function to act as an authorizer. API Gateway invokes this function for each request, passing it the token from the `Authorization` header. The Lambda function contains the logic to validate the token (e.g., check its signature against a public key, verify claims) and returns an IAM policy that either allows or denies the request.
- **When to Use**: Use this when you need to integrate with a non-Cognito Identity Provider (like Auth0, Okta, or an on-premise IdP) or when you have complex, dynamic authorization logic that can't be handled by Cognito scopes alone.

## Real-World Examples

### Example 1: End-User Mobile App
**Context**: A mobile app needs to fetch user-specific data.
**Challenge**: Securely authenticate millions of public users.
**Solution**: Use **Amazon Cognito**. Users sign up and log in via the mobile app. Cognito provides a JWT to the app, which is then sent with every API Gateway request. The API Gateway uses a built-in Cognito authorizer to validate the token before allowing access to the backend.
**Why**: It's a fully managed, scalable, and secure solution designed specifically for this use case, offloading all the complexity of user management.

### Example 2: Internal Microservices Communication
**Context**: An `order-service` needs to get customer details from a `customer-service`.
**Challenge**: Securely authenticate the machine-to-machine communication.
**Solution**: Use **IAM Authentication**. The `order-service` runs with an IAM Role that has a policy granting it `execute-api:Invoke` permissions on the `customer-service` API. When it makes a request, the AWS SDK automatically signs it using the role's temporary credentials. The `customer-service` API Gateway endpoint is configured to require `AWS_IAM` authorization.
**Why**: It leverages the native AWS security fabric, is highly secure, and avoids managing separate credentials for internal services.

### Example 3: Integrating with a Corporate Identity Provider
**Context**: An internal enterprise application needs to call an API, but users must authenticate with the company's existing Okta (OIDC) login.
**Challenge**: Validate tokens issued by a third-party IdP.
**Solution**: Use a **Lambda Authorizer**. The frontend authenticates the user against Okta and receives a JWT. This JWT is passed to API Gateway. The attached Lambda Authorizer fetches Okta's public keys (JWKS), verifies the token's signature and claims, and then returns a policy allowing the request to proceed.
**Why**: It provides the flexibility to integrate with any OIDC-compliant provider and allows for custom logic to map Okta roles to internal permissions.

## Common Pitfalls & Solutions

### Pitfall 1: Using IAM Users for End-User Authentication
**Problem**: Distributing IAM access keys to end-users or embedding them in a web/mobile client.
**Why it happens**: It seems like a direct way to grant access, but it's a massive security vulnerability, as these long-lived credentials can be easily stolen.
**Solution**: Never use IAM users for end-user authentication. Always use a dedicated Identity Provider like Cognito that provides temporary, short-lived tokens.
**Prevention**: Enforce organizational policies that forbid the creation of IAM users for applications and mandate the use of token-based services.

### Pitfall 2: Misunderstanding the Role of API Keys
**Problem**: Relying on API Keys as the sole mechanism for authentication.
**Why it happens**: The name is misleading. API Keys are for identification, not authentication.
**Solution**: Use API Keys for tracking usage, applying throttling limits via Usage Plans, and identifying clients. Always combine them with a proper authentication mechanism like Cognito, IAM, or a Lambda Authorizer.
**Prevention**: Treat API Keys as identifying metadata, not as a security credential.

## Follow-up Questions Preparation

### Likely Deep-Dive Questions
1.  **"How do you handle authorization after authentication is complete? For example, how do you ensure a user can only see their own orders?"**
    - With Cognito, you can use the `sub` (subject) claim in the JWT, which contains the user's unique ID. The backend service receives this ID and uses it in its database query (e.g., `SELECT * FROM orders WHERE user_id = :user_sub`).
2.  **"What are the performance trade-offs between a Cognito authorizer and a Lambda authorizer?"**
    - Cognito authorizers are highly optimized and have very low latency. Lambda authorizers introduce additional latency due to the Lambda function invocation. However, this can be mitigated by caching the authorizer's policy response for a configurable TTL (e.g., 5 minutes).
3.  **"How would you rotate credentials for an API using IAM authentication?"**
    - If using an IAM Role (best practice), credentials are rotated automatically by AWS. If using an IAM User, you must implement a key rotation policy, creating a new access key, deploying it, and deleting the old one. This is why roles are strongly preferred.

### Related Topics to Be Ready For
- **OAuth 2.0 Scopes**: How to use scopes defined in Cognito or a third-party IdP to grant fine-grained permissions to different parts of your API.
- **API Gateway Resource Policies**: Network-level access control that is evaluated *before* authentication mechanisms.

### Connection Points to Other Sections
- **Section 5 (Security & Encryption)**: This directly relates to Authentication and Session Management design patterns.
- **Section 6 (IAM)**: Builds on the core concepts of IAM users and roles.

## Sample Answer Framework

### Opening Statement
"For public APIs on AWS, the choice of authentication mechanism depends primarily on the client. The three common patterns—IAM, Cognito, and custom JWT authorizers—are each suited for different use cases. The best practice for public-facing web or mobile apps is to use a token-based flow with a service like Amazon Cognito."

### Core Answer Structure
1.  **Cognito for End-Users**: Start by explaining that Cognito is the standard for authenticating human users of a public application. Describe the token-based flow.
2.  **IAM for Services**: Contrast this with IAM authentication, explaining it's ideal for trusted, server-to-server communication within AWS, but insecure for public clients.
3.  **Lambda for Flexibility**: Introduce Lambda authorizers as the flexible solution for integrating with third-party identity providers or implementing custom logic.
4.  **Summarize Use Cases**: Briefly conclude by matching each mechanism to its primary use case: Cognito for users, IAM for services, and Lambda for custom integrations.

### Closing Statement
"By selecting the right mechanism for the right use case, you create a secure, scalable, and maintainable API architecture. For public APIs, this almost always means offloading user identity management to a service like Cognito and using the resulting tokens for authorization."

## Technical Deep-Dive Points

### Implementation Details

**Example Lambda Authorizer Policy Response:**
```json
{
  "principalId": "user|a1b2c3d4",
  "policyDocument": {
    "Version": "2012-10-17",
    "Statement": [
      {
        "Action": "execute-api:Invoke",
        "Effect": "Allow",
        "Resource": "arn:aws:execute-api:us-east-1:123456789012:abcdef123/prod/GET/orders/*"
      },
      {
        "Action": "execute-api:Invoke",
        "Effect": "Deny",
        "Resource": "arn:aws:execute-api:us-east-1:123456789012:abcdef123/prod/POST/admin/*"
      }
    ]
  },
  "context": {
    "tenantId": "xyz-789",
    "userRole": "premium_user"
  }
}
```

### Metrics and Measurement
- **API Gateway `4XX` Errors**: Monitor `401 Unauthorized` and `403 Forbidden` error rates to detect authentication and authorization issues.
- **Authorizer Latency**: Track the `AuthorizerLatency` metric in CloudWatch to measure the performance impact of Lambda authorizers.
- **Cognito Sign-in Failures**: Monitor failed sign-in attempts in Cognito to detect potential credential stuffing or brute-force attacks.

## Recommended Reading

### Official Documentation
- [API Gateway Access Control Documentation](https://docs.aws.amazon.com/apigateway/latest/developerguide/apigateway-control-access-to-api.html)
- [Using Amazon Cognito User Pools as authorizer](https://docs.aws.amazon.com/apigateway/latest/developerguide/apigateway-integrate-with-cognito.html)
- [Use API Gateway Lambda authorizers](https://docs.aws.amazon.com/apigateway/latest/developerguide/apigateway-use-lambda-authorizer.html)

### Industry Resources
- [JWT.io](https://jwt.io/): A great resource for understanding and debugging JSON Web Tokens.
- [AWS Blog: Introduction to API Gateway Custom Authorizers](https://aws.amazon.com/blogs/compute/introducing-custom-authorizers-in-amazon-api-gateway/)
