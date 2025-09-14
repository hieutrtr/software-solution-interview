# Integrating a VM-Hosted REST API with API Gateway and IAM Auth

## Original Question
> **How would you integrate a REST API deployed on a VM behind API Gateway with IAM auth?**

## Core Concepts

### Key Definitions
- **API Gateway HTTP Integration**: A type of integration that allows API Gateway to act as an HTTP proxy, forwarding requests to a specified HTTP endpoint, such as an application running on a Virtual Machine (VM).
- **IAM Authentication**: A security mechanism in API Gateway where incoming requests must be cryptographically signed using AWS credentials (Signature Version 4). API Gateway validates the signature to authenticate the requestor.
- **VPC Link**: A feature that allows API Gateway to securely connect to resources inside a private VPC without exposing them to the public internet. It typically uses a Network Load Balancer (NLB) to route traffic to private resources like VMs.
- **Signature Version 4 (SigV4)**: The protocol for signing AWS API requests. It provides authentication, data integrity, and protection against replay attacks.

### Fundamental Principles
- **Proxy Layer**: API Gateway acts as a secure, managed proxy or facade for your backend services. This decouples clients from the backend and centralizes concerns like authentication, rate limiting, and logging.
- **Identity-Based Authorization**: Access is controlled through IAM policies attached to the calling identity (user or role), not just network rules. This aligns with a Zero Trust security model.
- **Credential Abstraction**: The backend service on the VM does not need to handle AWS authentication. It receives a standard HTTP request, as API Gateway handles the entire IAM authentication and authorization flow.

## Best Practices & Industry Standards

### Architectural Flow

The end-to-end flow for this integration is as follows:

1.  **Client Signs Request**: The client application (which could be another service, a script, or a user) uses its AWS credentials (preferably temporary ones from an IAM Role) to sign an HTTP request using the SigV4 protocol. The AWS SDKs handle this automatically.
2.  **Request to API Gateway**: The client sends the signed request to the API Gateway endpoint.
3.  **API Gateway Authentication**: API Gateway receives the request, extracts the AWS credentials from the signature, and validates the signature's authenticity and integrity.
4.  **API Gateway Authorization**: Upon successful authentication, API Gateway checks the IAM policy attached to the client's identity. It verifies if the policy grants `execute-api:Invoke` permission for the specific API method being called.
5.  **Request Forwarding**: If authorized, API Gateway forwards the request to the configured backend—the HTTP endpoint of the application running on the VM. This can be done over the public internet or privately via a VPC Link.
6.  **Backend Processing**: The application on the VM receives a standard, un-signed HTTP request, processes it, and returns a response.
7.  **Response to Client**: API Gateway relays the response from the VM back to the client.

### Implementation Guidelines

#### 1. **Configure the API Gateway Method**
-   In the API Gateway console or via IaC, define your resource and method (e.g., `GET /users/{id}`).
-   In the **Method Request** settings, set **Authorization** to `AWS_IAM`.

#### 2. **Configure the Backend Integration**
-   In the **Integration Request** settings, choose the **Integration type**.
    -   **HTTP**: If the VM has a public IP or is behind a public-facing load balancer.
    -   **VPC Link**: If the VM is in a private VPC. This is the more secure, recommended approach. You would create a VPC Link connected to a Network Load Balancer that targets your VM.
-   Set the **Endpoint URL** to the address of your VM's application (e.g., `http://<vm-ip-address>:8080/users/{id}`).

#### 3. **Create the IAM Policy for Clients**
-   Define an IAM policy that grants invocation permission. Be as specific as possible.

    ```json
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "execute-api:Invoke",
                "Resource": "arn:aws:execute-api:us-east-1:123456789012:abcdef123/prod/GET/users/*"
            }
        ]
    }
    ```

#### 4. **Assign Permissions to the Client**
-   Attach the policy created in step 3 to the IAM User or IAM Role that will be calling the API.
-   For applications running on other AWS services (like another EC2 VM), it is best practice to assign an IAM Role to that service, which grants it the necessary permissions.

## Real-World Examples

### Example 1: Legacy Monolith Modernization
**Context**: A company has a monolithic application running on a large EC2 instance. They want to expose some of its functionality as a secure, modern REST API without rewriting the entire application.
**Challenge**: Securely expose a legacy HTTP endpoint without modifying the application's code to handle authentication.
**Solution**:
1.  An API Gateway was deployed in front of the EC2 instance.
2.  The API Gateway methods were configured with `AWS_IAM` authorization.
3.  The integration was set to `HTTP`, pointing to the private IP of the EC2 instance via a VPC Link and Network Load Balancer.
4.  New microservices, running on Lambda or ECS, were given IAM Roles with policies allowing them to invoke the API Gateway.
**Outcome**: The legacy application's functionality was securely exposed as a managed API. The company could control access using standard IAM policies and benefit from API Gateway features like caching and throttling, all without changing a line of code in the legacy monolith.
**Technologies**: API Gateway, IAM, VPC Link, Network Load Balancer, EC2.

### Example 2: Secure Jenkins CI/CD Integration
**Context**: A Jenkins server running on an EC2 VM needs to trigger a deployment process by calling an internal "deployments" API.
**Challenge**: Provide the Jenkins server with a secure, auditable way to authenticate with the deployments API.
**Solution**:
1.  The deployments API was fronted by API Gateway with IAM authentication.
2.  An IAM Role (`Jenkins-EC2-Role`) was created with a policy granting `execute-api:Invoke` permission specifically for the `POST /deployments` endpoint.
3.  This IAM Role was attached to the Jenkins EC2 instance as an instance profile.
4.  The Jenkins pipeline script used the AWS CLI (which automatically uses the instance profile credentials) to make a signed request to the API Gateway endpoint.
**Outcome**: The Jenkins server could securely call the API without any hardcoded credentials. Access could be easily rotated or revoked by modifying the IAM role, and all deployment triggers were logged in CloudTrail with the principal ARN of the Jenkins role.
**Technologies**: API Gateway, IAM Roles for EC2, AWS CLI, Jenkins.

## Common Pitfalls & Solutions

### Pitfall 1: Exposing the VM Backend Directly
**Problem**: Leaving the VM's application port open to the internet, allowing attackers to bypass the API Gateway entirely.
**Why it happens**: Incorrect security group configuration.
**Solution**: Configure the VM's security group to only allow inbound traffic from the API Gateway. If using a VPC Link, the security group should only allow traffic from the Network Load Balancer's private IP addresses.
**Prevention**: Use automated security group auditing tools and follow the principle of least privilege for network access.

### Pitfall 2: Hardcoding Credentials on the Client
**Problem**: An application or script calling the API has hardcoded IAM user access keys.
**Why it happens**: It seems like the easiest way to provide credentials.
**Solution**: Always use IAM Roles where possible. If the client is an EC2 instance, use an instance profile. If it's a container, use IAM Roles for Service Accounts (IRSA). If it's an external application, use temporary credentials via `sts:AssumeRole`.
**Prevention**: Implement credential scanning in your CI/CD pipeline to detect hardcoded secrets.

## Follow-up Questions Preparation

### Likely Deep-Dive Questions
1.  **"How would the integration change if the VM was in a private VPC?"**
    - You would need to use a VPC Link. This requires setting up a Network Load Balancer (NLB) in your VPC that targets the VM. You then create a VPC Link in API Gateway and point the integration to the NLB.
2.  **"How does the backend on the VM know who the original caller was?"**
    - By default, it doesn't. API Gateway authenticates the call but forwards a plain HTTP request. If the backend needs the caller's identity, you must configure the integration to pass it along. You can map the caller's ARN (`context.identity.caller`) in the Integration Request to a custom HTTP header (e.g., `X-Caller-ARN`) that the backend can read.
3.  **"Can you combine IAM authentication with other authorizers?"**
    - No, an API Gateway method can only have one authorizer configured at a time. You must choose between `AWS_IAM`, `COGNITO_USER_POOLS`, a `LAMBDA` authorizer, or `NONE`.

### Related Topics to Be Ready For
- **VPC Networking**: Understanding security groups, NACLs, and VPC Endpoints is crucial for a secure integration.
- **AWS Signature Version 4**: Having a high-level understanding of how the signing process works (canonical request, string to sign, etc.).

### Connection Points to Other Sections
- **Section 6 (IAM)**: This is a direct application of IAM roles and policies.
- **Section 5 (Security & Encryption)**: Relates to the broader topic of designing secure authentication and authorization systems.

## Sample Answer Framework

### Opening Statement
"Integrating a VM-hosted API with API Gateway using IAM authentication is a powerful pattern for modernizing and securing legacy services. The architecture involves using API Gateway as a secure proxy that handles all authentication and authorization before forwarding valid requests to the VM backend."

### Core Answer Structure
1.  **API Gateway Configuration**: Explain that you would set the method's authorization type to `AWS_IAM`.
2.  **Integration Type**: Describe the integration, mentioning the use of a VPC Link and NLB for private VMs as the most secure approach.
3.  **Client-Side Signing**: Explain that the client must sign requests using SigV4, preferably by using an IAM Role and the AWS SDK, which handles the signing automatically.
4.  **IAM Policy**: Detail the need for an `execute-api:Invoke` policy attached to the client's IAM role, scoped to the specific API resource.
5.  **Security Benefit**: Conclude by stating that this decouples authentication from the backend application, allowing you to leverage AWS-native security for a service that may not have a modern auth system.

### Closing Statement
"This pattern effectively creates a secure, auditable, and managed entry point for a VM-based service, allowing it to integrate seamlessly into a modern, cloud-native security posture without requiring any code changes on the backend application itself."

## Technical Deep-Dive Points

### Implementation Details

**Terraform for a Private Integration with VPC Link:**
```hcl
# Assumes an NLB and VPC are already created

resource "aws_api_gateway_vpc_link" "my_link" {
  name        = "my-vpc-link"
  target_arns = [aws_lb.my_nlb.arn]
}

resource "aws_api_gateway_integration" "my_integration" {
  rest_api_id = aws_api_gateway_rest_api.my_api.id
  resource_id = aws_api_gateway_resource.my_resource.id
  http_method = aws_api_gateway_method.my_method.http_method

  type                    = "HTTP_PROXY"
  integration_http_method = "ANY"
  connection_type         = "VPC_LINK"
  connection_id           = aws_api_gateway_vpc_link.my_link.id
  uri                     = aws_lb_listener.my_listener.arn
}
```

### Metrics and Measurement
- **API Gateway `403Forbidden` Errors**: A high count indicates issues with IAM policies or request signing on the client-side.
- **CloudTrail Logs**: Filter for `execute-api:Invoke` events. Audit the `userIdentity` section to verify that only authorized principals are calling the API.
- **NLB Health Checks**: Monitor the health of the backend VM target to ensure the integration is functional.

## Recommended Reading

### Official Documentation
- [Control access to an API with IAM permissions](https://docs.aws.amazon.com/apigateway/latest/developerguide/permissions.html)
- [Set up a private integration with a VPC Link](https://docs.aws.amazon.com/apigateway/latest/developerguide/set-up-private-integration.html)
- [Signing AWS requests with Signature Version 4](https://docs.aws.amazon.com/general/latest/gr/signature-version-4.html)
