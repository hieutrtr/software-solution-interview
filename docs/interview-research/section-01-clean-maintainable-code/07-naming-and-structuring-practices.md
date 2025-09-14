# Naming Conventions and Structuring Practices

## Original Question
> **What naming conventions and structuring practices do you follow when designing systems?**

## Core Concepts

### Key Definitions
- **Naming Convention**: A set of rules for choosing the character sequence to be used for identifiers (names) of variables, types, functions, and other entities in source code and documentation.
- **Structuring Practices (System Design)**: The set of principles and patterns used to organize the components of a software system. This includes defining modules, layers, service boundaries, and data flows.
- **Ubiquitous Language**: A term from Domain-Driven Design (DDD). It is the practice of building up a common, rigorous language between developers and users, which is used in all project artifacts, including code.
- **Self-Documenting Code**: Code that is clear and easy to read, where the names of variables, functions, and classes are expressive enough to make the code's intent obvious without needing additional comments.

### Fundamental Principles
- **Clarity and Consistency**: The ultimate goal of any convention or structure is to reduce cognitive load. A developer should be able to understand the purpose of a component or piece of data just by its name and location, and this understanding should be transferable across the entire system.
- **Intent over Implementation**: Names should reflect *what* a component does (its business purpose), not *how* it is implemented. For example, `OrderProcessingService` is better than `KafkaOrderConsumer`.
- **Structure Follows Strategy**: The way a system is structured should be a direct reflection of the business domain and the architectural strategy (e.g., microservices, monolith, event-driven).

## Best Practices & Industry Standards

My approach to naming and structure is to be deliberate and consistent, establishing clear patterns that scale from individual variables up to system-wide architecture.

### Naming Conventions

I apply specific, consistent conventions depending on the context.

-   **For Variables and Functions**: I use `camelCase` (e.g., `customerName`) or `snake_case` (e.g., `customer_name`) depending on the established standard for the programming language (e.g., camelCase for Java/C#/TypeScript, snake_case for Python).
    -   **Booleans**: Should be named as questions, e.g., `isEligible`, `hasSufficientInventory`.
    -   **Functions/Methods**: Should be named with verbs that describe their action or side effect, e.g., `calculateTotal()`, `saveCustomer(customer)`.

-   **For REST APIs**: I follow standard RESTful conventions.
    -   **Resources as Nouns**: Use plural nouns to identify resource collections (e.g., `/users`, `/orders`).
    -   **HTTP Verbs for Actions**: Use the HTTP method to denote the action (`GET`, `POST`, `PUT`, `DELETE`).
    -   **Hyphens for Readability**: Use `kebab-case` in URI paths (e.g., `/order-items`).

-   **For Microservices and Components**:
    -   Names should be based on the **business domain or capability** they represent (e.g., `PaymentGateway`, `InventoryService`, `NotificationDispatcher`).
    -   Avoid technical implementation details in the name.

-   **For Databases**:
    -   **Tables**: Plural nouns in `snake_case` (e.g., `customer_orders`).
    -   **Columns**: Descriptive nouns in `snake_case` (e.g., `first_name`, `order_date`).
    -   **Foreign Keys**: A consistent pattern of `singular_table_name_id` (e.g., `customer_id` in the `customer_orders` table).

### Structuring Practices

My approach to structuring a system is to ensure a clear separation of concerns, both at the code level and the architectural level.

1.  **Code-Level Structure (Inside a Service)**:
    -   I follow standard design patterns like **Layered Architecture** (e.g., Presentation/Controller, Business/Service, Data Access/Repository) or **Hexagonal Architecture** (Ports and Adapters).
    -   This ensures a clear separation of concerns: business logic is not mixed with database queries or HTTP handling.
    -   The directory structure reflects this architecture (e.g., `/controllers`, `/services`, `/repositories`).

2.  **Architectural Structure (System-Wide)**:
    -   **Domain-Driven Design (DDD)**: I use the principles of DDD to guide the decomposition of a large system. I work with domain experts to identify the core **Bounded Contexts**, which then become the natural boundaries for our microservices.
    -   **Event-Driven Architecture**: For communication between services, I favor an asynchronous, event-driven approach using a message broker like RabbitMQ or Kafka. This promotes loose coupling and resilience.
    -   **API Gateway Facade**: I use an API Gateway to act as a single entry point for external clients. This gateway provides a unified API and hides the complexity of the internal microservice architecture.

## Real-World Examples

### Example 1: Designing a New Microservice
**Context**: We needed to build a new service to handle user notifications.
**Challenge**: Define a clear name and structure that would be immediately understandable to the rest of the organization.
**Solution**:
1.  **Naming**: We named the service `notification-service`. The name clearly states its business capability. The corresponding database schema was named `notifications`, with tables like `email_templates` and `sent_notifications`.
2.  **Structure**: We designed the service using a Hexagonal Architecture. 
    -   The **core domain** contained the business logic for creating and templating notifications.
    -   It exposed **Ports** (interfaces) like `INotificationSender`.
    -   We then created **Adapters** that implemented these ports for specific technologies, like a `SendGridEmailAdapter` and a `TwilioSmsAdapter`.
**Outcome**: The structure was incredibly clean and maintainable. When we later needed to add push notifications, we simply had to add a new `FirebasePushAdapter`. The core business logic did not change. The naming and structure made it very easy for new developers to understand the service's purpose and how to extend it.

### Example 2: Standardizing API Naming
**Context**: An organization had multiple teams building APIs, and they all used different naming conventions (`/getUsers`, `/user/create`, `/orders_for_customer`).
**Challenge**: The inconsistency made the APIs difficult to use and discover for client applications.
**Solution**: I led an initiative to create and adopt a company-wide REST API Style Guide.
-   We documented a clear set of conventions based on industry best practices (plural nouns for resources, standard HTTP methods, etc.).
-   We used a linting tool (like Spectral) in our CI/CD pipeline to automatically check OpenAPI/Swagger specifications against these rules.
**Outcome**: All new APIs began to look and feel consistent. This dramatically reduced the learning curve for developers consuming other teams' APIs and improved the overall developer experience.

## Common Pitfalls & Solutions

### Pitfall 1: Naming Based on Technical Implementation
**Problem**: Naming a service `User-Mongo-Service` or a function `loopThroughArray()`.
**Why it happens**: Developers are thinking about *how* they are building it, not *what* it is for.
**Solution**: Always name based on business intent. The service is a `UserService`; the fact that it uses MongoDB is an implementation detail that could change. The function is `calculateInvoiceTotals()`; the fact that it uses a loop is irrelevant to the caller.
**Prevention**: Enforce this during code reviews. Ask the question: "Does this name describe the business purpose?"

### Pitfall 2: The "Utils" or "Common" Monolith
**Problem**: Creating a generic `common-library` or `utils-service` where all shared code is dumped.
**Why it happens**: It seems like an easy way to avoid duplicating code.
**Solution**: This inevitably becomes a highly coupled monolith where a change to a single utility function requires dozens of services to be re-tested and re-deployed. Be specific. If you have shared logic for validating addresses, create a dedicated `AddressValidationLibrary`, not a generic `common` library.
**Prevention**: Be disciplined about creating small, focused, and domain-specific shared libraries instead of a single catch-all module.

## Follow-up Questions Preparation

### Likely Deep-Dive Questions
1.  **"How do you handle versioning in your API naming and structure?"**
    - I advocate for URI-based versioning (e.g., `/v1/users`, `/v2/users`) as it's the most explicit and clearest for clients. The API Gateway can be used to route requests for different versions to different backend services, allowing for graceful upgrades and deprecation.
2.  **"When would you choose to break your own naming convention?"**
    - Very rarely, and only with a good reason that is documented in an ADR. An example might be for consistency with a well-known third-party API. If we are integrating with Stripe and their API uses a specific term, we might choose to adopt that same term in our corresponding internal service to reduce cognitive load for developers working with that integration, even if it slightly differs from our internal standard.

### Related Topics to Be Ready For
- **Domain-Driven Design (DDD)**: The primary methodology for defining service boundaries and a ubiquitous language.
- **RESTful API Design**: The set of constraints that guide the design of web APIs.

### Connection Points to Other Sections
- **Section 1 (Clean Code)**: These practices are a direct application of clean code principles at a system-wide level.
- **Section 8 (Architecture & Design)**: Naming and structure are the foundational elements of any architectural design.

## Sample Answer Framework

### Opening Statement
"My approach to naming and structuring is rooted in two principles: clarity and consistency. The goal is to design a system where any developer can look at a component's name and its place in the architecture and immediately understand its purpose. I achieve this by applying consistent conventions at every level, from individual variables to microservice boundaries."

### Core Answer Structure
1.  **Start with Naming**: Explain your conventions for different contexts. Mention using descriptive verbs for functions, plural nouns for REST resources, and business capabilities for microservices.
2.  **Move to Structure**: Describe your approach to system structure. Talk about using **Domain-Driven Design** to define service boundaries and a **Layered or Hexagonal Architecture** within each service to separate concerns.
3.  **Provide a Concrete Example**: Use a simple example, like designing a `NotificationService`, to illustrate how you would apply these naming and structuring practices together.
4.  **Emphasize Automation**: Mention that these conventions are not just suggestions; they are enforced automatically using linters and CI/CD pipeline checks to ensure consistency across all teams.

### Closing Statement
"By being deliberate about naming and structure, we create a system that is not only easier to understand and maintain but also more scalable. Clear boundaries and consistent names make it simpler to add new features, onboard new developers, and evolve the architecture over time."

## Technical Deep-Dive Points

### Implementation Details

**Example Directory Structure for a Service:**
```
notification-service/
├── cmd/           # Main application entry points
├── internal/      # Private application and library code
│   ├── api/       # Controllers, routes, HTTP handlers
│   ├── domain/    # Core business logic and entities
│   ├── repository/ # Data access layer
│   └── config/    # Configuration loading
├── api/           # Public API contracts (e.g., Protobuf files)
├── docs/          # Documentation, including ADRs
├── scripts/       # Build, deploy, and other scripts
├── Dockerfile
└── README.md
```

### Metrics and Measurement
- **Onboarding Time**: A good system structure and clear naming conventions should directly lead to a reduction in the time it takes for a new engineer to become productive.
- **Cross-Team Dependencies**: Track the number of pull requests that require changes across multiple service repositories. A good structure should minimize this, indicating loose coupling.

## Recommended Reading

### Industry Resources
- **Book**: "Domain-Driven Design: Tackling Complexity in the Heart of Software" by Eric Evans.
- **Book**: "Clean Architecture: A Craftsman's Guide to Software Structure and Design" by Robert C. Martin.
- [Microsoft REST API Guidelines](https://github.com/microsoft/api-guidelines/blob/vNext/azure/Guidelines.md)
