# SwiftHearty JWT Utility Library

A lightweight, secure, and easy-to-use JWT (JSON Web Token) utility library for Java applications. Inspired by Python's `pyjwt`, this library simplifies token generation, verification, and management while maintaining robust security features.

## Features

- Simple, fluent API for JWT operations
- Support for both symmetric (HMAC) and asymmetric (RSA) encryption
- Role-based access control integration
- Custom claims support
- Token refresh mechanism
- Token blacklisting
- Comprehensive exception handling
- Thoroughly tested with JUnit

## Installation

### Maven

Add the following to your `pom.xml`:

```xml
<dependencies>
    <!-- JWT Dependencies -->
    <dependency>
        <groupId>io.jsonwebtoken</groupId>
        <artifactId>jjwt-api</artifactId>
        <version>0.11.5</version>
    </dependency>
    <dependency>
        <groupId>io.jsonwebtoken</groupId>
        <artifactId>jjwt-impl</artifactId>
        <version>0.11.5</version>
        <scope>runtime</scope>
    </dependency>
    <dependency>
        <groupId>io.jsonwebtoken</groupId>
        <artifactId>jjwt-jackson</artifactId>
        <version>0.11.5</version>
        <scope>runtime</scope>
    </dependency>
</dependencies>
```

### Gradle

Add the following to your `build.gradle`:

```groovy
dependencies {
    implementation 'io.jsonwebtoken:jjwt-api:0.11.5'
    runtimeOnly 'io.jsonwebtoken:jjwt-impl:0.11.5'
    runtimeOnly 'io.jsonwebtoken:jjwt-jackson:0.11.5'
}
```

## Usage Examples

### Basic Token Generation and Verification

```java
// Create user details
UserDetails user = UserDetails.builder()
    .userId("123")
    .username("john_doe")
    .email("john@example.com")
    .addRole("USER")
    .build();

// Create JWT utility with symmetric key
JWTUtil jwtUtil = JWTUtil.createWithSymmetricKey();

// Generate token
String token = jwtUtil.generateToken(user);

// Verify token
boolean isValid = jwtUtil.verifyToken(token);

// Extract claims
Claims claims = jwtUtil.getClaims(token);
```

### Role-Based Access Control

```java
// Generate token with roles
UserDetails adminUser = UserDetails.builder()
    .userId("456")
    .username("admin_user")
    .email("admin@example.com")
    .addRole("ADMIN")
    .addRole("USER")
    .build();

JWTUtil jwtUtil = JWTUtil.createWithSymmetricKey();
String token = jwtUtil.generateToken(adminUser);

// Check if user has required role
boolean hasAdminAccess = jwtUtil.verifyTokenAndCheckRole(token, "ADMIN");
if (hasAdminAccess) {
    // Allow access to admin resources
}
```

### Using Asymmetric Keys

```java
// Create JWT utility with asymmetric key pair
JWTUtil jwtUtil = JWTUtil.createWithAsymmetricKey();

// Generate token
String token = jwtUtil.generateToken(user);

// Verify token
boolean isValid = jwtUtil.verifyToken(token);
```

### Token Refresh

```java
// Generate initial token
String initialToken = jwtUtil.generateToken(user);

// Later when token is about to expire
String refreshedToken = jwtUtil.refreshToken(initialToken);
// The original token is automatically blacklisted
```

### Custom Claims

```java
// Add custom claims to user
Map<String, Object> customClaims = new HashMap<>();
customClaims.put("department", "Engineering");
customClaims.put("location", "New York");

UserDetails user = UserDetails.builder()
    .userId("123")
    .username("john_doe")
    .email("john@example.com")
    .addRole("USER")
    .customClaims(customClaims)
    .build();

// Generate token with custom claims
String token = jwtUtil.generateToken(user);
```

## Security Considerations

### 1. Key Management

- For production environments, use secure key management solutions (e.g., vault, HSM)
- Rotate keys periodically
- For symmetric keys, ensure they are at least 32 bytes (256 bits) long
- For asymmetric keys, use at least 2048-bit RSA keys

### 2. Token Expiration

- Set short-lived tokens (30-60 minutes) for regular operations
- Use refresh tokens for longer sessions
- Validate expiration on every token use

### 3. Sensitive Data

- Do not store sensitive information (passwords, credit card numbers) in tokens
- Be cautious with personally identifiable information (PII)

### 4. HTTPS

- Always use HTTPS for transmitting tokens
- Set secure and httpOnly flags on cookies if storing tokens in cookies

### 5. Token Revocation

- Use the blacklist feature for token revocation
- Consider using a persistent blacklist for production environments

## API Documentation

### Key Classes

#### UserDetails

The `UserDetails` class represents user information and roles.

```java
// Create a new user with builder pattern
UserDetails user = UserDetails.builder()
    .userId("123")
    .username("john_doe")
    .email("john@example.com")
    .addRole("ADMIN")
    .build();

// Access user properties
String userId = user.getUserId();
List<String> roles = user.getRoles();
boolean isAdmin = user.hasRole("ADMIN");
```

#### JWTUtil

The `JWTUtil` class provides methods for token operations.

```java
// Create instance with symmetric key
JWTUtil jwtUtil = JWTUtil.createWithSymmetricKey();

// Set token expiration (in minutes)
jwtUtil.setTokenExpiration(30);

// Set refresh token expiration (in days)
jwtUtil.setRefreshTokenExpiration(7);

// Token operations
String token = jwtUtil.generateToken(user);
Claims claims = jwtUtil.getClaims(token);
UserDetails extractedUser = jwtUtil.getUserFromToken(token);
boolean isValid = jwtUtil.verifyToken(token);
String refreshedToken = jwtUtil.refreshToken(token);
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

