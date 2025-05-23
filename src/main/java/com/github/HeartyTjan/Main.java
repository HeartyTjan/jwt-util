package com.github.HeartyTjan;

import com.github.HeartyTjan.jwt.JWTUtil;
import com.github.HeartyTjan.model.UserDetails;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Main class demonstrating the usage of the JWT utility library.
 * This example shows how to:
 * - Create user details with roles and custom claims
 * - Generate tokens using both symmetric and asymmetric keys
 * - Verify tokens and check roles
 * - Extract claims from tokens
 * - Refresh tokens and manage blacklists
 * - Handle token validation errors
 * - Validate configuration parameters
 * - Use custom keys for token signing
 */
public class Main {
    private static final Logger logger = LoggerFactory.getLogger(Main.class);

    public static void main(String[] args) {
        logger.info("JWT Utility Library Example");
        logger.info("===========================");

        try {
            // Example 1: Symmetric Key JWT
            symmetricKeyExample();

            // Example 2: Asymmetric Key JWT
            asymmetricKeyExample();

            // Example 3: Role-based access control
            roleBasedAccessExample();

            // Example 4: Token refresh and blacklisting
            tokenRefreshExample();

            // Example 5: Error handling and security
            errorHandlingExample();

            // Example 6: Configuration validation
            configValidationExample();

            logger.info("\nAll examples completed successfully!");
        } catch (Exception e) {
            logger.error("Error running examples: {}", e.getMessage(), e);
        }
    }

    /**
     * Example 1: Demonstrates JWT operations using symmetric key encryption.
     */
    private static void symmetricKeyExample() {
        logger.info("\n--- Example 1: Symmetric Key JWT ---");

        // Step 1: Create user details with roles and custom claims
        logger.info("Step 1: Creating user details");
        UserDetails user = createSampleUser();
        logger.info("User created: {}", user);

        // Step 2: Create JWT utility with symmetric key
        logger.info("\nStep 2: Creating JWT utility with symmetric key");
        JWTUtil jwtUtil = JWTUtil.createWithSymmetricKey();
        jwtUtil.setTokenExpiration(30); // Set token to expire in 30 minutes
        logger.info("JWT utility created with symmetric key");

        // Step 3: Generate a token
        logger.info("\nStep 3: Generating token");
        String token = jwtUtil.generateToken(user);
        logger.info("Generated token: {}", token);

        // Step 4: Verify the token
        logger.info("\nStep 4: Verifying token");
        boolean isValid = jwtUtil.verifyToken(token);
        logger.info("Token is valid: {}", isValid);

        // Step 5: Extract claims from the token
        logger.info("\nStep 5: Extracting claims");
        Claims claims = jwtUtil.getClaims(token);
        logger.info("Token subject: {}", claims.getSubject());
        logger.info("Token issuance time: {}", claims.getIssuedAt());
        logger.info("Token expiration: {}", claims.getExpiration());

        // Step 6: Get remaining validity time
        logger.info("\nStep 6: Checking remaining validity time");
        long remainingMinutes = jwtUtil.getTokenRemainingValidityMinutes(token);
        logger.info("Token remains valid for approximately {} minutes", remainingMinutes);
    }

    /**
     * Example 2: Demonstrates JWT operations using asymmetric key encryption.
     */
    private static void asymmetricKeyExample() {
        logger.info("\n--- Example 2: Asymmetric Key JWT ---");

        // Step 1: Create user details
        logger.info("Step 1: Creating user details");
        UserDetails user = createSampleUser();

        // Step 2: Create JWT utility with asymmetric key pair
        logger.info("\nStep 2: Creating JWT utility with asymmetric key pair");
        JWTUtil jwtUtil = JWTUtil.createWithAsymmetricKey();
        logger.info("JWT utility created with asymmetric key pair (RSA)");

        // Step 3: Generate a token with custom roles
        logger.info("\nStep 3: Generating token with specific roles");
        List<String> customRoles = Arrays.asList("DEVELOPER", "TESTER");
        String token = jwtUtil.generateTokenWithRoles(user, customRoles);
        logger.info("Generated token with custom roles: {}", token);

        // Step 4: Extract user details from token
        logger.info("\nStep 4: Extracting user details from token");
        UserDetails extractedUser = jwtUtil.getUserFromToken(token);
        logger.info("Extracted user: {}", extractedUser);
        logger.info("Roles from token: {}", extractedUser.getRoles());
    }

    /**
     * Example 3: Demonstrates role-based access control with JWT.
     */
    private static void roleBasedAccessExample() {
        logger.info("\n--- Example 3: Role-Based Access Control ---");

        // Step 1: Create user details with specific roles
        logger.info("Step 1: Creating user with roles");
        UserDetails adminUser = UserDetails.builder()
                .userId("456")
                .username("admin_user")
                .email("admin@example.com")
                .addRole("ADMIN")
                .addRole("USER")
                .build();

        UserDetails regularUser = UserDetails.builder()
                .userId("789")
                .username("regular_user")
                .email("user@example.com")
                .addRole("USER")
                .build();

        // Step 2: Create JWT utility
        logger.info("\nStep 2: Creating JWT utility");
        JWTUtil jwtUtil = JWTUtil.createWithSymmetricKey();

        // Step 3: Generate tokens for both users
        logger.info("\nStep 3: Generating tokens");
        String adminToken = jwtUtil.generateToken(adminUser);
        String userToken = jwtUtil.generateToken(regularUser);

        // Step 4: Verify tokens with role checking
        logger.info("\nStep 4: Verifying tokens with role check");
        boolean adminHasAdminAccess = jwtUtil.verifyTokenAndCheckRole(adminToken, "ADMIN");
        boolean userHasAdminAccess = jwtUtil.verifyTokenAndCheckRole(userToken, "ADMIN");
        boolean userHasUserAccess = jwtUtil.verifyTokenAndCheckRole(userToken, "USER");

        logger.info("Admin user has ADMIN role: {}", adminHasAdminAccess);
        logger.info("Regular user has ADMIN role: {}", userHasAdminAccess);
        logger.info("Regular user has USER role: {}", userHasUserAccess);

        // Simulating role-based access control
        logger.info("\nSimulating protected resource access:");
        simulateAccessControl(adminToken, jwtUtil);
        simulateAccessControl(userToken, jwtUtil);
    }

    /**
     * Example 4: Demonstrates token refresh and blacklisting.
     */
    private static void tokenRefreshExample() {
        logger.info("\n--- Example 4: Token Refresh and Blacklisting ---");

        // Step 1: Create user and JWT utility
        logger.info("Step 1: Creating user and JWT utility");
        UserDetails user = createSampleUser();
        JWTUtil jwtUtil = JWTUtil.createWithSymmetricKey();

        // For demo purposes, set a short expiration
        jwtUtil.setTokenExpiration(60); // 60 minutes

        // Step 2: Generate initial token
        logger.info("\nStep 2: Generating initial token");
        String initialToken = jwtUtil.generateToken(user);
        logger.info("Initial token generated");

        // Step 3: Refresh the token
        logger.info("\nStep 3: Refreshing token");
        String refreshedToken = jwtUtil.refreshToken(initialToken);
        logger.info("Token refreshed");

        // Step 4: Verify the tokens
        logger.info("\nStep 4: Verifying both tokens");
        boolean originalValid = jwtUtil.verifyToken(initialToken);
        boolean refreshedValid = jwtUtil.verifyToken(refreshedToken);

        logger.info("Original token is valid: {} (should be false as it's blacklisted)", originalValid);
        logger.info("Refreshed token is valid: {} (should be true)", refreshedValid);

        // Step 5: Check blacklist size
        logger.info("\nStep 5: Checking blacklist");
        int blacklistSize = jwtUtil.getBlacklistSize();
        logger.info("Blacklist size: {} (should be 1)", blacklistSize);

        // Step 6: Clear blacklist
        logger.info("\nStep 6: Clearing blacklist");
        jwtUtil.clearBlacklist();
        logger.info("Blacklist cleared. New size: {}", jwtUtil.getBlacklistSize());

        // Always clean up resources in a real application
        logger.info("\nStep 7: Cleaning up resources");
    }

    /**
     * Helper method to create a sample user with roles and custom claims.
     */
    private static UserDetails createSampleUser() {
        // Create custom claims
        Map<String, Object> customClaims = new HashMap<>();
        customClaims.put("department", "Engineering");
        customClaims.put("location", "New York");
        customClaims.put("employeeId", 12345);

        // Create user with builder pattern
        return UserDetails.builder()
                .userId("123")
                .username("john_doe")
                .email("john@example.com")
                .addRole("ADMIN")
                .addRole("USER")
                .customClaims(customClaims)
                .build();
    }

    /**
     * Simulates access control to a protected resource.
     */
    private static void simulateAccessControl(String token, JWTUtil jwtUtil) {
        try {
            // Extract user from token
            UserDetails user = jwtUtil.getUserFromToken(token);

            logger.info("\nUser {} is attempting to access admin panel:", user.getUsername());

            // Check if user has admin role
            if (jwtUtil.verifyTokenAndCheckRole(token, "ADMIN")) {
                logger.info("✅ Access granted to admin panel for {}", user.getUsername());
            } else {
                logger.warn("❌ Access denied to admin panel for {} (requires ADMIN role)", user.getUsername());
            }

            logger.info("\nUser {} is attempting to access user dashboard:", user.getUsername());

            // Check if user has user role
            if (jwtUtil.verifyTokenAndCheckRole(token, "USER")) {
                logger.info("✅ Access granted to user dashboard for {}", user.getUsername());
            } else {
                logger.warn("❌ Access denied to user dashboard for {} (requires USER role)", user.getUsername());
            }

        } catch (JwtException e) {
            logger.warn("❌ Access denied: Invalid token");
        }
    }

    /**
     * Example 5: Demonstrates error handling for various JWT operations.
     */
    private static void errorHandlingExample() {
        logger.info("\n--- Example 5: Error Handling and Security ---");

        // Step 1: Create JWT utility and sample user
        logger.info("Step 1: Creating JWT utility and sample user");
        JWTUtil jwtUtil = JWTUtil.createWithSymmetricKey();
        UserDetails user = createSampleUser();

        // Step 2: Handle null user details
        logger.info("\nStep 2: Demonstrating null user details handling");
        try {
            jwtUtil.generateToken(null);
        } catch (IllegalArgumentException e) {
            logger.warn("Expected error: {}", e.getMessage());
        }

        // Step 3: Generate a valid token for tamper testing
        logger.info("\nStep 3: Generating token for tamper testing");
        String validToken = jwtUtil.generateToken(user);

        // Step 4: Test token tampering
        logger.info("\nStep 4: Testing tampered token detection");
        // Create a tampered token by changing the last character
        String tamperedToken = validToken.substring(0, validToken.length() - 1)
                + (validToken.charAt(validToken.length() - 1) == 'A' ? 'B' : 'A');

        boolean isValid = jwtUtil.verifyToken(tamperedToken);
        logger.info("Tampered token verification result: {} (should be false)", isValid);

        // Step 5: Test token expiration checking
        logger.info("\nStep 5: Testing token expiration checking");
        boolean isExpired = jwtUtil.isTokenExpired(tamperedToken);
        logger.info("Tampered token is considered expired: {} (should be true for invalid tokens)", isExpired);

        // Step 6: Handle invalid token formats
        logger.info("\nStep 6: Testing invalid token format handling");
        String[] invalidTokens = {"", "not.a.jwt", null, "   "};
        for (String invalidToken : invalidTokens) {
            try {
                boolean invalidTokenValid = jwtUtil.verifyToken(invalidToken);
                logger.info("Invalid token '{}' verification result: {} (should be false)",
                        invalidToken != null ? invalidToken : "null", invalidTokenValid);
            } catch (Exception e) {
                logger.warn("Error verifying invalid token: {}", e.getMessage());
            }
        }
    }

    /**
     * Example 6: Demonstrates configuration validation and custom key usage.
     */
    private static void configValidationExample() {
        logger.info("\n--- Example 6: Configuration Validation ---");

        // Step 1: Test expiration time validation
        logger.info("Step 1: Testing expiration time validation");
        JWTUtil jwtUtil = JWTUtil.createWithSymmetricKey();

        try {
            jwtUtil.setTokenExpiration(-10);
        } catch (IllegalArgumentException e) {
            logger.warn("Expected error for negative expiration: {}", e.getMessage());
        }

        try {
            jwtUtil.setTokenExpiration(0);
        } catch (IllegalArgumentException e) {
            logger.warn("Expected error for zero expiration: {}", e.getMessage());
        }

        // Step 2: Demonstrate custom expiration times
        logger.info("\nStep 2: Setting custom expiration times");
        jwtUtil.setTokenExpiration(120);  // 2 hours
        jwtUtil.setRefreshTokenExpiration(30);  // 30 days

        logger.info("Token expiration set to {} minutes", jwtUtil.getTokenExpirationMinutes());
        logger.info("Refresh token expiration set to {} days", jwtUtil.getRefreshTokenExpirationDays());

        // Step 3: Test custom symmetric key
        logger.info("\nStep 3: Using a custom symmetric key");
        try {
            JWTUtil.createWithSymmetricKey("too-short");
        } catch (IllegalArgumentException e) {
            logger.warn("Expected error for short key: {}", e.getMessage());
        }

        // Create a proper key
        String customKey = "this-is-a-secure-key-with-at-least-32-chars";
        JWTUtil customKeyJwtUtil = JWTUtil.createWithSymmetricKey(customKey);
        logger.info("Created JWT utility with custom symmetric key");

        // Test the custom key works
        UserDetails user = createSampleUser();
        String token = customKeyJwtUtil.generateToken(user);
        boolean tokenValid = customKeyJwtUtil.verifyToken(token);
        logger.info("Token created with custom key is valid: {}", tokenValid);

        // Step 4: Demonstrate key type checking
        logger.info("\nStep 4: Checking key types");
        logger.info("Symmetric key JWT type: {}", jwtUtil.getTokenType());

        JWTUtil asymJwtUtil = JWTUtil.createWithAsymmetricKey();
        logger.info("Asymmetric key JWT type: {}", asymJwtUtil.getTokenType());
    }
}
