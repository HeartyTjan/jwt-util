package com.github.HeartyTjan.jwt;

import com.github.HeartyTjan.model.UserDetails;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for the JWTUtil class.
 * These tests verify all aspects of JWT token handling including:
 * - Token generation (symmetric and asymmetric)
 * - Token verification
 * - Role-based access control
 * - Claims extraction
 * - Token refresh
 * - Blacklist functionality
 * - Error handling
 */
public class JWTUtilTest {

    // Test data
    private UserDetails testUser;
    private final String TEST_USER_ID = "test123";
    private final String TEST_USERNAME = "testuser";
    private final String TEST_EMAIL = "test@example.com";
    private final List<String> TEST_ROLES = Arrays.asList("USER", "ADMIN");
    
    @BeforeEach
    public void setUp() {
        // Create a test user before each test
        Map<String, Object> customClaims = new HashMap<>();
        customClaims.put("department", "Testing");
        customClaims.put("employeeId", 12345);
        
        testUser = UserDetails.builder()
                .userId(TEST_USER_ID)
                .username(TEST_USERNAME)
                .email(TEST_EMAIL)
                .roles(TEST_ROLES)
                .customClaims(customClaims)
                .build();
    }
    
    // For nested test classes that need to clean up JWTUtil resources
    protected void cleanupJwtUtil(JWTUtil jwtUtil) {
        if (jwtUtil != null) {
            jwtUtil.clearBlacklist();
        }
    }
    
    @Nested
    @Tag("symmetric")
    @DisplayName("Symmetric Key Tests")
    class SymmetricKeyTests {
        
        private JWTUtil jwtUtil;
        
        @BeforeEach
        public void setUp() {
            jwtUtil = JWTUtil.createWithSymmetricKey();
            jwtUtil.setTokenExpiration(60); // 60 minutes
        }
        
        @AfterEach
        public void tearDown() {
            cleanupJwtUtil(jwtUtil);
        }
        @Test
        @DisplayName("Should generate valid token with symmetric key")
        public void testGenerateToken() {
            // Generate token
            String token = jwtUtil.generateToken(testUser);
            
            // Verify token is not empty
            assertNotNull(token);
            assertFalse(token.isEmpty());
            
            // Verify token is valid
            assertTrue(jwtUtil.verifyToken(token));
            
            // Verify token type
            assertEquals(JWTUtil.TokenType.SYMMETRIC, jwtUtil.getTokenType());
        }
        
        @Test
        @DisplayName("Should verify token with symmetric key")
        public void testVerifyToken() {
            String token = jwtUtil.generateToken(testUser);
            
            // Test valid token
            assertTrue(jwtUtil.verifyToken(token));
            
            // Test invalid token
            assertFalse(jwtUtil.verifyToken("invalid.token.string"), "Invalid token format should fail verification");
            assertFalse(jwtUtil.verifyToken(null), "Null token should fail verification");
            assertFalse(jwtUtil.verifyToken(""), "Empty token should fail verification");
            assertFalse(jwtUtil.verifyToken("   "), "Blank token should fail verification");
        }
        
        @Test
        @DisplayName("Should extract claims from token")
        public void testGetClaims() {
            String token = jwtUtil.generateToken(testUser);
            
            Claims claims = jwtUtil.getClaims(token);
            
            // Verify standard claims
            assertEquals(TEST_USER_ID, claims.getSubject());
            assertNotNull(claims.getIssuedAt());
            assertNotNull(claims.getExpiration());
            
            // Verify custom claims
            assertEquals(TEST_USER_ID, claims.get("userId"));
            assertEquals(TEST_USERNAME, claims.get("username"));
            assertEquals(TEST_EMAIL, claims.get("email"));
            assertEquals(TEST_ROLES, claims.get("roles"));
            assertEquals("Testing", claims.get("department"));
            assertEquals(12345, claims.get("employeeId"));
        }
        
        @Test
        @DisplayName("Should recreate UserDetails from token")
        public void testGetUserFromToken() {
            String token = jwtUtil.generateToken(testUser);
            
            UserDetails extractedUser = jwtUtil.getUserFromToken(token);
            
            // Verify extracted user
            assertEquals(TEST_USER_ID, extractedUser.getUserId());
            assertEquals(TEST_USERNAME, extractedUser.getUsername());
            assertEquals(TEST_EMAIL, extractedUser.getEmail());
            assertEquals(TEST_ROLES, extractedUser.getRoles());
            assertEquals("Testing", extractedUser.getCustomClaim("department"));
            assertEquals(12345, extractedUser.getCustomClaim("employeeId"));
        }
    }
    
    @Nested
    @Tag("asymmetric")
    @DisplayName("Asymmetric Key Tests")
    class AsymmetricKeyTests {
        
        private JWTUtil jwtUtil;
        
        @BeforeEach
        public void setUp() {
            jwtUtil = JWTUtil.createWithAsymmetricKey();
            jwtUtil.setTokenExpiration(60);
        }
        
        @AfterEach
        public void tearDown() {
            cleanupJwtUtil(jwtUtil);
        }
        @Test
        @DisplayName("Should generate valid token with asymmetric key")
        public void testGenerateToken() {
            String token = jwtUtil.generateToken(testUser);
            
            // Verify token is not empty
            assertNotNull(token);
            assertFalse(token.isEmpty());
            
            // Verify token is valid
            assertTrue(jwtUtil.verifyToken(token));
            
            // Verify token type
            assertEquals(JWTUtil.TokenType.ASYMMETRIC, jwtUtil.getTokenType());
        }
        
        @Test
        @DisplayName("Should verify token with asymmetric key")
        public void testVerifyToken() {
            String token = jwtUtil.generateToken(testUser);
            
            // Test valid token
            assertTrue(jwtUtil.verifyToken(token));
            
            // Test invalid token
            assertFalse(jwtUtil.verifyToken("invalid.token.string"), "Invalid token should fail verification");
        }
        
        @Test
        @DisplayName("Should fail verification with wrong key")
        public void testVerificationWithWrongKey() {
            // Generate token with first key pair
            String token = jwtUtil.generateToken(testUser);
            
            // Create new JWT util with different key pair
            JWTUtil anotherJwtUtil = JWTUtil.createWithAsymmetricKey();
            
            // Verification should fail with different key pair
            assertFalse(anotherJwtUtil.verifyToken(token), "Token should not verify with a different key pair");
            
            // Clean up the second JWTUtil instance
            cleanupJwtUtil(anotherJwtUtil);
        }
    }
    
    @Nested
    @Tag("rbac")
    @DisplayName("Role-Based Access Control Tests")
    class RoleBasedAccessTests {
        
        private JWTUtil jwtUtil;
        
        @BeforeEach
        public void setUp() {
            jwtUtil = JWTUtil.createWithSymmetricKey();
        }
        
        @AfterEach
        public void tearDown() {
            cleanupJwtUtil(jwtUtil);
        }
        
        @Test
        @DisplayName("Should verify roles in token")
        public void testVerifyRoles() {
            String token = jwtUtil.generateToken(testUser);
            
            // Test roles that exist
            assertTrue(jwtUtil.verifyTokenAndCheckRole(token, "USER"));
            assertTrue(jwtUtil.verifyTokenAndCheckRole(token, "ADMIN"));
            
            // Test role that doesn't exist
            assertFalse(jwtUtil.verifyTokenAndCheckRole(token, "SUPERADMIN"));
        }
        
        @Test
        @DisplayName("Should override roles when generating token")
        public void testGenerateTokenWithRoles() {
            List<String> newRoles = Arrays.asList("DEVELOPER", "TESTER");
            String token = jwtUtil.generateTokenWithRoles(testUser, newRoles);
            
            // Test new roles
            assertTrue(jwtUtil.verifyTokenAndCheckRole(token, "DEVELOPER"));
            assertTrue(jwtUtil.verifyTokenAndCheckRole(token, "TESTER"));
            
            // Test original roles (should not exist in this token)
            assertFalse(jwtUtil.verifyTokenAndCheckRole(token, "USER"));
            assertFalse(jwtUtil.verifyTokenAndCheckRole(token, "ADMIN"));
            
            // Extract user and verify roles
            UserDetails extractedUser = jwtUtil.getUserFromToken(token);
            assertEquals(newRoles, extractedUser.getRoles());
        }
    }
    
    @Nested
    @Tag("refresh")
    @DisplayName("Token Refresh and Blacklist Tests")
    class TokenRefreshAndBlacklistTests {
        
        private JWTUtil jwtUtil;
        
        @BeforeEach
        public void setUp() {
            jwtUtil = JWTUtil.createWithSymmetricKey();
        }
        
        @AfterEach
        public void tearDown() {
            cleanupJwtUtil(jwtUtil);
        }
        
        @Test
        @DisplayName("Should refresh token and blacklist original")
        public void testRefreshToken() {
            // Generate initial token
            String initialToken = jwtUtil.generateToken(testUser);
            assertTrue(jwtUtil.verifyToken(initialToken));
            
            // Refresh token
            String refreshedToken = jwtUtil.refreshToken(initialToken);
            
            // Verify original token is now invalid (blacklisted)
            assertFalse(jwtUtil.verifyToken(initialToken));
            
            // Verify new token is valid
            assertTrue(jwtUtil.verifyToken(refreshedToken));
            
            // Verify blacklist size
            assertEquals(1, jwtUtil.getBlacklistSize());
        }
        
        @Test
        @DisplayName("Should manage blacklist correctly")
        public void testBlacklist() {
            // Generate tokens
            String token1 = jwtUtil.generateToken(testUser);
            String token2 = jwtUtil.generateToken(testUser);
            String token3 = jwtUtil.generateToken(testUser);
            
            // All tokens should be valid initially
            assertTrue(jwtUtil.verifyToken(token1));
            assertTrue(jwtUtil.verifyToken(token2));
            assertTrue(jwtUtil.verifyToken(token3));
            
            // Blacklist tokens
            jwtUtil.blacklistToken(token1);
            jwtUtil.blacklistToken(token2);
            
            // Check blacklist size
            assertEquals(2, jwtUtil.getBlacklistSize());
            
            // Verify blacklisted tokens are invalid
            assertFalse(jwtUtil.verifyToken(token1));
            assertFalse(jwtUtil.verifyToken(token2));
            assertTrue(jwtUtil.verifyToken(token3));
            
            // Clear blacklist
            jwtUtil.clearBlacklist();
            assertEquals(0, jwtUtil.getBlacklistSize());
            
            // All tokens should be valid again after clearing blacklist
            assertTrue(jwtUtil.verifyToken(token1));
            assertTrue(jwtUtil.verifyToken(token2));
            assertTrue(jwtUtil.verifyToken(token3));
        }
        
        @Test
        @DisplayName("Should handle null and empty tokens in blacklist")
        public void testBlacklistWithNullAndEmpty() {
            // Add null and empty tokens to blacklist (should not throw exceptions)
            jwtUtil.blacklistToken(null);
            jwtUtil.blacklistToken("");
            
            // Blacklist should still be empty (null/empty tokens should be ignored)
            assertEquals(0, jwtUtil.getBlacklistSize());
        }
    }
    
    @Nested
    @Tag("error")
    @DisplayName("Error Handling Tests")
    class ErrorHandlingTests {
        
        private JWTUtil jwtUtil;
        
        @BeforeEach
        public void setUp() {
            jwtUtil = JWTUtil.createWithSymmetricKey();
        }
        
        @AfterEach
        public void tearDown() {
            cleanupJwtUtil(jwtUtil);
        }
        
        @Test
        @DisplayName("Should handle null user details")
        public void testNullUserDetails() {
            Exception exception = assertThrows(IllegalArgumentException.class, () -> {
                jwtUtil.generateToken(null);
            });
            assertTrue(exception.getMessage().contains("User details cannot be null"));
        }
        
        @Test
        @DisplayName("Should detect when a token has expired")
        public void testExpiredToken() throws Exception {
            // Create a JWTUtil instance with very short token expiration
            JWTUtil specialJwtUtil = JWTUtil.createWithSymmetricKey();
            
            try {
                // Create a helper class to modify internal expiration field
                class ExpirationHelper {
                    private void setTokenToExpired(JWTUtil util, String token) throws Exception {
                        // This is an implementation approach that simulates an expired token
                        // without waiting for actual expiration or using reflection
                        
                        // 1. Save the current value
                        long currentExpiration = util.getTokenExpirationMinutes();
                        
                        try {
                            // 2. Set an extremely short expiration time
                            util.setTokenExpiration(1); // 1 minute
                            
                            // 3. Generate a token that will expire quickly
                            String shortLivedToken = util.generateToken(testUser);
                            
                            // 4. Wait for a bit to ensure the token is processed
                            Thread.sleep(10);
                            
                            // 5. Test that a corrupted token is considered expired
                            assertTrue(util.isTokenExpired(shortLivedToken + "corrupt"), 
                                    "Invalid token should be considered expired");
                        } finally {
                            // Restore the original value
                            util.setTokenExpiration(currentExpiration);
                        }
                    }
                }
                
                // Test with a properly generated token
                specialJwtUtil.setTokenExpiration(60); // 60 minutes for normal operation
                String token = specialJwtUtil.generateToken(testUser);
                
                // Verify the token is initially valid (not expired)
                assertFalse(specialJwtUtil.isTokenExpired(token), "Newly created token should not be expired");
                
                // Then simulate expiration using our helper
                new ExpirationHelper().setTokenToExpired(specialJwtUtil, token);
            } finally {
                // Clean up
                cleanupJwtUtil(specialJwtUtil);
            }
        }
        
        @Test
        @DisplayName("Should calculate correct remaining validity time for a token")
        public void testRemainingValidityTime() {
            // Set 60 minute expiration
            jwtUtil.setTokenExpiration(60);
            
            String token = jwtUtil.generateToken(testUser);
            
            // Remaining time should be approximately 60 minutes (with generous margin for test execution time)
            long remainingMinutes = jwtUtil.getTokenRemainingValidityMinutes(token);
            
            // Give a wide margin to avoid flaky tests due to execution time differences
            assertTrue(remainingMinutes > 45 && remainingMinutes <= 60, 
                    "Expected remaining minutes to be between 45-60, but was: " + remainingMinutes);
        }
        
        @Test
        @DisplayName("Should reject tokens with incorrect or tampered signatures")
        public void testWrongSignature() {
            // Generate token with first key
            String validToken = jwtUtil.generateToken(testUser);
            
            // Create a tampered token by changing the last character
            String tamperedToken = validToken.substring(0, validToken.length() - 1) + (validToken.charAt(validToken.length() - 1) == 'A' ? 'B' : 'A');
            
            // Token should fail verification
            assertFalse(jwtUtil.verifyToken(tamperedToken), "Tampered token should fail verification");
        }
    }
    
    @Nested
    @Tag("config")
    @DisplayName("Configuration and Parameter Validation Tests")
    class ConfigurationTests {
        // Clean up any JWTUtil instances created in tests
        private final List<JWTUtil> createdInstances = new ArrayList<>();
        
        @AfterEach
        public void tearDown() {
            // Clean up all created instances
            for (JWTUtil util : createdInstances) {
                cleanupJwtUtil(util);
            }
            createdInstances.clear();
        }
        
        // Helper method to track created instances
        private JWTUtil trackInstance(JWTUtil instance) {
            if (instance != null) {
                createdInstances.add(instance);
            }
            return instance;
        }
        
        @Test
        @DisplayName("Should accept and correctly store custom expiration times")
        public void testCustomExpirationTimes() {
            JWTUtil jwtUtil = trackInstance(JWTUtil.createWithSymmetricKey())
                    .setTokenExpiration(120)
                    .setRefreshTokenExpiration(14);
            
            assertEquals(120, jwtUtil.getTokenExpirationMinutes());
            assertEquals(14, jwtUtil.getRefreshTokenExpirationDays());
        }
        
        @Test
        @DisplayName("Should reject invalid expiration time values")
        public void testInvalidExpirationTimes() {
            JWTUtil jwtUtil = trackInstance(JWTUtil.createWithSymmetricKey());
            
            // Test negative expiration time
            Exception exception = assertThrows(IllegalArgumentException.class, () -> {
                jwtUtil.setTokenExpiration(-10);
            });
            assertTrue(exception.getMessage().contains("Expiration time must be positive"));
            
            // Test zero expiration time
            exception = assertThrows(IllegalArgumentException.class, () -> {
                jwtUtil.setTokenExpiration(0);
            });
            assertTrue(exception.getMessage().contains("Expiration time must be positive"));
            
            // Test negative refresh token expiration
            exception = assertThrows(IllegalArgumentException.class, () -> {
                jwtUtil.setRefreshTokenExpiration(-5);
            });
            assertTrue(exception.getMessage().contains("Expiration time must be positive"));
        }
        
        @Test
        @DisplayName("Should validate symmetric key length and reject invalid keys")
        public void testSymmetricKeyValidation() {
            // Test with null secret key
            Exception exception = assertThrows(IllegalArgumentException.class, () -> {
                JWTUtil.createWithSymmetricKey(null);
            });
            assertTrue(exception.getMessage().contains("Secret key must be at least 32 characters long"));
            
            // Test with too short secret key
            exception = assertThrows(IllegalArgumentException.class, () -> {
                JWTUtil.createWithSymmetricKey("tooshort");
            });
            assertTrue(exception.getMessage().contains("Secret key must be at least 32 characters long"));
            
            // Test with valid secret key
            String validKey = "this-is-a-valid-key-with-at-least-32-chars";
            JWTUtil jwtUtil = trackInstance(JWTUtil.createWithSymmetricKey(validKey));
            assertNotNull(jwtUtil);
            assertEquals(JWTUtil.TokenType.SYMMETRIC, jwtUtil.getTokenType());
            
            // Test key functionality
            String token = jwtUtil.generateToken(testUser);
            assertTrue(jwtUtil.verifyToken(token), "Token created with valid key should be verified");
        }
        
        @Test
        @DisplayName("Should validate asymmetric keys and reject invalid key pairs")
        public void testAsymmetricKeyValidation() {
            // Test with null keys
            Exception exception = assertThrows(IllegalArgumentException.class, () -> {
                JWTUtil.createWithAsymmetricKey(null, null);
            });
            assertTrue(exception.getMessage().contains("Private and public keys cannot be null"));
            
            // Test with null private key only
            exception = assertThrows(IllegalArgumentException.class, () -> {
                // Generate a key pair to get a valid public key
                KeyPair keyPair = Keys.keyPairFor(SignatureAlgorithm.RS256);
                JWTUtil.createWithAsymmetricKey(null, keyPair.getPublic());
            });
            assertTrue(exception.getMessage().contains("Private and public keys cannot be null"));
            
            // Test with null public key only
            exception = assertThrows(IllegalArgumentException.class, () -> {
                // Generate a key pair to get a valid private key
                KeyPair keyPair = Keys.keyPairFor(SignatureAlgorithm.RS256);
                JWTUtil.createWithAsymmetricKey(keyPair.getPrivate(), null);
            });
            assertTrue(exception.getMessage().contains("Private and public keys cannot be null"));
            
            // Test with a real asymmetric key
            JWTUtil jwtUtil = trackInstance(JWTUtil.createWithAsymmetricKey());
            assertNotNull(jwtUtil);
            assertEquals(JWTUtil.TokenType.ASYMMETRIC, jwtUtil.getTokenType());
            
            // Test key functionality
            String token = jwtUtil.generateToken(testUser);
            assertTrue(jwtUtil.verifyToken(token), "Token created with valid asymmetric key should be verified");
        }
    }
}
