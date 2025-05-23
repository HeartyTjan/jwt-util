package com.swiftHearty.model;

import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for the UserDetails class.
 * These tests verify the builder pattern, role management, custom claims handling,
 * and input validation.
 */
public class UserDetailsTest {

    /**
     * Tests the basic builder pattern functionality.
     */
    @Test
    public void testBuilder() {
        // Create user details with builder
        UserDetails user = UserDetails.builder()
                .userId("123")
                .username("johndoe")
                .email("john@example.com")
                .build();
        
        // Verify fields
        assertEquals("123", user.getUserId());
        assertEquals("johndoe", user.getUsername());
        assertEquals("john@example.com", user.getEmail());
        assertTrue(user.getRoles().isEmpty());
        assertTrue(user.getCustomClaims().isEmpty());
    }
    
    /**
     * Tests that required fields are validated.
     */
    @Test
    public void testRequiredFieldValidation() {
        // Test missing userId
        Exception exception = assertThrows(IllegalArgumentException.class, () -> {
            UserDetails.builder()
                    .username("johndoe")
                    .build();
        });
        assertTrue(exception.getMessage().contains("User ID is required"));
        
        // Test missing username
        exception = assertThrows(IllegalArgumentException.class, () -> {
            UserDetails.builder()
                    .userId("123")
                    .build();
        });
        assertTrue(exception.getMessage().contains("Username is required"));
        
        // Test empty userId
        exception = assertThrows(IllegalArgumentException.class, () -> {
            UserDetails.builder()
                    .userId("")
                    .username("johndoe")
                    .build();
        });
        assertTrue(exception.getMessage().contains("User ID is required"));
        
        // Test empty username
        exception = assertThrows(IllegalArgumentException.class, () -> {
            UserDetails.builder()
                    .userId("123")
                    .username("")
                    .build();
        });
        assertTrue(exception.getMessage().contains("Username is required"));
    }
    
    /**
     * Tests role management functionality.
     */
    @Test
    public void testRoleManagement() {
        // Test adding roles individually
        UserDetails user1 = UserDetails.builder()
                .userId("123")
                .username("johndoe")
                .addRole("ADMIN")
                .addRole("USER")
                .build();
        
        assertEquals(2, user1.getRoles().size());
        assertTrue(user1.getRoles().contains("ADMIN"));
        assertTrue(user1.getRoles().contains("USER"));
        assertTrue(user1.hasRole("ADMIN"));
        assertTrue(user1.hasRole("USER"));
        assertFalse(user1.hasRole("GUEST"));
        
        // Test setting roles as a list
        List<String> roles = Arrays.asList("DEVELOPER", "TESTER");
        UserDetails user2 = UserDetails.builder()
                .userId("456")
                .username("janedoe")
                .roles(roles)
                .build();
        
        assertEquals(2, user2.getRoles().size());
        assertTrue(user2.getRoles().contains("DEVELOPER"));
        assertTrue(user2.getRoles().contains("TESTER"));
        
        // Test that roles list is unmodifiable
        assertThrows(UnsupportedOperationException.class, () -> {
            user2.getRoles().add("ADMIN");
        });
    }
    
    /**
     * Tests custom claims handling.
     */
    @Test
    public void testCustomClaims() {
        // Test adding custom claims individually
        UserDetails user1 = UserDetails.builder()
                .userId("123")
                .username("johndoe")
                .addCustomClaim("department", "Engineering")
                .addCustomClaim("location", "New York")
                .build();
        
        assertEquals(2, user1.getCustomClaims().size());
        assertEquals("Engineering", user1.getCustomClaim("department"));
        assertEquals("New York", user1.getCustomClaim("location"));
        assertNull(user1.getCustomClaim("nonexistent"));
        
        // Test setting custom claims as a map
        Map<String, Object> claims = new HashMap<>();
        claims.put("age", 30);
        claims.put("active", true);
        
        UserDetails user2 = UserDetails.builder()
                .userId("456")
                .username("janedoe")
                .customClaims(claims)
                .build();
        
        assertEquals(2, user2.getCustomClaims().size());
        assertEquals(30, user2.getCustomClaim("age"));
        assertEquals(true, user2.getCustomClaim("active"));
        
        // Test that custom claims map is unmodifiable
        assertThrows(UnsupportedOperationException.class, () -> {
            user2.getCustomClaims().put("newClaim", "value");
        });
    }
    
    /**
     * Tests equals, hashCode, and toString methods.
     */
    @Test
    public void testObjectMethods() {
        UserDetails user1 = UserDetails.builder()
                .userId("123")
                .username("johndoe")
                .email("john@example.com")
                .build();
        
        UserDetails user2 = UserDetails.builder()
                .userId("123")
                .username("differentname")  // Different username but same ID
                .email("different@example.com")
                .build();
        
        UserDetails user3 = UserDetails.builder()
                .userId("456")  // Different ID
                .username("johndoe")
                .email("john@example.com")
                .build();
        
        // Test equals based on userId
        assertEquals(user1, user2);
        assertNotEquals(user1, user3);
        
        // Test hashCode based on userId
        assertEquals(user1.hashCode(), user2.hashCode());
        assertNotEquals(user1.hashCode(), user3.hashCode());
        
        // Test toString
        String toString = user1.toString();
        assertTrue(toString.contains("userId='123'"));
        assertTrue(toString.contains("username='johndoe'"));
        assertTrue(toString.contains("email='john@example.com'"));
    }
}

