package com.swiftHearty.model;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * UserDetails class that holds user information for JWT token generation.
 * This class uses the Builder pattern for easy and flexible object creation.
 * It stores essential user information, roles, and custom claims.
 *
 * @author SwiftHearty
 * @version 1.0
 */
public class UserDetails {
    
    // Essential user information
    private final String userId;
    private final String username;
    private final String email;
    
    // Role information
    private final List<String> roles;
    
    // Custom claims for additional user information
    private final Map<String, Object> customClaims;
    
    /**
     * Private constructor used by the Builder.
     * 
     * @param builder The builder containing the user details
     */
    private UserDetails(Builder builder) {
        this.userId = builder.userId;
        this.username = builder.username;
        this.email = builder.email;
        this.roles = Collections.unmodifiableList(new ArrayList<>(builder.roles));
        this.customClaims = Collections.unmodifiableMap(new HashMap<>(builder.customClaims));
    }
    
    /**
     * Get the user's unique identifier.
     * 
     * @return The user ID
     */
    public String getUserId() {
        return userId;
    }
    
    /**
     * Get the username.
     * 
     * @return The username
     */
    public String getUsername() {
        return username;
    }
    
    /**
     * Get the user's email address.
     * 
     * @return The email address
     */
    public String getEmail() {
        return email;
    }
    
    /**
     * Get the user's roles.
     * 
     * @return An unmodifiable list of roles
     */
    public List<String> getRoles() {
        return roles;
    }
    
    /**
     * Check if the user has a specific role.
     * 
     * @param role The role to check
     * @return true if the user has the role, false otherwise
     */
    public boolean hasRole(String role) {
        return roles.contains(role);
    }
    
    /**
     * Get custom claims associated with the user.
     * 
     * @return An unmodifiable map of custom claims
     */
    public Map<String, Object> getCustomClaims() {
        return customClaims;
    }
    
    /**
     * Get a specific custom claim value.
     * 
     * @param key The claim key
     * @return The claim value or null if not found
     */
    public Object getCustomClaim(String key) {
        return customClaims.get(key);
    }
    
    /**
     * Creates a new Builder instance for creating UserDetails objects.
     * 
     * @return A new Builder instance
     */
    public static Builder builder() {
        return new Builder();
    }
    
    /**
     * Builder class for creating UserDetails objects.
     */
    public static class Builder {
        private String userId;
        private String username;
        private String email;
        private List<String> roles = new ArrayList<>();
        private Map<String, Object> customClaims = new HashMap<>();
        
        /**
         * Set the user ID.
         * 
         * @param userId The user's unique identifier
         * @return This builder for method chaining
         */
        public Builder userId(String userId) {
            this.userId = userId;
            return this;
        }
        
        /**
         * Set the username.
         * 
         * @param username The username
         * @return This builder for method chaining
         */
        public Builder username(String username) {
            this.username = username;
            return this;
        }
        
        /**
         * Set the email address.
         * 
         * @param email The user's email address
         * @return This builder for method chaining
         */
        public Builder email(String email) {
            this.email = email;
            return this;
        }
        
        /**
         * Add a role to the user.
         * 
         * @param role The role to add
         * @return This builder for method chaining
         */
        public Builder addRole(String role) {
            this.roles.add(role);
            return this;
        }
        
        /**
         * Set all roles for the user (replaces any existing roles).
         * 
         * @param roles The list of roles
         * @return This builder for method chaining
         */
        public Builder roles(List<String> roles) {
            this.roles = new ArrayList<>(roles);
            return this;
        }
        
        /**
         * Add a custom claim to the user.
         * 
         * @param key The claim key
         * @param value The claim value
         * @return This builder for method chaining
         */
        public Builder addCustomClaim(String key, Object value) {
            this.customClaims.put(key, value);
            return this;
        }
        
        /**
         * Set all custom claims for the user (replaces any existing claims).
         * 
         * @param claims The map of custom claims
         * @return This builder for method chaining
         */
        public Builder customClaims(Map<String, Object> claims) {
            this.customClaims = new HashMap<>(claims);
            return this;
        }
        
        /**
         * Build the UserDetails object.
         * 
         * @return A new UserDetails instance
         * @throws IllegalArgumentException if required fields are missing
         */
        public UserDetails build() {
            // Validate required fields
            if (userId == null || userId.trim().isEmpty()) {
                throw new IllegalArgumentException("User ID is required");
            }
            if (username == null || username.trim().isEmpty()) {
                throw new IllegalArgumentException("Username is required");
            }
            
            return new UserDetails(this);
        }
    }
    
    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        UserDetails that = (UserDetails) o;
        return Objects.equals(userId, that.userId);
    }

    @Override
    public int hashCode() {
        return Objects.hash(userId);
    }

    @Override
    public String toString() {
        return "UserDetails{" +
                "userId='" + userId + '\'' +
                ", username='" + username + '\'' +
                ", email='" + email + '\'' +
                ", roles=" + roles +
                ", customClaims=" + customClaims +
                '}';
    }
}

