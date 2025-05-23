package com.swiftHearty.jwt;

import com.swiftHearty.model.UserDetails;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.SecretKey;
import java.security.Key;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Utility class for JWT operations, inspired by Python's pyjwt.
 * Supports symmetric (HS256) and asymmetric (RS256) keys, token generation,
 * verification, claims extraction, role-based checks, and blacklisting.
 * Usage:
 *   JWTUtil jwtUtil = JWTUtil.createWithSymmetricKey();
 *   String token = jwtUtil.generateToken(userDetails);
 *   boolean isValid = jwtUtil.verifyToken(token);
 *   Claims claims = jwtUtil.getClaims(token);
 */
public class JWTUtil {
    private static final Logger logger = LoggerFactory.getLogger(JWTUtil.class);

    private static final long DEFAULT_TOKEN_EXPIRATION_MINUTES = 60;
    private static final long DEFAULT_REFRESH_TOKEN_EXPIRATION_DAYS = 7;

    private static final String CLAIM_USER_ID = "userId";
    private static final String CLAIM_USERNAME = "username";
    private static final String CLAIM_EMAIL = "email";
    private static final String CLAIM_ROLES = "roles";

    private final Key signingKey;
    private final Key verificationKey;
    private final TokenType tokenType;
    private long tokenExpirationMinutes = DEFAULT_TOKEN_EXPIRATION_MINUTES;
    private long refreshTokenExpirationDays = DEFAULT_REFRESH_TOKEN_EXPIRATION_DAYS;
    private final Set<String> blacklist = Collections.newSetFromMap(new ConcurrentHashMap<>());

    public enum TokenType {
        SYMMETRIC,
        ASYMMETRIC
    }

    public static JWTUtil createWithSymmetricKey() {
        return new JWTUtil(Keys.secretKeyFor(io.jsonwebtoken.SignatureAlgorithm.HS256), TokenType.SYMMETRIC);
    }

    public static JWTUtil createWithSymmetricKey(String secretKey) {
        if (secretKey == null || secretKey.length() < 32) {
            throw new IllegalArgumentException("Secret key must be at least 32 characters long");
        }
        return new JWTUtil(Keys.hmacShaKeyFor(secretKey.getBytes()), TokenType.SYMMETRIC);
    }

    public static JWTUtil createWithAsymmetricKey() {
        KeyPair keyPair = Keys.keyPairFor(io.jsonwebtoken.SignatureAlgorithm.RS256);
        return new JWTUtil(keyPair.getPrivate(), keyPair.getPublic(), TokenType.ASYMMETRIC);
    }

    public static JWTUtil createWithAsymmetricKey(PrivateKey privateKey, PublicKey publicKey) {
        if (privateKey == null || publicKey == null) {
            throw new IllegalArgumentException("Private and public keys cannot be null");
        }
        return new JWTUtil(privateKey, publicKey, TokenType.ASYMMETRIC);
    }

    private JWTUtil(Key key, TokenType tokenType) {
        this.signingKey = key;
        this.verificationKey = key;
        this.tokenType = tokenType;
    }

    private JWTUtil(PrivateKey privateKey, PublicKey publicKey, TokenType tokenType) {
        this.signingKey = privateKey;
        this.verificationKey = publicKey;
        this.tokenType = tokenType;
    }

    public JWTUtil setTokenExpiration(long minutes) {
        if (minutes <= 0) {
            throw new IllegalArgumentException("Expiration time must be positive");
        }
        this.tokenExpirationMinutes = minutes;
        return this;
    }

    public JWTUtil setRefreshTokenExpiration(long days) {
        if (days <= 0) {
            throw new IllegalArgumentException("Expiration time must be positive");
        }
        this.refreshTokenExpirationDays = days;
        return this;
    }

    public String generateToken(UserDetails userDetails) {
        if (userDetails == null) {
            throw new IllegalArgumentException("User details cannot be null");
        }
        return generateTokenInternal(userDetails, userDetails.getRoles());
    }

    public String generateTokenWithRoles(UserDetails userDetails, List<String> roles) {
        if (userDetails == null) {
            throw new IllegalArgumentException("User details cannot be null");
        }
        return generateTokenInternal(userDetails, roles != null ? roles : Collections.emptyList());
    }

    public String generateRefreshToken(UserDetails userDetails) {
        if (userDetails == null) {
            throw new IllegalArgumentException("User details cannot be null");
        }
        Date now = new Date();
        Date expiration = Date.from(Instant.now().plus(refreshTokenExpirationDays, ChronoUnit.DAYS));

        return Jwts.builder()
                .setSubject(userDetails.getUserId())
                .claim(CLAIM_USER_ID, userDetails.getUserId())
                .setId(UUID.randomUUID().toString())
                .setIssuedAt(now)
                .setExpiration(expiration)
                .signWith(signingKey)
                .compact();
    }

    public boolean verifyToken(String token) {
        try {
            if (token == null || token.trim().isEmpty() || blacklist.contains(token)) {
                logger.debug("Token verification failed: null, empty, or blacklisted");
                return false;
            }
            Jwts.parserBuilder()
                    .setSigningKey(verificationKey)
                    .build()
                    .parseClaimsJws(token);
            return true;
        } catch (JwtException | IllegalArgumentException e) {
            logger.debug("Token verification failed: {}", e.getMessage());
            return false;
        }
    }

    public boolean verifyTokenAndCheckRole(String token, String requiredRole) {
        try {
            if (!verifyToken(token)) {
                return false;
            }
            Claims claims = getClaims(token);
            @SuppressWarnings("unchecked")
            List<String> roles = claims.get(CLAIM_ROLES, List.class);
            return roles != null && roles.contains(requiredRole);
        } catch (JwtException e) {
            logger.debug("Role check failed: {}", e.getMessage());
            return false;
        }
    }

    public Claims getClaims(String token) {
        if (token == null || token.trim().isEmpty()) {
            throw new IllegalArgumentException("Token cannot be null or empty");
        }
        try {
            return Jwts.parserBuilder()
                    .setSigningKey(verificationKey)
                    .build()
                    .parseClaimsJws(token)
                    .getBody();
        } catch (JwtException e) {
            logger.error("Failed to parse token: {}", e.getMessage());
            throw e;
        }
    }

    public UserDetails getUserFromToken(String token) {
        Claims claims = getClaims(token);
        @SuppressWarnings("unchecked")
        List<String> roles = claims.get(CLAIM_ROLES, List.class);
        if (roles == null) {
            roles = Collections.emptyList();
        }
        Map<String, Object> customClaims = new HashMap<>(claims);
        customClaims.remove(CLAIM_USER_ID);
        customClaims.remove(CLAIM_USERNAME);
        customClaims.remove(CLAIM_EMAIL);
        customClaims.remove(CLAIM_ROLES);
        customClaims.remove(Claims.SUBJECT);
        customClaims.remove(Claims.ISSUED_AT);
        customClaims.remove(Claims.EXPIRATION);
        customClaims.remove(Claims.ID);

        return UserDetails.builder()
                .userId(claims.get(CLAIM_USER_ID, String.class))
                .username(claims.get(CLAIM_USERNAME, String.class))
                .email(claims.get(CLAIM_EMAIL, String.class))
                .roles(roles)
                .customClaims(customClaims)
                .build();
    }

    public String refreshToken(String token) {
        if (token == null || token.trim().isEmpty()) {
            throw new IllegalArgumentException("Token cannot be null or empty");
        }
        if (blacklist.contains(token)) {
            throw new JwtException("Token is blacklisted");
        }
        if (!verifyToken(token)) {
            throw new JwtException("Invalid or expired token");
        }
        UserDetails user = getUserFromToken(token);
        blacklistToken(token);
        return generateToken(user);
    }

    public void blacklistToken(String token) {
        if (token != null && !token.trim().isEmpty()) {
            blacklist.add(token);
            logger.debug("Blacklisted token, size: {}", blacklist.size());
        }
    }

    public void clearBlacklist() {
        blacklist.clear();
    }

    public int getBlacklistSize() {
        return blacklist.size();
    }

    public boolean isTokenExpired(String token) {
        try {
            getClaims(token);
            return false;
        } catch (io.jsonwebtoken.ExpiredJwtException e) {
            return true;
        } catch (JwtException e) {
            logger.debug("Error checking token expiration: {}", e.getMessage());
            return true;
        }
    }

    public long getTokenRemainingValidityMinutes(String token) {
        try {
            Claims claims = getClaims(token);
            long expiration = claims.getExpiration().getTime();
            long now = Instant.now().toEpochMilli();
            return Math.max(0, (expiration - now) / (60 * 1000));
        } catch (JwtException e) {
            logger.debug("Error calculating token validity: {}", e.getMessage());
            return 0;
        }
    }

    public TokenType getTokenType() {
        return tokenType;
    }

    public long getTokenExpirationMinutes() {
        return tokenExpirationMinutes;
    }

    public long getRefreshTokenExpirationDays() {
        return refreshTokenExpirationDays;
    }

    private String generateTokenInternal(UserDetails userDetails, List<String> roles) {
        Date now = new Date();
        Date expiration = Date.from(Instant.now().plus(tokenExpirationMinutes, ChronoUnit.MINUTES));

        return Jwts.builder()
                .setSubject(userDetails.getUserId())
                .claim(CLAIM_USER_ID, userDetails.getUserId())
                .claim(CLAIM_USERNAME, userDetails.getUsername())
                .claim(CLAIM_EMAIL, userDetails.getEmail())
                .claim(CLAIM_ROLES, roles)
                .addClaims(userDetails.getCustomClaims())
                .setId(UUID.randomUUID().toString())
                .setIssuedAt(now)
                .setExpiration(expiration)
                .signWith(signingKey)
                .compact();
    }
}