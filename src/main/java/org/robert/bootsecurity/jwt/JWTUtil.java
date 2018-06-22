package org.robert.bootsecurity.jwt;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.CompressionCodecs;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.*;

public class JWTUtil {
    public static final String ROLE_REFRESH_TOKEN = "ROLE_REFRESH_TOKEN";

    private static final String CLAIM_KEY_USER_ID = "user_id";
    private static final String CLAIM_KEY_AUTHORITIES = "scope";
    private static final String CLAIM_KEY_ACCOUNT_ENABLED = "enabled";
    private static final String CLAIM_KEY_ACCOUNT_NON_LOCKED = "non_locked";
    private static final String CLAIM_KEY_ACCOUNT_NON_EXPIRED = "non_expired";

    @Value("${jwt.secret}")
    private String secret;

    @Value("${jwt.access_token.expiration}")
    private Long access_token_expiration;

    @Value("${jwt.refresh_token.expiration}")
    private Long refresh_token_expiration;

    private final SignatureAlgorithm SIGNATURE_ALGORITHM = SignatureAlgorithm.HS256;

    public JWTUserDetails getUserFromToken(String token) {
        JWTUserDetails user;
        try {
            final Claims claims = getClaimsFromToken(token);
            long userId = getUserIdFromToken(token);
            String username = claims.getSubject();
            List roles = (List) claims.get(CLAIM_KEY_AUTHORITIES);
            Collection<? extends GrantedAuthority> authorities = parseArrayToAuthorities(roles);
            boolean account_enabled = (Boolean) claims.get(CLAIM_KEY_ACCOUNT_ENABLED);
            boolean account_non_locked = (Boolean) claims.get(CLAIM_KEY_ACCOUNT_NON_LOCKED);
            boolean account_non_expired = (Boolean) claims.get(CLAIM_KEY_ACCOUNT_NON_EXPIRED);

            user = new JWTUserDetails(userId, username, "password", account_enabled, account_non_expired, true, account_non_locked, authorities);
        } catch (Exception e) {
            user = null;
        }
        return user;
    }

    public long getUserIdFromToken(String token) {
        long userId;
        try {
            final Claims claims = getClaimsFromToken(token);
            userId = (Long) claims.get(CLAIM_KEY_USER_ID);
        } catch (Exception e) {
            userId = 0;
        }
        return userId;
    }

    public String getUsernameFromToken(String token) {
        String username;
        try {
            final Claims claims = getClaimsFromToken(token);
            username = claims.getSubject();
        } catch (Exception e) {
            username = null;
        }
        return username;
    }

    public Date getCreatedDateFromToken(String token) {
        Date created;
        try {
            final Claims claims = getClaimsFromToken(token);
            created = claims.getIssuedAt();
        } catch (Exception e) {
            created = null;
        }
        return created;
    }

    public Date getExpirationDateFromToken(String token) {
        Date expiration;
        try {
            final Claims claims = getClaimsFromToken(token);
            expiration = claims.getExpiration();
        } catch (Exception e) {
            expiration = null;
        }
        return expiration;
    }

    private Claims getClaimsFromToken(String token) {
        Claims claims;
        try {
            claims = Jwts.parser()
                    .setSigningKey(secret)
                    .parseClaimsJws(token)
                    .getBody();
        } catch (Exception e) {
            claims = null;
        }
        return claims;
    }

    private Date generateExpirationDate(long expiration) {
        return new Date(System.currentTimeMillis() + expiration * 1000);
    }

    private Boolean isTokenExpired(String token) {
        final Date expiration = getExpirationDateFromToken(token);
        return expiration.before(new Date());
    }

    private Boolean isCreatedBeforeLastPasswordReset(Date created, Date lastPasswordReset) {
        return (lastPasswordReset != null && created.before(lastPasswordReset));
    }

    public String generateAccessToken(UserDetails userDetails) throws JsonProcessingException {
        JWTUserDetails user = (JWTUserDetails) userDetails;
        Map<String, Object> claims = generateClaims(user);
        ObjectMapper mapper = new ObjectMapper();
        claims.put(CLAIM_KEY_AUTHORITIES, mapper.writeValueAsString(authoritiesToArray((user.getAuthorities()))));
        return generateAccessToken(user.getUsername(), claims);
    }

    private Map<String, Object> generateClaims(JWTUserDetails user) {
        Map<String, Object> claims = new HashMap<>();
        claims.put(CLAIM_KEY_USER_ID, user.getUserId());
        claims.put(CLAIM_KEY_ACCOUNT_ENABLED, user.isEnabled());
        claims.put(CLAIM_KEY_ACCOUNT_NON_LOCKED, user.isAccountNonLocked());
        claims.put(CLAIM_KEY_ACCOUNT_NON_EXPIRED, user.isAccountNonExpired());
        return claims;
    }

    private String generateAccessToken(String subject, Map<String, Object> claims) {
        return generateToken(subject, claims, access_token_expiration);
    }

    private List authoritiesToArray(Collection<? extends GrantedAuthority> authorities) {
        List<String> list = new ArrayList<>();
        for (GrantedAuthority ga : authorities) {
            list.add(ga.getAuthority());
        }
        return list;
    }

    private Collection<? extends GrantedAuthority> parseArrayToAuthorities(List roles) {
        Collection<GrantedAuthority> authorities = new ArrayList<>();
        SimpleGrantedAuthority authority;
        for (Object role : roles) {
            authority = new SimpleGrantedAuthority(role.toString());
            authorities.add(authority);
        }
        return authorities;
    }

    public String generateRefreshToken(UserDetails userDetails) {
        JWTUserDetails user = (JWTUserDetails) userDetails;
        Map<String, Object> claims = generateClaims(user);
        // 只授于更新 token 的权限
        String roles[] = new String[]{JWTUtil.ROLE_REFRESH_TOKEN};
        ObjectMapper mapper = new ObjectMapper();

        try {
            claims.put(CLAIM_KEY_AUTHORITIES, mapper.writeValueAsString(roles));
        } catch (JsonProcessingException e) {
            e.printStackTrace();
        }

        return generateRefreshToken(user.getUsername(), claims);
    }

    private String generateRefreshToken(String subject, Map<String, Object> claims) {
        return generateToken(subject, claims, refresh_token_expiration);
    }

    public Boolean canTokenBeRefreshed(String token, Date lastPasswordReset) {
        final Date created = getCreatedDateFromToken(token);
        return !isCreatedBeforeLastPasswordReset(created, lastPasswordReset)
                && (!isTokenExpired(token));
    }

    public String refreshToken(String token) {
        String refreshedToken;
        try {
            final Claims claims = getClaimsFromToken(token);
            refreshedToken = generateAccessToken(claims.getSubject(), claims);
        } catch (Exception e) {
            refreshedToken = null;
        }
        return refreshedToken;
    }

    private String generateToken(String subject, Map<String, Object> claims, long expiration) {
        return Jwts.builder()
                .setClaims(claims)
                .setSubject(subject)
                .setId(UUID.randomUUID().toString())
                .setIssuedAt(new Date())
                .setExpiration(generateExpirationDate(expiration))
                .compressWith(CompressionCodecs.DEFLATE)
                .signWith(SIGNATURE_ALGORITHM, secret)
                .compact();
    }

    public Boolean validateToken(String token, UserDetails userDetails) {
        JWTUserDetails user = (JWTUserDetails) userDetails;
        final long userId = getUserIdFromToken(token);
        final String username = getUsernameFromToken(token);
        // final Date created = getCreatedDateFromToken(token);
        // final Date expiration = getExpirationDateFromToken(token);
        return (userId == user.getUserId()
                && username.equals(user.getUsername())
                && !isTokenExpired(token)
                /* && !isCreatedBeforeLastPasswordReset(created, userDetails.getLastPasswordResetDate()) */
        );
    }

}

