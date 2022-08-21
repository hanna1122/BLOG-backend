package com.example.blog.jwt;

import com.example.blog.dto.LoginResponse;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import java.util.ArrayList;
import java.util.Collection;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Component
public class JwtTokenUtil {

    private static final String secret = "jwtpassword";

    public static final long ACCESS_TOKEN_EXPIRE_TIME = 30 * 60 * 1000L;
    public static final long REFRESH_TOKEN_EXPIRE_TIME = 7 * 24 * 60 * 60 * 1000L;

    public String getUsernameFromToken(String token) {
        return getClaimFromToken(token, Claims::getId);
    }

    public String getUserAuthFromToken(String token) {
        final Claims claims = getAllClaimsFromToken(token);
        return claims.get("role").toString();
    }

    public <T> T getClaimFromToken(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = getAllClaimsFromToken(token);
        return claimsResolver.apply(claims);
    }

    private Claims getAllClaimsFromToken(String token) {
        return Jwts.parser().setSigningKey(secret).parseClaimsJws(token).getBody();
    }


    public Long getExpirationDateFromToken(String token) {
        Date date = getClaimFromToken(token, Claims::getExpiration);
        Long now = new Date().getTime();
        return (date.getTime() - now);
    }

    public LoginResponse generateTokenByEmail(String id, String auth) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("role", auth);
        String accessToken = generateToken(id, claims, new Date(System.currentTimeMillis() + ACCESS_TOKEN_EXPIRE_TIME));
        String refreshToken = generateToken(id, claims, new Date(System.currentTimeMillis() + REFRESH_TOKEN_EXPIRE_TIME));

        return LoginResponse.builder()
                .accessToken(accessToken)
                .accessTime(ACCESS_TOKEN_EXPIRE_TIME)
                .refreshToken(refreshToken)
                .refreshTime(REFRESH_TOKEN_EXPIRE_TIME)
                .build();
    }

    public String generateToken(String id, Map<String, Object> claims, Date date) {
        return doGenerateToken(id, claims, date);
    }

    private String doGenerateToken(String id, Map<String, Object> claims, Date date) {
        return Jwts.builder()
                .setClaims(claims)
                .setId(id)
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(date)
                .signWith(SignatureAlgorithm.HS512, secret)
                .compact();
    }

    public Boolean validateToken(String token) {
        try {
            Jws<Claims> claims = Jwts.parser().setSigningKey(secret).parseClaimsJws(token);
            return !claims.getBody().getExpiration().before(new Date());
        } catch (Exception e) {
            return false;
        }
    }

    public Authentication getAuthentication(String token) {
        String username = getUsernameFromToken(token);
        String auth = getUserAuthFromToken(token);

        Collection<GrantedAuthority> authorities = new ArrayList<>();
        authorities.add(new SimpleGrantedAuthority(auth));

        UserDetails userDetails = User.builder().username(username).authorities(authorities).password("").build();
        return new UsernamePasswordAuthenticationToken(userDetails, "", authorities);
    }


}
