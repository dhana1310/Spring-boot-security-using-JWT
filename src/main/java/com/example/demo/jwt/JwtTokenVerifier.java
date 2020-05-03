package com.example.demo.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import lombok.AllArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.crypto.SecretKey;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

@AllArgsConstructor
public class JwtTokenVerifier extends OncePerRequestFilter {

    private final JwtProperties jwtProperties;
    private final SecretKey secretKey;


    // token in the header will be like follows
    // "Authorization": "Bearer eyJhbGciOiJIUzM4NCJ9.eyJzdWIiOiJkaGFuYSIsImF1dGhvcml0aWVzIjpbeyJhdXRob3JpdHkiOiJST0xFX1NUVURFTlQifSx7ImF1dGhvcml0eSI6IlNUVURFTlRfUkVBRCJ9XSwiaWF0IjoxNTg4NTEyMjkxLCJleHAiOjE1ODkwNDkwMDAsImlzcyI6Ik15LXNwcmluZy10b2tlbi1pc3N1ZXIifQ.BbdG6JE3OB2llEckJP8KbHYtO3ZAfmQfH0yVGK3Aqys97yHcYYeWlC6_rHyeLEY9"

    // this token will be verified as follows
    // to see the token in decoded form, use https://jwt.io/

//    Decoded token ->
    /*
    // HEADER:ALGORITHM & TOKEN TYPE
    {
        "alg": "HS384"
    }

    // PAYLOAD:DATA
    {
        "sub": "dhana",
        "authorities": [
            {
                "authority": "ROLE_STUDENT"
            },
            {
                "authority": "STUDENT_READ"
            }
        ],
        "iat": 1588512291,
        "exp": 1589049000,
        "iss": "My-spring-token-issuer"
    }
    // VERIFY SIGNATURE
    HMACSHA256(
            base64UrlEncode(header) + "." +
    base64UrlEncode(payload),

    "your-256-bit-secret")
    */

    @Override
    @SuppressWarnings("unchecked")
    protected void doFilterInternal(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse,
                                    FilterChain filterChain) throws ServletException, IOException {

        String token = "";
        String authorizationToken = httpServletRequest.getHeader("Authorization");
        if (StringUtils.isEmpty(authorizationToken) || !authorizationToken.startsWith(jwtProperties.getTokenPrefix())) {
            filterChain.doFilter(httpServletRequest, httpServletResponse);
            return;
        }
        try {
            token = authorizationToken.replace(jwtProperties.getTokenPrefix(), "");
            Jws<Claims> claimsJws = Jwts.parserBuilder()
                    .setSigningKey(secretKey).build().parseClaimsJws(token);

            Claims body = claimsJws.getBody();
            String username = body.getSubject();

            var authorities = (List<Map<String, String>>) body.get(jwtProperties.getAuthoritiesKey());
            Set<GrantedAuthority> accessSet = authorities.stream().map(m -> new SimpleGrantedAuthority(m.get("authority"))).collect(Collectors.toSet());

            Authentication authentication = new UsernamePasswordAuthenticationToken(username, null, accessSet);
            SecurityContextHolder.getContext().setAuthentication(authentication);

        } catch (JwtException e) {
            throw new IllegalStateException(String.format("Token %s is invalid", token));
        }
        filterChain.doFilter(httpServletRequest, httpServletResponse);
    }
}
