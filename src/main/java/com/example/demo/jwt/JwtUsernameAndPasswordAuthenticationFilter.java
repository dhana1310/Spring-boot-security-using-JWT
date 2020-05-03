package com.example.demo.jwt;

import io.jsonwebtoken.Jwts;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.util.StringUtils;

import javax.crypto.SecretKey;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.sql.Date;
import java.time.LocalDate;
import java.util.Base64;
import java.util.StringTokenizer;

@Slf4j
@AllArgsConstructor
public class JwtUsernameAndPasswordAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private final AuthenticationManager authenticationManager;
    private final JwtProperties jwtProperties;
    private final SecretKey secretKey;

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {

        // when the credentials are passed, it is sent in the header as follows
        // "Authorization": "Basic ZmFtaWE6cGFzc3dvcmQ="  // before decoding
        // "Authorization": "Basic username:password"  // after decoding
        String headerValue = request.getHeader("Authorization");
        if (StringUtils.isEmpty(headerValue) || !headerValue.startsWith(jwtProperties.getTokenPrefixForTokenGeneration())) {
            authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(null, null));
        }
        Authentication authenticateRequest = getAuthenticationUsingHeader(headerValue);
        return authenticationManager.authenticate(authenticateRequest);
    }

    private Authentication getAuthenticationUsingHeader(String headerValue) {
        String encodedUserNameAndPassword = headerValue.replace(jwtProperties.getTokenPrefixForTokenGeneration(), "");
        String decodedUserNameAndPassword = new String(Base64.getDecoder().decode(encodedUserNameAndPassword));

        StringTokenizer stringTokenizer = new StringTokenizer(decodedUserNameAndPassword, ":");
        String username = stringTokenizer.nextToken();
        String password = stringTokenizer.nextToken();

        return new UsernamePasswordAuthenticationToken(username, password);
    }

    // if the credentials are correct, then create a token and send back to the user,
    // so that next time onwards he will use this token instead of actual credentials
    @Override
    protected void successfulAuthentication(HttpServletRequest request,
                                            HttpServletResponse response,
                                            FilterChain chain,
                                            Authentication authResult) {
        String token = Jwts.builder()
                .setSubject(authResult.getName())  // setting the username
                .claim(jwtProperties.getAuthoritiesKey(), authResult.getAuthorities()) // setting the permissions
                .setIssuedAt(new java.util.Date()) // start date of token
                .setExpiration(Date.valueOf(LocalDate.now().plusDays(jwtProperties.getValidityInDays()))) // end date of token
                .setIssuer(jwtProperties.getIssuer())  // Issuer
//                .setId("some-primary-key-in-database")
                .signWith(secretKey)  // key using which it is signed
                .compact();

        response.addHeader("Authorization", jwtProperties.getTokenPrefix() + token);

    }
}
