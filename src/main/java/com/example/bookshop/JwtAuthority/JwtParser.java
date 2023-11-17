package com.example.bookshop.JwtAuthority;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwt;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;
import java.util.Collection;
import java.util.List;

public class JwtParser {

    Jwt<?, ?> jwtObject;

    public JwtParser(String jwt, String secretKey) {
        parseJwt(jwt, secretKey);
    }

    Jwt<?, ?> parseJwt(String jwt, String secretKey) {
        byte[] secretKeyBytes = Base64.getEncoder().encode(secretKey.getBytes());
        SecretKey signingKey = new SecretKeySpec(secretKeyBytes, SignatureAlgorithm.HS512.getJcaName());
        io.jsonwebtoken.JwtParser jwtParser = Jwts.parserBuilder()
                .setSigningKey(signingKey)
                .build();
        this.jwtObject = jwtParser.parse(jwt);
        return this.jwtObject;
    }

    public Collection<? extends GrantedAuthority> extractAccountRole() {
        String role = ((Claims)jwtObject.getBody()).get("authority", String.class);
        return List.<SimpleGrantedAuthority>of(new SimpleGrantedAuthority(role));
    }

    public String getEmail() {
        return ((Claims)jwtObject.getBody()).get("email", String.class);
    }

}
