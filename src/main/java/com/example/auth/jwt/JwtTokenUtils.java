package com.example.auth.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.sql.Date;
import java.time.Instant;

@Slf4j
@Component
// JWT 생성, 인증 등의 기능을 가지고 있을 컴포넌트
public class JwtTokenUtils {
    // JWT 는 암호화를 거쳐서 만들어지는데,
    // 이를 위해서 암호키가 필요하다.
    private final Key signingKey;
    private final JwtParser jwtParser;

    public JwtTokenUtils(
            @Value("${jwt.secret}")
            String jwtSecret
    ) {
        this.signingKey = Keys.hmacShaKeyFor(jwtSecret.getBytes());
        // JWT 번역기 만들기
        this.jwtParser = Jwts
                .parserBuilder()
                .setSigningKey(this.signingKey)
                .build();
    }

    // 1. JWT가 유효한지 판단하는 메소드
    //    jjwt 라이브러리에서는 JWT 를 해석하는 과정에서
    //    유효하지 않으면 예외가 발생
    public boolean validate(String token) {
        try {
            // 정당한 JWT 면 true,
            // parseClaimsJws : 암호화된 JWT 를 해석하기 위한 메소드
            jwtParser.parseClaimsJws(token);
            return true;
        } catch (Exception e) {
            // 정당하지 않은 JWT 면 false
            log.warn("invalid jwt : {}", e.getClass());
            return false;
        }
    }

    // JWT 를 인자로 받고, 그 JWT 를 해석해서
    // 사용자 정보를 회수하는 메소드
    public Claims parseClaims(String token) {
        return jwtParser
                .parseClaimsJws(token)
                .getBody();
    }

    // 주어진 사용자 정보를 바탕으로 JWT 를 문자열로 생성
    public String generateToken(UserDetails userDetails) {
        // Claims : JWT 에 담기는 정보의 단위를 Claim 이라 부른다.
        //          Claim 은 Claim 들을 담기위한 Map의 상속 interface
        Claims jwtClaims = Jwts.claims()
                .setSubject(userDetails.getUsername())
                .setIssuedAt(Date.from(Instant.now()))
                .setExpiration(Date.from(Instant.now().plusSeconds(3600)));

        return  Jwts.builder()
                .setClaims(jwtClaims)
                .signWith(signingKey)
                .compact();
    }
}
