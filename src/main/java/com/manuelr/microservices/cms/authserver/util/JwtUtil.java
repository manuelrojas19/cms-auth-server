package com.manuelr.microservices.cms.authserver.util;

import com.manuelr.microservices.cms.authserver.dto.Token;
import io.jsonwebtoken.*;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Date;
import java.util.Objects;

@Component
public class JwtUtil {
    @Value("${authentication-dev.auth.tokenSecret}")
    private String tokenSecret;

    @Value("${authentication-dev.auth.tokenExpirationMsec}")
    private Long tokenExpirationMsec;

    @Value("${authentication-dev.auth.refreshTokenExpirationMsec}")
    private Long refreshTokenExpirationMsec;

    public Token generateAccessToken(String subject) {
        Date now = new Date();
        Long duration = now.getTime() + tokenExpirationMsec;
        Date expiryDate = new Date(duration);
        String token = Jwts.builder()
                .setSubject(subject)
                .setIssuedAt(now)
                .setExpiration(expiryDate)
                .signWith(SignatureAlgorithm.HS512, tokenSecret)
                .compact();
        return new Token(Token.TokenType.ACCESS, token, duration,
                LocalDateTime.ofInstant(expiryDate.toInstant(), ZoneId.systemDefault()));
    }

    public Token generateRefreshToken(String subject) {
        Date now = new Date();
        Long duration = now.getTime() + refreshTokenExpirationMsec;
        Date expiryDate = new Date(duration);
        String token = Jwts.builder()
                .setSubject(subject)
                .setIssuedAt(now)
                .setExpiration(expiryDate)
                .signWith(SignatureAlgorithm.HS512, tokenSecret)
                .compact();
        return new Token(Token.TokenType.REFRESH, token, duration,
                LocalDateTime.ofInstant(expiryDate.toInstant(), ZoneId.systemDefault()));
    }

    public String getUsernameFromToken(String token) {
        Claims claims = Jwts.parser().setSigningKey(tokenSecret).parseClaimsJws(token).getBody();
        return claims.getSubject();
    }

    public LocalDateTime getExpiryDateFromToken(String token) {
        Claims claims = Jwts.parser().setSigningKey(tokenSecret).parseClaimsJws(token).getBody();
        return LocalDateTime.ofInstant(claims.getExpiration().toInstant(), ZoneId.systemDefault());
    }

    public boolean validateToken(String token) {
        if (Objects.isNull(token)) return false;
        try {
            Jwts.parser().setSigningKey(tokenSecret).parse(token);
            return true;
        } catch (SignatureException ex) {
            ex.printStackTrace();
        } catch (MalformedJwtException ex) {
            ex.printStackTrace();
        } catch (ExpiredJwtException ex) {
            ex.printStackTrace();
        } catch (UnsupportedJwtException ex) {
            ex.printStackTrace();
        } catch (IllegalArgumentException ex) {
            ex.printStackTrace();
        }
        return false;
    }
}
