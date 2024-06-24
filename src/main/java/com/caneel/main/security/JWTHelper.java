package com.caneel.main.security;

import com.caneel.main.models.User;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import jakarta.servlet.ServletException;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import java.util.Date;

@Component
public class JWTHelper {

    @Value("${jwt.token.secret}")
    private String tokenSecret;

    public String generateToken(User user)
    {
        String id = user.getId();
        Date now = new Date();
        Date expireAt = new Date(now.getTime() + (24 * 60 * 60 * 1000));

        String token = Jwts.builder()
                .setSubject(id)
                .setIssuedAt(now)
                .setExpiration(expireAt)
                .signWith(SignatureAlgorithm.HS256,tokenSecret)
                .compact();
        return token;
    }

    private Claims parseToken(String token)
    {
        Claims claims = Jwts.parserBuilder()
                .setSigningKey(tokenSecret)
                .build()
                .parseClaimsJws(token)
                .getBody();
        return claims;
    }

    public String verifyToken(String token) throws ServletException
    {
        Claims claims = this.parseToken(token);
        String sub = claims.getSubject();
        Date expireAt = claims.getExpiration();
        if(new Date().after(expireAt)){
            throw new ServletException("Token Expired");
        }
        return sub;
    }
}
