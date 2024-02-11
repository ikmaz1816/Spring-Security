package com.security.springgate.filter;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.function.Function;

@Component
public class JwtService {

    private final String key="404E635266556A586E3272357538782F413F4428472B4B6250645367566B5970";
    public String extractSubject(String token)
    {
        return getClaim(Claims::getSubject,token);
    }

    public Date extractExpiration(String token)
    {
        return getClaim(Claims::getExpiration,token);
    }
    private Key getSigningKey() {
        byte[] keys= Decoders.BASE64.decode(key);
        return Keys.hmacShaKeyFor(keys);
    }
    public Claims getAllClaims(String token)
    {
        return Jwts.parserBuilder()
                .setSigningKey(getSigningKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    public <T> T getClaim(Function<Claims,T> claimResolver, String token)
    {
        Claims claim=getAllClaims(token);
        return claimResolver.apply(claim);
    }
    public String generateTokenWithoutClaims(UserDetails userDetails)
    {
        return generateTokenBuilder(new HashMap<>(),userDetails,9000000);
    }
    public String generateToken(
            HashMap<String,Object> map,
            UserDetails userDetails
    )
    {
        return generateTokenBuilder(map,userDetails,9000000);
    }

    private String generateTokenBuilder(HashMap<String, Object> map, UserDetails userDetails, long expiration) {
        return Jwts.builder()
                .setClaims(map)
                .setSubject(userDetails.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + expiration))
                .signWith(getSigningKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    public boolean isTokenValid(String jwt,UserDetails userDetails)
    {
        String username=extractSubject(jwt);
        return username.equals(userDetails.getUsername()) && !isExpired(jwt);
    }

    private boolean isExpired(String jwt) {
        return extractExpiration(jwt).before(new Date());
    }


}
