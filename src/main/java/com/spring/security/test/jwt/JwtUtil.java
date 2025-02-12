package com.spring.security.test.jwt;

import java.security.Key;
import java.util.Date;
import java.util.function.Function;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;

@Component // Marks this class as a Spring-managed component (bean)
public class JwtUtil {

	// A secret key used to sign JWT tokens (must be long enough for HS256)
	private final String SECRET_KEY = "heyThisIsAdityaPandhareFromKolhapurMaharashtra";

	 // Generates a signing key from the secret key
	private Key getSignInKey() {
		return Keys.hmacShaKeyFor(SECRET_KEY.getBytes());
	}

	// Extracts the username (subject) from the JWT token
	private String extractUserName(String token) {
		return extractClaim(token, Claims::getSubject);
	}

	// Extracts a specific claim from the JWT token
	private <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
		final Claims claim = extractAllClaims(token);
		return claimsResolver.apply(claim);
	}

	// Parses the JWT token and retrieves all claims
	private Claims extractAllClaims(String token) {

		return Jwts.parserBuilder().setSigningKey(getSignInKey()).build().parseClaimsJws(token).getBody();
	}

	// Generates a JWT token for a given UserDetails object
	private String generateToken(UserDetails userDetails) {
		return Jwts.builder().setSubject(userDetails.getUsername()).setIssuedAt(new Date())
				.setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 60)) // 1 hour validity
				.signWith(getSignInKey(), SignatureAlgorithm.HS256).compact();
	}

	// Validates the token by checking its username and expiration
	public boolean validateToken(String token, UserDetails userDetails) {
		final String userName = extractUserName(token);
		return (userName.equals(userDetails.getUsername()) && !isTokenExpired(token));
	}

	// Checks if the token is expired
	public boolean isTokenExpired(String token) {
		return extractClaim(token, Claims::getExpiration).before(new Date());
	}

}
