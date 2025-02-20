package com.spring.security.test.controllers;

import java.util.HashMap;
import java.util.Map;

import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.spring.security.test.config.CustomUserDetailService;
import com.spring.security.test.entity.AuthRequest;
import com.spring.security.test.entity.AuthResponse;
import com.spring.security.test.jwt.JwtUtil;

@RestController
@RequestMapping("/auth")
public class AuthController {

	private final AuthenticationManager authenticationManager;
	private final JwtUtil jwtUtil;
	private final CustomUserDetailService userDetailsService;
	
	public AuthController(AuthenticationManager authenticationManager,JwtUtil jwtUtil,
			CustomUserDetailService userDetailsService){
		this.authenticationManager=authenticationManager;
		this.jwtUtil=jwtUtil;
		this.userDetailsService=userDetailsService;
	}
	
	@PostMapping("/login")
	public ResponseEntity<?> login(@RequestBody AuthRequest authRequest) {
		
		try {
//			System.out.println("login called"+authRequest.password);
			
			authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(authRequest.username, authRequest.password));
			UserDetails userDetails=userDetailsService.loadUserByUsername(authRequest.username);
			
//			System.out.println("userDetails : "+userDetails);
			
			String accessToken=jwtUtil.generateToken(userDetails);
			String refreshToken=jwtUtil.generateRefreshToken(userDetails);
			Map<String , String> tokens = new HashMap<>();
			tokens.put("accessToken", accessToken);
			tokens.put("refreshToken", refreshToken);
			
//			System.out.println("token : "+token);
			
			return ResponseEntity.ok(tokens	);	
			
		}catch(Exception e) {
			System.out.println("login exception");
			return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid credintials");
		}
		
//		return jwtUtil.generateToken(userDetails);
	}
	
	@PostMapping("/refresh")
	public ResponseEntity<?> refreshToken(@RequestBody Map<String, String> requestMap){
		String refreshToken=requestMap.get("refreshToken");
		
		if(refreshToken==null) {
			return ResponseEntity.badRequest().body("Refresh token is missing");
		}
		try {
			// Optionally check if the token is a refresh token
			if(!jwtUtil.isRefreshToken(refreshToken))
			{
				return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid token type");
			}
			
			// Extract username from refresh token
			String userName=jwtUtil.extractUserName(refreshToken);
			UserDetails userDetails = userDetailsService.loadUserByUsername(userName);
			
			// Validate refresh token
			if(!jwtUtil.validateToken(refreshToken, userDetails)) {
				return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid or expired refresh token");
			}
			
			//Generate new tokens
			String newAccessToken=jwtUtil.generateToken(userDetails);
			String newRefreshToken=jwtUtil.generateRefreshToken(userDetails);
			
			Map<String,String> tokens=new HashMap<>();
			tokens.put("newAccessToken", newAccessToken);
			tokens.put("newRefreshToken", newRefreshToken);
			
			return ResponseEntity.ok(tokens);
		}catch(Exception e) {
			e.printStackTrace();
			return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Could not refresh token");
		}
	}
}
