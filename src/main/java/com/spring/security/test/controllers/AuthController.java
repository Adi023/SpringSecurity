package com.spring.security.test.controllers;

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
			
			String token=jwtUtil.generateToken(userDetails);
			
//			System.out.println("token : "+token);
			
			return ResponseEntity.ok(new AuthResponse(token));	
			
		}catch(Exception e) {
			System.out.println("login exception");
			return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid credintials");
		}
		
		
//		return jwtUtil.generateToken(userDetails);
	}
}
