package com.spring.security.test.jwt;

import java.io.IOException;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.spring.security.test.config.CustomUserDetailService;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.security.SignatureException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter  {

	private JwtUtil jwtUtil;
	private CustomUserDetailService userDetailService;
	
	public JwtAuthenticationFilter(JwtUtil jwtUtil,CustomUserDetailService userDetailService) {
		this.jwtUtil=jwtUtil;
		this.userDetailService=userDetailService;
	}
	
	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		
		final String authHeader=request.getHeader("Authorization");
		final String jwt;
		final String userName;
		
		

		// Bypass the filter for login endpoint
	    String requestPath = request.getServletPath();
	    if (requestPath.equals("/auth/login")) {
	        filterChain.doFilter(request, response);
	        return;
	    }
		
		//if(authHeader!=null && authHeader.startsWith("Bearer ")) {
		if (authHeader == null || !authHeader.startsWith("Bearer ")) {
			filterChain.doFilter(request, response);
			 System.out.println("Authorization header is missing");
			return;
		}
		 else if (!authHeader.startsWith("Bearer ")) {
		    System.out.println("Authorization header does not start with Bearer ");
		} 
		
		jwt=authHeader.substring(7);
		
		try {
			userName=jwtUtil.extractUserName(jwt);
		}catch(ExpiredJwtException | MalformedJwtException | SignatureException e) {
			response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Invalid JWT token");
			return;
		}
		
		if(userName!=null && SecurityContextHolder.getContext().getAuthentication()==null) {
			UserDetails userDetails=userDetailService.loadUserByUsername(userName);
			
			if(jwtUtil.validateToken(jwt, userDetails)) {
				UsernamePasswordAuthenticationToken authToken= new UsernamePasswordAuthenticationToken
						(userDetails,null,userDetails.getAuthorities());
				authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
				SecurityContextHolder.getContext().setAuthentication(authToken);
			}
		}
		
		filterChain.doFilter(request, response);
	}
}