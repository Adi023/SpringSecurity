package com.spring.security.test.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.spring.security.test.jwt.JwtAuthenticationFilter;

@Configuration
@EnableMethodSecurity
@EnableWebSecurity
public class SecurityConfig {

	private final JwtAuthenticationFilter jwtAuthenticationFilter;//
	private final CustomUserDetailService customUserDetailService;

	public SecurityConfig(CustomUserDetailService customUserDetailService,JwtAuthenticationFilter jwtAuthenticationFilter) {
		this.customUserDetailService = customUserDetailService;
		this.jwtAuthenticationFilter=jwtAuthenticationFilter;
	}

	@Bean
	protected PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}

	// after spring security 6 and
	// spring 3.3 use below method
	@Bean
	protected SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
		 http
	        .csrf(AbstractHttpConfigurer::disable)
	        .authorizeHttpRequests(auth -> auth
	            .requestMatchers("/home/public").permitAll()
	            .requestMatchers("/auth/login", "/auth/register", "/auth/refresh").permitAll()
	            .requestMatchers("/home/admin").hasAuthority("ROLE_ADMIN")
	            .requestMatchers("/home/normal").hasAuthority("ROLE_USER")
	            .requestMatchers("/users/**").hasAuthority("ROLE_USER") // Only ADMIN can access /users
	            .anyRequest().authenticated()
	        )
				// Add JWT filter
		.sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
		.addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);
        // Add custom JWT authentication filter

//				.formLogin(form -> form.defaultSuccessUrl("/home", true) // Redirect after successful login
//						.permitAll())
//				.logout(logout -> logout.logoutUrl("/logout").logoutSuccessUrl("/home/public") // Redirect to public
//						.permitAll()); // page after logout
		return http.build();
	}

	@Bean
	protected AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration)
			throws Exception {
		return authenticationConfiguration.getAuthenticationManager();
	}

	@Bean
	protected DaoAuthenticationProvider authenticationProvider() {
		DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
		authProvider.setUserDetailsService(customUserDetailService);
		authProvider.setPasswordEncoder(passwordEncoder());
		return authProvider;
	}

	// in memory authentication
//		@Bean
//		protected UserDetailsService userDetailsService() {
//			
//			return new CustomUserDetailService();
	//
//			UserDetails normalUser = User.withUsername("Aditya").password(passwordEncoder().encode("aditya"))
//					.roles("NORMAL").build();
	//
//			UserDetails adminUser = User.withUsername("Aditya1").password(passwordEncoder().encode("aditya")).roles("ADMIN")
//					.build();
	//
//			return new InMemoryUserDetailsManager(normalUser, adminUser);
//		}

//  @Bean
//  protected SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
//      http.csrf().disable()
//      .authorizeHttpRequests()
//      .requestMatchers("home/public")
//      .permitAll()
//      .anyRequest()
//      .authenticated()
//      .and()
//      .formLogin();
//      
//      return http.build();
//  }
}