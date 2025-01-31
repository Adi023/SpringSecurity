package com.spring.security.test.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableMethodSecurity
public class SecurityConfig {

	@Bean
	protected PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}

	// in memory authentication
	@Bean
	protected UserDetailsService userDetailsService() {
		
		return new CustomUserDetailService();
//
//		UserDetails normalUser = User.withUsername("Aditya").password(passwordEncoder().encode("aditya"))
//				.roles("NORMAL").build();
//
//		UserDetails adminUser = User.withUsername("Aditya1").password(passwordEncoder().encode("aditya")).roles("ADMIN")
//				.build();
//
//		return new InMemoryUserDetailsManager(normalUser, adminUser);
	}

	// after spring security 6 and
	// spring 3.3 use below method
	@Bean
	protected SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
		http.csrf(AbstractHttpConfigurer::disable)
				.authorizeHttpRequests(auth -> auth
//						.requestMatchers("/home/public").permitAll()
//						.requestMatchers("/home/admin").hasRole("ADMIN")
//						.requestMatchers("/home/normal").hasRole("NORMAL")
						.anyRequest().authenticated())
				.formLogin(form -> form.defaultSuccessUrl("/home", true) // Redirect after successful login
						.permitAll())
				.logout(logout -> logout.logoutUrl("/logout").logoutSuccessUrl("/home/public") // Redirect to public
				.permitAll());				  												   // page after logout
		return http.build();
	}

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