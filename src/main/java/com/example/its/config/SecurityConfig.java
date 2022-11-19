package com.example.its.config;

import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;

import lombok.RequiredArgsConstructor;

@EnableWebSecurity
@RequiredArgsConstructor

public class SecurityConfig {
	@Bean
	public SecurityFilterChain configure(HttpSecurity http) throws Exception {
		http
				.authorizeRequests()
				.anyRequest().authenticated()
				.and()
				.formLogin()
				//.usernameParameter("username") 
				//.passwordParameter("password")
				.loginPage("/login").permitAll();
		return http.build();
	}
}
	//public class SecurityConfig extends WebSecurityConfigurerAdapter{
	//	@Override
	//	protected void configure(HttpSecurity http) throws Exception {
	//		http
	//				.authorizeRequests()
	//				.mvcMatchers("/login/**").permitAll()
	//				.anyRequest().authenticated()
	//				.and()
	//				.formLogin()
	//				.loginPage("/login").permitAll();
	//	
	//	}

