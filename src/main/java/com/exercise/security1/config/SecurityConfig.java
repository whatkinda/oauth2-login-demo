package com.exercise.security1.config;

import com.exercise.security1.config.oauth.PrincipalOAuth2UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@RequiredArgsConstructor
@EnableWebSecurity
@Configuration
@EnableGlobalMethodSecurity(securedEnabled = true, prePostEnabled = true)
public class SecurityConfig {

    private final PrincipalOAuth2UserService principalOAuth2UserService;

    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        return http
                .csrf(csrf -> csrf
                        .disable())

                .authorizeRequests(auth -> auth
                        .antMatchers("/user/**").authenticated()    // 인증만 되면 들어갈 수 있는 주소
                        .antMatchers("/manager/**").access("hasRole('ADMIN') or hasRole('MANAGER')")
                        .antMatchers("/admin/**").access("hasRole('ADMIN')")
                        .anyRequest().permitAll())

                .formLogin(formLogin -> formLogin
                        .loginPage("/loginForm")
                        .loginProcessingUrl("/login")
                        .defaultSuccessUrl("/"))

                .oauth2Login(
                        oauth -> oauth
                                .loginPage("/loginForm")
                                .userInfoEndpoint(endpoint -> endpoint
                                        .userService(principalOAuth2UserService))
                )

                .build();
    }

}
