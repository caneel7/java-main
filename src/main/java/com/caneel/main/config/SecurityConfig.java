package com.caneel.main.config;

import com.caneel.main.security.JWTAuthentication;
import jakarta.servlet.DispatcherType;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.parameters.P;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;

@Configuration
@EnableWebSecurity
@EnableWebMvc
public class SecurityConfig {

    public static final String[] PUBLIC_URLS = {
           "/api/auth/**"
    };

    private CustomerUserDetailService customerUserDetailService;

    private AuthenticationEntryPoint authenticationEntryPoint;

    private JWTAuthentication jwtAuthentication;

    @Autowired
    public SecurityConfig(CustomerUserDetailService customerUserDetailService,AuthenticationEntryPoint authenticationEntryPoint,JWTAuthentication jwtAuthentication)
    {
        this.authenticationEntryPoint = authenticationEntryPoint;
        this.customerUserDetailService = customerUserDetailService;
        this.jwtAuthentication = jwtAuthentication;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception
    {
        http
                .csrf(AbstractHttpConfigurer::disable)
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(
                        auth ->
                                auth.dispatcherTypeMatchers(DispatcherType.FORWARD).permitAll()
                                        .requestMatchers(new AntPathRequestMatcher("/auth/**")).permitAll()
                                        .anyRequest().authenticated()
                );
        http.addFilterBefore(this.jwtAuthentication, UsernamePasswordAuthenticationFilter.class);
        return http.build();
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception
    {
        return authenticationConfiguration.getAuthenticationManager();
    }

    @Bean
    public PasswordEncoder passwordEncoder()
    {
        return new BCryptPasswordEncoder();
    }


}
