package com.security.demo.config;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import com.security.demo.security.RateLimitingFilter;
import com.security.demo.service.TokenBlacklistService;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.security.authentication.AuthenticationEventPublisher;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.DefaultAuthenticationEventPublisher;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
@EnableScheduling
@EnableConfigurationProperties(RsaKeyProperties.class)
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http, RateLimitingFilter rateLimitingFilter) {
        return http
                .csrf(AbstractHttpConfigurer::disable) // Disable for stateless APIs
                .addFilterBefore(rateLimitingFilter, UsernamePasswordAuthenticationFilter.class)
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/api/auth/**").permitAll() // Login/Register endpoints
                        .anyRequest().authenticated()               // Protect everything else
                )
                .sessionManagement(session -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS) // No sessions
                )
                .oauth2ResourceServer(oauth2 -> oauth2.jwt(Customizer.withDefaults())) // Enable JWT validation
                .build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public JwtDecoder jwtDecoder(RsaKeyProperties keys, TokenBlacklistService tokenBlacklistService) {
        NimbusJwtDecoder delegate = NimbusJwtDecoder.withPublicKey(keys.getPublicKey()).build();

        return token -> {
            Jwt jwt = delegate.decode(token);

            // Check if token has been blacklisted (revoked via logout)
            String tokenId = jwt.getId();
            if (tokenId != null && tokenBlacklistService.isBlacklisted(tokenId)) {
                throw new BadJwtException("Token has been revoked");
            }

            return jwt;
        };
    }

    @Bean
    public JwtEncoder jwtEncoder(RsaKeyProperties keys) {
        JWK jwk = new RSAKey.Builder(keys.getPublicKey()).privateKey(keys.getPrivateKey()).build();
        JWKSource<SecurityContext> jwks = new ImmutableJWKSet<>(new JWKSet(jwk));
        return new NimbusJwtEncoder(jwks);
    }

    // This bean allows Spring to broadcast security events (Success/Failure)
    @Bean
    public DefaultAuthenticationEventPublisher authenticationEventPublisher(ApplicationEventPublisher publisher) {
        return new DefaultAuthenticationEventPublisher(publisher);
    }

    @Bean
    public AuthenticationManager authManager(
            UserDetailsService userDetailsService,
            ApplicationEventPublisher eventPublisher) { // 1. Inject the event publisher

        var authProvider = new DaoAuthenticationProvider(userDetailsService);
        authProvider.setPasswordEncoder(passwordEncoder());

        ProviderManager providerManager = new ProviderManager(authProvider);

        // 2. Link the Manager to the Event System
        // This is the "Bridge" that allows LoginAttemptService to hear the success/failure
        providerManager.setAuthenticationEventPublisher(new DefaultAuthenticationEventPublisher(eventPublisher));

        return providerManager;
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config,
                                                       AuthenticationEventPublisher eventPublisher) throws Exception {
        // Get the default manager from Spring
        ProviderManager manager = (ProviderManager) config.getAuthenticationManager();

        // CRITICAL: This line tells the manager to actually publish events
        // when a user successfully logs in or fails.
        manager.setAuthenticationEventPublisher(eventPublisher);

        return manager;
    }
}
