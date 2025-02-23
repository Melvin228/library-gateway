package com.library.gateway.security.jwt;

import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;

@Component
public class JwtAuthenticationFilter extends AbstractGatewayFilterFactory<JwtAuthenticationFilter.Config> {

    public JwtAuthenticationFilter() {
        super(Config.class);
    }

    @Override
    public GatewayFilter apply(final Config config) {
        return (exchange, chain) -> {
            // Get the JWT token from the Authorization header
            final String token = exchange.getRequest().getHeaders().getFirst("Authorization");

            // Validate the token
            if (token == null || !isValidToken(token)) {
                // Reject the request if the token is invalid
                exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
                return exchange.getResponse().setComplete();
            }

            // If the token is valid, proceed to the next filter
            return chain.filter(exchange);
        };
    }

    private boolean isValidToken(String token) {
        // Add your JWT validation logic here
        // Example: Use a library like JJWT or Spring Security to validate the token
        return true; // Replace with actual validation logic
    }

    public static class Config {
        // Add configuration properties here if needed
    }
}