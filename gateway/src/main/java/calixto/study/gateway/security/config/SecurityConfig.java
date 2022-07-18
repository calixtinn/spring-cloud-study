package calixto.study.gateway.security.config;

import calixto.study.core.config.JWTConfiguration;
import calixto.study.gateway.security.filter.GatewayJWTTokenAuthorizationFilter;
import calixto.study.token.security.token.converter.TokenConverter;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.web.cors.CorsConfiguration;

@EnableWebFluxSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final TokenConverter tokenConverter;
    private final JWTConfiguration jwtConfiguration;

    @Bean
    public SecurityWebFilterChain filterChain(ServerHttpSecurity http) {
        http.csrf().disable()
                .cors().configurationSource(request -> new CorsConfiguration().applyPermitDefaultValues())
                .and()
                .authorizeExchange()
                .pathMatchers(jwtConfiguration.getLoginUrl()).permitAll()
                .pathMatchers("/course/admin/**").hasRole("ADMIN")
                .anyExchange().authenticated();
        http.addFilterAfter(new GatewayJWTTokenAuthorizationFilter(jwtConfiguration, tokenConverter), SecurityWebFiltersOrder.AUTHORIZATION);
        return http.build();
    }


}
