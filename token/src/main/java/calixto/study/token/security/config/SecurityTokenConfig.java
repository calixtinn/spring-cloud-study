package calixto.study.token.security.config;

import calixto.study.core.config.JWTConfiguration;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfiguration;

import javax.servlet.http.HttpServletResponse;

@RequiredArgsConstructor
public class SecurityTokenConfig {

    protected final JWTConfiguration jwtConfiguration;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        http.csrf().disable()
                            .cors().configurationSource(request -> new CorsConfiguration().applyPermitDefaultValues())
                            .and().sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                            .and().exceptionHandling().authenticationEntryPoint((req, resp, e) -> resp.sendError(HttpServletResponse.SC_UNAUTHORIZED))
                            .and()
                            .authorizeRequests()
                            .antMatchers(jwtConfiguration.getLoginUrl()).permitAll()
                            .antMatchers("/course/admin/**").hasRole("ADMIN")
                            .anyRequest().authenticated();

        return http.build();
    }
}
