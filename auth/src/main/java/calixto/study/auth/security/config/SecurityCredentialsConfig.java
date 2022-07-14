package calixto.study.auth.security.config;

import calixto.study.auth.security.filter.JwtUsernameAndPasswordAuthenticationFilter;
import calixto.study.core.config.JWTConfiguration;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfiguration;

import javax.servlet.http.HttpServletResponse;

@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityCredentialsConfig {

    private final UserDetailsService userDetailsService;
    private final JWTConfiguration jwtConfiguration;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        AuthenticationManagerBuilder authenticationManagerBuilder = http.getSharedObject(AuthenticationManagerBuilder.class);
        authenticationManagerBuilder.userDetailsService(userDetailsService).passwordEncoder(passwordEncoder());
        AuthenticationManager authenticationManager = authenticationManagerBuilder.build();

        http.csrf().disable()
                            .cors().configurationSource(request -> new CorsConfiguration().applyPermitDefaultValues())
                            .and().sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                            .and().exceptionHandling().authenticationEntryPoint((req, resp, e) -> resp.sendError(HttpServletResponse.SC_UNAUTHORIZED))
                            .and()
                            .authenticationManager(authenticationManager)
                            .addFilter(new JwtUsernameAndPasswordAuthenticationFilter(authenticationManager, jwtConfiguration))
                            .authorizeRequests()
                            .antMatchers(jwtConfiguration.getLoginUrl()).permitAll()
                            .antMatchers("/course/admin/**").hasRole("ADMIN")
                            .anyRequest().authenticated();

        return http.build();
    }

    @Bean
    public BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
