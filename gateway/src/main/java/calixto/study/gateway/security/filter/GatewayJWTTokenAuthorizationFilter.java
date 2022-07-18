package calixto.study.gateway.security.filter;

import calixto.study.core.config.JWTConfiguration;
import calixto.study.token.security.filter.JwtTokenAuthorizationFilter;
import calixto.study.token.security.token.converter.TokenConverter;
import calixto.study.token.security.util.SecurityContextUtil;
import com.nimbusds.jwt.SignedJWT;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import org.apache.commons.lang.StringUtils;
import org.apache.logging.log4j.util.Strings;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Objects;

@RequiredArgsConstructor
public class GatewayJWTTokenAuthorizationFilter implements WebFilter {

    protected final JWTConfiguration jwtConfiguration;
    protected final TokenConverter tokenConverter;

    @SneakyThrows
    private SignedJWT decryptValidating(String encryptedToken) {
        String signedToken = tokenConverter.decryptToken(encryptedToken);
        tokenConverter.validateTokenSignature(signedToken);
        return SignedJWT.parse(signedToken);
    }

    @SneakyThrows
    private SignedJWT validate(String signedToken) {
        tokenConverter.validateTokenSignature(signedToken);
        return SignedJWT.parse(signedToken);
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        String header = exchange.getRequest().getHeaders().getFirst(jwtConfiguration.getHeader().getName());
        if (Objects.isNull(header) || !header.startsWith(jwtConfiguration.getHeader().getPrefix())) {
            return chain.filter(exchange);
        }
        String token = header.replace(jwtConfiguration.getHeader().getPrefix(), Strings.EMPTY).trim();

        String signedToken = tokenConverter.decryptToken(token);

        tokenConverter.validateTokenSignature(signedToken);

        if ("signed".equalsIgnoreCase(jwtConfiguration.getType())) {
            exchange.getResponse().getHeaders().add("Authorization", jwtConfiguration.getHeader().getPrefix() + signedToken);
        }
        return chain.filter(exchange);
    }
}
