package calixto.study.gateway.security.filter;

import calixto.study.core.config.JWTConfiguration;
import calixto.study.token.security.filter.JwtTokenAuthorizationFilter;
import calixto.study.token.security.token.converter.TokenConverter;
import lombok.SneakyThrows;
import org.apache.logging.log4j.util.Strings;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Objects;

public class GatewayJWTTokenAuthorizationFilter extends JwtTokenAuthorizationFilter {

    public GatewayJWTTokenAuthorizationFilter(JWTConfiguration jwtConfiguration, TokenConverter tokenConverter) {
        super(jwtConfiguration, tokenConverter);
    }

    @Override
    @SuppressWarnings("duplicates")
    @SneakyThrows
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        String header = request.getHeader(jwtConfiguration.getHeader().getName());
        if(Objects.isNull(header) || !header.startsWith(jwtConfiguration.getHeader().getPrefix())) {
            filterChain.doFilter(request, response);
            return;
        }
        String token = header.replace(jwtConfiguration.getHeader().getPrefix(), Strings.EMPTY).trim();

        String signedToken = tokenConverter.decryptToken(token);

        tokenConverter.validateTokenSignature(signedToken);

        if("signed".equalsIgnoreCase(jwtConfiguration.getType())) {
            request.setAttribute("Authorization", jwtConfiguration.getHeader().getPrefix() + signedToken);
        }
        filterChain.doFilter(request, response);
    }
}
