package pl.iseebugs.Security.domain.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.log4j.Log4j2;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import pl.iseebugs.Security.domain.ApiResponse;

import java.io.IOException;

@Log4j2
@Component
class JWTAuthFilter extends OncePerRequestFilter {

    private final JWTUtils jwtUtils;
    private final AppUserInfoService appUserInfoService;

    JWTAuthFilter(JWTUtils jwtUtils, AppUserInfoService appUserInfoService) {
        this.jwtUtils = jwtUtils;
        this.appUserInfoService = appUserInfoService;
    }

    @Override
    protected void doFilterInternal(final HttpServletRequest request, final HttpServletResponse response, final FilterChain filterChain) throws ServletException, IOException {
        final String authHeader = request.getHeader("Authorization");

        if (authHeader == null || authHeader.isBlank()) {
            filterChain.doFilter(request, response);
            return;
        }

        final String jwtToken = authHeader.substring(7);
        final String userEmail = jwtUtils.extractUsername(jwtToken);

        if (request.getRequestURI().equals("/api/auth/refresh")) {
            if (userEmail != null && jwtUtils.isRefreshToken(jwtToken)) {
                log.info("Is refresh token");
                UserDetails userDetails = appUserInfoService.loadUserByUsername(userEmail);
                log.info("Load user");
                if (jwtUtils.isTokenValid(jwtToken, userDetails)) {
                    log.info("Valid refresh token");

                    SecurityContext securityContext = SecurityContextHolder.createEmptyContext();
                    UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(
                            userDetails, null, userDetails.getAuthorities()
                    );
                    token.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                    securityContext.setAuthentication(token);
                    SecurityContextHolder.setContext(securityContext);
                    log.info("Security context set: " + SecurityContextHolder.getContext().getAuthentication());
                }
                log.info("End of refresh token validation");
            } else {
                log.info("Invalid refresh token");
                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                response.setContentType("application/json");

                ApiResponse<Void> errorResponse = new ApiResponse<>();
                errorResponse.setStatusCode(HttpServletResponse.SC_UNAUTHORIZED);
                errorResponse.setMessage("Invalid or expired refresh token");

                ObjectMapper objectMapper = new ObjectMapper();
                String jsonResponse = objectMapper.writeValueAsString(errorResponse);

                response.getWriter().write(jsonResponse);
                return;
            }
        } else {
            if (userEmail != null && SecurityContextHolder.getContext().getAuthentication() == null) {
                log.info("Extracted email: " + userEmail);
                UserDetails userDetails = appUserInfoService.loadUserByUsername(userEmail);

                if (!jwtUtils.isTokenValid(jwtToken, userDetails)) {
                    response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                    response.getWriter().write("Invalid token");
                    return;
                }

                if (!jwtUtils.isAccessToken(jwtToken)) {
                    response.setStatus(HttpServletResponse.SC_FORBIDDEN);
                    response.getWriter().write("Only Access Token cannot be used to access this resource");
                    return;
                }

                SecurityContext securityContext = SecurityContextHolder.createEmptyContext();
                UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(
                        userDetails, null, userDetails.getAuthorities()
                );
                token.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                securityContext.setAuthentication(token);
                SecurityContextHolder.setContext(securityContext);
            }
        }
        filterChain.doFilter(request, response);
    }
}
