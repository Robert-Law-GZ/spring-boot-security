package org.robert.bootsecurity.filters;

import org.robert.bootsecurity.jwt.JWTUtil;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.annotation.Resource;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class JWTAuthenticationFilter extends BasicAuthenticationFilter {

    private static final String token_header = "Authentication";

    @Bean
    public JWTUtil jwtUtils(){
        return  new JWTUtil();
    }

    public JWTAuthenticationFilter(AuthenticationManager authenticationManager) {
        super(authenticationManager);
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws ServletException, IOException {

        String auth_token = request.getHeader(JWTAuthFilter.AUTH_HEADER);

        if (auth_token != null) {

            final String auth_token_start = "";

            if (!auth_token.isEmpty() && auth_token.startsWith(auth_token_start)) {
                auth_token = auth_token.substring(auth_token_start.length());
            }

            String username = jwtUtils().getUsernameFromToken(auth_token);
            logger.info(String.format("Checking authentication for user %s.", username));

            if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
                // It is not compelling necessary to load the use details from the database. You could also store the information
                // in the token and read it from it. It's up to you ;)
                // UserDetails userDetails = this.userDetailsService.loadUserByUsername(username);
                UserDetails userDetails = jwtUtils().getUserFromToken(auth_token);

                // For simple validation it is completely sufficient to just check the token integrity. You don't have to call
                // the database compellingly. Again it's up to you ;)
                if (jwtUtils().validateToken(auth_token, userDetails)) {
                    UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(userDetails, null, null);
                    authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                    logger.info(String.format("Authenticated user %s, setting security context", username));
                    SecurityContextHolder.getContext().setAuthentication(authentication);
                }
            }
        }

        chain.doFilter(request, response);
    }

}
