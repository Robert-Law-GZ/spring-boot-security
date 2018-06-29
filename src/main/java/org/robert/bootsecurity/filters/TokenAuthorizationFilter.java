package org.robert.bootsecurity.filters;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import org.robert.bootsecurity.entity.User;
import org.robert.bootsecurity.jwt.JWTHelper;
import org.robert.bootsecurity.jwt.JWTUtil;
import org.robert.bootsecurity.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class TokenAuthorizationFilter extends OncePerRequestFilter {
    private final static String SECRET="API-SECRET";

    @Bean
    public JWTUtil jwtUtils(){
        return  new JWTUtil();
    }

    @Autowired
    UserRepository userRepository;

    @Override
    protected void doFilterInternal(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, FilterChain filterChain) throws ServletException, IOException {
        String token=httpServletRequest.getHeader("Authorization");

        if (token!=null){
            Claims claims= JWTHelper.claimsFromToken(token);
            String username = claims.getSubject();
            User user = userRepository.findUserByUsername(username);

            if (user!=null){
                System.out.println("当前登录用户："+user.getName());

                UserDetails userDetails = jwtUtils().getUserFromToken(token);

                // For simple validation it is completely sufficient to just check the token integrity. You don't have to call
                // the database compellingly. Again it's up to you ;)
                    UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(userDetails, null, null);
                    authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(httpServletRequest));
                    logger.info(String.format("Authenticated user %s, setting security context", username));
                    SecurityContextHolder.getContext().setAuthentication(authentication);

            }

            System.out.println("====token:"+token);
        }

//        JWTUtil.validateToken(token);
        filterChain.doFilter(httpServletRequest,httpServletResponse);
    }

}
