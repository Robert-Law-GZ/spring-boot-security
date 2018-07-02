package org.robert.bootsecurity.filters;

import io.jsonwebtoken.Claims;
import org.robert.bootsecurity.entity.User;
import org.robert.bootsecurity.jwt.JWTHelper;
import org.robert.bootsecurity.jwt.JWTUserDetails;
import org.robert.bootsecurity.service.AccountService;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.NullRememberMeServices;
import org.springframework.security.web.authentication.RememberMeServices;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Enumeration;

public class JWTAuthFilter extends OncePerRequestFilter {
    public static final String AUTH_HEADER = "X-Authentication";

    private AuthenticationManager authenticationManager;
    private RememberMeServices rememberMeServices = new NullRememberMeServices();
    private AccountService accountService;

    public JWTAuthFilter(AuthenticationManager authenticationManager,AccountService accountService) {
        this.authenticationManager = authenticationManager;
        this.accountService=accountService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, FilterChain filterChain) throws ServletException, IOException {
        String header = httpServletRequest.getHeader(AUTH_HEADER);
        Enumeration<String> names = httpServletRequest.getParameterNames();

        while (names.hasMoreElements()){
            String name=names.nextElement();
            logger.error("参数名："+name+"    值："+httpServletRequest.getParameter(name));
        }

        if (header != null) {

            try {
                Claims claims = JWTHelper.claimsFromToken(header);
                String id = claims.getSubject();

                if (id != null) {

                    if (authenticationIsRequired(id)) {
                        User user=accountService.findById(Long.parseLong(id));
                        if (user!=null) {
                            UsernamePasswordAuthenticationToken authRequest = new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword());
                            JWTUserDetails userDetails = new JWTUserDetails(user.getId(), user.getUsername(), user.getPassword(), new ArrayList());
                            authRequest.setDetails(userDetails);
                            Authentication authResult = this.authenticationManager.authenticate(authRequest);
                            logger.info("Authentication success: " + authResult);

                            SecurityContextHolder.getContext().setAuthentication(authResult);
                            rememberMeServices.loginSuccess(httpServletRequest, httpServletResponse, authResult);
                        }else{
                            logger.info("验证失败，没有找到用户名");
                        }
                    }

                } else {
                    logger.info("验证失败，没有找到用户名");
                }

            } catch (AuthenticationException e) {
                SecurityContextHolder.clearContext();
                this.logger.info("Authentication request for failed: " + e);
                this.rememberMeServices.loginFail(httpServletRequest, httpServletResponse);
                return;
            }
        }

        filterChain.doFilter(httpServletRequest, httpServletResponse);
    }

    private boolean authenticationIsRequired(String username) {
        Authentication existingAuth = SecurityContextHolder.getContext().getAuthentication();
        if (existingAuth != null && existingAuth.isAuthenticated()) {
            if (existingAuth instanceof UsernamePasswordAuthenticationToken && !existingAuth.getName().equals(username)) {
                return true;
            } else {
                return existingAuth instanceof AnonymousAuthenticationToken;
            }
        } else {
            return true;
        }
    }

}
