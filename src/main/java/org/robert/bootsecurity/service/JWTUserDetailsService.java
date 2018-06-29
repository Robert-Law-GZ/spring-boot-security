package org.robert.bootsecurity.service;

import org.robert.bootsecurity.entity.User;
import org.robert.bootsecurity.jwt.JWTUserDetails;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

public class JWTUserDetailsService implements UserDetailsService {

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        if (username.equalsIgnoreCase("robert")) {
            User user = new User();
            user.setId(new Long(1));
            user.setUsername("robert");
            user.setPassword("123456");
            UserDetails userDetails = new JWTUserDetails(user.getId(), username, user.getPassword(), true, true, true, true, null);
            return userDetails;
        }else{
            throw new UsernameNotFoundException("用户名不存在");
        }
    }

}