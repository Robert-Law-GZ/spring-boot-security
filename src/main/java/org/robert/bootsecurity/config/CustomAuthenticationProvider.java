package org.robert.bootsecurity.config;

import org.robert.bootsecurity.entity.User;
import org.robert.bootsecurity.repository.UserRepository;
import org.robert.bootsecurity.service.AccountService;
import org.robert.bootsecurity.service.JWTUserDetailsService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.util.DigestUtils;

import java.util.ArrayList;

public class CustomAuthenticationProvider implements AuthenticationProvider {

    private JWTUserDetailsService userDetailsService;

    private BCryptPasswordEncoder bCryptPasswordEncoder;

    AccountService accountService;

    public CustomAuthenticationProvider(AccountService accountService) {
        this.accountService=accountService;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        // 获取认证的用户名 & 密码
        String username = authentication.getName();
        String password = authentication.getCredentials().toString();

        //通过用户名从数据库中查询该用户
        User user=accountService.findByUsername(username);

        if (user==null){
            throw new UsernameNotFoundException("用户不存在");
        }
//        UserDetails userDetails = userDetailsService.loadUserByUsername(username);
//
//        //判断密码(这里是md5加密方式)是否正确
//        String dbPassword = userDetails.getPassword();
////        String encoderPassword = DigestUtils.md5DigestAsHex(password.getBytes());
//
//        if (!dbPassword.equals(password)) {
//            throw new UsernameNotFoundException("密码错误");
//        }

        // 还可以从数据库中查出该用户所拥有的权限,设置到 authorities 中去,这里模拟数据库查询.
        ArrayList<GrantedAuthority> authorities = new ArrayList<>();
        SimpleGrantedAuthority grantedAuthority1=new SimpleGrantedAuthority("admin");
        SimpleGrantedAuthority grantedAuthority2=new SimpleGrantedAuthority("user");
        authorities.add(grantedAuthority1);
        authorities.add(grantedAuthority2);

        Authentication auth = new UsernamePasswordAuthenticationToken(username, password, authorities);

        return auth;
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return authentication.equals(UsernamePasswordAuthenticationToken.class);
    }

}
