package org.robert.bootsecurity.config;

import org.robert.bootsecurity.filters.JWTAuthFilter;
import org.robert.bootsecurity.service.AccountService;
import org.robert.bootsecurity.service.JWTUserDetailsService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;


@Configuration
@EnableWebSecurity
public class SecurityConfigurer extends WebSecurityConfigurerAdapter {

    private final static String[] AUTH_WHITELIST = {
            "/*",
            "/static/**"
    };
//    @Override
//    protected void configure(HttpSecurity http) throws Exception {
//        http.cors().and().csrf().disable()
//                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS).and()
//                .authorizeRequests()
//                .antMatchers(AUTH_WHITELIST).permitAll()
//                .anyRequest().authenticated()
//                .and()
//                .formLogin()
//                .loginPage("/login")
//                .permitAll();// 设置注销成功后跳转页面，默认是跳转到登录页面;
//    }

    @Bean
    public JWTUserDetailsService userDetailsService() {
        return new JWTUserDetailsService();
    }

    @Autowired
    AccountService accountService;

    @Bean
    public BCryptPasswordEncoder cryptPasswordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    PasswordEncoder passwordEncoder() {
        return new PasswordEncoder() {
            @Override
            public String encode(CharSequence charSequence) {
                return charSequence.toString();
            }

            @Override
            public boolean matches(CharSequence charSequence, String s) {
                return (charSequence.toString().equalsIgnoreCase(s));
            }
        };
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.authenticationProvider(new CustomAuthenticationProvider(accountService));
    }

    //    @Autowired
//    public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
//        auth
//                .inMemoryAuthentication()
//                .passwordEncoder(passwordEncoder())
//                .withUser("robert")
//                .password("654321")
//                .roles("ADMIN");
//    }

//    @Autowired
//    public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
//        auth.userDetailsService(userDetailsService()).passwordEncoder(passwordEncoder());
//    }

//    @Override
//    public void configure(WebSecurity web) throws Exception {
//        web.ignoring().antMatchers("/resources/**"); // #3
//    }
//
//    @Override
//    protected void configure(HttpSecurity http) throws Exception {
//        http.authorizeRequests()
//                .antMatchers("/*")
//                .permitAll() // #4
//                .antMatchers("/user/**")
//                .authenticated() // 7
//                .and()
//                .addFilter(new JWTAuthenticationFilter(authenticationManager()))
//                .addFilter(new JWTLoginFilter(authenticationManager()))
//                .formLogin()  // #8
//                .loginPage("/login")
//                .permitAll(); // #5
//    }

//    @Override
//    protected void configure(HttpSecurity http) throws Exception {
//        http.authorizeRequests()
//                .antMatchers("/*")
//                .permitAll() // #4
//                .antMatchers("/user/**")
//                .authenticated() // 7
//                .and()
//                .addFilterBefore(new TokenAuthorizationFilter(), BasicAuthenticationFilter.class)
//                .formLogin()  // #8
//                .loginPage("/login")
//                .permitAll(); // #5
//    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.csrf().disable().authorizeRequests()
                .antMatchers("/*")
                .permitAll()
                .antMatchers("/user/**")
                .authenticated()
                .and()
                .addFilterAfter(new JWTAuthFilter(authenticationManager(),accountService),BasicAuthenticationFilter.class)
                .formLogin()
                .loginPage("/login")
                .permitAll();
    }
}
