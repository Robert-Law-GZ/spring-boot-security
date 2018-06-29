package org.robert.bootsecurity.controller;

import com.fasterxml.jackson.core.JsonProcessingException;
import org.robert.bootsecurity.entity.User;
import org.robert.bootsecurity.filters.JWTAuthFilter;
import org.robert.bootsecurity.jwt.JWTHelper;
import org.robert.bootsecurity.jwt.JWTUserDetails;
import org.robert.bootsecurity.jwt.JWTUtil;
import org.robert.bootsecurity.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletResponse;
import java.util.ArrayList;

@Controller
public class RootController {

    @Autowired
    private UserRepository userRepository;

    @RequestMapping(value = "/login")
    public String login() {
        return "login_page";
    }

    @GetMapping(value = "/p2")
    public String page2() {
        return "page2";
    }

    @GetMapping(value = "/p1")
    public String page1() {
        return "page1";
    }

    @RequestMapping(value = "/p3", produces = "application/json;charset=UTF-8", method = RequestMethod.POST)
    @ResponseBody
    public User userInfo() {
        return new User();
    }

    @GetMapping(value = "/user/home")
    public String homepage() {
        return "user/root";
    }

    @RequestMapping(value = "/sign", method = RequestMethod.POST)
    public String sign(HttpServletResponse response, @RequestParam String username, @RequestParam String password) {
        User user = userRepository.findUserByUsername(username);

        if (user != null) {

            if (user.getPassword().equalsIgnoreCase(password)) {

                String token = JWTHelper.buildToken(username);
                response.addHeader(JWTAuthFilter.AUTH_HEADER, token);

                return "main";
            }
        }

        return "login_page";
    }

}
