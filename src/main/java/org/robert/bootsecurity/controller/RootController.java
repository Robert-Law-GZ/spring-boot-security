package org.robert.bootsecurity.controller;

import com.fasterxml.jackson.core.JsonProcessingException;
import org.robert.bootsecurity.jwt.JWTUserDetails;
import org.robert.bootsecurity.jwt.JWTUtil;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

import javax.servlet.http.HttpServletResponse;
import java.util.ArrayList;
import java.util.Collection;

@Controller
public class RootController {

    @GetMapping(value = "/login")
    public String login(){
        return "login_page";
    }

    @GetMapping(value = "/sign")
    public String sign(HttpServletResponse response){
        JWTUtil jwtUtil=new JWTUtil();
        ArrayList<GrantedAuthority> authorities = new ArrayList<>();
        JWTUserDetails userDetails=new JWTUserDetails(1,"robert","123456",authorities);

        try {
            String token=jwtUtil.generateAccessToken(userDetails);
            response.addHeader("authentication", token);
        } catch (JsonProcessingException e) {
            e.printStackTrace();
        }

        return "main";
    }

}
