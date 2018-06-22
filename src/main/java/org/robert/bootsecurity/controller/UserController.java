package org.robert.bootsecurity.controller;

import org.robert.bootsecurity.model.User;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.ArrayList;
import java.util.List;

@RestController
@RequestMapping(value = "/user")
public class UserController {

    @GetMapping(value = "/info")
    public User test() {
        User user = new User();
        return user;
    }

    @GetMapping(value = "/list")
    public List<User> list() {
        return new ArrayList<>();
    }

}
