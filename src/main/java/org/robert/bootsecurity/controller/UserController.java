package org.robert.bootsecurity.controller;

import org.robert.bootsecurity.entity.User;
import org.robert.bootsecurity.service.AccountService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.ArrayList;
import java.util.List;

@RestController
@RequestMapping(value = "/user")
public class UserController {

    @Autowired
    AccountService accountService;

    @GetMapping(value = "/info")
    public User test() {
        User user = new User();
        return user;
    }

    @GetMapping(value = "/list")
    public List<User> list() {
        List<User> list=new ArrayList();
        list.add(new User());
        list.add(new User());
        list.add(new User());
        return list;
    }

    @PostMapping(value = "/userById")
    public User findById(@RequestParam Long id){
        return accountService.findById(id);
    }

}
