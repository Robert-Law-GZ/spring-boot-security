package org.robert.bootsecurity.service;

import org.robert.bootsecurity.entity.User;
import org.robert.bootsecurity.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class AccountService {
    @Autowired
    UserRepository userRepository;

    public User findByUsername(String username){
        return  userRepository.findUserByUsername(username);
    }

    public List findAll(){
        return  userRepository.findAll();
    }

    public User findById(Long id){
        return userRepository.findUserById(id);
    }

}
