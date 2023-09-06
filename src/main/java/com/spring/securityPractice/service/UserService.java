package com.spring.securityPractice.service;


import com.spring.securityPractice.model.UserCreateDTO;
import com.spring.securityPractice.model.UserReadDto;

public interface UserService {
    UserReadDto createUser(UserCreateDTO user) throws Exception;
    UserReadDto getUser(String email);
    UserReadDto getUserByUserId(String id) throws Exception;
}