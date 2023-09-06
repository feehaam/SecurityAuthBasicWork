package com.spring.securityPractice.service.impl;

import com.spring.securityPractice.entity.UserEntity;
import com.spring.securityPractice.model.UserCreateDTO;
import com.spring.securityPractice.model.UserReadDto;
import com.spring.securityPractice.repository.UserRepository;
import com.spring.securityPractice.service.UserService;
import com.spring.securityPractice.utils.JWTUtils;
import org.modelmapper.ModelMapper;
import org.springframework.beans.BeanUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.Optional;

@Service
@Transactional
public class UserServiceImpl implements UserService, UserDetailsService {
    @Autowired
    private UserRepository userRepository;

    @Autowired
    private BCryptPasswordEncoder bCryptPasswordEncoder;
    @Override
    public UserReadDto createUser(UserCreateDTO user) throws Exception {
        ModelMapper modelMapper = new ModelMapper();
        if(userRepository.findByEmail(user.getEmail()).isPresent())
            throw new Exception("Record already exists");
        UserEntity userEntity = new UserEntity();
        userEntity.setEmail(user.getEmail());
        userEntity.setPassword(bCryptPasswordEncoder.encode(user.getPassword()));
        String publicUserId = JWTUtils.generateUserID(10);
        userEntity.setUserId(publicUserId);
        UserEntity storedUserDetails = userRepository.save(userEntity);
        return modelMapper.map(storedUserDetails, UserReadDto.class);
    }

    @Override
    public UserReadDto getUser(String email) {
        Optional<UserEntity> userOptional = userRepository.findByEmail(email);
        if(userOptional.isEmpty()){
            throw new UsernameNotFoundException("User not found");
        }
        UserEntity userEntity = userOptional.get();
        UserReadDto returnValue = new UserReadDto();
        BeanUtils.copyProperties(userEntity,returnValue);
        return returnValue;
    }

    @Override
    public UserReadDto getUserByUserId(String userId) throws Exception {
        Optional<UserEntity> userOptional = userRepository.findByUserId(userId);
        if(userOptional.isEmpty()){
            throw new UsernameNotFoundException("User not found");
        }
        UserEntity userEntity = userOptional.get();
        UserReadDto returnValue = new UserReadDto();
        BeanUtils.copyProperties(userEntity, returnValue);
        return returnValue;
    }
   @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
       Optional<UserEntity> userOptional = userRepository.findByEmail(email);
       if(userOptional.isEmpty()){
           throw new UsernameNotFoundException("User not found");
       }
       UserEntity userEntity = userOptional.get();
       return new User(userEntity.getEmail(),userEntity.getPassword(), true,true,true,true,new ArrayList<>());
    }
}