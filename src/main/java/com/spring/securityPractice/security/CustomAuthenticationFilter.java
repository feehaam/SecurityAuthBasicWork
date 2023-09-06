package com.spring.securityPractice.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.spring.securityPractice.SpringApplicationContext;
import com.spring.securityPractice.constants.AppConstants;
import com.spring.securityPractice.model.UserCreateDTO;
import com.spring.securityPractice.model.UserLoginCredResponse;
import com.spring.securityPractice.model.UserLoginDTO;
import com.spring.securityPractice.model.UserReadDto;
import com.spring.securityPractice.service.UserService;
import com.spring.securityPractice.utils.JWTUtils;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

@RequiredArgsConstructor
@Slf4j
public class CustomAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
    private final AuthenticationManager authenticationManager;
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) {
        try {
            UserLoginDTO credentials = new ObjectMapper().readValue(request.getInputStream(), UserLoginDTO.class);
            attemptCount.put(credentials.getEmail(), attemptCount.getOrDefault(credentials.getEmail(), 0) + 1);
            return authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(credentials.getEmail(),credentials.getPassword()));
        } catch (IOException e) {
            log.info("Exception occurred at attemptAuthentication method: {}",e.getLocalizedMessage());
            throw new RuntimeException(e);
        }
        catch (AuthenticationException ae){
            log.info("Exception occurred while attempting to authenticate user. method: {}",ae.getLocalizedMessage());
            throw new RuntimeException(ae);
        }
    }

    private final Map<String, Integer> attemptCount = new HashMap<String, Integer>();

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
        String user = ((User) authResult.getPrincipal()).getUsername();
        String accessToken = JWTUtils.generateToken(user);
        UserService userService = (UserService) SpringApplicationContext.getBean("userServiceImpl");
        UserReadDto userDto = userService.getUser(user);
        if(attemptCount.get(userDto.getEmail()) >= AppConstants.MAX_LOGIN_ATTEMPTS_LIMIT){
            restrictedResponse(response);
            return;
        }
        else{
            attemptCount.put(userDto.getEmail(), 0);
        }
        UserLoginCredResponse responseBody = new UserLoginCredResponse(userDto.getUserId(), userDto.getEmail(), AppConstants.TOKEN_PREFIX + accessToken);
        response.setContentType("application/json");
        new ObjectMapper().writeValue(response.getWriter(), responseBody);
    }

    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, AuthenticationException failed) {
        try{
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.setContentType("application/json");
            Map<String, String> errorResponse = new HashMap<>();
            errorResponse.put("Error", "Authentication failed!");
            errorResponse.put("Limit", "Max attempt: "+AppConstants.MAX_LOGIN_ATTEMPTS_LIMIT);
            new ObjectMapper().writeValue(response.getWriter(), errorResponse);
        }
        catch (IOException ioe){
            log.error("Failed to write unsuccessful login response", ioe);
        }
    }

    private void restrictedResponse(HttpServletResponse response) throws IOException {
        try{
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
            response.setContentType("application/json");
            Map<String, String> errorResponse = new HashMap<>();
            errorResponse.put("Restricted", "Your account has been locked for "+AppConstants.MAX_LOGIN_ATTEMPTS_LIMIT +" failed attempts.");
            new ObjectMapper().writeValue(response.getWriter(), errorResponse);
        }
        catch (IOException ioe){
            log.error("Failed to write restricted login response", ioe);
        }
    }
}