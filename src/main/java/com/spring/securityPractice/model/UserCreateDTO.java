package com.spring.securityPractice.model;

import lombok.*;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class UserCreateDTO {
    private long id;
    private String userId;
    private String email;
    private String password;
}