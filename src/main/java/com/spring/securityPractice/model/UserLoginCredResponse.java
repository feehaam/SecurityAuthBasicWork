package com.spring.securityPractice.model;

public class UserLoginCredResponse {
    private String userId;
    private String username;
    private String bearerToken;

    public UserLoginCredResponse(String userId, String username, String bearerToken) {
        this.userId = userId;
        this.username = username;
        this.bearerToken = bearerToken;
    }

    public String getUserId() {
        return userId;
    }

    public void setUserId(String userId) {
        this.userId = userId;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getBearerToken() {
        return bearerToken;
    }

    public void setBearerToken(String bearerToken) {
        this.bearerToken = bearerToken;
    }
}
