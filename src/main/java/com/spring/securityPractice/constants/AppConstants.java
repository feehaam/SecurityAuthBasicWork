package com.spring.securityPractice.constants;

public class AppConstants {
    public static final String TOKEN_SECRET = "MySecretMySecretMySecretMySecretMySecretMySecretMySecretMySecret";
    public static final long EXPIRATION_TIME = 1000 * 60 * 60 * 24 * 7; // 7 days
    public static final String SIGN_IN = "/login";
    public static final String SIGN_UP = "/create_account";
    public static final String HEADER_STRING = "token";
    public static final String TOKEN_PREFIX = "Bearer ";
    public static final Integer MAX_LOGIN_ATTEMPTS_LIMIT = 3;
}
