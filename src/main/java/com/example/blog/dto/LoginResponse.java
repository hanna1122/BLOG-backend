package com.example.blog.dto;

import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
public class LoginResponse {
    private String accessToken;
    private String refreshToken;

    public LoginResponse(String token) {
        accessToken = token;
    }
}
