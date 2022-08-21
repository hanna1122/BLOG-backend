package com.example.blog.dto;

import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
public class LoginResponse {
    private String accessToken;
    private String refreshToken;
    private Long accessTime;
    private Long refreshTime;


}
