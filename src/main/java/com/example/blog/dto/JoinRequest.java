package com.example.blog.dto;

import lombok.Data;

@Data
public class JoinRequest {
    private String email;
    private String password;
    private String userName;
    private String nickName;
    private String userAuth;
}
