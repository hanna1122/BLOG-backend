package com.example.blog.dto;

import lombok.Data;
import lombok.NoArgsConstructor;

import java.math.BigInteger;

@Data
@NoArgsConstructor
public class UserProfileResponse {
    private Long userId;
    private String email;
    private String userName;
    private String nickname;
    private String fileSrc;

    public UserProfileResponse(BigInteger userId, String email, String userName,String nickname, String fileSrc){
        this.userId = userId.longValue();
        this.email = email;
        this.userName = userName;
        this.nickname = nickname;
        this.fileSrc = fileSrc;
    }
}
