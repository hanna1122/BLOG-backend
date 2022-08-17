package com.example.blog.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.math.BigInteger;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class LikeRequest {
    private Long likeId;
    private Long boardId;
    private Long regId;
    private String likeYn;

    public LikeRequest(BigInteger likeId, BigInteger boardId, BigInteger regId, String likeYn){
        this.likeId = likeId.longValue();
        this.boardId = boardId.longValue();
        this.regId = regId.longValue();
        this.likeYn = likeYn;
    }
}
