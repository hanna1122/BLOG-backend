package com.example.blog.dto;

import com.fasterxml.jackson.annotation.JsonFormat;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.math.BigInteger;
import java.sql.Timestamp;
import java.time.LocalDateTime;

@NoArgsConstructor
@Data
public class PostResponse {
    private Long boardId;
    private String content;
    private int hit;
    @JsonFormat(shape= JsonFormat.Shape.STRING, pattern="yyyy-MM-dd HH:mm:ss")
    private LocalDateTime regDt;
    private String title;
    private Long regId;
    private String type;
    private int likeCount;
    private String likeYn;
    private Long likeId;
    private String nickname;
    private String fileSrc;
    private String profileSrc;

    public PostResponse(BigInteger boardId, String content, BigInteger hit, Timestamp regDt, String title, BigInteger regId, BigInteger likeCount, String likeYn, BigInteger likeId, String nickname, String fileSrc){
        this.boardId = boardId.longValue();
        this.content = content;
        this.hit = hit.intValue();
        this.regDt = regDt.toLocalDateTime();
        this.title = title;
        this.regId = regId.longValue();
        this.likeCount = likeCount.intValue();
        this.likeYn = likeYn;
        this.likeId = likeId == null ? null : likeId.longValue();
        this.nickname = nickname;
        this.fileSrc = fileSrc;

    }
}
