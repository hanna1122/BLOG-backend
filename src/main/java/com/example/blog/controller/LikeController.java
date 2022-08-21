package com.example.blog.controller;

import com.example.blog.dto.BoardPostRequest;
import com.example.blog.dto.LikeRequest;
import com.example.blog.model.Board;
import com.example.blog.service.LikeService;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiResponse;
import io.swagger.annotations.ApiResponses;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import java.security.Security;

@Api(description = "Like여부를 관리한다.", tags = "Like 관리")
@RestController
@RequiredArgsConstructor
public class LikeController {

    private final LikeService likeService;

    @ApiOperation(value = "like 등록", notes = "게시글에 대한 like 등록한다.")
    @ApiResponses({
            @ApiResponse(code = 200, message = "Success", response = Board.class),
            @ApiResponse(code = 400, message = "Bad Parameter"),
            @ApiResponse(code = 500, message = "Internal Server Error")
    })
    @PostMapping("/like/post")
    public ResponseEntity<Object> boardPost(@RequestBody LikeRequest likeRequest){
        String userId = SecurityContextHolder.getContext().getAuthentication().getName();
        likeService.likePost(likeRequest, userId);
        return ResponseEntity.ok("success");
    }

    @ApiOperation(value = "like 수정", notes = "게시글에 대한 like 수정한다.")
    @ApiResponses({
            @ApiResponse(code = 200, message = "Success", response = Board.class),
            @ApiResponse(code = 400, message = "Bad Parameter"),
            @ApiResponse(code = 500, message = "Internal Server Error")
    })
    @PutMapping("/like/update")
    public ResponseEntity<Object> boardUpdate(@RequestBody LikeRequest likeRequest){
        String userId = SecurityContextHolder.getContext().getAuthentication().getName();
        likeService.likeUpdate(likeRequest, userId);
        return ResponseEntity.ok("success");
    }
}
