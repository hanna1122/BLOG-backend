package com.example.blog.controller;

import com.example.blog.dto.CommentRequest;
import com.example.blog.model.Board;
import com.example.blog.model.Comment;
import com.example.blog.service.CommentService;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiResponse;
import io.swagger.annotations.ApiResponses;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@Api(description = "댓글을 관리한다.", tags = "댓글 관리")
@RestController
@RequiredArgsConstructor
public class CommentController {
    private final CommentService commentService;

    @ApiOperation(value="댓글 조회", notes="댓글을 조회한다.")
    @ApiResponses({
            @ApiResponse(code = 200, message = "Success", response = Board.class),
            @ApiResponse(code = 400, message = "Bad Parameter"),
            @ApiResponse(code = 500, message = "Internal Server Error")
    })
    @CrossOrigin("*")
    @GetMapping("/comment/get")
    public ResponseEntity<Object> getComment(Long BoardId) {
        List<Comment> result = commentService.getCommentList(BoardId);
        return ResponseEntity.ok(result);
    }

    @ApiOperation(value="댓글 등록", notes="댓글을 등록한다.")
    @ApiResponses({
            @ApiResponse(code = 200, message = "Success", response = Board.class),
            @ApiResponse(code = 400, message = "Bad Parameter"),
            @ApiResponse(code = 500, message = "Internal Server Error")
    })
    @PostMapping("/comment/post")
    public ResponseEntity<Object> commentPost(@RequestBody CommentRequest commentRequest){
        String email = SecurityContextHolder.getContext().getAuthentication().getName();
        commentService.commentPost(commentRequest, email);
        return ResponseEntity.ok("success");
    }

    @ApiOperation(value="댓글 수정", notes="댓글을 수정한다.")
    @ApiResponses({
            @ApiResponse(code = 200, message = "Success", response = Board.class),
            @ApiResponse(code = 400, message = "Bad Parameter"),
            @ApiResponse(code = 500, message = "Internal Server Error")
    })
    @PutMapping("/comment/update")
    public ResponseEntity<Object> commentUpdate(@RequestBody CommentRequest commentRequest){
        commentService.commentUpdate(commentRequest);

        return ResponseEntity.ok("success");
    }

    @ApiOperation(value="댓글 삭제", notes="댓글을 삭제한다.")
    @ApiResponses({
            @ApiResponse(code = 200, message = "Success", response = Board.class),
            @ApiResponse(code = 400, message = "Bad Parameter"),
            @ApiResponse(code = 500, message = "Internal Server Error")
    })
    @DeleteMapping("/comment/delete")
    public @ResponseBody ResponseEntity<Object> commentDelete(Long commentId){
        commentService.commentDelete(commentId);
        return ResponseEntity.ok("success");
    }

}
