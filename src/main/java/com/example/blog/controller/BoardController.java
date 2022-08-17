package com.example.blog.controller;

import com.example.blog.dto.BoardPostRequest;
import com.example.blog.dto.PostResponse;
import com.example.blog.model.Board;
import com.example.blog.service.AwsService;
import com.example.blog.service.PostService;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiResponse;
import io.swagger.annotations.ApiResponses;
import java.util.List;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

@Api(description = "블로그를 관리한다.", tags = "블로그 관리")
@RestController
@RequiredArgsConstructor
public class BoardController {

    private final PostService postService;

    private final AwsService awsService;


    @ApiOperation(value = "블로그 조회", notes = "블로그 포스트를 조회한다.")
    @ApiResponses({
        @ApiResponse(code = 200, message = "Success", response = Board.class),
        @ApiResponse(code = 400, message = "Bad Parameter"),
        @ApiResponse(code = 500, message = "Internal Server Error")
    })
    @CrossOrigin("*")
    @GetMapping("/board/get")
    public ResponseEntity<Object> getPost() {

        String userEmail = SecurityContextHolder.getContext().getAuthentication().getName();

        List<PostResponse> result = postService.getPost(userEmail);
        return ResponseEntity.ok(result);
    }

    @ApiOperation(value = "블로그 게시글 등록", notes = "블로그 게시글을 등록한다.")
    @ApiResponses({
            @ApiResponse(code = 200, message = "Success", response = Board.class),
            @ApiResponse(code = 400, message = "Bad Parameter"),
            @ApiResponse(code = 500, message = "Internal Server Error")
    })
    @PostMapping("/board/post")
    public @ResponseBody String boardPost(@RequestParam("files") MultipartFile[] files, @RequestParam("title") String title, @RequestParam("content") String content) throws Exception {


        String email = SecurityContextHolder.getContext().getAuthentication().getName();

        String s3Path = "/board";

        Board boardPost = postService.boardPost(email, title, content);
        Long boardId = boardPost.getBoardId();
        awsService.uploadMultipartFile(files,s3Path, boardId);


        return "success";
    }

    @ApiOperation(value = "블로그 게시글 수정", notes = "블로그 게시글을 수정한다.")
    @ApiResponses({
            @ApiResponse(code = 200, message = "Success", response = Board.class),
            @ApiResponse(code = 400, message = "Bad Parameter"),
            @ApiResponse(code = 500, message = "Internal Server Error")
    })
    @PutMapping("/board/update")
    public @ResponseBody String boardUpdate(@RequestBody BoardPostRequest boardPostRequest){

        postService.boardUpdate(boardPostRequest);
        return "success";
    }

    @ApiOperation(value = "블로그 게시글 삭제", notes = "블로그 게시글을 삭제한다.")
    @ApiResponses({
            @ApiResponse(code = 200, message = "Success", response = Board.class),
            @ApiResponse(code = 400, message = "Bad Parameter"),
            @ApiResponse(code = 500, message = "Internal Server Error")
    })
    @DeleteMapping("/board/delete")
    public @ResponseBody String boardDelete(Long boardId){

        postService.boardDelete(boardId);
        return "success";
    }

    @ApiOperation(value = "블로그 게시글 이미지 등록", notes = "블로그 게시글 이미지를 등록한다.")
    @ApiResponses({
            @ApiResponse(code = 200, message = "Success", response = Board.class),
            @ApiResponse(code = 400, message = "Bad Parameter"),
            @ApiResponse(code = 500, message = "Internal Server Error")
    })
    @PostMapping("/board/img-put")
    public @ResponseBody String uploadBoardImages(@RequestParam("files") MultipartFile[] files, Long boardId) throws Exception {

        String s3Path = "/board";
        awsService.uploadMultipartFile(files,s3Path, boardId);

        return "success";
    }

    @ApiOperation(value = "블로그 게시글 상세", notes = "블로그 게시글 상세 조회한다.")
    @ApiResponses({
            @ApiResponse(code = 200, message = "Success", response = Board.class),
            @ApiResponse(code = 400, message = "Bad Parameter"),
            @ApiResponse(code = 500, message = "Internal Server Error")
    })
    @GetMapping("/board/detail")
    public ResponseEntity<Board> boardDetail(Long boardId){

        Board board = postService.boardDetail(boardId);
        return ResponseEntity.ok(board);
    }

}




