package com.example.blog.controller;

import com.example.blog.dto.JoinRequest;
import com.example.blog.dto.LoginRequest;
import com.example.blog.dto.LoginResponse;
import com.example.blog.dto.UserDelRequest;
import com.example.blog.jwt.JwtTokenUtil;
import com.example.blog.jwt.JwtUserDetailsService;
import com.example.blog.model.User;
import com.example.blog.service.AwsService;
import com.example.blog.service.UserService;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiResponse;
import io.swagger.annotations.ApiResponses;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import javax.validation.Valid;

@Api(description = "회원을 관리한다.", tags = "회원관리")
@RestController
@RequiredArgsConstructor
public class UserController {

    private final UserService userService;

    private final JwtTokenUtil jwtTokenUtil;

    private final JwtUserDetailsService userDetailService;

    private final AwsService awsService;

    @ApiOperation(value = "로그인", notes = "로그인")
    @ApiResponses({
        @ApiResponse(code = 200, message = "Success", response = LoginResponse.class),
        @ApiResponse(code = 400, message = "Bad Parameter"),
        @ApiResponse(code = 401, message = "Access Denied"),
        @ApiResponse(code = 500, message = "Internal Server Error")
    })
    @CrossOrigin("*")
    @PostMapping("/auth/login")
    public ResponseEntity<Object> login(@RequestBody LoginRequest loginRequest) {
        final User member = userDetailService.authenticateByEmailAndPassword
                (loginRequest.getEmail(), loginRequest.getPassword());
        if(member==null){
            return new ResponseEntity<>("Access Denied", HttpStatus.UNAUTHORIZED);
        }else{
            final String token = jwtTokenUtil.generateTokenByEmail(member.getEmail(), member.getUserAuth());
            return ResponseEntity.ok(new LoginResponse(token));
        }

    }

    @ApiOperation(value = "회원가입", notes = "회원가입")
    @ApiResponses({
        @ApiResponse(code = 200, message = "Success", response = User.class),
        @ApiResponse(code = 400, message = "Bad Parameter"),
        @ApiResponse(code = 500, message = "Internal Server Error")
    })
    @CrossOrigin("*")
    @PostMapping("/auth/join")
    public ResponseEntity<Object> join(@RequestBody JoinRequest joinRequest) {
        return ResponseEntity.ok(userService.join(joinRequest));
    }

    @ApiOperation(value = "회원 수정", notes = "회원 정보를 수정한다.")
    @ApiResponses({
            @ApiResponse(code = 200, message = "Success", response = LoginResponse.class),
            @ApiResponse(code = 400, message = "Bad Parameter"),
            @ApiResponse(code = 500, message = "Internal Server Error")
    })
    @PutMapping("/update/User")
    public @ResponseBody String updeteUser(@RequestBody JoinRequest joinRequest){

        String email = SecurityContextHolder.getContext().getAuthentication().getName();
        userService.updateUser(email, joinRequest);

        return "success";
    }

    @ApiOperation(value = "회원 탈퇴", notes = "회원 탈퇴한다.")
    @ApiResponses({
            @ApiResponse(code = 200, message = "Success", response = LoginResponse.class),
            @ApiResponse(code = 400, message = "Bad Parameter"),
            @ApiResponse(code = 500, message = "Internal Server Error")
    })
    @DeleteMapping("/delete/User")
    public @ResponseBody String deleteUser(){

        String email = SecurityContextHolder.getContext().getAuthentication().getName();
        userService.deleteUser(email);
        return "success";
    }

    @ApiOperation(value = "프로필 사진 등록", notes = "프로필 사진을 등록한다.")
    @ApiResponses({
            @ApiResponse(code = 200, message = "Success", response = LoginResponse.class),
            @ApiResponse(code = 400, message = "Bad Parameter"),
            @ApiResponse(code = 500, message = "Internal Server Error")
    })
    @PostMapping("/profile/img-put")
    public @ResponseBody String uploadImages(@RequestParam("files") MultipartFile files) throws Exception {

        String s3Path = "/profile";

        Long fileId =  awsService.uploadProfileImg(files,s3Path).getImageId();
        userService.updateProfileImg(fileId);
        return "success";
    }

    @ApiOperation(value = "프로필 사진 조회", notes = "프로필 사진을 조회한다.")
    @ApiResponses({
            @ApiResponse(code = 200, message = "Success", response = LoginResponse.class),
            @ApiResponse(code = 400, message = "Bad Parameter"),
            @ApiResponse(code = 500, message = "Internal Server Error")
    })
    @GetMapping("/profile/detail")
    public ResponseEntity<Object> userDetail() {
        String email = SecurityContextHolder.getContext().getAuthentication().getName();

        return ResponseEntity.ok(userService.userDetail(email));
    }

}
