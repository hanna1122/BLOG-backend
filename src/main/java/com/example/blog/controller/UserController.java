package com.example.blog.controller;

import com.amazonaws.Response;
import com.example.blog.dto.*;
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
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import javax.servlet.http.HttpServletRequest;
import javax.validation.Valid;
import java.util.concurrent.TimeUnit;

@Api(description = "회원을 관리한다.", tags = "회원관리")
@RestController
@RequiredArgsConstructor
public class UserController {

    private final UserService userService;

    private final JwtTokenUtil jwtTokenUtil;

    private final JwtUserDetailsService userDetailService;

    private final AwsService awsService;

    private final RedisTemplate redisTemplate;

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
            final LoginResponse token = jwtTokenUtil.generateTokenByEmail(member.getEmail(), member.getUserAuth());

            redisTemplate.opsForValue().set("RefreshToken:"+member.getEmail(), token.getRefreshToken(), token.getRefreshTime(), TimeUnit.MILLISECONDS);
            return ResponseEntity.ok(token);
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
    public ResponseEntity<Object> updeteUser(@RequestBody JoinRequest joinRequest){

        String email = SecurityContextHolder.getContext().getAuthentication().getName();

        return ResponseEntity.ok(userService.updateUser(email, joinRequest));
    }

    @ApiOperation(value = "회원 탈퇴", notes = "회원 탈퇴한다.")
    @ApiResponses({
            @ApiResponse(code = 200, message = "Success", response = LoginResponse.class),
            @ApiResponse(code = 400, message = "Bad Parameter"),
            @ApiResponse(code = 500, message = "Internal Server Error")
    })
    @DeleteMapping("/delete/User")
    public ResponseEntity<Object> deleteUser(){

        String email = SecurityContextHolder.getContext().getAuthentication().getName();
        userService.deleteUser(email);
        return ResponseEntity.ok("success");
    }

    @ApiOperation(value = "프로필 사진 등록", notes = "프로필 사진을 등록한다.")
    @ApiResponses({
            @ApiResponse(code = 200, message = "Success", response = LoginResponse.class),
            @ApiResponse(code = 400, message = "Bad Parameter"),
            @ApiResponse(code = 500, message = "Internal Server Error")
    })
    @PostMapping("/profile/img-put")
    public ResponseEntity<Object> uploadImages(@RequestParam("files") MultipartFile files) throws Exception {

        String s3Path = "/profile";

        Long fileId =  awsService.uploadProfileImg(files,s3Path).getImageId();
        userService.updateProfileImg(fileId);
        return ResponseEntity.ok("success");
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

    @ApiOperation(value = "refreshtoken 재발급", notes = "refreshtoken 재발급")
    @ApiResponses({
            @ApiResponse(code = 200, message = "Success", response = LoginResponse.class),
            @ApiResponse(code = 400, message = "Bad Parameter"),
            @ApiResponse(code = 401, message = "Access Denied"),
            @ApiResponse(code = 500, message = "Internal Server Error")
    })
    @PostMapping("/auth/reissue")
    public ResponseEntity<Object> reissue(ReissueRequest reissueRequest){
        if(!jwtTokenUtil.validateToken(reissueRequest.getRefreshToken())){
            return new ResponseEntity<>("error", HttpStatus.UNAUTHORIZED);
        }
        String email = jwtTokenUtil.getUsernameFromToken(reissueRequest.getRefreshToken());
        String auth = jwtTokenUtil.getUserAuthFromToken(reissueRequest.getRefreshToken());

        String refreshToken = (String)redisTemplate.opsForValue().get("RefreshToken:"+email);
        if(!refreshToken.equals(reissueRequest.getRefreshToken())){
            return new ResponseEntity<>("error", HttpStatus.UNAUTHORIZED);
        }
        LoginResponse loginResponse = jwtTokenUtil.generateTokenByEmail(email, auth);

        redisTemplate.opsForValue().set("RefreshToken:"+email, loginResponse.getRefreshToken(), loginResponse.getRefreshTime(), TimeUnit.MILLISECONDS);

        return ResponseEntity.ok(loginResponse);
    }

    @ApiOperation(value = "로그아웃", notes = "로그아웃")
    @ApiResponses({
            @ApiResponse(code = 200, message = "Success", response = LoginResponse.class),
            @ApiResponse(code = 400, message = "Bad Parameter"),
            @ApiResponse(code = 401, message = "Access Denied"),
            @ApiResponse(code = 500, message = "Internal Server Error")
    })
    @PostMapping("/user/logout")
    public ResponseEntity<Object> logout(HttpServletRequest request){
        String requestTokenHeader = request.getHeader("Authorization");
        if(!jwtTokenUtil.validateToken(requestTokenHeader)){
            return new ResponseEntity<>("error", HttpStatus.UNAUTHORIZED);
        }

        String email = jwtTokenUtil.getUsernameFromToken(requestTokenHeader);

        if(redisTemplate.opsForValue().get("RefreshToken:"+email)!=null){
            redisTemplate.delete("RefreshToken:"+email);
        }

        Long expiration  = jwtTokenUtil.getExpirationDateFromToken(requestTokenHeader);
        redisTemplate.opsForValue().set(requestTokenHeader, "logout", expiration, TimeUnit.MILLISECONDS);

        return ResponseEntity.ok("success");
    }


}
