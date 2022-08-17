package com.example.blog.service;

import com.example.blog.dto.*;
import com.example.blog.model.Image;
import com.example.blog.model.User;
import com.example.blog.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.qlrm.mapper.JpaResultMapper;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;
import javax.persistence.Query;

@Service
@RequiredArgsConstructor
public class UserService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    @PersistenceContext
    private EntityManager em;

    /**

     * @Method Name : saveUser
     * @Method 설명 : 회원가입 비밀번호 암호화
     * @param user
     */
    public User saveUser(User user) {
        String pw = user.getPassword();
        pw = passwordEncoder.encode(pw);
        user.setPassword(pw);

        return userRepository.save(user);
    }


    /**

     * @Method Name : saveUser
     * @Method 설명 : 회원가입
     * @param joinRequest
     */
    public User join(JoinRequest joinRequest) {
        return saveUser(User.builder()
            .email(joinRequest.getEmail())
            .password(joinRequest.getPassword())
            .userName(joinRequest.getUserName())
            .nickname(joinRequest.getNickName())
            .userAuth(joinRequest.getUserAuth())
            .build());
    }

    /**

     * @Method Name : updateUser
     * @Method 설명 : 회원 정보 수정
     * @param email
     * @param joinRequest
     */
    public User updateUser(String email, JoinRequest joinRequest) {

        User updateUser = userRepository.findByEmailAndUseYn(email, "Y").get();
        updateUser.setPassword(joinRequest.getPassword());
        updateUser.setNickname(joinRequest.getNickName());


        return saveUser(updateUser);
    }

    /**

     * @Method Name : deleteUser
     * @Method 설명 : 회원 정보 삭제
     * @param email
     */
    public void deleteUser(String email){
        User deleteUser = userRepository.findByEmailAndUseYn(email, "Y").get();
        deleteUser.setUseYn("N");
        userRepository.save(deleteUser);
    }

    /**

     * @Method Name : userDetail
     * @Method 설명 : 회원 정보 조회
     * @param email
     */
    public UserProfileResponse userDetail(String email){

        Query query = em.createNativeQuery("select a.user_id, a.email, a.user_name, a.nickname,b.file_src from user a, image b where a.email = ? and a.user_img = b.image_id"
        );
        JpaResultMapper result = new JpaResultMapper();
        query.setParameter(1, email);
        return result.uniqueResult(query, UserProfileResponse.class);

    }

    /**

     * @Method Name : updateProfileImg
     * @Method 설명 : 회원 프로필사진 변경
     * @param fileId
     */
    public User updateProfileImg(Long fileId){
        String email = SecurityContextHolder.getContext().getAuthentication().getName();

        User user = userRepository.findByEmailAndUseYn(email, "Y").get();
        user.setUserImg(Image.builder().imageId(fileId).build());

        return userRepository.save(user);
    }


}
