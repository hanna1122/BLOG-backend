package com.example.blog.service;

import com.example.blog.dto.LikeRequest;
import com.example.blog.model.Board;
import com.example.blog.model.LikeBoard;
import com.example.blog.model.User;
import com.example.blog.repository.LikeRepository;
import com.example.blog.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;

@Service
@RequiredArgsConstructor
public class LikeService {

    private final LikeRepository likeRepository;

    private final UserRepository userRepository;

    @PersistenceContext
    private EntityManager em;

    /**

     * @Method Name : likePost
     * @Method 설명 : 좋아요등록
     * @param likeRequest
     * @param email 
     */
    public LikeBoard likePost(LikeRequest likeRequest, String email){
        Long regId = userRepository.findByEmailAndUseYn(email, "Y").get().getUserId();

        LikeBoard likeBoard = new LikeBoard().builder()
                .boardId(Board.builder().boardId(likeRequest.getBoardId()).build())
                .regId(User.builder().userId(regId).build())
                .likeYn(likeRequest.getLikeYn())
                .build();

        return likeRepository.save(likeBoard);
    }

    /**

     * @Method Name : likeUpdate
     * @Method 설명 : 좋아요 수정
     * @param likeRequest
     * @param email
     */
    public void likeUpdate(LikeRequest likeRequest, String email){
        Long boardId = likeRequest.getBoardId();
        Long regId = userRepository.findByEmailAndUseYn(email, "Y").get().getUserId();


            LikeBoard likeBoard = new LikeBoard().builder()
                .likeId(likeRequest.getLikeId())
                .boardId(Board.builder().boardId(likeRequest.getBoardId()).build())
                .regId(User.builder().userId(regId).build())
                .likeYn(likeRequest.getLikeYn())
                .build();


            likeRepository.save(likeBoard);



    }
}
