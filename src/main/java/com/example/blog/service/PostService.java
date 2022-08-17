package com.example.blog.service;

import com.example.blog.dto.BoardPostRequest;
import com.example.blog.dto.PostResponse;
import com.example.blog.model.Board;
import com.example.blog.model.User;
import com.example.blog.repository.ImageRepository;
import com.example.blog.repository.PostRepository;

import java.util.List;

import com.example.blog.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.qlrm.mapper.JpaResultMapper;
import org.springframework.stereotype.Service;

import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;
import javax.persistence.Query;

@Service
@RequiredArgsConstructor
public class PostService {

    private final PostRepository postRepository;

    private final ImageRepository imageRepository;

    private final UserRepository userRepository;

    @PersistenceContext
    private EntityManager em;

    /**

     * @Method Name : getPost
     * @Method 설명 : 블로그 리스트 조회
     * @param userEmail
     */
    public List<PostResponse> getPost(String userEmail) {

        Long userId = userRepository.findByEmailAndUseYn(userEmail, "Y").get().getUserId();


        Query query = em.createNativeQuery("SELECT b.board_id, b.content, b.hit, b.reg_dt, b.title, b.reg_id\n" +
                        ", (SELECT count(*) from like_board lb WHERE lb.board_id = b.board_id AND lb.like_yn = 'Y') as like_count\n" +
                        ", IFNULL(lb.like_yn, 'N') as like_yn \n" +
                        ", lb.like_id \n" +
                        ", u.nickname \n" +
                        ", i.file_src \n" +
                        "from board b \n" +
                        "inner join user u ON u.user_id = b.reg_id \n" +
                        "left join (select min(file_src) as file_src, board_id from image group by board_id) i ON i.board_id = b.board_id \n" +
                        "left join like_board lb ON b.board_id = lb.board_id and lb.reg_id=?"
                );
        JpaResultMapper result = new JpaResultMapper();
        query.setParameter(1, userId);
        return result.list(query, PostResponse.class);
    }

    /**

     * @Method Name : boardPost
     * @Method 설명 : 블로그 게시글 등록
     * @param email
     * @param title
     * @param content
     */
    public Board boardPost(String email, String title, String content) {

        Long userId = userRepository.findByEmailAndUseYn(email, "Y").get().getUserId();

        Board board = new Board().builder()
                .title(title)
                .content(content)
                .regId(User.builder().userId(userId).build())
                .build();
        return postRepository.save(board);
    }

    /**

     * @Method Name : boardPost
     * @Method 설명 : 블로그 게시글 수정
     * @param boardPostRequest
     */
    public Board boardUpdate(BoardPostRequest boardPostRequest){
        Board board = new Board().builder()
                .boardId(boardPostRequest.getBoardId())
                .title(boardPostRequest.getTitle())
                .content(boardPostRequest.getContent())
                .build();
        return postRepository.save(board);
    }

    /**

     * @Method Name : boardDelete
     * @Method 설명 : 블로그 게시글 삭제
     * @param boardId
     */
    public void boardDelete(Long boardId){
        postRepository.deleteById(boardId);
    }

    /**

     * @Method Name : boardDetail
     * @Method 설명 : 블로그 게시글 상세 조회
     * @param boardId
     */
    public Board boardDetail(Long boardId){

        Board board = postRepository.findById(boardId).get();

        return board;
    }
}
