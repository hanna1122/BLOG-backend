package com.example.blog.service;


import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringReader;
import java.text.SimpleDateFormat;
import java.util.Date;

import com.example.blog.model.Board;
import com.example.blog.model.Image;
import com.example.blog.repository.ImageRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.multipart.MultipartFile;

import com.amazonaws.services.s3.AmazonS3;
import com.amazonaws.services.s3.model.ObjectMetadata;
import com.amazonaws.services.s3.model.PutObjectRequest;

@Service
@RequiredArgsConstructor
@Transactional(rollbackFor = Exception.class)
public class AwsService {

    @Autowired
    private AmazonS3 s3Client;
    @Value("${aws.s3.bucket}")
    private String bucketName; //S3 버킷경로

    private final ImageRepository imageRepository;

    /**

     * @Method Name : uploadMultipartFile
     * @Method 설명 : 게시글 - S3 이미지 업로드
     * @param files
     * @param bucketKey (실제 저장할 경로)
     * @param boardId
     * @throws IOException
     */
    public void uploadMultipartFile(MultipartFile[] files,String bucketKey, Long boardId) throws IOException{

        ObjectMetadata omd = new ObjectMetadata();
        String fileName = "img_"+getNowTime24();

        for(int i=0; i<files.length; i++) {
            omd.setContentType(files[i].getContentType());
            omd.setContentLength(files[i].getSize());
            omd.setHeader("filename",fileName+"_"+i);
            s3Client.putObject(new PutObjectRequest(bucketName+bucketKey,fileName+"_"+i,files[i].getInputStream(),omd));

            String uploadSrc = s3Client.getUrl(bucketName+bucketKey,fileName+"_"+i).toString();
            Image image = new Image().builder()
                .boardId(Board.builder().boardId(boardId).build())
                .fileName(fileName+"_"+i)
                .fileSrc(uploadSrc)
                .build();
            imageRepository.save(image);
        }
    }

    /**

     * @Method Name : uploadProfileImg
     * @Method 설명 : 프로필 - S3 이미지 업로드
     * @param files
     * @param bucketKey (실제 저장할 경로)
     * @throws IOException
     */
    public Image uploadProfileImg(MultipartFile files,String bucketKey) throws IOException{

        ObjectMetadata omd = new ObjectMetadata();
        String fileName = "img_"+getNowTime24();

            omd.setContentType(files.getContentType());
            omd.setContentLength(files.getSize());
            omd.setHeader("filename",fileName);
            s3Client.putObject(new PutObjectRequest(bucketName+bucketKey,fileName,files.getInputStream(),omd));

            String uploadSrc = s3Client.getUrl(bucketName+bucketKey,fileName).toString();
            Image image = new Image().builder()
                    .fileName(fileName)
                    .fileSrc(uploadSrc)
                    .build();


            return imageRepository.save(image);

    }

    public static String getNowTime24() {
        long time = System.currentTimeMillis();
        SimpleDateFormat dayTime = new SimpleDateFormat("yyyyMMddkkmmss");
        String str = dayTime.format(new Date(time));
        return str;
    }

}
