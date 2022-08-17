package com.example.blog.exception;

import org.json.simple.JSONObject;

public class ErrorException {
    public static JSONObject JsonErrorResponse(int errorCode,String errorMessage){
        JSONObject jsonObject = new JSONObject();
        jsonObject.put("errorCode", errorCode);
        jsonObject.put("errorMessage", errorMessage);
        return jsonObject;
    }
}
