package com.example.blog.exception;

import com.google.gson.Gson;
import org.json.simple.JSONObject;
import org.springframework.validation.BindingResult;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseBody;

import java.util.Map;
import java.util.stream.Collectors;

@ControllerAdvice
@ResponseBody
public class GlobalException {

    @ExceptionHandler
    public JSONObject validException(MethodArgumentNotValidException e){
        BindingResult bindingResult = e.getBindingResult();
        Gson gson = new Gson();
        Map<String, String> map = bindingResult.getFieldErrors().stream().collect(
                Collectors.toMap(FieldError::getField, FieldError::getDefaultMessage));
        String msg = gson.toJson(map);

        return ErrorException.JsonErrorResponse(400, "Bad Parameter : " + msg);
    }
}
