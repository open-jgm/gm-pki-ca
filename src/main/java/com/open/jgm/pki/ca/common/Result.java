package com.open.jgm.pki.ca.common;

import lombok.Data;

@Data
public class Result<T> {

    private String code;
    private String msg;
    private T data;

    private Result() {}

    public static <T> Result<T> success(T data) {
        Result<T> r = new Result<>();
        r.code = "0";
        r.msg = "success";
        r.data = data;
        return r;
    }

    public static <T> Result<T> success() {
        Result<T> r = new Result<>();
        r.code = "0";
        r.msg = "success";
        return r;
    }

    public static <T> Result<T> error(String msg) {
        Result<T> r = new Result<>();
        r.code = "500";
        r.msg = msg;
        return r;
    }
}
