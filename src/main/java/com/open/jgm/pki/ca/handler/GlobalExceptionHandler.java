package com.open.jgm.pki.ca.handler;

import com.open.jgm.pki.ca.cert.exception.CertException;
import com.open.jgm.pki.ca.framework.exception.BusinessException;
import com.open.jgm.pki.ca.framework.model.Response;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.util.stream.Collectors;

@Slf4j
@RestControllerAdvice
public class GlobalExceptionHandler {

    /** 证书领域异常：返回 400 + 业务提示 */
    @ExceptionHandler(CertException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public Response<Void> handleCertException(CertException e) {
        log.error("证书操作异常: {}", e.getMessage(), e);
        return Response.error("400", e.getMessage());
    }

    /** 业务异常：直接将 message 返回给前端 */
    @ExceptionHandler(BusinessException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public Response<Void> handleBusinessException(BusinessException e) {
        log.warn("业务异常: {}", e.getMessage());
        return Response.error("400", e.getMessage());
    }

    /** 参数校验异常：收集所有字段错误 */
    @ExceptionHandler(MethodArgumentNotValidException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public Response<Void> handleValidation(MethodArgumentNotValidException e) {
        String msg = e.getBindingResult().getFieldErrors().stream()
                .map(fe -> fe.getField() + ": " + fe.getDefaultMessage())
                .collect(Collectors.joining("; "));
        log.warn("参数校验失败: {}", msg);
        return Response.error("400", msg);
    }

    /** 兜底异常 */
    @ExceptionHandler(Exception.class)
    @ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
    public Response<Void> handleException(Exception e) {
        log.error("系统异常", e);
        return Response.error("500", "服务器内部错误，请联系管理员");
    }
}
