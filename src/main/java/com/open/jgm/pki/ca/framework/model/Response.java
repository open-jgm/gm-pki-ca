/*
 * Copyright 2026 open-gm-jca contributors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.open.jgm.pki.ca.framework.model;

import com.open.jgm.pki.ca.framework.EasyAdminConstants;
import cn.hutool.core.util.StrUtil;
import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;
import lombok.AllArgsConstructor;
import lombok.Data;
import org.slf4j.MDC;
import org.springframework.context.annotation.DependsOn;

/**
 * @author open-gm-jca contributors
 */
@Data
@AllArgsConstructor
@ApiModel
@DependsOn
public class Response<T> {
    @ApiModelProperty(notes = "响应码，非0 即为异常", example = "0")
    private final String code;
    @ApiModelProperty(notes = "响应消息", example = "提交成功")
    private final String msg;
    @ApiModelProperty(notes = "响应数据")
    private final T data;
    @ApiModelProperty(notes = "traceId")
    private final String traceId;

    @ApiModelProperty(notes = "请求id")
    private final Boolean success;

    protected Response(String code, String msg, T data) {
        this.code = code;
        this.msg = msg;
        this.data = data;
        this.success = StrUtil.equals("0", code);
        this.traceId = MDC.get(EasyAdminConstants.TRACE_ID);
    }

    public static <T> Response<T> ok(T data) {
        return new Response<>("0", "操作成功", data);
    }

    public static <Void> Response<Void> ok() {
        return new Response<Void>("0", "操作成功", null);
    }

    public static <T> Response<T> error(T data) {
        return new Response<>("400", "", data);
    }

    public static <T> Response<T> error(String code, String msg, T data) {
        return new Response<>(code, msg, data);
    }

    public static <T> Response<T> error(String code, String msg) {
        return new Response<>(code, msg, null);
    }
}
