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

import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;

/**
 * @author open-gm-jca contributors
 */
@ApiModel
public class PageResponse<T> extends Response<T> {

    @ApiModelProperty(notes = "数量")
    private Long count;

    public PageResponse(String code, String msg, T data, Long count) {
        super(code, msg, data);
        this.count = count;
    }

    public static <T> PageResponse<T> ok(T data, Long count) {
        return new PageResponse<>("0", "", data, count);
    }

    public Long getCount() {
        return count;
    }

    public void setCount(Long count) {
        this.count = count;
    }
}
