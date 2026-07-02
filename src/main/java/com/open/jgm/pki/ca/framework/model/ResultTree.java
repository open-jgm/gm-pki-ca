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

import lombok.Data;

/**
 * Describe: 前端 tree 结果封装数据
 * Author: 就 眠 仪 式
 * CreateTime: 2019/10/23
 */
@Data
public class ResultTree {

    /**
     * 状态信息
     */
    private Status status = new Status();

    /**
     * 返回数据
     */
    private Object data;

    /**
     * 所需内部类
     */
    @Data
    public class Status {

        private Integer code = 200;

        private String message = "默认";
    }

    public static ResultTree data(Object data) {
        ResultTree resultTree = new ResultTree();
        resultTree.setData(data);
        return resultTree;
    }
}
