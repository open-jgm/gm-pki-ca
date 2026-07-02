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
 * Describe: 前 端 表 格 数 据 封 装
 * Author: 就 眠 仪 式
 * CreateTime: 2019/10/23
 */
@Data
public class ResultTable {

    /**
     * 状态码
     */
    private Integer code;

    /**
     * 提示消息
     */
    private String msg;

    /**
     * 消息总量
     */
    private Long count;

    /**
     * 数据对象
     */
    private Object data;

    /**
     * 构 建
     */
    public static ResultTable pageTable(long count, Object data) {
        ResultTable resultTable = new ResultTable();
        resultTable.setData(data);
        resultTable.setCode(0);
        resultTable.setCount(count);
        return resultTable;
    }

    public static ResultTable dataTable(Object data) {
        ResultTable resultTable = new ResultTable();
        resultTable.setData(data);
        resultTable.setCode(0);
        return resultTable;
    }

}
