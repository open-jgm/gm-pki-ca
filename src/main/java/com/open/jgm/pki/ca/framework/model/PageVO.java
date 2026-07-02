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

//package business.framework.model;
//
//import cn.hutool.core.collection.CollUtil;
//import cn.hutool.core.util.StrUtil;
//import com.baomidou.mybatisplus.core.metadata.OrderItem;
//import com.baomidou.mybatisplus.extension.plugins.pagination.Page;
//import io.swagger.annotations.ApiModelProperty;
//import lombok.Data;
//
//import java.io.Serializable;
//import java.util.ArrayList;
//import java.util.List;
//
///**
// * 查询参数
// */
//@Data
//public class PageVO implements Serializable {
//
//    private static final long serialVersionUID = 1L;
//
//    /**
//     * 每页显示条数，默认 10
//     */
//    @ApiModelProperty(value = "每页显示条数，默认 10")
//    private long size = 10;
//    /**
//     * 当前页，默认1，第一页
//     */
//    @ApiModelProperty(value = "当前页，默认1，第一页")
//    private long current = 1;
//
//    /**
//     * 排序字段信息
//     * 排序字段和排序类型
//     * create_time desc,user_no asc.
//     */
//    @ApiModelProperty(value = "排序字段和排序类型，例如：create_time desc,user_no asc.")
//    private String orderBy;
//
//
//    public Page toPage() {
//        Page page = new Page();
//        page.setCurrent(current);
//        page.setSize(size);
//        if (StrUtil.isNotBlank(orderBy)) {
//            List<OrderItem> orders = new ArrayList<>();
//            String[] orderItems = StrUtil.splitToArray(orderBy, ",");
//            for (String orderItemStr : orderItems) {
//                String[] orderAndSort = StrUtil.splitToArray(orderItemStr, " ");
//                if (CollUtil.size(orderAndSort) != 2) {
//                    continue;
//                }
//                String order = orderAndSort[0];
//                String sort = orderAndSort[1];
//                orders.add(new OrderItem(order, StrUtil.equalsIgnoreCase("ASC", sort)));
//            }
//            page.setOrders(orders);
//        }
//        return page;
//    }
//}
