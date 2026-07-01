package com.open.jgm.pki.ca.cert.dto.request;

import com.fasterxml.jackson.annotation.JsonAlias;
import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import lombok.Data;

import java.io.Serializable;

@Data
@ApiModel("CSR 生成请求")
public class CsrGenerateRequest implements Serializable {

    @NotBlank(message = "DN_CN 不能为空")
    @ApiModelProperty(value = "CSR 主体 CN（唯一标识）", required = true, example = "张三")
    @JsonAlias("dn_cn")
    private String dnCn;

    @NotBlank(message = "DN_C 不能为空")
    @ApiModelProperty(value = "国家", required = true, example = "CN")
    @JsonAlias("dn_c")
    private String dnC;

    @ApiModelProperty(value = "省/市", example = "hunan")
    @JsonAlias("dn_st")
    private String dnSt;

    @ApiModelProperty(value = "市/县", example = "changsha")
    @JsonAlias("dn_l")
    private String dnL;

    @ApiModelProperty(value = "街道地址")
    @JsonAlias("dn_street")
    private String dnStreet;

    @NotBlank(message = "DN_O 不能为空")
    @ApiModelProperty(value = "单位", required = true, example = "openCA")
    @JsonAlias("dn_o")
    private String dnO;

    @NotBlank(message = "DN_OU 不能为空")
    @ApiModelProperty(value = "部门", required = true, example = "dev")
    @JsonAlias("dn_ou")
    private String dnOu;

    @Email(message = "邮箱格式不正确")
    @ApiModelProperty(value = "邮箱")
    @JsonAlias("dn_email")
    private String dnEmail;
}
