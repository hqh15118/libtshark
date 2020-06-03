package com.tonggong.libtshark.pre_processor3.bean;

import com.alibaba.fastjson.annotation.JSONField;
import lombok.Data;

import java.io.Serializable;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;

/**
 * #project packet-master-web
 *
 * @author hongqianhui
 * #create_time 2019-05-11 - 21:23
 */

@Data
public class RowLayer implements Serializable{
    public String protocol;
    public String[] frame_protocols = {"--"};
    public String[] eth_dst = {"--"};
    public String[] frame_cap_len = {"--"};
    public String[] eth_src = {"--"};
    public String[] ip_src = {"--"};
    public String[] ip_dst = {"--"};
    //raw data
    public String[] custom_ext_raw_data = {""};
}
