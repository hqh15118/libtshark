package com.tonggong.libtshark.pre_processor3.dumpcap;


/**
 * #project MLenningPro
 *
 * @author hongqianhui
 * @create_time 2020-02-05 - 18:49
 */
public interface DataCallback<T>{
    void callback(T data);
}
