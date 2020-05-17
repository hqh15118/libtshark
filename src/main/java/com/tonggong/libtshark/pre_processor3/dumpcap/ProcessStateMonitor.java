package com.tonggong.libtshark.pre_processor3.dumpcap;


/**
 * #project MLenningPro
 *
 * @author hongqianhui
 * @create_time 2020-03-13 - 15:57
 */
public interface ProcessStateMonitor {
    void start();
    void error(Throwable e, String errorMsg);
    void running(String info);
    void finish(Throwable e);
}
