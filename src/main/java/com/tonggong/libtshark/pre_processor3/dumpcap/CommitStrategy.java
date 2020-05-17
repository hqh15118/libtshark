package com.tonggong.libtshark.pre_processor3.dumpcap;

/**
 * #project MLenningPro
 *
 * @author hongqianhui
 * @create_time 2020-03-16 - 13:55
 */
public interface CommitStrategy {

    void commit(String topic, int offset);

    void finish(String topic);
}
