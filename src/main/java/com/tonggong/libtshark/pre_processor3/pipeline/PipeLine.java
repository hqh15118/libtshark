package com.tonggong.libtshark.pre_processor3.pipeline;


/**
 * #project spring-boot-starter
 *
 * @author hongqianhui
 * #create_time 2019-04-23 - 10:40
 */
public interface PipeLine {
    PipeLine addLast(AbstractHandler handler);

    /**
     * 压入第一个数据
     * @param t 压入的数据
     */
    void pushDataAtHead(Object t);

    AbstractHandler getFirstHandler();
}
