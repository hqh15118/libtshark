package com.tonggong.libtshark.pre_processor3.dumpcap;

/**
 * #project MLenningPro
 *
 * @author hongqianhui
 * @create_time 2020-02-04 - 13:36
 */
interface IPcapInputStream {
    /**
     * sync process
     * @param buffer
     */
    void readFrame(byte[] buffer);

    /**
     * Acyn process
     * @param bufferSize
     */
    //void readFrame1(int bufferSize);
}
