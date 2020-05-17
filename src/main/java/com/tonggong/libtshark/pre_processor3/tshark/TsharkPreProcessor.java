package com.tonggong.libtshark.pre_processor3.tshark;


public interface TsharkPreProcessor {
    void startCapture(String iFace);
    void stopCapture();
    void restartCapture();
}
