package com.tonggong.libtshark.pre_processor3.dumpcap;

import lombok.Builder;
import lombok.Getter;

@Builder
@Getter
public class DumpcapCaptureConfig {
    private String dumpcap;
    private String tempPath;
    private int switchFileSize;
}
