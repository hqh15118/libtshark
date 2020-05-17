package com.tonggong.libtshark.pre_processor3.tshark;

import java.util.List;

public interface PreProcessorListener {

    default void tsharkProcessStarted(int id,Process process,
                              String command,
                              List<String> protocol){

    }

    default void tsharkProcessFailed(int id,Process process,
                                     String command,
                                     List<String> protocol){

    }
}
