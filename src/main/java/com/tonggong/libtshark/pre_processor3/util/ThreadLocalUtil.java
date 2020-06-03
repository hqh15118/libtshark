package com.tonggong.libtshark.pre_processor3.util;

public class ThreadLocalUtil {

    private static final StringBuilder GLOBAL_STRING_BUILDER = new StringBuilder(65536);

    public static StringBuilder getEmptyStringBuilder(){
        if (GLOBAL_STRING_BUILDER.length() > 0) {
            GLOBAL_STRING_BUILDER.delete(0, GLOBAL_STRING_BUILDER.length());
        }
        return GLOBAL_STRING_BUILDER;
    }
}
