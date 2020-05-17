package com.tonggong.libtshark.pre_processor3.dumpcap;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * #project MLenningPro
 *
 * @author hongqianhui
 * @create_time 2020-03-16 - 14:20
 */
public class LRUMap<K,V> extends LinkedHashMap<K,V> {

    private int cacheSize;

    public LRUMap(int cacheSize,float loadFactor){
        super(cacheSize,loadFactor,true);
        this.cacheSize = cacheSize;
    }

    @Override
    protected boolean removeEldestEntry(Map.Entry<K, V> eldest) {
        boolean tooBig = size() > cacheSize;
        if (tooBig){
            beforeRemove(eldest);
        }
        return tooBig;
    }

    public void beforeRemove(Map.Entry<K, V> eldest){

    }
}
