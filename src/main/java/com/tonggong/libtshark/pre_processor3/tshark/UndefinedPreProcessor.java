package com.tonggong.libtshark.pre_processor3.tshark;


import java.util.ArrayList;
import java.util.List;


/**
 * #project packet-master-web
 *
 * @author hongqianhui
 * #create_time 2019-05-14 - 20:32
 */

/**
 * 用于捕获除了必须报文之外的其他报文
 */
public class UndefinedPreProcessor extends BasePreProcessor {

    private List<String> cacheList = null;
    @Override
    public List<String> protocolFilterField() {
        if (cacheList != null){
            return cacheList;
        }
        StringBuilder sb = new StringBuilder();
        List<String> captureProtocolSet = BasePreProcessor.announcedProtocols();
        int i = 0;
        int setSize = captureProtocolSet.size();
        for (String s : captureProtocolSet) {
            if (i < setSize - 1) {
                sb.append(" not ").append(s).append(" and");
            }else{
                sb.append(" not ").append(s);
            }
            i++;
        }
        cacheList = new ArrayList<String>(){
            {
                add(sb.toString());
            }
        };
        return cacheList;
    }

    @Override
    public List<String> filterFields() {
        return new ArrayList<String>(0){
            {

            }
        };
    }

    @Override
    public String filter() {
        return "";
    }

}
