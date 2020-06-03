package com.tonggong.libtshark.pre_processor3.util;

import lombok.extern.slf4j.Slf4j;

/**
 * #project packet-master-web
 *
 * @author hongqianhui
 * #create_time 2019-04-29 - 21:19
 */
@Slf4j
public class PacketDecodeUtil {
    /*
     *  string : 03:00:00:1f:02:f0:80:32:01:00:00:cc:c1:00:0e:00:00:04:01:12:0a:10:02:00:11:00:01:84:00:00:20
     *  ----> byte[] : 03 00 00 1f 02 f0 80 32 01 00 00 cc c1 00 0e 00 00 04 01 12 0a 10 02 00 11 00 01 84 00 00 20
     */
    private static final byte[] EMPTY = new byte[]{};

    /**
     * decode non : string
     * String trailer = "00020d04fc6aa8defba27a10fc6aa8defba27a80";
     *         String fsc = "0x00000075";
     * @param s
     * @return
     */
    public static byte[] hexStringToByteArray2(String s) {
        return hexStringToByteArray2(s,0);
    }


    public static byte[] hexStringToByteArray2(String s , int offset) {
        int len = s.length();
        if (len == 0){
            return EMPTY;
        }
        int byteArraySize = (len - offset) >>> 1;
        byte[] data = new byte[byteArraySize];
        int j = 0;
        for (int i = offset ; i < len; i += 2) {
            data[j] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i+1), 16));
            j++;
        }
        return data;
    }



    /**
     * 01:02:03:04
     * 01 02 03 04
     * @param trailerAndFsc
     * @return
     */
    public static byte[] hexToString(String trailerAndFsc){
        if (trailerAndFsc.length() == 0){
            return EMPTY;
        }
        if (!trailerAndFsc.contains(":")){  //
            return hexStringToByteArray2(trailerAndFsc);
        }
        byte[] allBytes = new byte[(trailerAndFsc.length() + 1) / 3];
        int i = 0;
        int len = allBytes.length;
        for (; i < len; i += 3) {
            allBytes[i / 3] = (byte) ((Character.digit(trailerAndFsc.charAt(i), 16) << 4)
                    + Character.digit(trailerAndFsc.charAt(i+1), 16));
        }
        i = i / 3;
        int point = 0;
        for (int j = 0; j < len; j+=2) {
            allBytes[i + point] = (byte) ((Character.digit(trailerAndFsc.charAt(j), 16) << 4)
                    + Character.digit(trailerAndFsc.charAt(j+1), 16));
            point++;
        }
        return allBytes;
    }

    //eth:llc:tcp:data
    public static String discernPacket(String protocolStack){
        if(protocolStack.endsWith("data"))
        {
            StringBuilder sb = ThreadLocalUtil.getEmptyStringBuilder();
            char ch;
            for (int i = protocolStack.length() - 6;; i--) {
                if ((ch = protocolStack.charAt(i))!=':'){
                    sb.append(ch);
                }else{
                    break;
                }
            }
            return sb.reverse().toString();
        }
        return getUnDefinedPacketProtocol(protocolStack);
    }

    public static String getUnDefinedPacketProtocol(String protocolStack){
        StringBuilder sb = ThreadLocalUtil.getEmptyStringBuilder();
        sb.delete(0,sb.length());
        int index = protocolStack.lastIndexOf(":");
        if (index < 0){
            return protocolStack;
        }
        for (int i = index + 1 ; i < protocolStack.length() ; i ++){
            sb.append(protocolStack.charAt(i));
        }
        return sb.toString();
    }
}
