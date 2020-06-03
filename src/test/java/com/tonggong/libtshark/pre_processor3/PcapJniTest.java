package com.tonggong.libtshark.pre_processor3;

import com.tonggong.libtshark.pre_processor3.jni.PcapLib;

public class PcapJniTest {

    public static void main(String[] args) {
        /**
         * C:\Program Files\Java\jdk1.8.0_211\bin;
         * C:\Windows\Sun\Java\bin;
         * C:\Windows\system32;
         * C:\Windows;
         * C:\Program Files (x86)\Common Files\Oracle\Java\javapath;
         * C:\Windows\system32;
         * C:\Windows;
         * C:\Windows\System32\Wbem;
         * C:\Windows\System32\WindowsPowerShell\v1.0\;
         * C:\Windows\System32\OpenSSH\;
         * C:\Program Files\nodejs\;
         * D:\Git\cmd;
         * C:\Users\zjucsc\Desktop\Release;
         * C:\Users\zjucsc\AppData\Roaming\npm;
         * D:\Git\bin;
         * C:\Users\zjucsc\AppData\Local\Programs\Python\Python38;
         * C:\Users\zjucsc\AppData\Local\Microsoft\WindowsApps;
         * C:\Program Files\Java\jdk1.8.0_211\bin;
         * D:\software\apache-zookeeper-3.6.1-bin\apache-zookeeper-3.6.1-bin\bin;
         * C:\Users\zjucsc\AppData\Local\Programs\Python\Python38\Scripts;
         * ;.
         */
        System.out.println(System.getProperty("java.library.path"));

        PcapLib pcapLib = new PcapLib();
        pcapLib.sendPacket(new byte[]{0x01},0,1);
        pcapLib.showAllIFaceName();
    }
}
