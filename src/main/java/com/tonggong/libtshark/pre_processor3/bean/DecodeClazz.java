package com.tonggong.libtshark.pre_processor3.bean;

import lombok.Data;
import lombok.extern.slf4j.Slf4j;

import java.lang.reflect.Field;

@Data
@Slf4j
public class DecodeClazz {
    private String[] protocols;
    private Class<?>[] classes;
    public DecodeClazz(String[] protocols, Class<?>[] classes){
        this.protocols = protocols;
        if (classes == null){
            return;
        }
        for (int i = 0; i < classes.length; i++) {
            Class<?> rawClazz = classes[i];
            Field[] fields = rawClazz.getDeclaredFields();
            if (fields.length == 0){
                throw new  RuntimeException("can not find top level field (should be named as *layer*)!");
            }
            boolean find = false;
            for (Field field : fields) {
                if (field.getName().toLowerCase().contains("layer")){
                    classes[i] = field.getType();
                    find = true;
                    break;
                }
            }
            if (!find){
                throw new  RuntimeException("can not find top level field (should be named as *layer*)!");
            }
        }
        this.classes = classes;
    }
    public Class<?> getClazzByProtocolStack(String protocolStack){
        if (protocols == null || classes == null){
            return null;
        }
        int index = 0;
        for (String protocol : protocols) {
            if (protocolStack.contains(protocol)){
                break;
            }
            index++;
        }
        if (index >= classes.length){
            log.error("配置文件协议名[{}] 与 解析协议栈[{}]结尾字符串未对应，重新添加！使用UndefinedPacket！",protocols,protocolStack);
            return GlobalArgs.undefinedPacketClass;
        }
        return classes[index];
    }
}
