package com.tonggong.libtshark.pre_processor3.util.sm4;

/**
 * Created by $(USER) on $(DATE)
 */

import com.tonggong.libtshark.pre_processor3.util.ByteUtils;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.codec.binary.Base64;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Properties;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Slf4j
public class SM4Utils {

//    public static String secretKey = "0123456789abcdeffedcba9876543210";
    public static String iv = "";
//    public static boolean hexString = true;

    public SM4Utils() {
    }

    private static class TsharkProperties {
        public String libpcapFilter;
        public String tsharkSessionReset = "100000";
        public String macAddress = "11:22:33:44:55:66";
        public String secretKey;
        public boolean hexString;
    }

    private static final TsharkProperties tsharkProperties = new TsharkProperties();

    static {
        Properties properties = new Properties();
        try {
            properties.load(new FileInputStream(new File("config/tshark.properties")));
            tsharkProperties.macAddress = properties.getProperty("mac_address");
            tsharkProperties.secretKey = properties.getProperty("secret_key");
            tsharkProperties.hexString = Boolean.parseBoolean(properties.getProperty("hex_string"));
        } catch (IOException e) {
            log.error("load tshark properties failed,use default properties : [{}]", tsharkProperties);
        }
    }

    public String encryptData_ECB(String plainText) {
        try {
            SM4Context ctx = new SM4Context();
            ctx.isPadding = true;
            ctx.mode = SM4.SM4_ENCRYPT;

            byte[] keyBytes;
//            if (hexString) {
//                keyBytes = ByteUtils.hexStringToBytes(secretKey);
//            } else {
//                keyBytes = secretKey.getBytes();
//            }
            if (tsharkProperties.hexString) {
                keyBytes = ByteUtils.hexStringToBytes(tsharkProperties.secretKey);
            } else {
                keyBytes = tsharkProperties.secretKey.getBytes();
            }

            SM4 sm4 = new SM4();
            sm4.sm4_setkey_enc(ctx, keyBytes);
            byte[] encrypted = sm4.sm4_crypt_ecb(ctx, plainText.getBytes("UTF-8"));
            return ByteUtils.byteToHex(encrypted);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    /**
     * 解密
     *
     * @param encrypted
     * @return
     */
    public static byte[] decryptData_ECB(byte[] encrypted) {
        try {
            String cipherText = Base64.encodeBase64String(encrypted);
            //cipherText = new BASE64Encoder().encode(encrypted);
            if (cipherText != null && cipherText.trim().length() > 0) {
                Pattern p = Pattern.compile("\\s*|\t|\r|\n");
                Matcher m = p.matcher(cipherText);
                cipherText = m.replaceAll("");
            }

            SM4Context ctx = new SM4Context();
            ctx.isPadding = true;
            ctx.mode = SM4.SM4_DECRYPT;

            byte[] keyBytes;
//            if (hexString) {
//                keyBytes = ByteUtils.hexStringToBytes(secretKey);
//            } else {
//                keyBytes = secretKey.getBytes();
//            }
            if (tsharkProperties.hexString) {
                keyBytes = ByteUtils.hexStringToBytes(tsharkProperties.secretKey);
            } else {
                keyBytes = tsharkProperties.secretKey.getBytes();
            }

            SM4 sm4 = new SM4();
            sm4.sm4_setkey_dec(ctx, keyBytes);
            return sm4.sm4_crypt_ecb(ctx, Base64.decodeBase64(cipherText));

        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public static String decryptData_ECB(String cipherText) {
        try {
            byte[] encrypted = ByteUtils.hexToByte(cipherText);
            return new String(decryptData_ECB(encrypted), StandardCharsets.UTF_8);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    public byte[] decryptData_ECB2(String cipherText) {
        try {
            byte[] encrypted = ByteUtils.hexToByte(cipherText);
            return decryptData_ECB(encrypted);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    public String encryptData_CBC(String plainText) {
        try {
            SM4Context ctx = new SM4Context();
            ctx.isPadding = true;
            ctx.mode = SM4.SM4_ENCRYPT;

            byte[] keyBytes;
            byte[] ivBytes;
//            if (hexString) {
//                keyBytes = ByteUtils.hexStringToBytes(secretKey);
//                ivBytes = ByteUtils.hexStringToBytes(iv);
//            } else {
//                keyBytes = secretKey.getBytes();
//                ivBytes = iv.getBytes();
//            }
            if (tsharkProperties.hexString) {
                keyBytes = ByteUtils.hexStringToBytes(tsharkProperties.secretKey);
                ivBytes = ByteUtils.hexStringToBytes(iv);
            } else {
                keyBytes = tsharkProperties.secretKey.getBytes();
                ivBytes = iv.getBytes();
            }

            SM4 sm4 = new SM4();
            sm4.sm4_setkey_enc(ctx, keyBytes);
            byte[] encrypted = sm4.sm4_crypt_cbc(ctx, ivBytes, plainText.getBytes("UTF-8"));
            return ByteUtils.byteToHex(encrypted);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    public String decryptData_CBC(String cipherText) {
        try {
            byte[] encrypted = ByteUtils.hexToByte(cipherText);
            cipherText = Base64.encodeBase64String(encrypted);
            ;
            //cipherText = new BASE64Encoder().encode(encrypted);
            if (cipherText != null && cipherText.trim().length() > 0) {
                Pattern p = Pattern.compile("\\s*|\t|\r|\n");
                Matcher m = p.matcher(cipherText);
                cipherText = m.replaceAll("");
            }
            SM4Context ctx = new SM4Context();
            ctx.isPadding = true;
            ctx.mode = SM4.SM4_DECRYPT;

            byte[] keyBytes;
            byte[] ivBytes;
//            if (hexString) {
//                keyBytes = ByteUtils.hexStringToBytes(secretKey);
//                ivBytes = ByteUtils.hexStringToBytes(iv);
//            } else {
//                keyBytes = secretKey.getBytes();
//                ivBytes = iv.getBytes();
//            }
            if (tsharkProperties.hexString) {
                keyBytes = ByteUtils.hexStringToBytes(tsharkProperties.secretKey);
                ivBytes = ByteUtils.hexStringToBytes(iv);
            } else {
                keyBytes = tsharkProperties.secretKey.getBytes();
                ivBytes = iv.getBytes();
            }

            SM4 sm4 = new SM4();
            sm4.sm4_setkey_dec(ctx, keyBytes);
            //byte[] decrypted = sm4.sm4_crypt_cbc(ctx, ivBytes, new BASE64Decoder().decodeBuffer(cipherText));
            byte[] decrypted = sm4.sm4_crypt_cbc(ctx, ivBytes, Base64.decodeBase64(cipherText));
            /*String text = new String(decrypted, "UTF-8");
            return text.substring(0,text.length()-1);*/
            return new String(decrypted, "UTF-8");
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }
}
