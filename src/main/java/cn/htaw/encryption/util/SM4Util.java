package cn.htaw.encryption.util;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.engines.SM4Engine;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.paddings.PKCS7Padding;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.SecureRandom;
import java.security.Security;
import java.util.Arrays;

/**
 * SM4对称加密工具类（基于国密标准GM/T 0002-2012）
 * 模式：CBC（需16字节IV）
 * 填充：PKCS7
 */
public class SM4Util {
    static {
        // 确保BouncyCastleProvider已加载
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    // SM4密钥长度固定为16字节（128位）
    public static final int KEY_SIZE = 16;
    // CBC模式下IV长度固定为16字节
    public static final int IV_SIZE = 16;

    /**
     * 生成随机SM4密钥（16字节）
     */
    public static byte[] generateKey() {
        byte[] key = new byte[KEY_SIZE];
        new SecureRandom().nextBytes(key);
        return key;
    }

    /**
     * 生成随机IV向量（16字节，用于CBC模式）
     */
    public static byte[] generateIV() {
        byte[] iv = new byte[IV_SIZE];
        new SecureRandom().nextBytes(iv);
        return iv;
    }

    /**
     * SM4加密（CBC模式 + PKCS7填充）
     * @param key 16字节密钥
     * @param iv 16字节IV向量
     * @param data 待加密数据
     * @return 加密后的数据
     */
    public static byte[] encrypt(byte[] key, byte[] iv, byte[] data) throws SM4Exception {
        // 校验输入参数
        if (key == null || key.length != KEY_SIZE) {
            throw new IllegalArgumentException("SM4密钥必须为" + KEY_SIZE + "字节");
        }
        if (iv == null || iv.length != IV_SIZE) {
            throw new IllegalArgumentException("IV必须为" + IV_SIZE + "字节");
        }
        if (data == null) {
            return new byte[0];
        }

        try {
            // 初始化加密器
            SM4Engine engine = new SM4Engine();
            CBCBlockCipher cbcBlockCipher = new CBCBlockCipher(engine);
            PaddedBufferedBlockCipher cipher = new PaddedBufferedBlockCipher(cbcBlockCipher, new PKCS7Padding());
            CipherParameters params = new ParametersWithIV(new KeyParameter(key), iv);
            cipher.init(true, params);

            // 执行加密
            byte[] output = new byte[cipher.getOutputSize(data.length)];
            int length = cipher.processBytes(data, 0, data.length, output, 0);
            length += cipher.doFinal(output, length);

            return Arrays.copyOf(output, length);
        } catch (Exception e) {
            throw new SM4Exception("SM4加密失败", e);
        }
    }

    /**
     * SM4解密（CBC模式 + PKCS7填充）
     * @param key 16字节密钥
     * @param iv 16字节IV向量（需与加密时一致）
     * @param encryptedData 加密后的数据
     * @return 解密后的原始数据
     */
    public static byte[] decrypt(byte[] key, byte[] iv, byte[] encryptedData) throws SM4Exception {
        // 校验输入参数
        if (key == null || key.length != KEY_SIZE) {
            throw new IllegalArgumentException("SM4密钥必须为" + KEY_SIZE + "字节");
        }
        if (iv == null || iv.length != IV_SIZE) {
            throw new IllegalArgumentException("IV必须为" + IV_SIZE + "字节");
        }
        if (encryptedData == null || encryptedData.length == 0) {
            return new byte[0];
        }

        try {
            // 初始化解密器
            SM4Engine engine = new SM4Engine();
            CBCBlockCipher cbcBlockCipher = new CBCBlockCipher(engine);
            PaddedBufferedBlockCipher cipher = new PaddedBufferedBlockCipher(cbcBlockCipher, new PKCS7Padding());
            CipherParameters params = new ParametersWithIV(new KeyParameter(key), iv);
            cipher.init(false, params);

            // 执行解密
            byte[] output = new byte[cipher.getOutputSize(encryptedData.length)];
            int length = cipher.processBytes(encryptedData, 0, encryptedData.length, output, 0);
            length += cipher.doFinal(output, length);

            return Arrays.copyOf(output, length);
        } catch (Exception e) {
            throw new SM4Exception("SM4解密失败（可能密钥/IV不匹配或数据损坏）", e);
        }
    }

    /**
     * SM4相关异常类
     */
    public static class SM4Exception extends Exception {
        public SM4Exception(String message, Throwable cause) {
            super(message, cause);
        }
    }
}