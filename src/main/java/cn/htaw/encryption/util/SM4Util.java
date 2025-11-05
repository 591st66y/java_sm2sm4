package cn.htaw.encryption.util;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.engines.SM4Engine;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.paddings.PKCS7Padding;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;

import java.security.SecureRandom;
import java.security.Security;

public class SM4Util {
    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    private static final String ALGORITHM_NAME = "SM4";
    // CBC模式需要16字节IV
    private static final int IV_LENGTH = 16;
    // SM4密钥长度为16字节
    private static final int KEY_SIZE = 16;
    // IV长度为16字节（CBC模式）
    private static final int IV_SIZE = 16;

    /**
     * 生成随机SM4密钥
     */
    public static byte[] generateKey() {
        byte[] key = new byte[KEY_SIZE];
        new SecureRandom().nextBytes(key);
        return key;
    }

    /**
     * 生成随机IV
     */
    public static byte[] generateIV() {
        byte[] iv = new byte[IV_SIZE];
        new SecureRandom().nextBytes(iv);
        return iv;
    }



    // SM4加密（CBC模式）
    public static byte[] encrypt(byte[] key, byte[] iv, byte[] data) throws Exception {
        SM4Engine engine = new SM4Engine();
        CBCBlockCipher cbcBlockCipher = new CBCBlockCipher(engine);
        // 注释掉原始代码
//        org.bouncycastle.crypto.Cipher cipher = new org.bouncycastle.crypto.Cipher( cbcBlockCipher, new PKCS7Padding());
        PaddedBufferedBlockCipher cipher = new PaddedBufferedBlockCipher(cbcBlockCipher, new PKCS7Padding());
        CipherParameters keyParam = new KeyParameter(key);
        CipherParameters keyParamWithIV = new ParametersWithIV(keyParam, iv);
        cipher.init(true, keyParamWithIV);
        byte[] output = new byte[cipher.getOutputSize(data.length)];
        int length = cipher.processBytes(data, 0, data.length, output, 0);
        length += cipher.doFinal(output, length);
        byte[] result = new byte[length];
        System.arraycopy(output, 0, result, 0, length);
        return result;
    }

    // SM4解密（CBC模式）
    public static byte[] decrypt(byte[] key, byte[] iv, byte[] encryptedData) throws Exception {
        SM4Engine engine = new SM4Engine();
        CBCBlockCipher cbcBlockCipher = new CBCBlockCipher(engine);
        // 注释掉原始代码
//        org.bouncycastle.crypto.Cipher cipher = new org.bouncycastle.crypto.Cipher(cbcBlockCipher, new PKCS7Padding());
        PaddedBufferedBlockCipher cipher = new PaddedBufferedBlockCipher(cbcBlockCipher, new PKCS7Padding());
        CipherParameters keyParam = new KeyParameter(key);
        CipherParameters keyParamWithIV = new ParametersWithIV(keyParam, iv);
        cipher.init(false, keyParamWithIV);

        byte[] output = new byte[cipher.getOutputSize(encryptedData.length)];
        int length = cipher.processBytes(encryptedData, 0, encryptedData.length, output, 0);
        length += cipher.doFinal(output, length);
        byte[] result = new byte[length];
        System.arraycopy(output, 0, result, 0, length);
        return result;
    }
}