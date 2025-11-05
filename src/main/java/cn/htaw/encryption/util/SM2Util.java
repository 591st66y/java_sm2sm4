package cn.htaw.encryption.util;

import org.bouncycastle.asn1.gm.GMNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.math.ec.ECPoint;

import java.security.SecureRandom;
import java.security.Security;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

/**
 * SM2非对称加密工具类（基于国密标准GM/T 0003-2012）
 */
public class SM2Util {
    // 静态加载BouncyCastleProvider
    static {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    // SM2推荐曲线参数（sm2p256v1）
    private static final X9ECParameters x9ECParameters = GMNamedCurves.getByName("sm2p256v1");
    private static final ECDomainParameters ecDomainParameters = new ECDomainParameters(
            x9ECParameters.getCurve(),
            x9ECParameters.getG(),
            x9ECParameters.getN()
    );

    /**
     * 生成SM2密钥对（默认返回压缩格式公钥）
     * @return 包含公钥（64字节）和私钥（32字节）的Map
     */
    public static Map<String, byte[]> generateKeyPair() throws Exception {
        return generateKeyPair(true);
    }

    /**
     * 生成SM2密钥对
     * @param compressed 是否返回压缩格式公钥（true:64字节，false:65字节）
     * @return 包含公钥和私钥的Map
     */
    public static Map<String, byte[]> generateKeyPair(boolean compressed) throws Exception {
        // 初始化密钥生成器
        ECKeyPairGenerator generator = new ECKeyPairGenerator();
        ECKeyGenerationParameters keyGenerationParameters = new ECKeyGenerationParameters(
                ecDomainParameters, new SecureRandom()
        );
        generator.init(keyGenerationParameters);

        // 生成密钥对
        AsymmetricCipherKeyPair keyPair = generator.generateKeyPair();
        ECPublicKeyParameters publicKeyParams = (ECPublicKeyParameters) keyPair.getPublic();
        ECPrivateKeyParameters privateKeyParams = (ECPrivateKeyParameters) keyPair.getPrivate();

        // 公钥编码（压缩/非压缩格式）
        ECPoint ecPoint = publicKeyParams.getQ();
        byte[] publicKey = ecPoint.getEncoded(compressed);

        // 私钥编码（确保32字节，去除可能的0填充）
        byte[] privateKey = privateKeyParams.getD().toByteArray();
        if (privateKey.length == 33) {
            privateKey = Arrays.copyOfRange(privateKey, 1, 33); // 去除首位0填充
        } else if (privateKey.length != 32) {
            throw new IllegalStateException("生成的私钥长度异常: " + privateKey.length + "字节");
        }

        Map<String, byte[]> keys = new HashMap<>(2);
        keys.put("publicKey", publicKey);
        keys.put("privateKey", privateKey);
        return keys;
    }

    /**
     * SM2加密（使用公钥）
     * @param publicKey 公钥字节数组（压缩格式64字节，非压缩格式65字节）
     * @param data 待加密数据（建议长度≤245字节）
     * @return 加密后的数据
     */
    public static byte[] encrypt(byte[] publicKey, byte[] data) throws Exception {
        // 校验输入
        if (publicKey == null || (publicKey.length != 64 && publicKey.length != 65)) {
            throw new IllegalArgumentException("SM2公钥必须为64字节（压缩）或65字节（非压缩）");
        }
        if (data == null || data.length == 0) {
            throw new IllegalArgumentException("待加密数据不能为空");
        }

        // 解析公钥
        ECPoint ecPoint;
        try {
            ecPoint = x9ECParameters.getCurve().decodePoint(publicKey);
        } catch (Exception e) {
            throw new InvalidKeyException("公钥解析失败，可能不是有效的SM2公钥", e);
        }
        ECPublicKeyParameters publicKeyParams = new ECPublicKeyParameters(ecPoint, ecDomainParameters);

        // 初始化SM2加密器
        org.bouncycastle.crypto.engines.SM2Engine engine = new org.bouncycastle.crypto.engines.SM2Engine();
        engine.init(true, new org.bouncycastle.crypto.params.ParametersWithRandom(
                publicKeyParams, new SecureRandom()
        ));

        // 执行加密
        try {
            return engine.processBlock(data, 0, data.length);
        } catch (Exception e) {
            throw new EncryptionException("SM2加密失败", e);
        }
    }

    /**
     * SM2解密（使用私钥）
     * @param privateKey 私钥字节数组（32字节）
     * @param encryptedData 加密后的数据
     * @return 解密后的数据
     */
    public static byte[] decrypt(byte[] privateKey, byte[] encryptedData) throws Exception {
        // 校验输入
        if (privateKey == null || privateKey.length != 32) {
            throw new IllegalArgumentException("SM2私钥必须为32字节");
        }
        if (encryptedData == null || encryptedData.length == 0) {
            throw new IllegalArgumentException("待解密数据不能为空");
        }

        // 解析私钥
        java.math.BigInteger d = new java.math.BigInteger(1, privateKey);
        ECPrivateKeyParameters privateKeyParams = new ECPrivateKeyParameters(d, ecDomainParameters);

        // 初始化SM2解密器
        org.bouncycastle.crypto.engines.SM2Engine engine = new org.bouncycastle.crypto.engines.SM2Engine();
        engine.init(false, privateKeyParams);

        // 执行解密
        try {
            return engine.processBlock(encryptedData, 0, encryptedData.length);
        } catch (Exception e) {
            throw new DecryptionException("SM2解密失败（可能密钥不匹配或数据损坏）", e);
        }
    }

    // 自定义异常类（细化异常类型）
    public static class EncryptionException extends Exception {
        public EncryptionException(String message, Throwable cause) {
            super(message, cause);
        }
    }

    public static class DecryptionException extends Exception {
        public DecryptionException(String message, Throwable cause) {
            super(message, cause);
        }
    }

    public static class InvalidKeyException extends Exception {
        public InvalidKeyException(String message, Throwable cause) {
            super(message, cause);
        }
    }
}