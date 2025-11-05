package cn.htaw.encryption.util;

import org.bouncycastle.asn1.gm.GMNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.signers.SM2Signer;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.encoders.Hex;

import java.security.SecureRandom;
import java.security.Security;
import java.util.HashMap;
import java.util.Map;

public class SM2Util {
    // 静态加载BouncyCastleProvider
    static {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    // SM2推荐曲线参数
    private static final X9ECParameters x9ECParameters = GMNamedCurves.getByName("sm2p256v1");
    private static final ECDomainParameters ecDomainParameters = new ECDomainParameters(
            x9ECParameters.getCurve(),
            x9ECParameters.getG(),
            x9ECParameters.getN()
    );

    /**
     * 生成SM2密钥对
     * @return 包含公钥和私钥的Map
     */
    public static Map<String, byte[]> generateKeyPair() throws Exception {
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

        // 公钥编码（压缩格式）
        ECPoint ecPoint = publicKeyParams.getQ();
        byte[] publicKey = ecPoint.getEncoded(false); // false表示压缩格式，true表示非压缩

        // 私钥编码
        byte[] privateKey = privateKeyParams.getD().toByteArray();

        Map<String, byte[]> keys = new HashMap<>();
        keys.put("publicKey", publicKey);
        keys.put("privateKey", privateKey);
        return keys;
    }

    /**
     * SM2加密
     * @param publicKey 公钥字节数组
     * @param data 待加密数据
     * @return 加密后的数据
     */
    public static byte[] encrypt(byte[] publicKey, byte[] data) throws Exception {
        // 解析公钥
        ECPoint ecPoint = x9ECParameters.getCurve().decodePoint(publicKey);
        ECPublicKeyParameters publicKeyParams = new ECPublicKeyParameters(ecPoint, ecDomainParameters);

        // 初始化SM2加密器（使用BouncyCastle的SM2实现）
        org.bouncycastle.crypto.engines.SM2Engine engine = new org.bouncycastle.crypto.engines.SM2Engine();
        engine.init(true, new org.bouncycastle.crypto.params.ParametersWithRandom(
                publicKeyParams, new SecureRandom()
        ));

        // 执行加密
        return engine.processBlock(data, 0, data.length);
    }

    /**
     * SM2解密
     * @param privateKey 私钥字节数组
     * @param encryptedData 加密后的数据
     * @return 解密后的数据
     */
    public static byte[] decrypt(byte[] privateKey, byte[] encryptedData) throws Exception {
        // 解析私钥
        java.math.BigInteger d = new java.math.BigInteger(1, privateKey);
        ECPrivateKeyParameters privateKeyParams = new ECPrivateKeyParameters(d, ecDomainParameters);

        // 初始化SM2解密器
        org.bouncycastle.crypto.engines.SM2Engine engine = new org.bouncycastle.crypto.engines.SM2Engine();
        engine.init(false, privateKeyParams);

        // 执行解密
        return engine.processBlock(encryptedData, 0, encryptedData.length);
    }
}