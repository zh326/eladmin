package me.zhengjie.utils;

import org.apache.poi.util.StringUtil;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

/**
 * @Rsa 非对称加密工具类
 * @Author zhuhuan
 * @CreateDate 2020/3/26 21:06
 * @Version 1.0
 */
public class RsaUtil {

    //加密算法
    private static final String KEY_ALGORITHM = "RSA";
    //秘钥默认长度
    private static final int DEFAULT_KEY_SIZE = 2048;
    //获取公钥的Key
    private static final String PUBLIC_KEY = "PublicKey";
    //获取私钥的Key
    private static final String PRIVATE_KEY = "PrivateKey";

    /**
     * @Description 生成密钥对（公钥/秘钥）
     * @Author zhuhuan
     * @CreateDate 2020/3/26 23:09
     * @Version 1.0
     */
    public static Map<String, byte[]> generateKey() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(KEY_ALGORITHM);
        keyPairGenerator.initialize(DEFAULT_KEY_SIZE);
        KeyPair keyPair = keyPairGenerator.genKeyPair();
        // 获取公钥
        byte[] publicKeyBytes = keyPair.getPublic().getEncoded();
        publicKeyBytes = Base64.getEncoder().encode(publicKeyBytes);
        // 获取私钥
        byte[] privateKeyBytes = keyPair.getPrivate().getEncoded();
        privateKeyBytes = Base64.getEncoder().encode(privateKeyBytes);
        // 密钥对
        Map<String, byte[]> keyMap = new HashMap<>(2);
        keyMap.put(PUBLIC_KEY, publicKeyBytes);
        keyMap.put(PRIVATE_KEY, privateKeyBytes);
        return keyMap;
    }

    /**
     * @param publicKeyFile  输出公钥文件路径
     * @param privateKeyFile 输出私钥文件路径
     * @Description 输出秘钥文件
     * @Author zhuhuan
     * @CreateDate 2020/3/26 23:10
     * @Version 1.0
     */
    public static void outputKey(String publicKeyFile, String privateKeyFile) throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(KEY_ALGORITHM);
        keyPairGenerator.initialize(DEFAULT_KEY_SIZE);
        KeyPair keyPair = keyPairGenerator.genKeyPair();
        // 获取公钥
        byte[] publicKeyBytes = keyPair.getPublic().getEncoded();
        publicKeyBytes = Base64.getEncoder().encode(publicKeyBytes);
        outputFile(publicKeyFile, publicKeyBytes);
        // 获取私钥
        byte[] privateKeyBytes = keyPair.getPrivate().getEncoded();
        privateKeyBytes = Base64.getEncoder().encode(privateKeyBytes);
        outputFile(privateKeyFile, privateKeyBytes);
    }

    /**
     * @param filePath 公钥文件路径
     * @return 公钥对象
     * @Description 读取公钥文件，返回公钥对象
     * @Author zhuhuan
     * @CreateDate 2020/3/26 23:38
     * @Version 1.0
     */
    public static PublicKey getPublicKey(String filePath) throws Exception {
        byte[] bytes = readFile(filePath);
        return getPublicKey(bytes);
    }

    /**
     * @param bytes 公钥的字节形式
     * @return 公钥对象
     * @Description 根据公钥字节返回公钥对象
     * @Author zhuhuan
     * @CreateDate 2020/3/26 23:39
     * @Version 1.0
     */
    private static PublicKey getPublicKey(byte[] bytes) throws Exception {
        bytes = Base64.getDecoder().decode(bytes);
        X509EncodedKeySpec spec = new X509EncodedKeySpec(bytes);
        KeyFactory factory = KeyFactory.getInstance(KEY_ALGORITHM);
        return factory.generatePublic(spec);
    }

    /**
     * @param filePath 私钥文件路径
     * @return 私钥对象
     * @Description 读取私钥文件返回私钥对象
     * @Author zhuhuan
     * @CreateDate 2020/3/26 23:31
     * @Version 1.0
     */
    public static PrivateKey getPrivateKey(String filePath) throws Exception {
        byte[] bytes = readFile(filePath);
        return getPrivateKey(bytes);
    }

    /**
     * @param bytes 私钥的字节形式
     * @return 私钥对象
     * @Description 根据私钥字节返回私钥对象
     * @Author zhuhuan
     * @CreateDate 2020/3/26 23:34
     * @Version 1.0
     */
    private static PrivateKey getPrivateKey(byte[] bytes) throws NoSuchAlgorithmException, InvalidKeySpecException {
        bytes = Base64.getDecoder().decode(bytes);
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(bytes);
        KeyFactory factory = KeyFactory.getInstance(KEY_ALGORITHM);
        return factory.generatePrivate(spec);
    }

    /**
     * @param filePath 读取文件路径
     * @Description 读取文件
     * @Author zhuhuan
     * @CreateDate 2020/3/26 23:05
     * @Version 1.0
     */
    private static byte[] readFile(String filePath) throws Exception {
        return Files.readAllBytes(new File(filePath).toPath());
    }

    /**
     * @param filePath 输出文件路径
     * @param bytes    输出字节
     * @Description 输出文件
     * @Author zhuhuan
     * @CreateDate 2020/3/26 23:11
     * @Version 1.0
     */
    private static void outputFile(String filePath, byte[] bytes) throws IOException {
        File file = new File(filePath);
        if (!file.exists()) {
            file.createNewFile();
        }
        Files.write(file.toPath(), bytes);
    }

    public static void main(String[] args) throws Exception {
        /*Map<String, byte[]> keyMap = RsaUtil.generateKey();
        System.out.println(new String(keyMap.get(PUBLIC_KEY)));
        System.out.println(new String(keyMap.get(PRIVATE_KEY)));*/

        /*String publicKeyFile = "D:\\rsa_public.pub";
        String privateKeyFile = "D:\\private.key";
        //输出秘钥文件
        RsaUtil.outputKey(publicKeyFile, privateKeyFile);
        //读取秘钥文件
        PublicKey publicKey = RsaUtil.getPublicKey(publicKeyFile);
        PrivateKey privateKey = RsaUtil.getPrivateKey(privateKeyFile);
        System.out.println(publicKey.getFormat());
        System.out.println(privateKey.getFormat());*/
    }
}
