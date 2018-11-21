

import java.io.ByteArrayOutputStream;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

import javax.crypto.Cipher;



public class RSAUtils {

	public static final String PRIVATE_KEY = "MIICeAIBADANBgkqhkiG9w0BAQEFAASCAmIwggJeAgEAAoGBALtk9FG0+5pILHyLBTIPRcNDBO/UQDeGHsvSC8Q7qv/uT9h71BQAP6EuHpUTXrquHYOavxhu33niDfzFdUy5Yh0k8G0+4MJrFwEJ/k6oyHHbeLtoYj45La1KnaJzPATC+jW4qSAC9gwcJAWxNQkG6SlRLJA1dfe7b27xUtjNsn6bAgMBAAECgYEAsazkodvRetTXqTY+tNoaMSsIMUSzpnF6HZKIKYTRe1u/ROkTies6aV5LDNmSxbl0rmU4rrfhF7UnwfSOZTKYPJpGiuLcTtu05MYWuDKdqhD5t+uZ4lWYzFMUGuByvMXANc+STM+xTYJnrtLT85+GqO3F1VEEXqSMYJQ1qrgLJYECQQD8o9+KZNV1A5Yol43UxnANKkGMj+qkbVxZuZr/EOLFgw1K3XUbB9hdHMW8HAeUrP2MTyHo31Gg9l8svRc5aWphAkEAveLyzPe2ULjaS0JbcOrgFheHo2euFIDlNQPXxsX3+UaP1IDXUXCO0BZ/GsQ5qwOJl8x8SWanYpD3+BtiWpuiewJBAKVgUDAzmVcjpeOkcX9a9nZntsjgXGSOAenqCX/1+bv48XaUSNgM5qDs+LMOVhgItWBnXHcn2DNZkyuiC9XVH4ECQQCAr1MYsS9vGTdnFXte1O40SpHznYoN/yRWf1o2LWfWGYnT29UQLhW60+QjwaPLT8RpiX0ZSWZamCBUlkpbWWoNAkBw0BO0z974TKL7JetuWVuVCBVbkJQLtbFo9drMq0Aq6DQLmcZo7LKrK20d/qrvscCpWkFiSPGskPhM0COW5hb9";

	public static final String PUBLIC_KEY = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC7ZPRRtPuaSCx8iwUyD0XDQwTv1EA3hh7L0gvEO6r/7k/Ye9QUAD+hLh6VE166rh2Dmr8Ybt954g38xXVMuWIdJPBtPuDCaxcBCf5OqMhx23i7aGI+OS2tSp2iczwEwvo1uKkgAvYMHCQFsTUJBukpUSyQNXX3u29u8VLYzbJ+mwIDAQAB";

	/** RSA最大加密明文大小 */
	private static final int MAX_ENCRYPT_BLOCK = 117;

	/** RSA最大解密密文大小 */
	private static final int MAX_DECRYPT_BLOCK = 128;

	/** 加密算法RSA */
	private static final String KEY_ALGORITHM = "RSA";

	/**
	 * 生成公钥和私钥
	 * 
	 * @throws Exception
	 * 
	 */
	public static void getKeys() throws Exception {
		KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
		keyPairGen.initialize(1024);
		KeyPair keyPair = keyPairGen.generateKeyPair();
		RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
		RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();

		String publicKeyStr = getPublicKeyStr(publicKey);
		String privateKeyStr = getPrivateKeyStr(privateKey);

		System.out.println("公钥\r\n" + publicKeyStr);
		System.out.println("私钥\r\n" + privateKeyStr);
	}

	/**
	 * 公钥加密
	 * 
	 * @param data
	 * @return
	 * @throws Exception
	 */
	public static String encryptByPublicKey(String data) throws Exception {
		byte[] dataByte = data.getBytes();
		byte[] keyBytes = Base64Utils.decode(PUBLIC_KEY);
		X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(keyBytes);
		KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
		Key publicK = keyFactory.generatePublic(x509KeySpec);
		// 对数据加密
		// Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
		Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		cipher.init(Cipher.ENCRYPT_MODE, publicK);
		int inputLen = dataByte.length;
		ByteArrayOutputStream out = new ByteArrayOutputStream();
		int offSet = 0;
		byte[] cache;
		int i = 0;
		// 对数据分段加密
		while (inputLen - offSet > 0) {
			if (inputLen - offSet > MAX_ENCRYPT_BLOCK) {
				cache = cipher.doFinal(dataByte, offSet, MAX_ENCRYPT_BLOCK);
			} else {
				cache = cipher.doFinal(dataByte, offSet, inputLen - offSet);
			}
			out.write(cache, 0, cache.length);
			i++;
			offSet = i * MAX_ENCRYPT_BLOCK;
		}
		byte[] encryptedData = out.toByteArray();
		out.close();
		return Base64Utils.encode(encryptedData);
	}

	/**
	 * 私钥解密
	 * 
	 * @param data
	 * @return
	 * @throws Exception
	 */
	public static String decryptByPrivateKey(String data) throws Exception {
		byte[] encryptedData = Base64Utils.decode(data);
		byte[] keyBytes = Base64Utils.decode(PRIVATE_KEY);
		PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(keyBytes);
		KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
		Key privateK = keyFactory.generatePrivate(pkcs8KeySpec);
		// Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
		Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");

		cipher.init(Cipher.DECRYPT_MODE, privateK);
		int inputLen = encryptedData.length;
		ByteArrayOutputStream out = new ByteArrayOutputStream();
		int offSet = 0;
		byte[] cache;
		int i = 0;
		// 对数据分段解密
		while (inputLen - offSet > 0) {
			if (inputLen - offSet > MAX_DECRYPT_BLOCK) {
				cache = cipher.doFinal(encryptedData, offSet, MAX_DECRYPT_BLOCK);
			} else {
				cache = cipher.doFinal(encryptedData, offSet, inputLen - offSet);
			}
			out.write(cache, 0, cache.length);
			i++;
			offSet = i * MAX_DECRYPT_BLOCK;
		}
		byte[] decryptedData = out.toByteArray();
		out.close();
		return new String(decryptedData);
	}

	/**
	 * 从字符串中加载公钥
	 * 
	 * @param publicKeyStr 公钥数据字符串
	 * @throws Exception 加载公钥时产生的异常
	 */
	public static PublicKey loadPublicKey(String publicKeyStr) throws Exception {
		try {
			byte[] buffer = Base64Utils.decode(publicKeyStr);
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			X509EncodedKeySpec keySpec = new X509EncodedKeySpec(buffer);
			return (RSAPublicKey) keyFactory.generatePublic(keySpec);
		} catch (NoSuchAlgorithmException e) {
			throw new Exception("无此算法");
		} catch (InvalidKeySpecException e) {
			throw new Exception("公钥非法");
		} catch (NullPointerException e) {
			throw new Exception("公钥数据为空");
		}
	}

	/**
	 * 从字符串中加载私钥<br>
	 * 加载时使用的是PKCS8EncodedKeySpec（PKCS#8编码的Key指令）。
	 * 
	 * @param privateKeyStr
	 * @return
	 * @throws Exception
	 */
	public static PrivateKey loadPrivateKey(String privateKeyStr) throws Exception {
		try {
			byte[] buffer = Base64Utils.decode(privateKeyStr);
			// X509EncodedKeySpec keySpec = new X509EncodedKeySpec(buffer);
			PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(buffer);
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			return (RSAPrivateKey) keyFactory.generatePrivate(keySpec);
		} catch (NoSuchAlgorithmException e) {
			throw new Exception("无此算法");
		} catch (InvalidKeySpecException e) {
			throw new Exception("私钥非法");
		} catch (NullPointerException e) {
			throw new Exception("私钥数据为空");
		}
	}

	// 得到私钥base64编码后的
	public static String getPrivateKeyStr(PrivateKey privateKey) throws Exception {
		return new String(Base64Utils.encode(privateKey.getEncoded()));
	}

	// 得到公共base64编码后的
	public static String getPublicKeyStr(PublicKey publicKey) throws Exception {
		return new String(Base64Utils.encode(publicKey.getEncoded()));
	}

}