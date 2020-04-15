package challengetwo;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;

public class MainChallengeTwo {

	private final String securityProviderBC = "BC";
	private final String securityProviderSUN = "SUN";
	private final String keyStoreFile = "studentstore.ks";
	private final String keyStoreType = "JKS";
	private final String certificateFileStudent = "studentCertificate.cer";
	private final String certificateFileISM = "ISM_PGP.cer";
	private final String certificateType = "X509";
	private final String keyStorePassword = "passks";
	private final String keyAlias = "private1";
	private final String keyPassword = "passism1";
	private final String signatureAlgorithm = "MD5WithRSA";
	private final String asymetricEncryptionAlgorithm = "RSA";
	private final String asymetricEncryptionAlgorithmMode = "ECB";
	private final String asymetricEncryptionAlgorithmPadding = "PKCS1padding";
	private final String symmetricEncryptionAlgorithm = "AES";
	private final String symmetricEncryptionAlgorithmMode = "CBC";
	private final String symmetricEncryptionAlgorithmPadding = "PKCS5padding";
	private final String aesEncryptedPasswordFile = "Session.key";
	private final String aesEncryptedMessageFile1 = "message1.enc";
	private final String aesEncryptedMessageFile2 = "message2.enc";
	private final String aesEncryptedMessageFile3 = "message3.enc";
	private final String aesDecryptedMessageFile1 = "message1.txt";
	private final String aesDecryptedMessageFile2 = "message2.txt";
	private final String aesDecryptedMessageFile3 = "message3.txt";
	private final String receivedMessageSignature = "signature.ds";
	private final String responseFile = "response.txt";
	private final String responseEncryptedFile = "response.enc";
	private final String responseSignatureFile = "response.ds";

	static {
		Security.addProvider(new BouncyCastleProvider());
		if (Security.getProvider("BC") == null) {
			System.exit(-1);
		}
	}

	public MainChallengeTwo() {
		super();
	}

	private PublicKey readPublicKeyFromCertificate(String certificateFile, String certificateType,
			String securityProvider) throws Exception {
		File inputFile = new File(certificateFile);
		if (inputFile.exists()) {
			FileInputStream fileInputStream = new FileInputStream(inputFile);
			CertificateFactory certificateFactory = CertificateFactory.getInstance(certificateType, securityProvider);
			X509Certificate x509Certificate = (X509Certificate) certificateFactory.generateCertificate(fileInputStream);
			PublicKey publicKey = x509Certificate.getPublicKey();
			fileInputStream.close();
			return publicKey;
		} else {
			throw new FileNotFoundException("Certificate File Not Found!");
		}
	}

	private PublicKey readPublicKeyFromKeyStore(String keyStoreFile, String keyStoreType, String keyStorepassword,
			String keyAlias, String keyPassowrd, String securityProvider) throws Exception {
		File inputFile = new File(keyStoreFile);
		if (inputFile.exists()) {
			FileInputStream fileInputStream = new FileInputStream(inputFile);
			KeyStore keyStore = KeyStore.getInstance(keyStoreType, securityProvider);
			keyStore.load(fileInputStream, keyStorepassword.toCharArray());
			PublicKey publicKey = null;
			Key key = keyStore.getKey(keyAlias, keyPassowrd.toCharArray());
			if (key instanceof PrivateKey) {
				Certificate certificate = keyStore.getCertificate(keyAlias);
				publicKey = certificate.getPublicKey();
			}
			return publicKey;
		} else {
			throw new FileNotFoundException("Keystore File Not Found!");
		}
	}

	private PrivateKey readPrivateKeyFromKeyStore(String keyStoreFile, String keyStoreType, String keyStorePassword,
			String keyAlias, String keyPassword, String securityProvider) throws Exception {
		File inputFile = new File(keyStoreFile);
		if (inputFile.exists()) {
			FileInputStream fileInputStream = new FileInputStream(inputFile);
			KeyStore keyStore = KeyStore.getInstance(keyStoreType, securityProvider);
			keyStore.load(fileInputStream, keyStorePassword.toCharArray());
			PrivateKey privateKey = null;
			Key key = keyStore.getKey(keyAlias, keyPassword.toCharArray());
			if (key instanceof PrivateKey) {
				privateKey = (PrivateKey) key;
			}
			return privateKey;
		} else {
			throw new FileNotFoundException("Keystore File Not Found!");
		}
	}

	public byte[] decryptRSA(String encryptedFile, String encryptionAlgorithm, String encryptionAlgorithmMode,
			String encryptionAlgorithmPadding, PrivateKey privateKey) throws Exception {
		File file = new File(encryptedFile);
		if (file.exists()) {
			String algorithmTransformation = encryptionAlgorithm + "/" + encryptionAlgorithmMode + "/"
					+ encryptionAlgorithmPadding;
			Cipher cipher = Cipher.getInstance(algorithmTransformation);
			cipher.init(Cipher.DECRYPT_MODE, privateKey);
			FileInputStream fileInputStream = new FileInputStream(file);
			byte buffer[] = new byte[(int) file.length()];
			fileInputStream.read(buffer);
			byte decrypted[] = cipher.doFinal(buffer);
			fileInputStream.close();
			return decrypted;
		} else {
			throw new FileNotFoundException(encryptedFile + " Not Found!");
		}
	}

	public boolean encryptAES(String inputFileName, String algorithm, String algorithmMode, String paddingMode,
			String provider, String secretKey, String outputFileName) throws Exception {
		File inputFile = new File(inputFileName);
		if (inputFile.exists()) {
			File outputFile = new File(outputFileName);
			if (outputFile.exists()) {
				outputFile.createNewFile();
			}
			FileInputStream fileInputStream = new FileInputStream(inputFile);
			FileOutputStream fileOutputStream = new FileOutputStream(outputFile);
			String algorithSettings = algorithm + "/" + algorithmMode + "/" + paddingMode;
			Cipher cipher = Cipher.getInstance(algorithSettings, provider);
			Key key = new SecretKeySpec(secretKey.getBytes(), algorithm);
			byte IV[] = new byte[secretKey.getBytes().length];
			for (int i = 0; i < IV.length; i++) {
				IV[i] = (byte) 0x01;
			}
			IvParameterSpec ivParameterSpec = new IvParameterSpec(IV);
			cipher.init(Cipher.ENCRYPT_MODE, key, ivParameterSpec);
			int numberOfBytesRead = 0;
			byte readBuffer[] = new byte[cipher.getBlockSize()];
			byte writeBuffer[];
			numberOfBytesRead = fileInputStream.read(readBuffer);
			while (numberOfBytesRead != -1) {
				int outputSize = cipher.getOutputSize(numberOfBytesRead);
				writeBuffer = new byte[outputSize];
				int numberOfOutputBytes = cipher.update(readBuffer, 0, numberOfBytesRead, writeBuffer);
				fileOutputStream.write(writeBuffer, 0, numberOfOutputBytes);
				numberOfBytesRead = fileInputStream.read(readBuffer);
			}
			writeBuffer = cipher.doFinal();
			fileOutputStream.write(writeBuffer);
			fileOutputStream.close();
			fileInputStream.close();
			return true;
		} else {
			throw new FileNotFoundException("File Not Found!");
		}
	}

	public boolean decryptAES(String inputFileName, String outputFileName, String algorithm, String algorithmMode,
			String paddingMode, String provider, String secretKey) throws Exception {
		File inputFile = new File(inputFileName);
		if (inputFile.exists()) {
			File outputFile = new File(outputFileName);
			if (outputFile.exists()) {
				outputFile.createNewFile();
			}
			FileInputStream fileInputStream = new FileInputStream(inputFile);
			FileOutputStream fileOutputStream = new FileOutputStream(outputFile);
			String algorithSettings = algorithm + "/" + algorithmMode + "/" + paddingMode;
			Cipher cipher = Cipher.getInstance(algorithSettings, provider);
			Key key = new SecretKeySpec(secretKey.getBytes(), algorithm);
			byte IV[] = new byte[secretKey.getBytes().length];
			for (int i = 0; i < IV.length; i++) {
				IV[i] = (byte) 0x01;
			}
			IvParameterSpec ivParameterSpec = new IvParameterSpec(IV);
			cipher.init(Cipher.DECRYPT_MODE, key, ivParameterSpec);
			int numberOfBytesRead = 0;
			byte readBuffer[] = new byte[cipher.getBlockSize()];
			byte writeBuffer[];
			numberOfBytesRead = fileInputStream.read(readBuffer);
			while (numberOfBytesRead != -1) {
				int outputSize = cipher.getOutputSize(numberOfBytesRead);
				writeBuffer = new byte[outputSize];
				int numberOfOutputBytes = cipher.update(readBuffer, 0, numberOfBytesRead, writeBuffer);
				fileOutputStream.write(writeBuffer, 0, numberOfOutputBytes);
				numberOfBytesRead = fileInputStream.read(readBuffer);
			}
			writeBuffer = cipher.doFinal();
			fileOutputStream.write(writeBuffer);
			fileOutputStream.close();
			fileInputStream.close();
			return true;
		} else {
			throw new FileNotFoundException("File Not Found!");
		}
	}

	private void GenerateSignatureFile(String fileToSignPath, String signAlgorithm, PrivateKey privateKey,
			String securityProvider, String signatureFilePath) throws IOException, InvalidKeyException,
			NoSuchAlgorithmException, SignatureException, NoSuchProviderException {
		File toBeSigned = new File(fileToSignPath);
		if (toBeSigned.exists()) {
			FileInputStream toBeSignedStream = new FileInputStream(toBeSigned);
			byte[] fileBuffer = new byte[4096];
			int numberOfBytesRead = 0;

			Signature signature = Signature.getInstance(signAlgorithm, securityProvider);
			signature.initSign(privateKey);

			numberOfBytesRead = toBeSignedStream.read(fileBuffer);
			while (numberOfBytesRead != -1) {
				signature.update(fileBuffer, 0, numberOfBytesRead);
				numberOfBytesRead = toBeSignedStream.read(fileBuffer);
			}
			toBeSignedStream.close();
			byte[] signatureData = signature.sign();
			System.out.println(fileToSignPath + " Signature = " + Hex.toHexString(signatureData));
			File signatureFile = new File(signatureFilePath);
			if (signatureFile.exists()) {
				signatureFile.createNewFile();
			}
			FileOutputStream fileOutputStream = new FileOutputStream(signatureFile);
			fileOutputStream.write(signatureData);
			fileOutputStream.close();
		} else {
			throw new FileNotFoundException(toBeSigned + " Not Found!");
		}
	}

	private boolean checkSignature(byte[] givenSignature, String filename, String signAlgorithm, String provider,
			PublicKey publicKey) throws IOException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {
		File f = new File(filename);
		byte[] content = new byte[(int) f.length()];
		FileInputStream fis = new FileInputStream(f);
		int noBytesread = fis.read(content);
		fis.close();
		Signature signature = Signature.getInstance(signAlgorithm);
		signature.initVerify(publicKey);
		signature.update(content, 0, noBytesread);
		return signature.verify(givenSignature);
	}

	private String Exercise1() throws Exception {
		PrivateKey privateKey = this.readPrivateKeyFromKeyStore(this.keyStoreFile, this.keyStoreType,
				this.keyStorePassword, this.keyAlias, this.keyPassword, this.securityProviderSUN);
		byte[] dec = this.decryptRSA(this.aesEncryptedPasswordFile, this.asymetricEncryptionAlgorithm,
				this.asymetricEncryptionAlgorithmMode, this.asymetricEncryptionAlgorithmPadding, privateKey);
		String aesPassword = new String(dec);
		return aesPassword;
	}

	private String Exercise2() throws Exception {
		String aesPassword = this.Exercise1();
		this.decryptAES(this.aesEncryptedMessageFile1, this.aesDecryptedMessageFile1, this.symmetricEncryptionAlgorithm,
				this.symmetricEncryptionAlgorithmMode, this.symmetricEncryptionAlgorithmPadding,
				this.securityProviderBC, aesPassword);
		this.decryptAES(this.aesEncryptedMessageFile2, this.aesDecryptedMessageFile2, this.symmetricEncryptionAlgorithm,
				this.symmetricEncryptionAlgorithmMode, this.symmetricEncryptionAlgorithmPadding,
				this.securityProviderBC, aesPassword);
		this.decryptAES(this.aesEncryptedMessageFile3, this.aesDecryptedMessageFile3, this.symmetricEncryptionAlgorithm,
				this.symmetricEncryptionAlgorithmMode, this.symmetricEncryptionAlgorithmPadding,
				this.securityProviderBC, aesPassword);
		PublicKey publicKey = this.readPublicKeyFromCertificate(this.certificateFileISM, this.certificateType,
				this.securityProviderBC);

		File f = new File(this.receivedMessageSignature);
		FileInputStream fis = new FileInputStream(f);
		int sigSize = (int) f.length();
		byte[] signature = new byte[sigSize];
		fis.read(signature);
		fis.close();

		String legitMessage = null;
		if (this.checkSignature(signature, this.aesDecryptedMessageFile1, this.signatureAlgorithm,
				this.signatureAlgorithm, publicKey)) {
			legitMessage = this.aesDecryptedMessageFile1;
		}
		if (this.checkSignature(signature, this.aesDecryptedMessageFile2, this.signatureAlgorithm,
				this.signatureAlgorithm, publicKey)) {
			legitMessage = this.aesDecryptedMessageFile2;
		}
		if (this.checkSignature(signature, this.aesDecryptedMessageFile3, this.signatureAlgorithm,
				this.signatureAlgorithm, publicKey)) {
			legitMessage = this.aesDecryptedMessageFile3;
		}
		return legitMessage;
	}

	private void Exercise3() throws Exception {
		String aesPassword = this.Exercise1();
		this.encryptAES(this.responseFile, this.symmetricEncryptionAlgorithm, this.symmetricEncryptionAlgorithmMode,
				this.symmetricEncryptionAlgorithmPadding, this.securityProviderBC, aesPassword,
				this.responseEncryptedFile);
		PrivateKey privateKey = this.readPrivateKeyFromKeyStore(this.keyStoreFile, this.keyStoreType,
				this.keyStorePassword, this.keyAlias, this.keyPassword, this.securityProviderSUN);
		this.GenerateSignatureFile(this.responseEncryptedFile, this.signatureAlgorithm, privateKey,
				this.securityProviderBC, this.responseSignatureFile);

		File signatureFile = new File(this.responseSignatureFile);
		FileInputStream fileInputStream = new FileInputStream(signatureFile);
		byte[] signatureData = new byte[(int) signatureFile.length()];
		fileInputStream.read(signatureData);
		fileInputStream.close();

		PublicKey publicKey = this.readPublicKeyFromCertificate(this.certificateFileStudent, this.certificateType,
				this.securityProviderBC);
		//PublicKey publicKey = this.readPublicKeyFromKeyStore(this.keyStoreFile, this.keyStoreType,
		//		this.keyStorePassword, this.keyAlias, this.keyPassword, this.securityProviderSUN);
		if (this.checkSignature(signatureData, this.responseEncryptedFile, this.signatureAlgorithm,
				this.securityProviderBC, publicKey)) {
			System.out.println("Signature Check By Receiver: OK!");
		} else {
			System.out.println("Signature Check By Receiver: KO!");
		}
	}

	public void Run() throws Exception {
		String aesPassword = this.Exercise1();
		System.out.println("Aes Password is: " + aesPassword);
		String legitMessage = this.Exercise2();
		System.out.println("Legit Message is: " + legitMessage);
		this.Exercise3();
	}

	public static void main(String[] args) {
		MainChallengeTwo challengeTwo = new MainChallengeTwo();
		try {
			challengeTwo.Run();
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
}