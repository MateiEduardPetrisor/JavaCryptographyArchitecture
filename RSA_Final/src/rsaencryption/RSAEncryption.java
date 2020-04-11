package rsaencryption;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class RSAEncryption {

	private final String file1 = "file1.txt";
	private final String file2 = "file2.txt";
	private final String file1Encrypted = "file1.enc";
	private final String file2Encrypted = "file2.enc";
	private final String file1Decrypted = "file1.enc.txt";
	private final String file2Decrypted = "file2.enc.txt";
	private final String securityProviderBC = "BC";
	private final String securityProviderSUN = "SUN";
	private final String encryptionAlgorithm = "RSA";
	private final String encryptionAlgorithmMode = "ECB";
	private final String encryptionAlgorithmPadding = "PKCS1Padding";
	private final String certificateFile = "sampleCertificate.cer";
	private final String certificateType = "X509";
	private final String keyStoreFile = "sampleKeyStore.ks";
	private final String keyStoreType = "JKS";
	private final String keyStorePass = "P@ssw0rd!";
	private final String keyAlias = "org";
	private final String keyPass = "k3yP@ssw0rd";
	private final int bufferSize = 4096;

	static {
		Security.addProvider(new BouncyCastleProvider());
		if (Security.getProvider("BC") == null) {
			throw new SecurityException("Bouncy Castle Provider Not Found!");
		} else {
			System.out.println(Security.getProvider("BC"));
		}
	}

	public RSAEncryption() {
		super();
	}

	private PrivateKey readPrivateKeyFromKeyStore(String keyStoreFilePath, String keyStoreType, String keyStorePassword,
			String keyAlias, String keyPassword, String securityProvider)
			throws KeyStoreException, NoSuchProviderException, NoSuchAlgorithmException, CertificateException,
			IOException, UnrecoverableKeyException {
		File keyStoreFile = new File(keyStoreFilePath);
		if (keyStoreFile.exists()) {
			FileInputStream keyStoreStream = new FileInputStream(keyStoreFile);
			KeyStore keyStore = KeyStore.getInstance(keyStoreType, securityProvider);
			keyStore.load(keyStoreStream, keyStorePassword.toCharArray());
			PrivateKey privateKey = null;
			Key key = keyStore.getKey(keyAlias, keyPassword.toCharArray());
			if (key instanceof PrivateKey) {
				privateKey = (PrivateKey) key;
			}
			return privateKey;
		} else {
			throw new FileNotFoundException(keyStoreFilePath + " Not Found!");
		}
	}

	private PublicKey readPublicKeyFromKeyStore(String keyStoreFilePath, String keyStoreType, String keyStorePassword,
			String keyAlias, String keyPassword, String securityProvider) throws NoSuchAlgorithmException,
			CertificateException, IOException, UnrecoverableKeyException, KeyStoreException, NoSuchProviderException {
		File keyStoreFile = new File(keyStoreFilePath);
		if (keyStoreFile.exists()) {
			FileInputStream keyStoreStream = new FileInputStream(keyStoreFile);
			KeyStore keyStore = KeyStore.getInstance(keyStoreType);
			keyStore.load(keyStoreStream, keyStorePassword.toCharArray());
			PublicKey publicKey = null;
			Key key = keyStore.getKey(keyAlias, keyPassword.toCharArray());
			if (key instanceof PrivateKey) {
				Certificate certificate = keyStore.getCertificate(keyAlias);
				publicKey = certificate.getPublicKey();
			}
			return publicKey;
		} else {
			throw new FileNotFoundException(keyStoreFilePath + " Not Found!");
		}
	}

	private PublicKey readPublicKeyFromCertificate(String certificateFilePath, String certificateType,
			String securityProvider) throws CertificateException, IOException, NoSuchProviderException {
		File certFile = new File(certificateFilePath);
		if (certFile.exists()) {
			FileInputStream certFileStream = new FileInputStream(certFile);
			CertificateFactory certificateFactory = CertificateFactory.getInstance(certificateType, securityProvider);
			X509Certificate x509Certificate = (X509Certificate) certificateFactory.generateCertificate(certFileStream);
			PublicKey publicKey = x509Certificate.getPublicKey();
			certFileStream.close();
			return publicKey;
		} else {
			throw new FileNotFoundException(certificateFilePath + " Not Found!");
		}
	}

	private void encryptFile(String fileToEncryptPath, String encryptionAlgorithm, String encryptionAlgorithmMode,
			String encryptionAlgorithmPadding, PrivateKey privateKey, String securityProvider, String encryptedFilePath)
			throws IOException, NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException,
			InvalidKeyException, InvalidAlgorithmParameterException, ShortBufferException, IllegalBlockSizeException,
			BadPaddingException {
		File fileToEncrypt = new File(fileToEncryptPath);
		if (fileToEncrypt.exists()) {
			File encryptedFile = new File(encryptedFilePath);
			if (encryptedFile.exists()) {
				encryptedFile.createNewFile();
			}
			FileInputStream fileToEncyptStream = new FileInputStream(fileToEncrypt);
			FileOutputStream encryptedFileStream = new FileOutputStream(encryptedFile);
			String encryptionAlgorithmSettings = encryptionAlgorithm + "/" + encryptionAlgorithmMode + "/"
					+ encryptionAlgorithmPadding;
			Cipher cipher = Cipher.getInstance(encryptionAlgorithmSettings, securityProvider);
			cipher.init(Cipher.ENCRYPT_MODE, privateKey);
			int numberOfBytesRead = 0;
			byte readBuffer[] = new byte[this.bufferSize];
			byte writeBuffer[];
			numberOfBytesRead = fileToEncyptStream.read(readBuffer);
			while (numberOfBytesRead != -1) {
				writeBuffer = cipher.update(readBuffer, 0, numberOfBytesRead);
				if (writeBuffer != null) {
					encryptedFileStream.write(writeBuffer);
				}
				numberOfBytesRead = fileToEncyptStream.read(readBuffer);
			}
			writeBuffer = cipher.doFinal();
			if (writeBuffer != null) {
				encryptedFileStream.write(writeBuffer);
			}
			fileToEncyptStream.close();
			encryptedFileStream.close();
			System.out.println("File[" + fileToEncryptPath + "] Encrypted With " + encryptionAlgorithmSettings
					+ " Encrypted File[" + encryptedFilePath + "]");
		} else {
			throw new FileNotFoundException("File[" + fileToEncrypt + "] Not Found!");
		}
	}

	private void decryptFile(String encryptedFilePath, String encryptionAlgorithm, String encryptionAlgorithmMode,
			String encryptionAlgorithmPadding, PublicKey publicKey, String securityProvider, String decryptedFilePath)
			throws IOException, NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException,
			InvalidKeyException, InvalidAlgorithmParameterException, ShortBufferException, IllegalBlockSizeException,
			BadPaddingException {
		File fileToDecrypt = new File(encryptedFilePath);
		if (fileToDecrypt.exists()) {
			File decryptedFile = new File(decryptedFilePath);
			if (decryptedFile.exists()) {
				decryptedFile.createNewFile();
			}
			FileInputStream encryptedFileStream = new FileInputStream(fileToDecrypt);
			FileOutputStream decryptedFileStream = new FileOutputStream(decryptedFile);
			String encryptionAlgorithmSettings = encryptionAlgorithm + "/" + encryptionAlgorithmMode + "/"
					+ encryptionAlgorithmPadding;
			Cipher cipher = Cipher.getInstance(encryptionAlgorithmSettings, securityProvider);
			cipher.init(Cipher.DECRYPT_MODE, publicKey);
			int numberOfBytesRead = 0;
			byte readBuffer[] = new byte[this.bufferSize];
			byte writeBuffer[];
			numberOfBytesRead = encryptedFileStream.read(readBuffer);
			while (numberOfBytesRead != -1) {
				writeBuffer = cipher.update(readBuffer, 0, numberOfBytesRead);
				if (writeBuffer != null) {
					decryptedFileStream.write(writeBuffer);
				}
				numberOfBytesRead = encryptedFileStream.read(readBuffer);
			}
			writeBuffer = cipher.doFinal();
			if (writeBuffer != null) {
				decryptedFileStream.write(writeBuffer);
			}
			encryptedFileStream.close();
			decryptedFileStream.close();
			System.out.println("File[" + encryptedFilePath + "] Decrypted With " + encryptionAlgorithmSettings
					+ " Encrypted File[" + decryptedFilePath + "]");
		} else {
			throw new FileNotFoundException("File[" + fileToDecrypt + "] Not Found!");
		}
	}

	public void Run() throws CertificateException, NoSuchProviderException, IOException, UnrecoverableKeyException,
			KeyStoreException, NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException,
			InvalidAlgorithmParameterException, ShortBufferException, IllegalBlockSizeException, BadPaddingException {
		PublicKey publicKeyFromKeyStore = this.readPublicKeyFromKeyStore(this.keyStoreFile, this.keyStoreType,
				this.keyStorePass, this.keyAlias, this.keyPass, this.securityProviderSUN);
		PrivateKey privateKeyFromKeyStore = this.readPrivateKeyFromKeyStore(this.keyStoreFile, this.keyStoreType,
				this.keyStorePass, this.keyAlias, this.keyPass, this.securityProviderSUN);
		PublicKey publicKeyFromCertificate = this.readPublicKeyFromCertificate(this.certificateFile,
				this.certificateType, this.securityProviderBC);
		this.encryptFile(this.file1, this.encryptionAlgorithm, this.encryptionAlgorithmMode,
				this.encryptionAlgorithmPadding, privateKeyFromKeyStore, this.securityProviderBC, this.file1Encrypted);
		this.encryptFile(this.file2, this.encryptionAlgorithm, this.encryptionAlgorithmMode,
				this.encryptionAlgorithmPadding, privateKeyFromKeyStore, this.securityProviderBC, this.file2Encrypted);
		this.decryptFile(this.file1Encrypted, this.encryptionAlgorithm, this.encryptionAlgorithmMode,
				this.encryptionAlgorithmPadding, publicKeyFromKeyStore, this.securityProviderBC, this.file1Decrypted);
		this.decryptFile(this.file2Encrypted, this.encryptionAlgorithm, this.encryptionAlgorithmMode,
				this.encryptionAlgorithmPadding, publicKeyFromCertificate, this.securityProviderBC,
				this.file2Decrypted);
	}

	public static void main(String[] args) {
		RSAEncryption rsaEncryption = new RSAEncryption();
		try {
			rsaEncryption.Run();
		} catch (UnrecoverableKeyException | InvalidKeyException | CertificateException | NoSuchProviderException
				| KeyStoreException | NoSuchAlgorithmException | NoSuchPaddingException
				| InvalidAlgorithmParameterException | ShortBufferException | IllegalBlockSizeException
				| BadPaddingException | IOException e) {
			e.printStackTrace();
		}
	}
}