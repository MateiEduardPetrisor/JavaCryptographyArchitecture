package desencryption;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class DESEncrypt {

	private final String file1 = "file1.txt";
	private final String file2 = "file2.txt";
	private final String file1Encrypted = "file1.enc";
	private final String file2Encrypted = "file2.enc";
	private final String file1Decrypted = "file1.enc.txt";
	private final String file2Decrypted = "file2.enc.txt";
	private final String securityProvider = "BC";
	private final String encryptionAlgorithm = "DES";
	private final String encryptionAlgorithmMode = "ECB";
	private final String encryptionAlgorithmPadding = "PKCS5Padding";
	private final String encryptionAlgorithmKey = "P@ssw0rd";

	static {
		Security.addProvider(new BouncyCastleProvider());
		if (Security.getProvider("BC") == null) {
			throw new SecurityException("Bouncy Castle Provider Not Found!");
		} else {
			System.out.println(Security.getProvider("BC"));
		}
	}

	public DESEncrypt() {
		super();
	}

	private void encryptFile(String fileToEncryptPath, String encryptionAlgorithm, String encryptionAlgorithmMode,
			String encryptionAlgorithmPadding, String encryptionAlgorithmKey, String securityProvider,
			String encryptedFilePath) throws IOException, NoSuchAlgorithmException, NoSuchProviderException,
			NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, ShortBufferException,
			IllegalBlockSizeException, BadPaddingException {
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
			Key key = new SecretKeySpec(encryptionAlgorithmKey.getBytes(), encryptionAlgorithm);
			cipher.init(Cipher.ENCRYPT_MODE, key);
			int numberOfBytesRead = 0;
			byte readBuffer[] = new byte[cipher.getBlockSize()];
			// System.out.println("Cipher Block Size: " + cipher.getBlockSize());
			byte writeBuffer[];
			numberOfBytesRead = fileToEncyptStream.read(readBuffer);
			while (numberOfBytesRead != -1) {
				int outputSize = cipher.getOutputSize(numberOfBytesRead);
				writeBuffer = new byte[outputSize];
				int numberOfOutputBytes = cipher.update(readBuffer, 0, numberOfBytesRead, writeBuffer);
				encryptedFileStream.write(writeBuffer, 0, numberOfOutputBytes);
				numberOfBytesRead = fileToEncyptStream.read(readBuffer);
			}
			writeBuffer = cipher.doFinal();
			encryptedFileStream.write(writeBuffer);
			fileToEncyptStream.close();
			encryptedFileStream.close();
			System.out.println("File[" + fileToEncryptPath + "] Encrypted With " + encryptionAlgorithmSettings
					+ " Encrypted File[" + encryptedFilePath + "]");
		} else {
			throw new FileNotFoundException("File[" + fileToEncrypt + "] Not Found!");
		}
	}

	private void decryptFile(String encryptedFilePath, String encryptionAlgorithm, String encryptionAlgorithmMode,
			String encryptionAlgorithmPadding, String encryptionAlgorithmKey, String securityProvider,
			String decryptedFilePath) throws IOException, NoSuchAlgorithmException, NoSuchProviderException,
			NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException,
			BadPaddingException, ShortBufferException {
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
			Key key = new SecretKeySpec(encryptionAlgorithmKey.getBytes(), encryptionAlgorithm);
			cipher.init(Cipher.DECRYPT_MODE, key);
			int numberOfBytesRead = 0;
			byte readBuffer[] = new byte[cipher.getBlockSize()];
			// System.out.println("Cipher Block Size: " + cipher.getBlockSize());
			byte writeBuffer[];
			numberOfBytesRead = encryptedFileStream.read(readBuffer);
			while (numberOfBytesRead != -1) {
				int outputSize = cipher.getOutputSize(numberOfBytesRead);
				writeBuffer = new byte[outputSize];
				int numberOfOutputBytes = cipher.update(readBuffer, 0, numberOfBytesRead, writeBuffer);
				decryptedFileStream.write(writeBuffer, 0, numberOfOutputBytes);
				numberOfBytesRead = encryptedFileStream.read(readBuffer);
			}
			writeBuffer = cipher.doFinal();
			decryptedFileStream.write(writeBuffer);
			encryptedFileStream.close();
			decryptedFileStream.close();
			System.out.println("File[" + encryptedFilePath + "] Decrypted With " + encryptionAlgorithmSettings
					+ " Encrypted File[" + decryptedFilePath + "]");
		} else {
			throw new FileNotFoundException("File[" + fileToDecrypt + "] Not Found!");
		}
	}

	public void Run() throws InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException,
			NoSuchPaddingException, InvalidAlgorithmParameterException, ShortBufferException, IllegalBlockSizeException,
			BadPaddingException, IOException {
		this.encryptFile(this.file1, this.encryptionAlgorithm, this.encryptionAlgorithmMode,
				this.encryptionAlgorithmPadding, this.encryptionAlgorithmKey, this.securityProvider,
				this.file1Encrypted);
		this.encryptFile(this.file2, this.encryptionAlgorithm, this.encryptionAlgorithmMode,
				this.encryptionAlgorithmPadding, this.encryptionAlgorithmKey, this.securityProvider,
				this.file2Encrypted);
		this.decryptFile(this.file1Encrypted, this.encryptionAlgorithm, this.encryptionAlgorithmMode,
				this.encryptionAlgorithmPadding, this.encryptionAlgorithmKey, this.securityProvider,
				this.file1Decrypted);
		this.decryptFile(this.file2Encrypted, this.encryptionAlgorithm, this.encryptionAlgorithmMode,
				this.encryptionAlgorithmPadding, this.encryptionAlgorithmKey, this.securityProvider,
				this.file2Decrypted);
	}

	public static void main(String[] args) {
		DESEncrypt desEncrypt = new DESEncrypt();
		try {
			desEncrypt.Run();
		} catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchProviderException | NoSuchPaddingException
				| InvalidAlgorithmParameterException | ShortBufferException | IllegalBlockSizeException
				| BadPaddingException | IOException e) {
			e.printStackTrace();
		}
	}
}