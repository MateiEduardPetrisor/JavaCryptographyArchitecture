package hashmessageauthenticationcode;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.util.Arrays;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;

public class FileHashMac {

	private final String file1 = "File1.txt";
	private final String file2 = "file2.txt";
	private final String file1Mac = "file1.mac";
	private final String file2Mac = "file2.mac";
	private final String securityProvider = "BC";
	private final String hashMacAlgorithm = "HmacSHA512";
	private final String hashMacAlgorithmKey = "P@ssw0rd!";
	private final int bufferSize = 4096;

	static {
		Security.addProvider(new BouncyCastleProvider());
		if (Security.getProvider("BC") == null) {
			throw new SecurityException("Bouncy Castle Provider Not Found!");
		} else {
			System.out.println(Security.getProvider("BC"));
		}
	}

	public FileHashMac() {
		super();
	}

	private void hashMacFile(String fileToHashMacPath, String hashMacAlgorithm, String securityProvider,
			String hashMacAlgorithmKey, String hashMacFilePath)
			throws NoSuchAlgorithmException, NoSuchProviderException, IOException, InvalidKeyException {
		File fileToHash = new File(fileToHashMacPath);
		if (fileToHash.exists()) {
			FileInputStream fileInputStream = new FileInputStream(fileToHash);
			Mac mac = Mac.getInstance(hashMacAlgorithm, securityProvider);
			Key key = new SecretKeySpec(hashMacAlgorithmKey.getBytes(), hashMacAlgorithm);
			mac.init(key);
			byte readBuffer[] = new byte[this.bufferSize];
			int numberOfBytesRead = 0;
			numberOfBytesRead = fileInputStream.read(readBuffer);
			while (numberOfBytesRead != -1) {
				mac.update(readBuffer, 0, numberOfBytesRead);
				numberOfBytesRead = fileInputStream.read(readBuffer);
			}
			fileInputStream.close();
			byte[] macData = mac.doFinal();
			System.out.println(fileToHashMacPath + " HashMAC = " + Hex.toHexString(macData));
			File hashMacFile = new File(hashMacFilePath);
			if (hashMacFile.exists()) {
				hashMacFile.createNewFile();
			}
			FileOutputStream macFileStream = new FileOutputStream(hashMacFile);
			macFileStream.write(macData);
			macFileStream.close();
		} else {
			throw new FileNotFoundException(fileToHashMacPath + " Not Found!");
		}
	}

	private boolean checkHashMac(String hashMacFilePath, String hashMacAlgorithm, String securityProvider,
			String hashMacAlgorithmKey, String fileToBeCheckedFilePath)
			throws IOException, InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException {
		File hashMacFile = new File(hashMacFilePath);
		if (hashMacFile.exists()) {
			FileInputStream hashMacFileStream = new FileInputStream(hashMacFile);
			int hashMacFileSize = (int) hashMacFile.length();
			byte[] macData = new byte[hashMacFileSize];
			hashMacFileStream.read(macData);
			hashMacFileStream.close();

			File fileToBeChecked = new File(fileToBeCheckedFilePath);
			if (fileToBeChecked.exists()) {
				FileInputStream fileInputStream = new FileInputStream(fileToBeChecked);
				Mac mac = Mac.getInstance(hashMacAlgorithm, securityProvider);
				Key key = new SecretKeySpec(hashMacAlgorithmKey.getBytes(), hashMacAlgorithm);
				mac.init(key);
				byte readBuffer[] = new byte[this.bufferSize];
				int numberOfBytesRead = 0;
				numberOfBytesRead = fileInputStream.read(readBuffer);
				while (numberOfBytesRead != -1) {
					mac.update(readBuffer, 0, numberOfBytesRead);
					numberOfBytesRead = fileInputStream.read(readBuffer);
				}
				fileInputStream.close();
				byte[] fileMacData = mac.doFinal();
				if (Arrays.equals(macData, fileMacData)) {
					return true;
				}
				return false;
			} else {
				throw new FileNotFoundException(fileToBeCheckedFilePath + " Not Found!");
			}
		} else {
			throw new FileNotFoundException(hashMacFilePath + " Not Found!");
		}
	}

	public void Run() throws NoSuchAlgorithmException, NoSuchProviderException, IOException, InvalidKeyException {
		this.hashMacFile(this.file1, this.hashMacAlgorithm, this.securityProvider, this.hashMacAlgorithmKey,
				this.file1Mac);
		this.hashMacFile(this.file2, this.hashMacAlgorithm, this.securityProvider, this.hashMacAlgorithmKey,
				this.file2Mac);

		if (this.checkHashMac(this.file1Mac, this.hashMacAlgorithm, this.securityProvider, this.hashMacAlgorithmKey,
				this.file1)) {
			System.out.println(this.file1 + " MAC OK!");
		} else {
			System.out.println(this.file1 + " MAC KO!");
		}

		if (this.checkHashMac(this.file1Mac, this.hashMacAlgorithm, this.securityProvider, this.hashMacAlgorithmKey,
				this.file2)) {
			System.out.println(this.file2 + " MAC OK!");
		} else {
			System.out.println(this.file2 + " MAC KO!");
		}
	}

	public static void main(String[] args) {
		FileHashMac fileHashMac = new FileHashMac();
		try {
			fileHashMac.Run();
		} catch (NoSuchAlgorithmException | NoSuchProviderException | IOException | InvalidKeyException e) {
			e.printStackTrace();
		}
	}
}