package filehash;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;

public class FileHash {

	private final String securityProvider = "BC";
	private final String hashAlgorithm = "SHA1";
	private final String file1 = "file1.txt";
	private final String file2 = "file2.txt";
	private final int bufferSize = 4096;

	static {
		Security.addProvider(new BouncyCastleProvider());
		if (Security.getProvider("BC") == null) {
			throw new SecurityException("Bouncy Castle Provider Not Found!");
		} else {
			System.out.println(Security.getProvider("BC"));
		}
	}

	public FileHash() {
		super();
	}

	private byte[] hashFile(String fileToHashPath, String hashAlgorithm, String securityProvider)
			throws NoSuchAlgorithmException, NoSuchProviderException, IOException {
		File fileToHash = new File(fileToHashPath);
		if (fileToHash.exists()) {
			FileInputStream fileToHashStream = new FileInputStream(fileToHash);
			MessageDigest messageDigest = MessageDigest.getInstance(hashAlgorithm, securityProvider);
			byte[] fileBuffer = new byte[this.bufferSize];
			int numberOfBytesRead = 0;
			numberOfBytesRead = fileToHashStream.read(fileBuffer);
			while (numberOfBytesRead != -1) {
				messageDigest.update(fileBuffer, 0, numberOfBytesRead);
				numberOfBytesRead = fileToHashStream.read(fileBuffer);
			}
			byte[] hashValue = messageDigest.digest();
			fileToHashStream.close();
			return hashValue;
		} else {
			throw new FileNotFoundException(fileToHashPath + " Not Found!");
		}
	}

	public void Run() throws NoSuchAlgorithmException, NoSuchProviderException, IOException {
		byte[] file1Hash = this.hashFile(this.file1, this.hashAlgorithm, this.securityProvider);
		byte[] file2Hash = this.hashFile(this.file2, this.hashAlgorithm, this.securityProvider);
		System.out.println(this.file1 + " Hash = " + Hex.toHexString(file1Hash));
		System.out.println(this.file2 + " Hash = " + Hex.toHexString(file2Hash));
	}

	public static void main(String[] args) {
		FileHash fileHash = new FileHash();
		try {
			fileHash.Run();
		} catch (NoSuchAlgorithmException | NoSuchProviderException | IOException e) {
			e.printStackTrace();
		}
	}
}