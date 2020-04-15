package challegenone;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileWriter;
import java.io.IOException;
import java.security.DigestException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.util.Scanner;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;

public class MainChallengeOne {

	private final String firstHashAlg = "MD5";
	private final String secondHashAlg = "SHA1";
	private final String passwordPrefix = "ism";
	private final String securityProvider = "BC";
	private final String mostUsedPasswordsFile = "10-million-password-list-top-1000000.txt";
	private final String mostUsedPrefixedPasswordsFile = "10-million-password-list-top-1000000.Prefixed.txt";
	private final String mostUsedPrefixedPasswordsFileHashedMdFive = "10-million-password-list-top-1000000.Prefixed.MD5.txt";
	private final String mostUsedPrefixedPasswordsFileHashedShaOne = "10-million-password-list-top-1000000.Prefixed.SHA1.txt";
	private final String hashedPasswordToFind = "e8258482e63cdf96701f0bc3796018f00ed442b5";

	public MainChallengeOne() {
		super();
	}

	private void generateMostUsedPasswordsWithPrefix(String passwordsFile, String destinationFile) throws IOException {
		File mostUsedPasswordsFile = new File(passwordsFile);
		File mostUsedPasswordsPrefixedFile = new File(destinationFile);
		if (mostUsedPasswordsFile.exists()) {
			mostUsedPasswordsPrefixedFile.createNewFile();
			Scanner scanner = new Scanner(mostUsedPasswordsFile);
			FileWriter fileWriter = new FileWriter(mostUsedPasswordsPrefixedFile);
			while (scanner.hasNext()) {
				String password = scanner.nextLine();
				String prefixedPassword = this.passwordPrefix + password + System.lineSeparator();
				fileWriter.write(prefixedPassword);
			}
			scanner.close();
			fileWriter.close();
		} else {
			throw new FileNotFoundException(passwordsFile + " Not Found!");
		}
	}

	private void hashMostUsedPasswords(String passwordsFile, String hashAlgorithm, String destinationFile)
			throws NoSuchAlgorithmException, NoSuchProviderException, DigestException, IOException {
		File mostUsedPasswordsPrefixed = new File(passwordsFile);
		File mostUsedPasswordsHashed = new File(destinationFile);
		mostUsedPasswordsHashed.createNewFile();
		if (mostUsedPasswordsPrefixed.exists()) {
			Scanner scanner = new Scanner(mostUsedPasswordsPrefixed);
			MessageDigest messageDigest = MessageDigest.getInstance(hashAlgorithm, this.securityProvider);
			FileWriter fileWriter = new FileWriter(mostUsedPasswordsHashed);
			while (scanner.hasNext()) {
				String password = scanner.nextLine();
				messageDigest.update(password.getBytes(), 0, password.length());
				fileWriter.write(Hex.toHexString(messageDigest.digest()) + System.lineSeparator());
			}
			scanner.close();
			fileWriter.close();
		} else {
			throw new FileNotFoundException(passwordsFile + " Not Found!");
		}
	}

	private void bruteForceHashedPassword(String passwordsFile) throws FileNotFoundException {
		File file = new File(passwordsFile);
		if (file.exists()) {
			Scanner scanner = new Scanner(file);
			while (scanner.hasNext()) {
				String passwordToCheck = scanner.nextLine();
				if (passwordToCheck.equals(this.hashedPasswordToFind)) {
					System.out.println("Brute Force On Password Completed!");
					scanner.close();
					return;
				}
			}
			scanner.close();
		} else {
			throw new FileNotFoundException(passwordsFile + " Not Found!");
		}
	}

	public void Run() throws IOException, NoSuchAlgorithmException, NoSuchProviderException, DigestException {

		long T0 = System.currentTimeMillis();
		this.generateMostUsedPasswordsWithPrefix(this.mostUsedPasswordsFile, this.mostUsedPrefixedPasswordsFile);
		long T1 = System.currentTimeMillis();
		System.out.println("Time Spent On Appending Prefix To The Passwords: 	" + (T1 - T0));

		this.hashMostUsedPasswords(this.mostUsedPrefixedPasswordsFile, this.firstHashAlg,
				this.mostUsedPrefixedPasswordsFileHashedMdFive);
		long T2 = System.currentTimeMillis();
		System.out.println("Time Spent On Hashing Passwords With MD5:        	" + (T2 - T1));

		this.hashMostUsedPasswords(this.mostUsedPrefixedPasswordsFileHashedMdFive, this.secondHashAlg,
				this.mostUsedPrefixedPasswordsFileHashedShaOne);
		long T3 = System.currentTimeMillis();
		System.out.println("Time Spent On Hashing Passwords With SHA1:       	" + (T3 - T2));

		this.bruteForceHashedPassword(this.mostUsedPrefixedPasswordsFileHashedShaOne);
		long T4 = System.currentTimeMillis();
		System.out.println("Time Spent On Brute Force:                       	" + (T4 - T3));
		System.out.println("Time Spent Total:                               	" + (T4 - T0));
	}

	static {
		Security.addProvider(new BouncyCastleProvider());
		if (Security.getProvider("BC") == null) {
			throw new SecurityException("Bouncy Castle Provider Not Found!");
		}
	}

	public static void main(String[] args) {
		MainChallengeOne challengeOne = new MainChallengeOne();
		try {
			challengeOne.Run();
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (NoSuchProviderException e) {
			e.printStackTrace();
		} catch (DigestException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
}