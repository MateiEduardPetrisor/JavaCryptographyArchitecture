package electronicsignature;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;

public class ElectronicSignature {

	private final String file1 = "file1.txt";
	private final String file2 = "file2.txt";
	private final String file1Signature = "file1.sig";
	private final String file2Signature = "file2.sig";
	private final String certificateFile = "sampleCertificate.cer";
	private final String certificateType = "X509";
	private final String keyStoreFile = "sampleKeyStore.ks";
	private final String keyStoreType = "JKS";
	private final String keyStorePass = "P@ssw0rd!";
	private final String keyAlias = "org";
	private final String keyPass = "k3yP@ssw0rd";
	private final String securityProviderBC = "BC";
	private final String securityProviderSUN = "SUN";
	private final String signatureAlgorithm = "SHA1WithRSA";
	private final int bufferSize = 4096;

	static {
		Security.addProvider(new BouncyCastleProvider());
		if (Security.getProvider("BC") == null) {
			throw new SecurityException("Bouncy Castle Provider Not Found!");
		} else {
			System.out.println(Security.getProvider("BC"));
		}
	}

	public ElectronicSignature() {
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
			KeyStore keyStore = KeyStore.getInstance(keyStoreType, securityProvider);
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

	private void GenerateSignatureFile(String fileToSignPath, String signAlgorithm, PrivateKey privateKey,
			String securityProvider, String signatureFilePath) throws IOException, InvalidKeyException,
			NoSuchAlgorithmException, SignatureException, NoSuchProviderException {
		File toBeSigned = new File(fileToSignPath);
		if (toBeSigned.exists()) {
			FileInputStream toBeSignedStream = new FileInputStream(toBeSigned);
			byte[] fileBuffer = new byte[this.bufferSize];
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

	private boolean VerifySignatureFile(String signatureFilePath, String signAlgorithm, PublicKey publicKey,
			String securityProvider, String fileToVerifyPath) throws IOException, InvalidKeyException,
			NoSuchAlgorithmException, SignatureException, NoSuchProviderException {
		File signatureFile = new File(signatureFilePath);
		if (signatureFile.exists()) {
			FileInputStream signatureFileStream = new FileInputStream(signatureFile);
			int signatureFileSize = (int) signatureFile.length();
			byte[] signatureData = new byte[signatureFileSize];
			signatureFileStream.read(signatureData);
			signatureFileStream.close();

			Signature signature = Signature.getInstance(signAlgorithm, securityProvider);
			signature.initVerify(publicKey);

			File toBeVerified = new File(fileToVerifyPath);
			if (toBeVerified.exists()) {
				FileInputStream toBeVerifiedStream = new FileInputStream(toBeVerified);
				byte[] fileBuffer = new byte[this.bufferSize];
				int numberOfBytesRead = 0;
				numberOfBytesRead = toBeVerifiedStream.read(fileBuffer);
				while (numberOfBytesRead != -1) {
					signature.update(fileBuffer, 0, numberOfBytesRead);
					numberOfBytesRead = toBeVerifiedStream.read(fileBuffer);
				}
				toBeVerifiedStream.close();
				return signature.verify(signatureData);
			} else {
				throw new FileNotFoundException(toBeVerified + " Not Found!");
			}
		} else {
			throw new FileNotFoundException(signatureFilePath + " Not Found!");
		}
	}

	public void Run() throws InvalidKeyException, NoSuchAlgorithmException, SignatureException, IOException,
			UnrecoverableKeyException, KeyStoreException, NoSuchProviderException, CertificateException {
		PrivateKey keyStorePrivateKey = this.readPrivateKeyFromKeyStore(this.keyStoreFile, this.keyStoreType,
				this.keyStorePass, this.keyAlias, this.keyPass, this.securityProviderSUN);
		PublicKey keyStorePublicKey = this.readPublicKeyFromKeyStore(this.keyStoreFile, this.keyStoreType,
				this.keyStorePass, this.keyAlias, this.keyPass, this.securityProviderSUN);
		PublicKey certificatePublicKey = this.readPublicKeyFromCertificate(this.certificateFile, this.certificateType,
				this.securityProviderBC);

		this.GenerateSignatureFile(this.file1, this.signatureAlgorithm, keyStorePrivateKey, this.securityProviderBC,
				this.file1Signature);
		this.GenerateSignatureFile(this.file2, this.signatureAlgorithm, keyStorePrivateKey, this.securityProviderBC,
				this.file2Signature);

		if (this.VerifySignatureFile(this.file1Signature, this.signatureAlgorithm, keyStorePublicKey,
				this.securityProviderBC, this.file1)) {
			System.out.println(this.file1Signature + " Signature OK!");
		} else {
			System.out.println(this.file1Signature + " Signature KO!");
		}

		if (this.VerifySignatureFile(this.file2Signature, this.signatureAlgorithm, certificatePublicKey,
				this.securityProviderBC, this.file1)) {
			System.out.println(this.file2Signature + " Signature OK!");
		} else {
			System.out.println(this.file2Signature + " Signature KO!");
		}
	}

	public static void main(String[] args) {
		ElectronicSignature eSignature = new ElectronicSignature();
		try {
			eSignature.Run();
		} catch (InvalidKeyException | NoSuchAlgorithmException | SignatureException | IOException
				| UnrecoverableKeyException | KeyStoreException | NoSuchProviderException | CertificateException e) {
			e.printStackTrace();
		}
	}
}