SET JAVA_INSTALL="C:\Program Files\Java\jdk1.8.0_241\bin"
SET KEYSTORE_FILE="C:\EclipseWorkspace\Electronic_Signature_Final\sampleKeyStore.ks"
SET CERTIFICATE_FILE="C:\EclipseWorkspace\Electronic_Signature_Final\sampleCertificate.cer"

CD /D %JAVA_INSTALL%
IF EXIST %KEYSTORE_FILE% (
	DEL %KEYSTORE_FILE% /Q
	DEL %CERTIFICATE_FILE% /Q
)

keytool.exe -genkeypair -dname "CN=sample.jca, O=Home, C=RO" -alias org -keypass k3yP@ssw0rd -keyalg RSA -keysize 4096 -keystore %KEYSTORE_FILE% -storepass P@ssw0rd! -validity 3650 -storetype JKS
keytool.exe -export -alias org -storepass P@ssw0rd! -file %CERTIFICATE_FILE% -keystore %KEYSTORE_FILE%

PAUSE