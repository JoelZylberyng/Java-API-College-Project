import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.Base64;
import java.util.Properties;

/**
 * Class used for Decryption.
 * The class decrypts a cipher text and verifies it using the correct configurations and encryption parameters.
 */
public class Decrypt {

    private KeyStore m_keyStore;
    private Signature m_signature;
    private String m_cipherText;
    private char[] m_keystorePass;
    private byte[] m_secretKeyParams;
    private byte[] m_fileDataInBytes;

    //region encryption parameters.
    private byte[] m_fileSignature;
    private byte[] m_encryptedKey;
    private byte[] m_ivParams;
    //endregion

    //region properties
    private String m_encryptType;
    private String m_encryptMode ;
    private String m_encryptProvider;
    private String m_paddingMethod;
    private String m_asymetricKeyAlgo;
    private String m_asymetricKeyProvider;
    private String m_signatureType;
    private String m_signatureProvider;
    private String m_targetFile = "decrypted.txt";
    private String m_userBAlias;
    private String m_userAAlias;
    private String m_keystorePath;
    private String m_keystoreType;
    //endregion

    /**
     * Constructor. Sets properties, receiver keystore and secret key parameters.
     * @param propertiesFile - Configurations file.
     * @param keystorePass - Password to receiver's keystore.
     * @throws CertificateException
     * @throws NoSuchAlgorithmException
     * @throws KeyStoreException
     * @throws IOException
     * @throws NoSuchPaddingException
     * @throws UnrecoverableKeyException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     * @throws NoSuchProviderException
     * @throws InvalidKeyException
     */
    public Decrypt (Properties propertiesFile, String keystorePass) throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException, NoSuchPaddingException, UnrecoverableKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchProviderException, InvalidKeyException {
        this.m_keystorePass = keystorePass.toCharArray();
        getProperties(propertiesFile);
        setKeyStore();
        createSecretKeyParams();
    }

    /**
     * Loads encryption properties and parameters from configurations file.
     * @param prop - Properties file.
     */
    private void getProperties(Properties prop) {

        // setting properties
        m_cipherText = prop.getProperty("encryptedFile");
        m_userAAlias = prop.getProperty("userAAlias");
        m_userBAlias = prop.getProperty("userBAlias");
        m_encryptType = prop.getProperty("textEncryptionType");
        m_encryptMode = prop.getProperty("textEncryptionMode");
        m_encryptProvider = prop.getProperty("textEncryptionProvider");
        m_paddingMethod = prop.getProperty("textEncryptionPadding");
        m_asymetricKeyAlgo = prop.getProperty("asymmetricKeyEncryptionAlgorithm");
        m_asymetricKeyProvider = prop.getProperty("asymmetricKeyEncryptionAlgoProvider");
        m_signatureType = prop.getProperty("signatureAlgorithm");
        m_signatureProvider = prop.getProperty("signatureProvider");
        m_keystorePath = prop.getProperty("keystoreBPath");
        m_keystoreType = prop.getProperty("keystoreBType");

        // setting encryption params
        Base64.Decoder decoder = Base64.getDecoder();
        m_encryptedKey = decoder.decode(prop.getProperty("encryptedKey"));
        m_fileSignature = decoder.decode(prop.getProperty("signature"));
        m_ivParams = decoder.decode(prop.getProperty("iv_params"));
        m_fileDataInBytes = decoder.decode(prop.getProperty("fileDataInBytes"));
    }

    /**
     * Loads receiver's Keystore.
     * @throws IOException
     * @throws KeyStoreException
     * @throws CertificateException
     * @throws NoSuchAlgorithmException
     */
    protected void setKeyStore() throws IOException, KeyStoreException, CertificateException, NoSuchAlgorithmException {
        FileInputStream fin = new FileInputStream(m_keystorePath);
        m_keyStore = KeyStore.getInstance(m_keystoreType);
        m_keyStore.load(fin, m_keystorePass);
    }

    /**
     * Reconstructs the cipher secret key from the given encryption parameters, using receiver's private key.
     * @throws UnrecoverableKeyException
     * @throws NoSuchAlgorithmException
     * @throws KeyStoreException
     * @throws NoSuchProviderException
     * @throws NoSuchPaddingException
     * @throws BadPaddingException
     * @throws IllegalBlockSizeException
     * @throws InvalidKeyException
     */
    private void createSecretKeyParams() throws UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException, NoSuchProviderException, NoSuchPaddingException, BadPaddingException, IllegalBlockSizeException, InvalidKeyException {
        PrivateKey userBPrivateKey = (PrivateKey) m_keyStore.getKey(m_userBAlias, m_keystorePass);
        Cipher keyCipher = Cipher.getInstance(m_asymetricKeyAlgo, m_asymetricKeyProvider);
        keyCipher.init(Cipher.DECRYPT_MODE, userBPrivateKey);
        m_secretKeyParams = keyCipher.doFinal(m_encryptedKey);
    }

    /**
     * The main function that drives the decryption process.
     * This function uses the re-created secret key, given IV params and properties to decrypt the cipher text if it verifies it with signature.
     */
    public void decrypt(){
        try {
            SecretKeySpec keySpec = new SecretKeySpec(m_secretKeyParams, m_encryptType);
            IvParameterSpec ivSpec = new IvParameterSpec(m_ivParams);

            Cipher decryptCipher = Cipher.getInstance(m_encryptType + "/"
                                                        + m_encryptMode + "/"
                                                        + m_paddingMethod,
                                                          m_encryptProvider);

            decryptCipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);

            boolean verify = verifySignature();
            if(verify) {
                System.out.println("Signature is valid, decrypting file...");
                FileInputStream fis = new FileInputStream(m_cipherText);
                CipherOutputStream cos = new CipherOutputStream(new FileOutputStream(m_targetFile), decryptCipher);
                decryptFile(fis, cos);
                System.out.println("Decryption complete!");
            }else
                System.out.println("Signature not valid, no decryption initialized");

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * Reads the cipher text, decrypts it and writes it to target file.
     * @param fis - File stream reading the cipher text.
     * @param cos - Cipher stream that decrypts the cipher text and writes to target file.
     */
    private void decryptFile(FileInputStream fis, CipherOutputStream cos) {
        byte[] buff = new byte[256];
        try {
            int hasMoreToRead = fis.read(buff);
            while (hasMoreToRead != -1) {
                cos.write(buff, 0 ,hasMoreToRead);
                hasMoreToRead = fis.read(buff);
            }
            fis.close();
            cos.close();

        } catch (Exception e) {
            e.printStackTrace();
            return;
        }
    }

    /**
     * Reconstructs and verifies the signature.
     * @return true if signature matches, false if it doesn't.
     * @throws KeyStoreException
     * @throws NoSuchProviderException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws IOException
     * @throws SignatureException
     */
    private boolean verifySignature() throws KeyStoreException, NoSuchProviderException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {

        PublicKey publicKey = m_keyStore.getCertificate(m_userAAlias).getPublicKey();
        m_signature = Signature.getInstance(m_signatureType, m_signatureProvider);
        m_signature.initVerify(publicKey);
        m_signature.update(m_fileDataInBytes);
        return m_signature.verify(m_fileSignature);
    }

}
