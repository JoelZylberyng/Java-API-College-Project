import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.io.*;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.Base64;
import java.util.Properties;

/**
 * Class used for encryption.
 * the class encrypts a text file using crypto configurations from a properties file (given by the user) and signs the data.
 */
public class Encrypt {


    private SecretKey m_secretCipherKey;
    private KeyStore m_keyStore;
    private Signature m_signature;
    private File m_plaintext;
    private byte[] m_fileDataInBytes;
    private char[] m_keystorePass;

    //region encrypted variables
    // Encryption parameters that will be written to the new config file.
    private byte[] m_fileSignature;
    private byte[] m_encryptedKey;
    private IvParameterSpec m_iv;
    //endregion

    //region properties
    // Modular configurations, taken from the given properties file.
    private String m_encryptType;
    private String m_encryptMode ;
    private String m_encryptProvider;
    private String m_paddingMethod;
    private String m_ivAlgorithm;
    private String m_ivProvider;
    private int m_ivSize = 16;
    private String m_symmetricKeyType;
    private String m_symmetricProvider;
    private String m_asymetricKeyAlgo;
    private String m_asymetricKeyProvider;
    private String m_signatureType;
    private String m_signatureProvider;
    private String m_targetFile = "encrypted.txt";
    private String m_userBAlias;
    private String m_userAAlias;
    private String m_keystoreAPath;
    private String m_keystoreAType;
    private String m_keystoreBPath;
    private String m_keystoreBType;
    //endregion

    /**
     * Constructor for the Encrypt object.
     * @param userProperties - Configuration file containing Cryptography algorithms, aliases and Sender keystore.
     * @param keystorePass - Password of sender keystore.
     * @param fileToEncrypt - the plain text you wish to encrypt.
     * @throws NoSuchAlgorithmException
     * @throws KeyStoreException
     * @throws IOException
     * @throws NoSuchProviderException
     * @throws CertificateException
     */
    public Encrypt(Properties userProperties, String keystorePass, File fileToEncrypt) throws NoSuchAlgorithmException, KeyStoreException, IOException, NoSuchProviderException, CertificateException {
        this.m_plaintext = fileToEncrypt;
        this.m_keystorePass = keystorePass.toCharArray();
        getProperties(userProperties);
        generateSecretKey();
        generateIV();
        setKeyStore();
    }

    /**
     * Sets Cryptography configurations from properties file.
     * @param prop - properties file.
     */
    private void getProperties(Properties prop) {

        m_userAAlias = prop.getProperty("userAAlias");
        m_userBAlias = prop.getProperty("userBAlias");
        m_keystoreAPath = prop.getProperty("keystoreAPath");
        m_keystoreAType = prop.getProperty("keystoreAType");
        m_encryptType = prop.getProperty("textEncryptionType");
        m_encryptMode = prop.getProperty("textEncryptionMode");
        m_encryptProvider = prop.getProperty("textEncryptionProvider");
        m_paddingMethod = prop.getProperty("textEncryptionPadding");
        m_ivAlgorithm = prop.getProperty("ivAlgorithm");
        m_ivProvider = prop.getProperty("ivAlgoProvider");
        m_symmetricKeyType = prop.getProperty("symmetricKeyType");
        m_symmetricProvider = prop.getProperty("symmetricKeyProvider");
        m_asymetricKeyAlgo = prop.getProperty("asymmetricKeyEncryptionAlgorithm");
        m_asymetricKeyProvider = prop.getProperty("asymmetricKeyEncryptionAlgoProvider");
        m_signatureType = prop.getProperty("signatureAlgorithm");
        m_signatureProvider = prop.getProperty("signatureProvider");
        m_keystoreBPath = prop.getProperty("keystoreBPath");
        m_keystoreBType = prop.getProperty("keystoreBType");
    }

    /**
     * Loads the Keystore of the sender.
     * @throws IOException
     * @throws KeyStoreException
     * @throws CertificateException
     * @throws NoSuchAlgorithmException
     */
    protected void setKeyStore() throws IOException, KeyStoreException, CertificateException, NoSuchAlgorithmException {
        FileInputStream fin = new FileInputStream(m_keystoreAPath);
        m_keyStore = KeyStore.getInstance(m_keystoreAType);
        m_keyStore.load(fin, m_keystorePass);
    }

    /**
     * The main function that drives the encryption process.
     * Encrypts the plain text file using a Cipher with given configurations, and signs the data.
     */
    protected void encrypt() {
        try{
            Cipher messageCipher = Cipher.getInstance(m_encryptType + "/"
                                                    + m_encryptMode + "/"
                                                    + m_paddingMethod,
                                                      m_encryptProvider);

            messageCipher.init(Cipher.ENCRYPT_MODE, m_secretCipherKey, m_iv);
            CipherInputStream cis = new CipherInputStream(new FileInputStream(m_plaintext), messageCipher);
            FileOutputStream  fos = new FileOutputStream(m_targetFile);
            encryptFile(fos, cis);

            readFileContent();
            configureAndSign();

            System.out.println("Encryption complete");

        }
        catch(Exception e){
            e.printStackTrace();
        }
    }

    /**
     * Reads the data of the text file into bytes so that it can be signed.
     * @throws IOException
     */
    private void readFileContent() throws IOException {
        Path filePath = FileSystems.getDefault().getPath(m_targetFile);
        m_fileDataInBytes = Files.readAllBytes(filePath);
    }

    /**
     * Reads from text file, encrypts the text and writes it to a target file.
     * @param fos - File stream that writes cipher text to target file.
     * @param cis - Cipher stream that reads and encrypts plain text file.
     */
    private void encryptFile(FileOutputStream fos, CipherInputStream cis){
        byte[] buff = new byte[256];
        try {
            int hasMoreToRead = cis.read(buff);
            while (hasMoreToRead != -1) {
                fos.write(buff, 0 ,hasMoreToRead);
                hasMoreToRead = cis.read(buff);
            }
            cis.close();
            fos.close();

        } catch (Exception e) {
            e.printStackTrace();
            return;
        }
    }

    /**
     * Generates a secret random key.
     * @throws NoSuchProviderException
     * @throws NoSuchAlgorithmException
     */
    private void generateSecretKey() throws NoSuchProviderException, NoSuchAlgorithmException {
        KeyGenerator keygenerator = KeyGenerator.getInstance(m_symmetricKeyType, m_symmetricProvider);
        SecureRandom random = SecureRandom.getInstance(m_ivAlgorithm, m_ivProvider);
        keygenerator.init(128, random);
        m_secretCipherKey = keygenerator.generateKey();
    }

    /**
     * Generates a random IV.
     * @throws NoSuchAlgorithmException
     * @throws NoSuchProviderException
     */
    private void generateIV() throws NoSuchAlgorithmException, NoSuchProviderException {

        SecureRandom secureRandom = SecureRandom.getInstance(m_ivAlgorithm, m_ivProvider);
        byte[] ivArr = new byte[m_ivSize];
        secureRandom.nextBytes(ivArr);
        m_iv = new IvParameterSpec(ivArr);

    }

    /**
     * Function that organises the creation of the signature, encryption of the secret key and the writing of the Decryption properties file.
     * @throws UnrecoverableKeyException
     * @throws NoSuchAlgorithmException
     * @throws KeyStoreException
     * @throws SignatureException
     * @throws NoSuchProviderException
     * @throws InvalidKeyException
     * @throws NoSuchPaddingException
     * @throws BadPaddingException
     * @throws IllegalBlockSizeException
     * @throws IOException
     */
    private void configureAndSign() throws UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException, SignatureException, NoSuchProviderException, InvalidKeyException, NoSuchPaddingException, BadPaddingException, IllegalBlockSizeException, IOException {
        generateSignature();
        encryptKey();
        writeConfigFile();
    }

    /**
     * Loads the sender's private key from his keystore.
     * @return sender's private key.
     * @throws UnrecoverableKeyException
     * @throws NoSuchAlgorithmException
     * @throws KeyStoreException
     */
    private PrivateKey loadUserPrivateKey() throws UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException {
        PrivateKey userPrivateKey = (PrivateKey) m_keyStore.getKey(m_userAAlias, m_keystorePass);
        return  userPrivateKey;
    }

    /**
     * Generates the signature for verification.
     * @throws NoSuchProviderException
     * @throws NoSuchAlgorithmException
     * @throws UnrecoverableKeyException
     * @throws KeyStoreException
     * @throws InvalidKeyException
     * @throws SignatureException
     */
    private void generateSignature() throws NoSuchProviderException, NoSuchAlgorithmException, UnrecoverableKeyException, KeyStoreException, InvalidKeyException, SignatureException {
        m_signature = Signature.getInstance(m_signatureType, m_signatureProvider);
        m_signature.initSign(loadUserPrivateKey());
        m_signature.update(m_fileDataInBytes);

        m_fileSignature = m_signature.sign();
    }

    /**
     * Encrypts the secret key used for the encryption, using the receivers public key.
     * @throws KeyStoreException
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws NoSuchProviderException
     * @throws InvalidKeyException
     * @throws BadPaddingException
     * @throws IllegalBlockSizeException
     */
    private void encryptKey() throws KeyStoreException, NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        PublicKey publicKey = m_keyStore.getCertificate(m_userBAlias).getPublicKey();
        Cipher keyCipher = Cipher.getInstance(m_asymetricKeyAlgo, m_asymetricKeyProvider);
        keyCipher.init(Cipher.ENCRYPT_MODE, publicKey);
        m_encryptedKey = keyCipher.doFinal(m_secretCipherKey.getEncoded());
    }

    /**
     * Writes all encryption configurations used, the encrypted secret key, the signature, IV params to "Decryption.properties" file.
     * @throws IOException
     */
    private void writeConfigFile() throws IOException {
        Properties prop = new Properties();
        FileOutputStream fis = new FileOutputStream("Decryption.properties");
        Base64.Encoder encoder = Base64.getEncoder();
        prop.setProperty("encryptedKey", encoder.encodeToString(m_encryptedKey));
        prop.setProperty("signature", encoder.encodeToString(m_fileSignature));
        prop.setProperty("iv_params", encoder.encodeToString(m_iv.getIV()));
        prop.setProperty("userAAlias", m_userAAlias);
        prop.setProperty("userBAlias", m_userBAlias);
        prop.setProperty("textEncryptionType", m_encryptType);
        prop.setProperty("textEncryptionMode", m_encryptMode);
        prop.setProperty("textEncryptionProvider", m_encryptProvider);
        prop.setProperty("textEncryptionPadding", m_paddingMethod);
        prop.setProperty("asymmetricKeyEncryptionAlgorithm", m_asymetricKeyAlgo);
        prop.setProperty("asymmetricKeyEncryptionAlgoProvider", m_asymetricKeyProvider);
        prop.setProperty("signatureAlgorithm", m_signatureType);
        prop.setProperty("signatureProvider", m_signatureProvider);
        prop.setProperty("encryptedFile", m_targetFile);
        prop.setProperty("keystoreBPath", m_keystoreBPath);
        prop.setProperty("keystoreBType", m_keystoreBType);
        prop.setProperty("fileDataInBytes", encoder.encodeToString(m_fileDataInBytes));
        prop.store(fis, null);
        fis.close();
    }

}