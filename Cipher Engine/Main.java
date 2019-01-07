import java.io.*;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.Properties;
import java.util.Scanner;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
/**
 * Entry point for the program.
 * The program encrypts "plaintext.txt" file located at same directory, outputs cipher text to "encryptedText.txt"
 * and then immediately attempts to verify and decrypt it. If the verification is valid, the program
 *  decrpypts the cipher text and outputs result to "decryptedText.txt", otherwise it prints a message that verification failed.
 *
 * The user can use an existing properties file or create a new one for the encryption process.
 * Usage:
 * java [-jar CipherEngine.jar | Main] [properties file name] [plain text file] [keystore a password] [keystore b password]
 *                          or
 * java [-jar CipherEngine.jar | Main] [keystore a password] [plain text file] [keystore b password]
**/
public class Main {

    public static void main(String[] args) {

        Properties encryptionProperties = new Properties();
        Properties decryptionProperties = new Properties();
        InputStream input;
        OutputStream output;

        if (args.length == 4) {

            try {
                input = new FileInputStream(args[0]);
                File i_file = new File(args[1]);
                String keystorePassA = args[2];
                String keystorePassB = args[3];
                encryptionProperties.load(input);
                Encrypt encryptor = new Encrypt(encryptionProperties, keystorePassA, i_file);
                encryptor.encrypt();

                input = new FileInputStream("Decryption.properties");
                decryptionProperties.load(input);

                Decrypt decryptor = new Decrypt(decryptionProperties, keystorePassB);
                decryptor.decrypt();

            } catch (Exception e) {exceptionControl(e);}
        }

        else if (args.length == 3){

            try (Scanner propertiesReader = new Scanner(System.in)){
                output = new FileOutputStream("UserEncryption.properties");

                //region user input
                System.out.println("Please Enter The User A Alias Followed By An ENTER");
                encryptionProperties.setProperty("userAAlias", propertiesReader.nextLine());

                System.out.println("Please Enter The User B Alias Followed By An ENTER");
                encryptionProperties.setProperty("userBAlias", propertiesReader.nextLine());

                System.out.println("Please Enter The KeyStore A Path Followed By An ENTER");
                encryptionProperties.setProperty("keystoreAPath", propertiesReader.nextLine());

                System.out.println("Please Enter The KeyStore A Type Followed By An ENTER");
                encryptionProperties.setProperty("keystoreAType", propertiesReader.nextLine());

                System.out.println("Please Enter The KeyStore B Path Followed By An ENTER");
                encryptionProperties.setProperty("keystoreBPath", propertiesReader.nextLine());

                System.out.println("Please Enter The KeyStore B Type Followed By An ENTER");
                encryptionProperties.setProperty("keystoreBType", propertiesReader.nextLine());

                System.out.println("Please Enter The Text Encryption Type Followed By An ENTER");
                encryptionProperties.setProperty("textEncryptionType", propertiesReader.nextLine());

                System.out.println("Please Enter The Text Encryption Mode Followed By An ENTER");
                encryptionProperties.setProperty("textEncryptionMode", propertiesReader.nextLine());

                System.out.println("Please Enter The Text Encryption Provider Followed By An ENTER");
                encryptionProperties.setProperty("textEncryptionProvider", propertiesReader.nextLine());

                System.out.println("Please Enter The Text Encryption Padding Followed By An ENTER");
                encryptionProperties.setProperty("textEncryptionPadding", propertiesReader.nextLine());

                System.out.println("Please Enter The Initial Vector Algorithm Followed By An ENTER");
                encryptionProperties.setProperty("ivAlgorithm", propertiesReader.nextLine());

                System.out.println("Please Enter The Initial Vector Algorithm Provider Followed By An ENTER");
                encryptionProperties.setProperty("ivAlgoProvider", propertiesReader.nextLine());

                System.out.println("Please Enter The Symmetric Key Type Followed By An ENTER");
                encryptionProperties.setProperty("symmetricKeyType", propertiesReader.nextLine());

                System.out.println("Please Enter The Symmetric Key Provider Followed By An ENTER");
                encryptionProperties.setProperty("symmetricKeyProvider", propertiesReader.nextLine());

                System.out.println("Please Enter The Asymmetric Key Encryption Algorithm Provider Followed By An ENTER");
                encryptionProperties.setProperty("asymmetricKeyEncryptionAlgoProvider", propertiesReader.nextLine());

                System.out.println("Please Enter The Signature Algorithm Followed By An ENTER");
                encryptionProperties.setProperty("signatureAlgorithm", propertiesReader.nextLine());

                System.out.println("Please Enter The Signature Provider Followed By An ENTER");
                encryptionProperties.setProperty("signatureProvider", propertiesReader.nextLine());
                //endregion

                encryptionProperties.store(output, null);

                File i_file = new File(args[0]);
                String keystorePassA = args[1];
                String keystorePassB = args[2];

                Encrypt encryptor = new Encrypt(encryptionProperties, keystorePassA, i_file);
                encryptor.encrypt();

                input = new FileInputStream("Decryption.properties");
                decryptionProperties.load(input);

                Decrypt decryptor = new Decrypt(decryptionProperties, keystorePassB);
                decryptor.decrypt();

            } catch(Exception exception) {exceptionControl(exception);}
        }

        else{
            System.out.println("usage:\njava -jar CipherEngine.jar [properties filename] [plain text file] [keystore a password] [keystore b password]\n" +
                                                             "java -jar CipherEngine.jar [plain text file] [keystore a password] [keystore b password]\n");
        }
    }

    private static void exceptionControl(Exception exception) {
        if(exception instanceof IOException)
        {
            System.out.println("IO Exception.");
            exception.printStackTrace();
        }
        else if(exception instanceof NoSuchAlgorithmException)
        {
            System.out.println("No such cryptography algorithm.");
            exception.printStackTrace();
        }
        else if(exception instanceof KeyStoreException)
        {
            System.out.println("Keystore doesn't exist, please type the correct path of keystore.");
            exception.printStackTrace();
        }
        else if(exception instanceof NoSuchProviderException)
        {
            System.out.println("NO such cryptography provider.");
            exception.printStackTrace();
        }
        else if(exception instanceof CertificateException)
        {
            System.out.println("Certificate doesn't exist.");
            exception.printStackTrace();
        }
        else if(exception instanceof UnrecoverableKeyException)
        {
            System.out.println("Key doesn't exist in key store and/or can not be recovered.");
            exception.printStackTrace();
        }
        else if(exception instanceof SignatureException)
        {
            System.out.println("Wrong signature algorithm and/or provider");
            exception.printStackTrace();
        }
        else if(exception instanceof NoSuchPaddingException)
        {
            System.out.println("No such padding method exist.");
            exception.printStackTrace();
        }
        else if(exception instanceof InvalidKeyException)
        {
            System.out.println("Requested Key is invalid.");
            exception.printStackTrace();
        }
        else if(exception instanceof BadPaddingException)
        {
            System.out.println("Wrong padding method chosen for cryptography algorithm");
            exception.printStackTrace();
        }
        else if(exception instanceof IllegalBlockSizeException)
        {
            System.out.println("Illegal Block Size");
            exception.printStackTrace();
        }

    }
}
