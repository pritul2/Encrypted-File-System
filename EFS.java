
/**
 * @author Pritul Manish
 * @netid PMD220000
 * @email pritul.dave@utdallas.edu
 */

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.nio.ByteBuffer;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.spec.KeySpec;
import java.util.Arrays;

public class EFS extends Utility {

    private static final int USER_NAME_LENGTH = 128;
    private static final int PWD_LENGTH = 32;
    private static final int SALT_LENGTH = 16;
    private static final int HEADER_LENGTH = USER_NAME_LENGTH + PWD_LENGTH + SALT_LENGTH;
    private static final int SECRET_DATA_LENGTH = 128;
    private static final int METADATA_LENGTH = HEADER_LENGTH + SECRET_DATA_LENGTH;
    private static final int HMAC_LENGTH = 32;
   

    public EFS(Editor e) {
        super(e);
        set_username_password();
    }

    /**
     * Steps to consider...
     * <p>
     * - add padded username and password salt to header
     * <p>
     * - add password hash and file length to secret data
     * <p>
     * - AES encrypt padded secret data
     * <p>
     * - add header and encrypted secret data to metadata
     * <p>
     * - compute HMAC for integrity check of metadata
     * <p>
     * - add metadata and HMAC to metadata file block
     * <p>
     */

    private String padString(String str, int length) {
        StringBuilder padded_str = new StringBuilder(str);
        while (padded_str.length() < length) {
            padded_str.append('\0');
        }
        return padded_str.toString();
    }

    private byte[] longToBytes(long input) {
        ByteBuffer bf = ByteBuffer.allocate(Long.BYTES);
        bf.putLong(input);
        return bf.array();
    }

    private long bytesToLong(byte[] bytes) {
        ByteBuffer bf = ByteBuffer.wrap(bytes);
        return bf.getLong();
    }

    private byte[] padToMultiple(byte[] data, int blockSize) {
        int padding = blockSize - (data.length % blockSize);
        byte[] paddedData = new byte[data.length + padding];
        System.arraycopy(data, 0, paddedData, 0, data.length);
        for (int i = data.length; i < paddedData.length; i++) {
            paddedData[i] = (byte) padding;
        }
        return paddedData;
    }

    private byte[] deriveKeyFromPassword(String password, byte[] salt) throws Exception {
        int iterations = 1000;
        int keyLength = 256;
        KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, iterations, keyLength);
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        byte[] key = factory.generateSecret(spec).getEncoded();
        return key;
    }

    private byte[] getPasswordHash(String password, byte[] salt) throws Exception{
        // Padding password salt
        String padded_password = padString(password, 128);
    
        byte[] passwordBytes = padded_password.getBytes();
    
        byte[] saltedPasswordBytes = new byte[passwordBytes.length + salt.length];
    
        System.arraycopy(passwordBytes, 0, saltedPasswordBytes, 0, passwordBytes.length);
        System.arraycopy(salt, 0, saltedPasswordBytes, passwordBytes.length, salt.length);
    
        byte[] hashed_pwd = hash_SHA256(saltedPasswordBytes);
    
        return hashed_pwd;
    }

    @Override
    public void create(String file_name, String user_name, String password) throws Exception {

        if (user_name.length() > 128 || password.length() > 128) {
            throw new IllegalArgumentException("User name and password must be at most 128 bytes");
        }

        // Creating a new director with name same as file name
        File dir = new File(file_name);
        dir.mkdirs();
        File metadata_file = new File(dir, "0");
        metadata_file.createNewFile();

        // Generting salt
        byte[] salt = secureRandomNumber(16);
        System.out.println("Salt length "+salt.length);
        System.out.println("Salt  "+new String(salt));

        // Padding username
        String padded_user_name = padString(user_name, 128);

        // Making hashed password
        byte[] hashed_pwd = getPasswordHash(password,salt);
        System.out.println(new String(hashed_pwd));
        // Adding padded username and password salt to header
        byte[] header = new byte[padded_user_name.length() + hashed_pwd.length + salt.length];
        System.arraycopy(padded_user_name.getBytes(), 0, header, 0, padded_user_name.length());
        System.arraycopy(hashed_pwd, 0, header, padded_user_name.length(), hashed_pwd.length);
        System.arraycopy(salt, 0, header, padded_user_name.length() + hashed_pwd.length, salt.length);

        // System.out.println("Padded user name"+ padded_user_name.length());
        // System.out.println("Salted password"+saltedPasswordBytes.length);
        // System.out.println("Hashed password"+hashed_pwd.length);
        // System.out.println("header size"+header.length);
        System.out.println("Meta data file "+metadata_file.length());
        byte[] file_length = longToBytes(metadata_file.length());

        // System.out.println("file_length size"+file_length.length);

        // Creating secret data array of length pwd_hash + file_length
        byte[] secret_data = new byte[hashed_pwd.length + file_length.length];

        // System.out.println("secret_data size"+secret_data.length);

        // Adding password hash and File length to secret data
        System.arraycopy(hashed_pwd, 0, secret_data, 0, hashed_pwd.length);
        System.arraycopy(file_length, 0, secret_data, hashed_pwd.length, file_length.length);

        // Padding the secret data
        secret_data = padToMultiple(secret_data, 128);

        // System.out.println("Secret data length"+ secret_data.length);

        // Generating key on the basis of password
        byte[] pwd_base_key = deriveKeyFromPassword(padString(password, 128), salt);
        System.out.println("Key "+new String(pwd_base_key));
        // Encrypting secret data
        byte[] encrypted_secret_data = encript_AES(secret_data, pwd_base_key);

        // System.out.println("Encrypted Secret data length"+
        // encrypted_secret_data.length);

        // Adding header and encrypted secret data to metadata
        byte[] metadata = new byte[header.length + encrypted_secret_data.length];
        System.arraycopy(header, 0, metadata, 0, header.length);
        System.arraycopy(encrypted_secret_data, 0, metadata, header.length, encrypted_secret_data.length);

        // System.out.println("metadata length"+ metadata.length);

        // Computing HMAC on metadata
        byte[] hmac = hash_SHA256(metadata);

        // Writing metadata and HMAC to file
        FileOutputStream metadata_output = new FileOutputStream(metadata_file);

        // System.out.println("metadata length"+ metadata.length);
        // System.out.println("hmac length"+ hmac.length);

        metadata_output.write(metadata);
        metadata_output.write("\n".getBytes());
        metadata_output.write(hmac);

        metadata_output.close();

        return;
    }
    private boolean validate_HMAC(byte[] metadata){

        // Checking if the length of the metadata file is valid
        if (metadata.length != HEADER_LENGTH + SECRET_DATA_LENGTH +  HMAC_LENGTH + 1) {
            throw new Exception("Invalid File length");
        }

        // Extracting metadata bytes and HMAC from metadata file
        byte[] metadata_bytes = new byte[METADATA_LENGTH];
        byte[] hmac = new byte[HMAC_LENGTH];
        FileInputStream read_metadata = new FileInputStream(meta);
        read_metadata.read(metadata_bytes);
        read_metadata.skip(1);
        read_metadata.read(hmac);
        read_metadata.close();

        // Computing HMAC of metadata bytes
        byte[] computed_hmac = hash_SHA256(metadata_bytes);

        return Arrays.equals(hmac, computed_hmac);

    }
    /**
     * Steps to consider...
     * <p>
     * - check if metadata file size is valid
     * <p>
     * - get username from metadata
     * <p>
     */

    @Override
    public String findUser(String file_name) throws Exception {
        // Creating file objects for the file and its metadata
        File file = new File(file_name);
        File meta = new File(file, "0");

        // Reading the metadata file into a byte array
        FileInputStream metadata_input = new FileInputStream(meta);

        byte[] metadata = metadata_input.readAllBytes();

        // Checking if the computed HMAC matches with the HMAC from metadata file
        if (!validate_HMAC(metadata)) {
            throw new Exception("Metadata file has been tampered with!");
        }

        metadata_input.close();

        // Extracting the user name from metadata
        byte[] user_name_bytes = Arrays.copyOfRange(metadata, 0, 128);
        String user_name = new String(user_name_bytes).trim();

        // Printing the user name and returning it
        System.out.println(user_name);
        return user_name;

    }

    /**
     * Steps to consider...:
     * <p>
     * - get password, salt then AES key
     * <p>
     * - decrypt password hash out of encrypted secret data
     * <p>
     * - check the equality of the two password hash values
     * <p>
     * - decrypt file length out of encrypted secret data
     */
    private long convertToLong(byte[] bytes)
    {
        long value = 0l;
 
        // Iterating through for loop
        for (byte b : bytes) {
            // Shifting previous value 8 bits to right and
            // add it with next value
            value = (value << 8) + (b & 255);
        }
 
        return value;
    }

    private boolean verify_pwd(byte[] metadata, String password) throws Exception{
        // Deriving the salt from header
        byte[] salt = Arrays.copyOfRange(metadata, USER_NAME_LENGTH+PWD_LENGTH, HEADER_LENGTH);

        byte[] encrypted_secret_data = Arrays.copyOfRange(metadata, HEADER_LENGTH, METADATA_LENGTH);

        // Getting hashed password
        byte[] hashed_pwd_2 = getPasswordHash(password,salt);

        // Getting password base key
        byte[] pwd_base_key = deriveKeyFromPassword(padString(password, 128), salt);

        // Decrypting the secret data
        byte[] secret_data = decript_AES(encrypted_secret_data, pwd_base_key);

        // Getting the hashed password1 and password 2
        byte[] hashed_pwd = Arrays.copyOfRange(secret_data, 0, PWD_LENGTH);

        return Arrays.equals(hashed_pwd, hashed_pwd_2);
        
    }

    @Override
    public int length(String file_name, String password) throws Exception {

        // Reading the meta data file
        File dir = new File(file_name);
        File metadata_file = new File(dir, "0");
        FileInputStream metadata_input = new FileInputStream(metadata_file);
        byte[] metadata = metadata_input.readAllBytes();

        //Verify HMAC
        if (!validate_HMAC(metadata)) {
            throw new Exception("Metadata file has been tampered with!");
        }

        //Comparing both the hashed passwords
        if (!verify_pwd(metadata,password)){
            throw new Exception("Password Does not Match");
        }

        // Decrypting the file length
        long file_length = bytesToLong(Arrays.copyOfRange(secret_data, PWD_LENGTH, secret_data.length));
        
        System.out.println(file_length);

        return (int)file_length;

    }

    /**
     * Steps to consider...:
     * <p>
     * - verify password
     * <p>
     * - check check if requested starting position and length are valid
     * <p>
     * - decrypt content data of requested length
     */
    @Override
    public byte[] read(String file_name, int starting_position, int len, String password) throws Exception {
        File dir = new File(file_name);
        File metadata_file = new File(dir, "0");
        FileInputStream metadata_input = new FileInputStream(metadata_file);
        byte[] metadata = metadata_input.readAllBytes();
        
        //Verify HMAC
        if (!validate_HMAC(metadata)) {
            throw new Exception("Metadata file has been tampered with!");
        }

        //Comparing both the hashed passwords
        if (!verify_pwd(metadata,password)){
            throw new Exception("Password Does not Match");
        }


        
        return null;
    }

    /**
     * Steps to consider...:
     * <p>
     * - verify password
     * <p>
     * - check check if requested starting position and length are valid
     * <p>
     * - ### main procedure for update the encrypted content ###
     * <p>
     * - compute new HMAC and update metadata
     */
    @Override
    public void write(String file_name, int starting_position, byte[] content, String password) throws Exception {
        File dir = new File(file_name);
        File metadata_file = new File(dir, "0");
        FileInputStream metadata_input = new FileInputStream(metadata_file);
        byte[] metadata = metadata_input.readAllBytes();

        //Finding file length and verifing the password
        int file_length = length(file_name,password);


        if ( (starting_position < 0 || starting_position >= file_length) || (len < 0 || starting_position + len > file_length) {
            throw new IllegalArgumentException("Invalid starting position");
        }

    }

    /**
     * Steps to consider...:
     * <p>
     * - verify password
     * <p>
     * - check the equality of the computed and stored HMAC values for metadata and
     * physical file blocks
     * <p>
     */
    @Override
    public boolean check_integrity(String file_name, String password) throws Exception {
        return true;
    }

    /**
     * Steps to consider...
     * <p>
     * - verify password
     * <p>
     * - truncate the content after the specified length
     * <p>
     * - re-pad, update metadata and HMAC
     * <p>
     */
    @Override
    public void cut(String file_name, int length, String password) throws Exception {
    }

    public static void main(String[] args) {
        Editor edr = new Editor();
        EFS efs = new EFS(edr);
        try {
            efs.create("my_file2", "HelloWORLD", "macbook");
            System.out.println(efs.findUser("my_file2"));
            System.out.println(efs.length("my_file2","macbook"));
        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
        }

    }

}
