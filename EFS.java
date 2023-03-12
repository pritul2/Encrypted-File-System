
/**
 * @author Pritul Manish
 * @netid PMD220000
 * @email pritul.dave@utdallas.edu
 */

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;

import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import java.security.Key;
import java.security.spec.KeySpec;
import java.util.Arrays;

public class EFS extends Utility {

    private static final int USER_NAME_LENGTH = 128;
    private static final int PWD_LENGTH = 32;
    private static final int SALT_LENGTH = 16;
    private static final int HEADER_LENGTH = USER_NAME_LENGTH + PWD_LENGTH + SALT_LENGTH;
    private static final int SECRET_DATA_LENGTH = 128;
    private static final int METADATA_LENGTH = HEADER_LENGTH+SECRET_DATA_LENGTH;
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

    /*private byte[] ISO7816_4Pad(byte[] data, int blocksize) throws Exception {
        // Create a key and initialize the cipher
        byte[] keyBytes = new byte[blocksize];
        Key key = new SecretKeySpec(keyBytes, "AES");
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key);
    
        // Pad the data using PKCS#7 padding
        byte[] paddedData = cipher.doFinal(data);
    
        return paddedData;
    }*/

    public static byte[] ISO7816_4Pad(byte[] message, int blockSize) {
        int paddingLength = blockSize - (message.length % blockSize);
        byte[] paddedMessage = new byte[message.length + paddingLength];
        System.arraycopy(message, 0, paddedMessage, 0, message.length);
        paddedMessage[message.length] = (byte) 0x80;
        for (int i = message.length + 1; i < paddedMessage.length; i++) {
            paddedMessage[i] = 0x00;
        }
        return paddedMessage;
    }
    

    /*private byte[] ISO7816_4Pad(byte[] data, int blocksize) {
        int padSize = blocksize - (data.length % blocksize);
        byte[] paddedData = new byte[data.length + padSize];
        System.arraycopy(data, 0, paddedData, 0, data.length);
        for (int i = 0; i < padSize; i++) {
            paddedData[data.length + i % padSize] = (byte) padSize;
        
        return paddedData;
    }*/

    private byte[] deriveKeyFromPassword(String password, byte[] salt) throws Exception {
        int iterations = 1000;
        int keyLength = 256;
        KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, iterations, keyLength);
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        byte[] key = factory.generateSecret(spec).getEncoded();
        return key;
    }

    private byte[] getPasswordHash(String password, byte[] salt) throws Exception {
        // Padding password salt
        String padded_password = padString(password, 128);

        byte[] passwordBytes = padded_password.getBytes();

        byte[] saltedPasswordBytes = new byte[passwordBytes.length + salt.length];

        System.arraycopy(passwordBytes, 0, saltedPasswordBytes, 0, passwordBytes.length);
        System.arraycopy(salt, 0, saltedPasswordBytes, passwordBytes.length, salt.length);

        byte[] hashed_pwd = hash_SHA256(saltedPasswordBytes);

        return hashed_pwd;
    }

    private byte[] getMetadata(String file_name) throws Exception{
        File dir = new File(file_name);
        File metadata_file = new File(dir, "0");
        FileInputStream metadata_input = new FileInputStream(metadata_file);
        byte[] metadata = metadata_input.readAllBytes();
        return metadata;
    }
    /*private byte[] round_off(byte[] written_content) {
        int len = written_content.length;
        int require_pad = len - (int) (Math.ceil(len/16))*16;
        return ISO7816_4Pad(written_content, require_pad);
    }*/

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
        System.out.println("Salt length " + salt.length);
        System.out.println("Salt  " + new String(salt));

        // Padding username
        String padded_user_name = padString(user_name, 128);

        // Making hashed password
        byte[] hashed_pwd = getPasswordHash(password, salt);
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
        System.out.println("Meta data file " + metadata_file.length());
        
        // Because metadata file not considered in storage we are placing its file size as 0
        byte[] file_length = longToBytes(0);

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
        System.out.println("Key " + new String(pwd_base_key));
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

        /*metadata_output.write(metadata);
        metadata_output.write("\n".getBytes());
        metadata_output.write(hmac);*/

        // generate the padding bytes
        byte[] combine_data = new byte[metadata.length +"\n".getBytes().length+ hmac.length];
        System.arraycopy(metadata, 0, combine_data, 0, metadata.length);
        System.arraycopy("\n".getBytes(), 0, combine_data, metadata.length, "\n".length());
        System.arraycopy(hmac, 0, combine_data, metadata.length+"\n".length(), hmac.length);


        byte[] padding = ISO7816_4Pad(combine_data, 1024);
        metadata_output.write(padding);
        metadata_output.close();

        return;
    }

    private boolean validate_HMAC(byte[] metadata, File meta) throws Exception {

        // Checking if the length of the metadata file is valid
        if (metadata.length != 1024) {
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
        if (!validate_HMAC(metadata, meta)) {
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
    private long convertToLong(byte[] bytes) {
        long value = 0l;

        // Iterating through for loop
        for (byte b : bytes) {
            // Shifting previous value 8 bits to right and
            // add it with next value
            value = (value << 8) + (b & 255);
        }

        return value;
    }

    private boolean verify_pwd(byte[] metadata, String password) throws Exception {
        // Deriving the salt from header
        byte[] salt = Arrays.copyOfRange(metadata, USER_NAME_LENGTH + PWD_LENGTH, HEADER_LENGTH);

        byte[] encrypted_secret_data = Arrays.copyOfRange(metadata, HEADER_LENGTH, METADATA_LENGTH);

        // Getting hashed password
        byte[] hashed_pwd_2 = getPasswordHash(password, salt);

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

        File dir = new File(file_name);
        File metadata_file = new File(dir, "0");

        // Reading the meta data file
        byte[] metadata = getMetadata(file_name);

        // Verify HMAC
        if (!validate_HMAC(metadata, metadata_file)) {
            throw new Exception("Metadata file has been tampered with!");
        }

        // Comparing both the hashed passwords
        if (!verify_pwd(metadata, password)) {
            throw new Exception("Password Does not Match");
        }

        byte[] salt = Arrays.copyOfRange(metadata, USER_NAME_LENGTH + PWD_LENGTH, HEADER_LENGTH);
        byte[] pwd_base_key = deriveKeyFromPassword(padString(password, 128), salt);
        byte[] encrypted_secret_data = Arrays.copyOfRange(metadata, HEADER_LENGTH, METADATA_LENGTH);
        byte[] secret_data = decript_AES(encrypted_secret_data, pwd_base_key);
        // Decrypting the file length
        long file_length = bytesToLong(Arrays.copyOfRange(secret_data, PWD_LENGTH, secret_data.length));

        System.out.println(file_length);

        return (int) file_length;

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

        File root = new File(file_name);

        int file_length = length(file_name, password);

        if (starting_position + len > file_length) {
            throw new Exception();
        }

        int start_block = starting_position / Config.BLOCK_SIZE;

        int end_block = (starting_position + len) / Config.BLOCK_SIZE;

        String toReturn = "";

        for (int i = start_block + 1; i <= end_block + 1; i++) {
            String temp = byteArray2String(read_from_file(new File(root, Integer.toString(i))));
            if (i == end_block + 1) {
                temp = temp.substring(0, starting_position + len - end_block * Config.BLOCK_SIZE);
            }
            if (i == start_block + 1) {
                temp = temp.substring(starting_position - start_block * Config.BLOCK_SIZE);
            }
            toReturn += temp;
        }


        System.out.println(toReturn);

        return toReturn.getBytes("UTF-8");
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
        String str_content = new String(content, StandardCharsets.UTF_8);
        int len = str_content.length();

        File root = new File(file_name);
        int file_length = length(file_name, password);

        if (starting_position > file_length || starting_position < 0) {
            throw new Exception("Please check starting position!");
        }

        int Block_size = 912;
        int num_blocks = (int) Math.ceil((double) content.length / Config.BLOCK_SIZE);

        int start_block = starting_position / Block_size;
        int end_block = (starting_position + len - 1) / Block_size;

        byte[] metadata = getMetadata(file_name);
        byte[] salt = Arrays.copyOfRange(metadata, USER_NAME_LENGTH + PWD_LENGTH, HEADER_LENGTH);
        StringBuilder padded_str = new StringBuilder(password);
        while (padded_str.length() < 128) {
            padded_str.append('\0');
        }
        String padded_password = padded_str.toString();

        for (int i = start_block + 1; i <= end_block + 1; i++) {
            int sp = (i - 1) * Block_size - starting_position;
            int ep = (i) * Block_size - starting_position;
            String prefix = "";
            String postfix = "";
            if (i == start_block + 1 && starting_position != start_block * Block_size) {

                prefix = new String(read_from_file(new File(root, Integer.toString(i))), StandardCharsets.UTF_8);
                prefix = prefix.substring(0, starting_position - start_block * Block_size);
                sp = Math.max(sp, 0);
            }

            if (i == end_block + 1) {
                File end = new File(root, Integer.toString(i));
                if (end.exists()) {

                    postfix = new String(read_from_file(new File(root, Integer.toString(i))), StandardCharsets.UTF_8);

                    if (postfix.length() > starting_position + len - end_block * Block_size) {
                        postfix = postfix.substring(starting_position + len - end_block * Block_size);
                    } else {
                        postfix = "";
                    }
                }
                ep = Math.min(ep, len);
            }

            String toWrite = prefix + str_content.substring(sp, ep) + postfix;
            byte[] written_content = toWrite.getBytes();
            int lastIndex = salt.length - 1;
            salt[lastIndex] += 1;

            byte[] pwd_base_key = deriveKeyFromPassword(padded_password, salt);
            //written_content = round_off(written_content);
            if(written_content.length<912){
                written_content = ISO7816_4Pad(written_content, (912));
            }
            byte[] encrypted_secret_data = encript_AES(written_content, pwd_base_key);
            byte[] computed_hmac = hash_SHA256(encrypted_secret_data);

            byte[] combined = new byte[encrypted_secret_data.length + computed_hmac.length];

            System.arraycopy(encrypted_secret_data, 0, combined, 0, encrypted_secret_data.length);
            System.arraycopy(computed_hmac, 0, combined,encrypted_secret_data.length, computed_hmac.length);

            byte[] combinedAndPadded = ISO7816_4Pad(combined, 1024);

            save_to_file(combinedAndPadded, new File(root, Integer.toString(i)));
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

    private static String getContent(){
        String content = new String("Lorem ipsum dolor sit amet, consectetur adipiscing elit. Suspendisse ut sem nunc. Nulla facilisi. Nulla facilisi. Sed non malesuada tortor. Maecenas euismod euismod ipsum, vel feugiat quam. Morbi vestibulum placerat tellus vel feugiat. Nullam eget rutrum felis. Duis sed nibh pharetra, gravida neque nec, tempor magna. Sed ac risus non mauris elementum euismod. Donec dignissim, mauris vel hendrerit pharetra, sapien tortor mattis lectus, id dapibus turpis ipsum ut nunc. Aliquam erat volutpat. Sed iaculis neque ac lacus tincidunt faucibus. Donec vel nisi quis erat tincidunt sollicitudin vel vel odio. Vestibulum euismod diam in quam varius, nec iaculis orci consequat. Sed vel blandit tellus. Etiam a dolor libero. Fusce lobortis, elit in laoreet interdum, ante ante dictum magna, sit amet luctus quam sapien at ipsum. Sed bibendum lorem non massa malesuada, non consectetur eros faucibus. Nulla facilisi. Sed fermentum feugiat sapien, at efficitur velit volutpat vel. Duis bibendum est eu arcu tincidunt, nec scelerisque erat vehicula. In sit amet massa tristique, ultrices purus vel, imperdiet quam. Donec rutrum purus vel nibh aliquet, a luctus ipsum facilisis. Nulla fringilla est odio, in tincidunt ipsum congue id. Nulla facilisi. Sed vulputate aliquam nulla, eu mollis purus semper ac. Duis quis arcu euismod, consectetur dolor id, posuere quam. Nunc vel erat lectus. Donec volutpat erat elit, eu viverra nibh fermentum eu. Praesent in leo a sapien molestie maximus. Duis non imperdiet dolor. Nam vehicula auctor purus, eget cursus arcu cursus sed. Fusce maximus lectus non magna vehicula malesuada. Suspendisse malesuada diam eget nibh porttitor, vitae blandit ante varius. Duis varius fringilla nisl, vel feugiat sapien laoreet at. Sed in velit neque. Vestibulum suscipit blandit magna, a pellentesque nisl maximus vitae. Aenean commodo risus sed risus ultricies tristique a vel nisi. Sed commodo elit sit amet dolor aliquam venenatis. Praesent at bibendum urna. Etiam vel ex sed leo finibus venenatis. Sed sed ipsum sit amet elit rutrum suscipit vel vel elit. Nulla varius blandit leo, quis bibendum ante molestie sit amet. Donec id luctus lectus. Quisque rutrum felis at mi tincidunt posuere. Donec pretium mi eu sem dignissim fringilla. Morbi gravida lorem vel mauris auctor, eget eleifend nibh efficitur. Nulla facilisi. In hac habitasse platea dictumst. Suspendisse viverra justo at felis malesuada, vel mattis leo varius. Maecenas maximus augue ac bibendum aliquet. Vivamus sit amet purus ac arcu pulvinar egestas. Integer faucibus");
        return content;
    }

    public static void main(String[] args) {
         Editor edr = new Editor();
         EFS efs = new EFS(edr);
         try {
             efs.create("my_file6", "HelloWORLD", "macbook");
             System.out.println(efs.findUser("my_file6"));
             System.out.println(efs.length("my_file6","macbook"));
             efs.write("my_file6",0,getContent().getBytes(),"macbook");
         } catch (Exception e) {
             System.err.println("Error: " + e.getMessage());
         }
 
     }

}