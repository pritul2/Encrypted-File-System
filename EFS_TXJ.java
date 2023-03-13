
/**
 * @author Tweensi Jasani
 * @netid TXJ220003
 * @email txj220003@utdallas.edu
 */

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.nio.ByteBuffer;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.spec.KeySpec;
import java.util.Arrays;
import java.io.IOException;
import java.io.ByteArrayOutputStream;
import java.security.MessageDigest;
import java.nio.charset.StandardCharsets;

import java.security.SecureRandom;
import java.io.ByteArrayOutputStream;

public class EFS_TXJ extends Utility{

    private static final int USER_NAME_LENGTH = 128;
    private static final int PWD_LENGTH = 32;
    private static final int SALT_LENGTH = 16;
    private static final int HEADER_LENGTH = USER_NAME_LENGTH + PWD_LENGTH + SALT_LENGTH;
    private static final int SECRET_DATA_LENGTH = 128;
    private static final int METADATA_LENGTH = HEADER_LENGTH+SECRET_DATA_LENGTH;
    private static final int HMAC_LENGTH = 32;

    public EFS(Editor e)
    {
        super(e);
        set_username_password();
    }

    public static String bytesToHex(byte[] bytes) {
        StringBuilder hex = new StringBuilder();
        for (byte b : bytes) {
            hex.append(String.format("%02x", b));
        }
        return hex.toString();
    }

    public static byte[] padMultiple(byte[] data, int blockSize) {
        int padding = blockSize - (data.length % blockSize);
        byte[] paddedData = Arrays.copyOf(data, data.length + padding);
        Arrays.fill(paddedData, data.length, paddedData.length, (byte) padding);
        return paddedData;
    }

    private byte[] deriveKey(String password, byte[] salt) throws Exception {
        int iterations = 1000;
        int keyLength = 256;
        KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, iterations, keyLength);
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        byte[] key = factory.generateSecret(spec).getEncoded();
        return key;
    }

    private byte[] longToBytes(long input) {
        ByteBuffer buffer = ByteBuffer.allocate(Long.BYTES);
        buffer.putLong(input);
        return buffer.array();
    }
   
    /**
     * Steps to consider... <p>
     *  - add padded username and password salt to header <p>
     *  - add password hash and file length to secret data <p>
     *  - AES encrypt padded secret data <p>
     *  - add header and encrypted secret data to metadata <p>
     *  - compute HMAC for integrity check of metadata <p>
     *  - add metadata and HMAC to metadata file block <p>
     */
    @Override
    public void create(String file_name, String user_name, String password) throws Exception {

        try {
            if (user_name.length() > 128) {
                throw new Exception("User name exceeds length");
            }
            if (password.length() > 128) {
                throw new Exception("Password exceeds length");
            }
        } catch (Exception ex) {
            throw ex;
        }

        File dir = new File(file_name);
        dir.mkdirs();
        File meta = new File(dir, "0");
        // meta.createNewFile();
        System.out.println("start");

        StringBuilder padded_name = new StringBuilder(user_name);
        while (padded_name.length() < 128) {
            padded_name.append('\0');
        }

        String padded_username = padded_name.toString();

        StringBuilder padded_str = new StringBuilder(password);
        while (padded_str.length() < 128) {
            padded_str.append('\0');
        }
        System.out.println("line 102");

        String padded_password = padded_str.toString();

        SecureRandom random = new SecureRandom();
        byte[] salt = new byte[16];
        random.nextBytes(salt);
        System.out.println("line 109");

        byte[] passwordBytes = padded_password.getBytes();
        byte[] salted_password = new byte[passwordBytes.length + salt.length];
        System.arraycopy(passwordBytes, 0, salted_password, 0, passwordBytes.length);
        System.arraycopy(salt, 0, salted_password, passwordBytes.length, salt.length);
        byte[] hashed_salted_password = hash_SHA256(salted_password);
        System.out.println("line 116");
        
        byte[] header = ByteBuffer.allocate(padded_username.length() + hashed_salted_password.length + salt.length)
                        .put(padded_username.getBytes())
                        .put(hashed_salted_password)
                        .put(salt)
                        .array();
        System.out.println("line 123");

        byte[] file_length = longToBytes(0);
        byte[] secret_data = new byte[hashed_salted_password.length + file_length.length];
        System.out.println("line 124");

        int secret_data_idx = 0;

        for (byte b : hashed_salted_password) {
            secret_data[secret_data_idx++] = b;
        }

        for (byte b : file_length) {
            secret_data[secret_data_idx++] = b;
        }

        secret_data = padMultiple(secret_data, 128);
        System.out.println("line 137");

        byte[] pwd_key = deriveKey(padded_password, salt);
        byte[] encrypted_secret = encript_AES(secret_data, pwd_key);
        System.out.println("encrypted_secret "+ encrypted_secret);

        byte[] meta_data = new byte[header.length + encrypted_secret.length];
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        outputStream.write(header);
        outputStream.write(encrypted_secret);
        meta_data = outputStream.toByteArray();
        System.out.println("line 147");

        byte[] hmac = hash_SHA256(meta_data);
        // FileOutputStream output = new FileOutputStream(meta);
        ByteArrayOutputStream output = new ByteArrayOutputStream();

        byte[] combine_data = new byte[meta_data.length +"\n".getBytes().length+ hmac.length];
        System.arraycopy(meta_data, 0, combine_data, 0, meta_data.length);
        System.arraycopy("\n".getBytes(), 0, combine_data, meta_data.length, "\n".length());
        System.arraycopy(hmac, 0, combine_data, meta_data.length+"\n".length(), hmac.length);
        byte[] padding = ISO7816_4Pad(combine_data, 1024);
        output.write(padding);
        System.out.println("data"+ output);
        byte[] outputBytes = output.toByteArray();
        save_to_file(outputBytes, meta);

        return;
    }

    /**
     * Steps to consider... <p>
     *  - check if metadata file size is valid <p>
     *  - get username from metadata <p>
     */

    private boolean compare_HMAC(byte[] metadata, File meta) throws Exception {

        byte[] metadata_bytes = new byte[304];
        byte[] hmac = new byte[32];
        try (FileInputStream read_meta = new FileInputStream(meta)) {
            if (read_meta.read(metadata_bytes) != 304) {
                throw new IOException("file length Error");
            }
            if (read_meta.skip(1) != 1) {
                throw new IOException("Failed to skip byte");
            }
            if (read_meta.read(hmac) != 32) {
                throw new IOException("Invalid HMAC length");
            }
        }
        byte[] computed_hmac = hash_SHA256(metadata_bytes);

        return MessageDigest.isEqual(hmac, computed_hmac);

    }

    @Override
    public String findUser(String file_name) throws Exception {

        File file = new File(file_name);
        File meta = new File(file, "0");
        byte[] metadata;
        try (FileInputStream meta_input = new FileInputStream(meta)) {
            metadata = meta_input.readAllBytes();
            if (!compare_HMAC(metadata, meta)) {
                throw new SecurityException("Metadata file has been tampered!");
            }
            meta_input.close();
            byte[] username_bytes = Arrays.copyOfRange(metadata, 0, 128);
            String user_name = new String(username_bytes, StandardCharsets.UTF_8).trim();
            return user_name;
        }
        
    }

    /**
     * Steps to consider...:<p>
     *  - get password, salt then AES key <p>     
     *  - decrypt password hash out of encrypted secret data <p>
     *  - check the equality of the two password hash values <p>
     *  - decrypt file length out of encrypted secret data
     */

     private byte[] getPasswordHash(String password, byte[] salt) throws Exception {
        // Padding password salt
        StringBuilder padded_str = new StringBuilder(password);
        while (padded_str.length() < 128) {
            padded_str.append('\0');
        }
        String padded_password = padded_str.toString();

        byte[] passwordBytes = padded_password.getBytes();
        byte[] salted_password = new byte[passwordBytes.length + salt.length];
        System.arraycopy(passwordBytes, 0, salted_password, 0, passwordBytes.length);
        System.arraycopy(salt, 0, salted_password, passwordBytes.length, salt.length);
        byte[] hashed_salted_password = hash_SHA256(salted_password);

        return hashed_salted_password;
    }

    private boolean verify_password(byte[] metadata, String password) throws Exception {
        // Extracting the salt from metadata
        byte[] salt = Arrays.copyOfRange(metadata, HEADER_LENGTH - SALT_LENGTH, HEADER_LENGTH);

        // Deriving the password key using salt
        StringBuilder padded_str = new StringBuilder(password);
        while (padded_str.length() < 128) {
            padded_str.append('\0');
        }
        String padded_password = padded_str.toString();
        byte[] pwd_base_key = deriveKey(padded_password, salt);

        // Decrypting the encrypted secret data using password key
        byte[] encrypted_secret_data = Arrays.copyOfRange(metadata, HEADER_LENGTH, METADATA_LENGTH);
        byte[] secret_data = decript_AES(encrypted_secret_data, pwd_base_key);

        // Extracting the hashed password from secret data
        byte[] hashed_pwd = Arrays.copyOfRange(secret_data, 0, PWD_LENGTH);

        // Comparing hashed password with derived password hash
        byte[] hashed_pwd_2 = getPasswordHash(password, salt);
        return Arrays.equals(hashed_pwd, hashed_pwd_2);
    }

    @Override
    public int length(String file_name, String password) throws Exception {

        File dir = new File(file_name);
        File meta = new File(dir, "0");

        try (FileInputStream metadata_input = new FileInputStream(meta)) {
            byte[] metadata = metadata_input.readAllBytes();

            // Verify HMAC
            if (!compare_HMAC(metadata, meta)) {
                throw new Exception("Metadata file has been tampered!");
            }

            // Verify password
            if (!verify_password(metadata, password)) {
                throw new Exception("Password does not match");
            }

            byte[] salt = Arrays.copyOfRange(metadata, USER_NAME_LENGTH + PWD_LENGTH, HEADER_LENGTH);
            StringBuilder padded_str = new StringBuilder(password);
            while (padded_str.length() < 128) {
                padded_str.append('\0');
            }
            String padded_password = padded_str.toString();
            byte[] pwd_base_key = deriveKey(padded_password, salt);
            byte[] encrypted_secret_data = Arrays.copyOfRange(metadata, HEADER_LENGTH, METADATA_LENGTH);
            byte[] secret_data = decript_AES(encrypted_secret_data, pwd_base_key);

            // Decrypt file length
            ByteBuffer buffer = ByteBuffer.wrap(Arrays.copyOfRange(secret_data, PWD_LENGTH, secret_data.length));
            long file_length = buffer.getLong();

            System.out.println("File length: " + file_length);

            return (int) file_length;
        }    

    }

    /**
     * Steps to consider...:<p>
     *  - verify password <p>
     *  - check check if requested starting position and length are valid <p>
     *  - decrypt content data of requested length 
     */
    @Override
    public byte[] read(String file_name, int starting_position, int len, String password) throws Exception {
    	File root = new File(file_name);

        // Verify password
        byte[] metadata = getMetadata(file_name);
        if (!verify_password(metadata, password)) {
            throw new Exception("Password does not match");
        }

        int file_length = length(file_name, password);
        if (starting_position + len > file_length) {
            throw new Exception();
        }
        int Block_size = 912;
        starting_position = starting_position - 1;
        int start_block = (starting_position) / Block_size;
        int end_block = (starting_position + len) / Block_size;
    
        byte[] salt = Arrays.copyOfRange(metadata, USER_NAME_LENGTH + PWD_LENGTH, HEADER_LENGTH);
        int last_index = salt.length-1;
        salt[last_index] += start_block;

        StringBuilder padded_str = new StringBuilder(password);
        while (padded_str.length() < 128) {
            padded_str.append('\0');
        }
        String padded_password = padded_str.toString();

        String toReturn = "";
        for (int i = start_block + 1; i <= end_block + 1; i++) {
            byte[] encrypted_text=read_from_file(new File(root, Integer.toString(i)));
            salt[last_index]  += 1;
            byte[] encrypted_text_unpad = Arrays.copyOfRange(encrypted_text, 0, Block_size);

            byte[] pwd_base_key = deriveKey(padded_password, salt);
            byte[] plain_text = decript_AES(encrypted_text_unpad, pwd_base_key);
            String temp = new String(plain_text, StandardCharsets.UTF_8);
            System.out.println("temp: "+temp);
            if (i == end_block + 1) {
                temp = temp.substring(0, starting_position + len - end_block * Block_size);
            }
            if (i == start_block + 1) {
                temp = temp.substring(starting_position - start_block * Block_size); //Index out of bound
            }
            toReturn += temp;
        }
        System.out.println("Final print \n\n"+toReturn);
        return toReturn.getBytes("UTF-8");
    }

    
    /**
     * Steps to consider...:<p>
	 *	- verify password <p>
     *  - check check if requested starting position and length are valid <p>
     *  - ### main procedure for update the encrypted content ### <p>
     *  - compute new HMAC and update metadata 
     */

    private byte[] getMetadata(String file_name) throws Exception{
        File dir = new File(file_name);
        File metadata_file = new File(dir, "0");
        FileInputStream metadata_input = new FileInputStream(metadata_file);
        byte[] metadata = metadata_input.readAllBytes();
        return metadata;
    }

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


    @Override
    public void write(String file_name, int starting_position, byte[] content, String password) throws Exception {

        // Verify password
        byte[] metadata = getMetadata(file_name);
        if (!verify_password(metadata, password)) {
            throw new Exception("Password does not match");
        }
        System.out.println("pre data");
        String str_content = new String(content, StandardCharsets.UTF_8);//byteArray2String(content);
        int len = str_content.length();
        System.out.println("data "+ len);
        File root = new File(file_name);
        int file_length = length(file_name, password);

        if (starting_position > file_length || starting_position < 0) {
            throw new Exception("Please check starting position!");
        }

        int Block_size = 912;
        System.out.println(Config.BLOCK_SIZE + " and " + Block_size);
        int num_blocks = (int) Math.ceil((double) content.length / Config.BLOCK_SIZE);

        int start_block = starting_position / Block_size;
        int end_block = (starting_position + len -1) / Block_size;

        byte[] salt = Arrays.copyOfRange(metadata, USER_NAME_LENGTH + PWD_LENGTH, HEADER_LENGTH);
        StringBuilder padded_str = new StringBuilder(password);
        while (padded_str.length() < 128) {
            padded_str.append('\0');
        }
        String padded_password = padded_str.toString();
        System.out.println("line 409");

        int lastIndex = salt.length - 1;
        salt[lastIndex] += start_block;

        for (int i = start_block + 1; i <= end_block + 1; i++) {
            int sp = (i - 1) * Block_size - starting_position;
            int ep = (i) * Block_size - starting_position;
            String prefix = "";
            String postfix = "";

            salt[lastIndex] += 1;
            byte[] pwd_base_key = deriveKey(padded_password, salt);

            if (i == start_block + 1 && starting_position != start_block * Block_size) {
                byte[] encrypted_prefix=read_from_file(new File(root, Integer.toString(i)));
                byte[] plain_prefix = decript_AES(encrypted_prefix, pwd_base_key);
                prefix = new String(plain_prefix, StandardCharsets.UTF_8);
                // prefix = new String(read_from_file(new File(root, Integer.toString(i))), StandardCharsets.UTF_8);//byteArray2String(read_from_file(new File(root, Integer.toString(i))));
                prefix = prefix.substring(0, starting_position - start_block * Block_size);
                sp = Math.max(sp, 0);
                System.out.println("line 420");
            }

            if (i == end_block + 1) {
                File end = new File(root, Integer.toString(i));
                if (end.exists()) {
                    byte[] encrypted_postfix=read_from_file(new File(root, Integer.toString(i)));
                    byte[] plain_postfix = decript_AES(encrypted_postfix, pwd_base_key);
                    postfix = new String(plain_postfix, StandardCharsets.UTF_8);
                    //postfix = new String(read_from_file(new File(root, Integer.toString(i))), StandardCharsets.UTF_8);//byteArray2String(read_from_file(new File(root, Integer.toString(i))));

                    if (postfix.length() > starting_position + len - end_block * Block_size) {
                        postfix = postfix.substring(starting_position + len - end_block * Block_size);
                    } else {
                        postfix = "";
                    }
                    System.out.println("line 435");
                }
                ep = Math.min(ep, len);
            }

            String toWrite = prefix + str_content.substring(sp, ep) + postfix;
            System.out.println("str_content "+ str_content);
            System.out.println("towrite "+toWrite);
            byte[] written_content = toWrite.getBytes();
            System.out.println("written_content "+written_content.length);

            System.out.println("line 443");
            
            // written_content = round_off(written_content);
            if(written_content.length<912){
                written_content = ISO7816_4Pad(written_content, 912);
            }
            System.out.println("pwd_base_key "+pwd_base_key);
            System.out.println("written_content "+written_content);

            byte[] encrypted_secret_data = encript_AES(written_content, pwd_base_key);
            System.out.println("encrypted_secret_data "+encrypted_secret_data.length);
            byte[] computed_hmac = hash_SHA256(encrypted_secret_data);
            System.out.println("computed_hmac "+computed_hmac.length);
            System.out.println("line 452");

            byte[] combined = new byte[encrypted_secret_data.length + computed_hmac.length];
            System.out.println("combined "+combined.length);

            System.arraycopy(encrypted_secret_data, 0, combined, 0, encrypted_secret_data.length);
            System.arraycopy(computed_hmac, 0, combined, encrypted_secret_data.length, computed_hmac.length);

            byte[] combinedAndPadded = ISO7816_4Pad(combined, 1024);
            System.out.println("line 460");

            // byte[] combinedAndPadded = new byte[combined.length + padded.length];
            // System.arraycopy(combined, 0, combinedAndPadded, 0, combined.length);
            // System.arraycopy(padded, 0, combinedAndPadded, combined.length, padded.length);
            System.out.println("length of file "+ combinedAndPadded.length);

            save_to_file(combinedAndPadded, new File(root, Integer.toString(i)));
        }


        //update meta data
        System.out.println("editing metadata");

        // get new content length
        if (starting_position + len > length(file_name, password)){
            byte[] file_len = longToBytes(starting_position + len);
            System.out.println("file_len "+ file_len);
            byte[] hashed_salted_password = Arrays.copyOfRange(metadata, USER_NAME_LENGTH, USER_NAME_LENGTH + PWD_LENGTH);
            byte[] meta_secret_data = new byte[hashed_salted_password.length + file_len.length];
        
            int secret_data_idx = 0;
            for (byte b : hashed_salted_password) {
                meta_secret_data[secret_data_idx++] = b;
            }
            for (byte b : file_len) {
                meta_secret_data[secret_data_idx++] = b;
            }

            meta_secret_data = padMultiple(meta_secret_data, 128);

            byte[] get_salt = Arrays.copyOfRange(metadata, USER_NAME_LENGTH + PWD_LENGTH, HEADER_LENGTH);
            byte[] pwd_key = deriveKey(padded_password, get_salt);
            byte[] encrypted_secret = encript_AES(meta_secret_data, pwd_key);

            byte[] header = Arrays.copyOfRange(metadata, 0, HEADER_LENGTH);

            byte[] meta_data = new byte[header.length + encrypted_secret.length];
            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            outputStream.write(header);
            outputStream.write(encrypted_secret);
            meta_data = outputStream.toByteArray();
            System.out.println("line 147");

            byte[] hmac = hash_SHA256(meta_data);
            ByteArrayOutputStream output = new ByteArrayOutputStream();

            byte[] combine_data = new byte[meta_data.length +"\n".getBytes().length+ HMAC_LENGTH];
            System.arraycopy(meta_data, 0, combine_data, 0, meta_data.length);
            System.arraycopy("\n".getBytes(), 0, combine_data, meta_data.length, "\n".length());
            System.arraycopy(hmac, 0, combine_data, meta_data.length+"\n".length(), HMAC_LENGTH);
            byte[] padding = ISO7816_4Pad(combine_data, 1024);
            output.write(padding);
            System.out.println("data"+ output);
            byte[] outputBytes = output.toByteArray();
        
            File dir = new File(file_name);
            File metadata_file = new File(dir, "0");
            save_to_file(outputBytes, metadata_file);
            System.out.println("finish");
        }    

    }

    /**
     * Steps to consider...:<p>
  	 *  - verify password <p>
     *  - check the equality of the computed and stored HMAC values for metadata and physical file blocks<p>
     */
    @Override
    public boolean check_integrity(String file_name, String password) throws Exception {
        
        System.out.println("start");
        File dir = new File(file_name);
        File meta = new File(dir, "0");

        // Verify password
        byte[] metadata = getMetadata(file_name);
        if (!verify_password(metadata, password)) {
            throw new Exception("Password does not match");
        }
        System.out.println("password_verified");

        // Verify HMAC
        if (!compare_HMAC(metadata, meta)) {
            return false;
        }
        System.out.println("metadata verified");

        int Block_size = 912;
        int file_length = length(file_name, password);
        int start_block = 1;
        int end_block = (int) (Math.ceil((float)file_length / (float)Block_size));
        System.out.println("blocks calculated " + end_block);

        for (int i = start_block; i <= end_block; i++) {
            
            File temp = new File(dir, Integer.toString(i));
            FileInputStream temp_input = new FileInputStream(temp);
            byte[] tempdata = temp_input.readAllBytes();
            System.out.println("tempdata");

            byte[] hmac = Arrays.copyOfRange(tempdata, Block_size, Block_size + HMAC_LENGTH);
            System.out.println("hmac got");
            byte[] data = Arrays.copyOfRange(tempdata, 0, Block_size);
            System.out.println("data got");
            byte[] computed_hmac = hash_SHA256(data);
            System.out.println("hmac done");

            if (!Arrays.equals(hmac, computed_hmac)) {
                return false;
            }
            System.out.println("condition verified");
            temp_input.close();
        }
        System.out.println("end");
    	return true;
  }

    /**
     * Steps to consider... <p>
     *  - verify password <p>
     *  - truncate the content after the specified length <p>
     *  - re-pad, update metadata and HMAC <p>
     */
    @Override
    public void cut(String file_name, int length, String password) throws Exception {

       // Verify password
        byte[] metadata = getMetadata(file_name);
        if (!verify_password(metadata, password)) {
            throw new Exception("Password does not match");
        } 

    }
    private static String getContent(){
        //String content = new String("Lorem ipsum dolor sit amet, consectetur adipiscing elit. Suspendisse ut sem nunc. Nulla facilisi. Nulla facilisi. Sed non malesuada tortor. Maecenas euismod euismod ipsum, vel feugiat quam. Morbi vestibulum placerat tellus vel feugiat. Nullam eget rutrum felis. Duis sed nibh pharetra, gravida neque nec, tempor magna. Sed ac risus non mauris elementum euismod. Donec dignissim, mauris vel hendrerit pharetra, sapien tortor mattis lectus, id dapibus turpis ipsum ut nunc. Aliquam erat volutpat. Sed iaculis neque ac lacus tincidunt faucibus. Donec vel nisi quis erat tincidunt sollicitudin vel vel odio. Vestibulum euismod diam in quam varius, nec iaculis orci consequat. Sed vel blandit tellus. Etiam a dolor libero. Fusce lobortis, elit in laoreet interdum, ante ante dictum magna, sit amet luctus quam sapien at ipsum. Sed bibendum lorem non massa malesuada, non consectetur eros faucibus. Nulla facilisi. Sed fermentum feugiat sapien, at efficitur velit volutpat vel. Duis bibendum est eu arcu tincidunt, nec scelerisque erat vehicula. In sit amet massa tristique, ultrices purus vel, imperdiet quam. Donec rutrum purus vel nibh aliquet, a luctus ipsum facilisis. Nulla fringilla est odio, in tincidunt ipsum congue id. Nulla facilisi. Sed vulputate aliquam nulla, eu mollis purus semper ac. Duis quis arcu euismod, consectetur dolor id, posuere quam. Nunc vel erat lectus. Donec volutpat erat elit, eu viverra nibh fermentum eu. Praesent in leo a sapien molestie maximus. Duis non imperdiet dolor. Nam vehicula auctor purus, eget cursus arcu cursus sed. Fusce maximus lectus non magna vehicula malesuada. Suspendisse malesuada diam eget nibh porttitor, vitae blandit ante varius. Duis varius fringilla nisl, vel feugiat sapien laoreet at. Sed in velit neque. Vestibulum suscipit blandit magna, a pellentesque nisl maximus vitae. Aenean commodo risus sed risus ultricies tristique a vel nisi. Sed commodo elit sit amet dolor aliquam venenatis. Praesent at bibendum urna. Etiam vel ex sed leo finibus venenatis. Sed sed ipsum sit amet elit rutrum suscipit vel vel elit. Nulla varius blandit leo, quis bibendum ante molestie sit amet. Donec id luctus lectus. Quisque rutrum felis at mi tincidunt posuere. Donec pretium mi eu sem dignissim fringilla. Morbi gravida lorem vel mauris auctor, eget eleifend nibh efficitur. Nulla facilisi. In hac habitasse platea dictumst. Suspendisse viverra justo at felis malesuada, vel mattis leo varius. Maecenas maximus augue ac bibendum aliquet. Vivamus sit amet purus ac arcu pulvinar egestas. Integer faucibus");
        String content = new String("With IT, the world has become much smaller to the hands. You can get quick and easy access to information from all over the world and even share, see or chat with people miles away. Business transactions, space exploration, watching movies, and buying digital books has become much easier than before all through a click of the computer. In this manner, information technology is revolutionizing the world with its greatest advantage. It makes the process of information sharing much easy, fast, cheap, and enjoyable. In a nutshell, IT has made the world a better place with reduced workload and advanced comfort.With IT, the world has become much smaller to the hands. You can get quick and easy access to information from all over the world and even share, see or chat with people miles away. Business transactions, space exploration, watching movies, and buying digital books has become much easier than before all through a click of the computer. In this manner, information technology is revolutionizing the world with its greatest advantage. It makes the process of information sharing much easy, fast, cheap, and enjoyable. In a nutshell, IT has made the world a better place with reduced workload and advanced comfort.");
        return content;
    }

    public static void main(String[] args) {
         Editor edr = new Editor();
         EFS efs = new EFS(edr);
         try {
             //efs.create("my_file9", "HelloWORLD", "macbook");
             //System.out.println(efs.findUser("my_file9"));
             //System.out.println(efs.length("my_file9","macbook"));
             //efs.write("my_file9",0,getContent().getBytes(),"macbook");
             //efs.write("my_file9",900,"Hello world".getBytes(),"macbook");
             efs.read("my_file9",900,50,"macbook");
             System.out.println(efs.check_integrity("my_file9","macbook"));
         } catch (Exception e) {
             System.err.println("Error: " + e.getMessage());
         }
 
     }
  
}
