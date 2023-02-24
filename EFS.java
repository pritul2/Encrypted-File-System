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
 import java.nio.file.Files;
 
 import javax.crypto.SecretKeyFactory;
 import javax.crypto.spec.PBEKeySpec;
 import java.security.spec.KeySpec;
 import java.util.Arrays;
 
 public class EFS extends Utility{
 
     private static final int HMAC_SIZE = 128;
 
     public EFS(Editor e)
     {
         super(e);
         set_username_password();
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
 
     private String padString(String str, int length) {
         StringBuilder padded_str = new StringBuilder(str);
         while (padded_str.length() < length) {
             padded_str.append('\0');
         }
         return padded_str.toString();
     }
     private byte[] longToBytes(long input){
         ByteBuffer bf = ByteBuffer.allocate(Long.BYTES);
         bf.putLong(input);
         return bf.array();
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
     private byte[] deriveKeyFromPassword(String password, byte[] salt) throws Exception{
         int iterations = 1000;
         int keyLength = 256;
         KeySpec spec = new PBEKeySpec(password.toCharArray(),salt,iterations,keyLength);
         SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
         byte[] key = factory.generateSecret(spec).getEncoded();
         return key;
     }
 
     @Override
     public void create(String file_name, String user_name, String password) throws Exception {
 
         if (user_name.length() > 128 || password.length() > 128) {
             throw new IllegalArgumentException("User name and password must be at most 128 bytes");
         }
 
         // Creating a new director with name same as file name
         File dir = new File(file_name);
         dir.mkdirs();
         File metadata_file = new File(dir,"0");
         metadata_file.createNewFile();
 
         // Generating a random 16B salt to add to password
         byte[] salt = secureRandomNumber(16);
 
         // Padding username and password salt
         String padded_user_name = padString(user_name, 128);
         String padded_password = padString(password, 128);
         byte[] passwordBytes = padded_password.getBytes();
         byte[] saltedPasswordBytes = new byte[passwordBytes.length + salt.length];
         System.arraycopy(passwordBytes, 0, saltedPasswordBytes, 0, passwordBytes.length);
         System.arraycopy(salt, 0, saltedPasswordBytes, passwordBytes.length, salt.length);
         byte[] hashed_pwd = hash_SHA256(saltedPasswordBytes);
         System.out.println(hashed_pwd);
         
         // Adding padded username and password salt to header
         byte[] header = (padded_user_name + hashed_pwd).getBytes(StandardCharsets.US_ASCII);
 
         byte[] file_length = longToBytes(metadata_file.length());
 
         // Creating secret data array of length pwd_hash + file_length
         byte[] secret_data = new byte[hashed_pwd.length + file_length.length];
 
         // Adding password hash and File length to secret data
         System.arraycopy(hashed_pwd, 0, secret_data, 0, hashed_pwd.length);
         System.arraycopy(file_length, 0, secret_data, hashed_pwd.length, file_length.length);
         
         // Padding the secret data
         secret_data = padToMultiple(secret_data, 128);
 
         // Generating key on the basis of password
         byte [] pwd_base_key = deriveKeyFromPassword(padded_password,salt);
 
         // Encrypting secret data
         byte[] encrypted_secret_data = encript_AES(secret_data,pwd_base_key);
 
         // Adding header and encrypted secret data to metadata
         byte[] metadata = new byte[header.length+encrypted_secret_data.length];
         System.arraycopy(header, 0, metadata, 0, header.length);
         System.arraycopy(encrypted_secret_data, 0, metadata, header.length, encrypted_secret_data.length);
 
         // Computing HMAC on metadata
         byte[] hmac = hash_SHA256(metadata);
 
         // Writing metadata and HMAC to file
         FileOutputStream metadata_output = new FileOutputStream(metadata_file);
 
         metadata_output.write(metadata);
         metadata_output.write(hmac);
 
         metadata_output.close();
 
         return;
     }
 
     /**
      * Steps to consider... <p>
      *  - check if metadata file size is valid <p>
      *  - get username from metadata <p>
      */
     @Override
     public String findUser(String file_name) throws Exception {
         /**byte[] metadata = Files.readAllBytes(file_name+"/0");
         byte[] hmac = Arrays.copyOfRange(metadata, metadata.length - HMAC_SIZE, metadata.length);
 
         FileInputStream metadata_input = new FileInputStream(file_name + "0");
         long metadata_size = metadata_input.getChannel().size();
 
         // check if metadata file size is valid
         if (metadata_size <= HMAC_SIZE) {
             throw new IllegalArgumentException("Invalid metadata file size");
         }**/
 
         return null;
     }
 
     /**
      * Steps to consider...:<p>
      *  - get password, salt then AES key <p>     
      *  - decrypt password hash out of encrypted secret data <p>
      *  - check the equality of the two password hash values <p>
      *  - decrypt file length out of encrypted secret data
      */
     @Override
     public int length(String file_name, String password) throws Exception {
         return 0;
     }
 
     /**
      * Steps to consider...:<p>
      *  - verify password <p>
      *  - check check if requested starting position and length are valid <p>
      *  - decrypt content data of requested length 
      */
     @Override
     public byte[] read(String file_name, int starting_position, int len, String password) throws Exception {
         return null;
     }
 
     
     /**
      * Steps to consider...:<p>
      *	- verify password <p>
      *  - check check if requested starting position and length are valid <p>
      *  - ### main procedure for update the encrypted content ### <p>
      *  - compute new HMAC and update metadata 
      */
     @Override
     public void write(String file_name, int starting_position, byte[] content, String password) throws Exception {
     }
 
     /**
      * Steps to consider...:<p>
        *  - verify password <p>
      *  - check the equality of the computed and stored HMAC values for metadata and physical file blocks<p>
      */
     @Override
     public boolean check_integrity(String file_name, String password) throws Exception {
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
     }
 
     public static void main(String [] args){
         Editor edr = new Editor();
         EFS efs = new EFS(edr);
         try{
         efs.create("my_file2","pritul","macbook");
         }
         catch(Exception e){
             System.err.println("Error: " + e.getMessage());
         }
 
         
     }
   
 }
 