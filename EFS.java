 import java.io.ByteArrayOutputStream;
 import java.io.File;
 import java.io.FileInputStream;
 import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
 import java.nio.charset.StandardCharsets;
 import javax.crypto.SecretKeyFactory;
 import javax.crypto.spec.PBEKeySpec;
 import java.security.spec.KeySpec;
 import java.util.Arrays;
 
 public class EFS extends Utility {
 
     private static final int USER_LENGTH = 128;
     private static final int PASSWORD_L = 32;
     private static final int LENGTH_SALT = 16;
     private static final int HEADER = USER_LENGTH + PASSWORD_L + LENGTH_SALT;
     private static final int SECRET_LENGTH = 128;
     private static final int METADATA_LENGTH = HEADER+SECRET_LENGTH;
     private static final int HMAC = 32;
     private static final int SECRET_BLOCK_SIZE = 848; 
 
     public EFS(Editor e) {
         super(e);
         set_username_password();
     }
 


     public byte[] createMetaData(byte[] header, byte[] encrypted_secret) {
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    try {
        out.write(header);
        out.write(encrypted_secret);
    } catch (IOException e) {
        e.printStackTrace();
    }
    byte[] meta_data = out.toByteArray();
    return meta_data;
}
public byte[] getSaltByteArray(byte[] metadata) {
    byte[] get_salt = Arrays.copyOfRange(metadata, USER_LENGTH + PASSWORD_L, HEADER);
    return get_salt;
}

public void combineAndSave(byte[] encrypted_secret_data, byte[] computed_hmac, File root, int Eblock) throws Exception {
    byte[] combined = new byte[encrypted_secret_data.length + computed_hmac.length];

    System.arraycopy(encrypted_secret_data, 0, combined, 0, encrypted_secret_data.length);
    System.arraycopy(computed_hmac, 0, combined, encrypted_secret_data.length, computed_hmac.length);

    byte[] combinedAndPadded = ISO_padding_algo(combined, 1024);

    save_to_file(combinedAndPadded, new File(root, Integer.toString(Eblock + 1)));
}


public byte[] readAndCopyFile(File root, int Eblock, int Block_size) throws Exception {
    byte[] encrypted_file = read_from_file(new File(root, Integer.toString(Eblock + 1)));
    byte[] encrypted_file_unpad = Arrays.copyOfRange(encrypted_file, 0, Block_size);
    return encrypted_file_unpad;
}

     private String padString(String str, int length) {
         StringBuilder padded_str = new StringBuilder(str);
         while (padded_str.length() < length) {
             padded_str.append('\0');
         }
         return padded_str.toString();
     }
 public byte[] combineData(byte[] meta_data, byte[] hmac) {
    byte[] combine_data = new byte[meta_data.length +"\n".getBytes().length+ HMAC];
    System.arraycopy(meta_data, 0, combine_data, 0, meta_data.length);
    System.arraycopy("\n".getBytes(), 0, combine_data, meta_data.length, "\n".length());
    System.arraycopy(hmac, 0, combine_data, meta_data.length+"\n".length(), HMAC);
    return combine_data;
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

     public static byte[] ISO_padding_algo(byte[] message, int blockSize) {
         int paddingLength = blockSize - (message.length % blockSize);
         byte[] paddedMessage = new byte[message.length + paddingLength];
         System.arraycopy(message, 0, paddedMessage, 0, message.length);
         paddedMessage[message.length] = (byte) 0x80;
         for (int i = message.length + 1; i < paddedMessage.length; i++) {
             paddedMessage[i] = 0x00;
         }
         return paddedMessage;
     }
     
 
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

     private void updateMetadata(int length, byte[] metadata, String file_name) throws Exception{
        //update meta data
        byte[] file_len = longToBytes(length);
        byte[] hashed_salted_password = Arrays.copyOfRange(metadata, USER_LENGTH, USER_LENGTH + PASSWORD_L);
        byte[] meta_secret_data = new byte[hashed_salted_password.length + file_len.length];
    
        int secret_data_idx = 0;
        for (byte b : hashed_salted_password) {
            meta_secret_data[secret_data_idx++] = b;
        }
        for (byte b : file_len) {
            meta_secret_data[secret_data_idx++] = b;
        }

        meta_secret_data = padToMultiple(meta_secret_data, 128);


        
        byte[] get_salt = getSaltByteArray(metadata);
        
        byte[] pwd_key = deriveKeyFromPassword(padString(password, 128), get_salt);
        byte[] encrypted_secret = encript_AES(meta_secret_data, pwd_key);

        byte[] header = Arrays.copyOfRange(metadata, 0, HEADER);

        byte[] meta_data = new byte[header.length + encrypted_secret.length];

        meta_data = createMetaData(header,encrypted_secret);

        
        byte[] hmac = hash_SHA256(meta_data);
        ByteArrayOutputStream output = new ByteArrayOutputStream();

        byte[] combine_data = combineData(meta_data,hmac);

        byte[] padding = ISO_padding_algo(combine_data, 1024);

        output.write(padding);

        byte[] outputBytes = output.toByteArray();
    
        File dir = new File(file_name);
        File metadata_file = new File(dir, "0");
        save_to_file(outputBytes, metadata_file);
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
 
 
         // Padding username
         String padded_user_name = padString(user_name, 128);
 
         // Making hashed password
         byte[] hashed_pwd = getPasswordHash(password, salt);
 
         // Adding padded username and password salt to header
         byte[] header = new byte[padded_user_name.length() + hashed_pwd.length + salt.length];
         System.arraycopy(padded_user_name.getBytes(), 0, header, 0, padded_user_name.length());
         System.arraycopy(hashed_pwd, 0, header, padded_user_name.length(), hashed_pwd.length);
         System.arraycopy(salt, 0, header, padded_user_name.length() + hashed_pwd.length, salt.length);
 
         // System.out.println("Padded user name"+ padded_user_name.length());
         // System.out.println("Salted password"+saltedPasswordBytes.length);
         // System.out.println("Hashed password"+hashed_pwd.length);
         // System.out.println("header size"+header.length);
         
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
         byte[] baseKey = deriveKeyFromPassword(padString(password, 128), salt);
         // Encrypting secret data
         byte[] encrypted_secret_data = encript_AES(secret_data, baseKey);
 
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
 
 
         byte[] padding = ISO_padding_algo(combine_data, 1024);
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
         byte[] hmac = new byte[HMAC];
         FileInputStream read_metadata = new FileInputStream(meta);
         read_metadata.read(metadata_bytes);
         read_metadata.skip(1);
         read_metadata.read(hmac);
         read_metadata.close();
 
         // Computing HMAC of metadata bytes
         byte[] computed_hmac = hash_SHA256(metadata_bytes);
 
         return Arrays.equals(hmac, computed_hmac);
 
     }
 
     
 

 
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
         return user_name;
 
     }
 

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
         byte[] salt = Arrays.copyOfRange(metadata, USER_LENGTH + PASSWORD_L, HEADER);
 
         byte[] encrypted_secret_data = Arrays.copyOfRange(metadata, HEADER, METADATA_LENGTH);
 
         // Getting hashed password
         byte[] hashed_pwd_2 = getPasswordHash(password, salt);
 
         // Getting password base key
         byte[] baseKey = deriveKeyFromPassword(padString(password, 128), salt);
 
         // Decrypting the secret data
         byte[] secret_data = decript_AES(encrypted_secret_data, baseKey);
 
         // Getting the hashed password1 and password 2
         byte[] hashed_pwd = Arrays.copyOfRange(secret_data, 0, PASSWORD_L);
 
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
 
         byte[] salt = Arrays.copyOfRange(metadata, USER_LENGTH + PASSWORD_L, HEADER);
         byte[] baseKey = deriveKeyFromPassword(padString(password, 128), salt);
         byte[] encrypted_secret_data = Arrays.copyOfRange(metadata, HEADER, METADATA_LENGTH);
         byte[] secret_data = decript_AES(encrypted_secret_data, baseKey);
         // Decrypting the file length
         long file_length = bytesToLong(Arrays.copyOfRange(secret_data, PASSWORD_L, secret_data.length));
 
         return (int) file_length;
 
     }

     @Override
     public byte[] read(String file_name, int starting_position, int len, String password) throws Exception {
         File root = new File(file_name);
 
         // Verify password
         byte[] metadata = getMetadata(file_name);
         if (!verify_pwd(metadata, password)) {
             throw new Exception("Password does not match");
         }
 
         int file_length = length(file_name, password);
         if (starting_position + len > file_length) {
             throw new Exception();
         }
         int Sblock = (starting_position) / SECRET_BLOCK_SIZE;
         int Eblock = (starting_position + len) / SECRET_BLOCK_SIZE;
     
         byte[] salt = Arrays.copyOfRange(metadata, USER_LENGTH + PASSWORD_L, HEADER);
         int last_index = salt.length-1;
         salt[last_index] += Sblock;

 
         String toReturn = "";
         for (int i = Sblock + 1; i <= Eblock + 1; i++) {
             byte[] encrypted_text=read_from_file(new File(root, Integer.toString(i)));
             salt[last_index]  += 1;
             byte[] encrypted_text_unpad = Arrays.copyOfRange(encrypted_text, 0, SECRET_BLOCK_SIZE);
             byte[] baseKey = deriveKeyFromPassword(padString(password, 128), salt);
             
             byte[] simple_text = decript_AES(encrypted_text_unpad, baseKey);
             String temp = new String(simple_text, StandardCharsets.UTF_8);
             if (i == Eblock + 1) {
                 temp = temp.substring(0, starting_position + len - Eblock * SECRET_BLOCK_SIZE);
             }
             if (i == Sblock + 1) {
                 temp = temp.substring(starting_position - Sblock * SECRET_BLOCK_SIZE); //Index out of bound
             }
             toReturn += temp;
         }
         return toReturn.getBytes();
     }
     
     public String getPostfix(File root, int i, byte[] baseKey, int Block_size, int starting_position, int len, int Eblock, int ep) throws Exception {
        String postfix = "";
        File end = new File(root, Integer.toString(i));
        if (end.exists()) {
            byte[] encrypted_postfix = read_from_file(new File(root, Integer.toString(i)));
            byte[] encrypted_postfix_unpad = Arrays.copyOfRange(encrypted_postfix, 0, Block_size);
            byte[] plain_postfix = decript_AES(encrypted_postfix_unpad, baseKey);
            postfix = new String(plain_postfix, StandardCharsets.UTF_8);
    
            if (postfix.length() > starting_position + len - Eblock * Block_size) {
                postfix = postfix.substring(starting_position + len - Eblock * Block_size);
            } else {
                postfix = "";
            }
        }
        ep = Math.min(ep, len);
        return postfix;
    }
    

     @Override
     public void write(String file_name, int starting_position, byte[] content, String password) throws Exception {
         // Verify password
         byte[] metadata = getMetadata(file_name);
         if (!verify_pwd(metadata, password)) {
             throw new Exception("Password does not match");
         }
         String str_content = new String(content, StandardCharsets.UTF_8);//byteArray2String(content);
         int len = str_content.length();
         File root = new File(file_name);
         int file_length = length(file_name, password);
 
         if (starting_position > file_length || starting_position < 0) {
             throw new Exception("Please check starting position!");
         }
 

 
         int Sblock = starting_position / SECRET_BLOCK_SIZE;
         int Eblock = (starting_position + len -1) / SECRET_BLOCK_SIZE;
 
         byte[] salt = Arrays.copyOfRange(metadata, USER_LENGTH + PASSWORD_L, HEADER);

 
         int lastIndex = salt.length - 1;
         salt[lastIndex] += Sblock;
 
         for (int i = Sblock + 1; i <= Eblock + 1; i++) {
             int sp = (i - 1) * SECRET_BLOCK_SIZE - starting_position;
             int ep = (i) * SECRET_BLOCK_SIZE - starting_position;
             String prefix = "";
             String postfix = "";
 
             salt[lastIndex] += 1;
             byte[] baseKey = deriveKeyFromPassword(padString(password, 128), salt);;
 
             if (i == Sblock + 1 && starting_position != Sblock * SECRET_BLOCK_SIZE) {
                 byte[] encrypted_prefix=read_from_file(new File(root, Integer.toString(i)));
                 byte[] encrypted_text_unpad = Arrays.copyOfRange(encrypted_prefix, 0, SECRET_BLOCK_SIZE);
                 byte[] plain_prefix = decript_AES(encrypted_text_unpad, baseKey);
                 prefix = new String(plain_prefix, StandardCharsets.UTF_8);
                 prefix = prefix.substring(0, starting_position - Sblock * SECRET_BLOCK_SIZE);
                 sp = Math.max(sp, 0);
             }
 
             if (i == Eblock + 1) {
                File end = new File(root, Integer.toString(i));
                if (end.exists()) {
                    byte[] encrypted_postfix=read_from_file(new File(root, Integer.toString(i)));
                    byte[] encrypted_postfix_unpad = Arrays.copyOfRange(encrypted_postfix, 0, SECRET_BLOCK_SIZE);
                    byte[] plain_postfix = decript_AES(encrypted_postfix_unpad, baseKey);
                    postfix = new String(plain_postfix, StandardCharsets.UTF_8);

                    if (postfix.length() > starting_position + len - Eblock * SECRET_BLOCK_SIZE) {
                        postfix = postfix.substring(starting_position + len - Eblock * SECRET_BLOCK_SIZE);
                    } else {
                        postfix = "";
                    }
                // postfix = getPostfix(root,i,baseKey,SECRET_BLOCK_SIZE,starting_position,len,Eblock,ep);
             }
             ep = Math.min(ep, len);
            } 
 
             String toWrite = prefix + str_content.substring(sp, ep) + postfix;
 
             byte[] written_content = toWrite.getBytes();
 
             
             byte[] combinedAndPadded = EncryptAndCombine(baseKey, written_content);
 
             save_to_file(combinedAndPadded, new File(root, Integer.toString(i)));
         }
 
 
         // get new content length
         if (starting_position + len > length(file_name, password)){
             updateMetadata(starting_position + len, metadata, file_name);
         }    
     }

     private byte[] EncryptAndCombine(byte[] baseKey, byte[] written_content) throws Exception{
        // written_content = round_off(written_content);
        if(written_content.length<SECRET_BLOCK_SIZE){
            written_content = ISO_padding_algo(written_content, SECRET_BLOCK_SIZE);
        }

        byte[] encrypted_secret_data = encript_AES(written_content, baseKey);
        byte[] computed_hmac = hash_SHA256(encrypted_secret_data);

        byte[] combined = new byte[encrypted_secret_data.length + computed_hmac.length];

        System.arraycopy(encrypted_secret_data, 0, combined, 0, encrypted_secret_data.length);
        System.arraycopy(computed_hmac, 0, combined, encrypted_secret_data.length, computed_hmac.length);

        return ISO_padding_algo(combined, 1024);
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
         File dir = new File(file_name);
         File meta = new File(dir, "0");
 
         // Verify password
         byte[] metadata = getMetadata(file_name);
         if (!verify_pwd(metadata, password)) {
             throw new Exception("Password does not match");
         }
 
         // Verify HMAC
         if (!validate_HMAC(metadata, meta)) {
             return false;
         }
 
         int file_length = length(file_name, password);
         int Sblock = 1;
         int Eblock = (int) (Math.ceil((float)file_length / (float)SECRET_BLOCK_SIZE));
 
         for (int i = Sblock; i <= Eblock; i++) {
             
             File temp = new File(dir, Integer.toString(i));
             FileInputStream temp_input = new FileInputStream(temp);
             byte[] tData = temp_input.readAllBytes();
 
             byte[] hmac = Arrays.copyOfRange(tData, SECRET_BLOCK_SIZE, SECRET_BLOCK_SIZE + HMAC);
             byte[] data = Arrays.copyOfRange(tData, 0, SECRET_BLOCK_SIZE);
             byte[] computed_hmac = hash_SHA256(data);
 
             if (!Arrays.equals(hmac, computed_hmac)) {
                 return false;
             }
             temp_input.close();
         }
         return true;
   }
 
     @Override
     public void cut(String file_name, int length, String password) throws Exception {
 
         // Verify password
          byte[] metadata = getMetadata(file_name);
          if (!verify_pwd(metadata, password)) {
              throw new Exception("Password does not match");
          } 
  
          byte[] salt = Arrays.copyOfRange(metadata, USER_LENGTH + PASSWORD_L, HEADER);
          int last_index = salt.length-1;
  
          File root = new File(file_name);
          int file_length = length(file_name, password);
  
          if (length > file_length) {
              throw new Exception();
          }
  
          int Block_size = SECRET_BLOCK_SIZE;

          int Eblock = (length) / Block_size;
          salt[last_index] += Eblock+1;
  
          
          byte[] unpadding_encrypted = readAndCopyFile(root, Eblock, Block_size);
          byte[] baseKey = deriveKeyFromPassword(padString(password, 128), salt);
          byte[] simple_text = decript_AES(unpadding_encrypted, baseKey);
          String str = new String(simple_text, StandardCharsets.UTF_8);
  
          str = str.substring(0, length - Eblock * Block_size);
          byte[] written_content = str.getBytes();
          
          if(written_content.length<SECRET_BLOCK_SIZE){
              written_content = ISO_padding_algo(written_content, SECRET_BLOCK_SIZE);
          }
  
          byte[] encrypted_secret_data = encript_AES(written_content, baseKey);
          byte[] computed_hmac = hash_SHA256(encrypted_secret_data);
  
          combineAndSave(encrypted_secret_data, computed_hmac, root, Eblock);
  
          int cur = Eblock + 2;
          File file = new File(root, Integer.toString(cur));
          while (file.exists()) {
              file.delete();
              cur++;
          }
  
          //update meta data
          updateMetadata(length, metadata, file_name);
      }
 

 }
