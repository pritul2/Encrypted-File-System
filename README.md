# Encrypted-File-System-EFS-
<p align="left"><b><i> Contributors: </b><br/>
Pritul Dave, Tweensie Jasani <br/> Computer Science - University of Texas Dallas </i><br/><br/>

In a traditional file system, files are usually stored on disks unencrypted. When the disks are stolen by
someone, contents of those files can be easily recovered by the malicious people.
Encrypted File System (EFS) is developed to prevent such leakages. In an EFS, files on disks are all
encrypted, nobody can decrypt the files without knowing the required secret. Therefore, even if a EFS disk
is stolen, or if otherwise an adversary can read the file stored on the disk, its files are kept confidential. EFS
has been implemented in a number of operating systems, such as Solaris, Windows NT, and Linux.
In this project, you are asked to implement a simulated version of EFS in Java. More specifically, you
will need to implement several library functions, which simulates the functionalities of EFS.

## a) Meta-data design

The header and the encrypted secret are the two parts of the metadata. Three fields—padded username, hashed salted password, and salt—that are concatenated together make up the header. Bytes 0-127, 128-159, and 160–175 are used to store these fields, accordingly.
Two fields—file length and hashed salted password—that are combined and padded to a multiple of 128 bytes make up the encrypted secret. Then, using a key created from the salt and the padding of the password, the encrypted secret is encrypted using the AES encryption technique.
The metadata is made up of the header and the encrypted secret. Before being written to the "0" file, the metadata is next padded with the ISO7816-4 padding method to a multiple of 1024 bytes.
The metadata is concluded with an HMAC (a cryptographic hash function) and a newline character.

## b) User authentication

When a user creates an account, the system creates a new directory specifically for that user, which is named after their username. Within this directory, the system generates a metadata file called "0". This metadata file contains important information about the user's account, including their hashed and salted password, which is encrypted using the Advanced Encryption Standard (AES) algorithm and a key derived from the user's password.
The metadata file also contains a header that includes the user's padded username, which is a version of their username with extra characters added for security purposes. Additionally, the header includes the hashed and salted password again, as well as the salt used to generate the password hash.
Overall, this process is designed to securely store the user's password and other important information, such as their username, while also providing a level of encryption to protect against unauthorized access to the account.
To authenticate the user, the system retrieves the metadata file that is associated with the user's account. The system then extracts the salt and encrypted password data from the metadata file. The salt is used to add an extra layer of security by making it harder for attackers to guess the user's password.
Next, the system derives a password key from the password entered by the user and the salt that was retrieved from the metadata file. The password key is then used to decrypt the encrypted password data from the metadata file, and the system extracts the hashed and salted password from it.
Once the hashed and salted password is obtained, the system computes the hash of the password entered by the user using the retrieved salt. The computed hash is then compared with the retrieved hashed password from the metadata file. If the two match, then the system authenticates the user and allows them to log in. If the two do not match, the system denies access to the account, indicating that the password entered by the user is incorrect.
Overall, this process helps to ensure that only authorized users are able to log in to the system and access their account, while protecting the user's password from being compromised in the event of a security breach.



## c) Encryption design

The files are encrypted using the AES symmetric-key encryption algorithm, which means that the same key is used for both encryption and decryption. The encryption process occurs before the data is written to the file.
For the Counter mode technique, a salt value is used as the initialization vector (IV) and is incremented for each block. The key used for encryption is derived from the password using a key derivation function that takes both the salt value and password into account.
Each file consists of 1024 bytes, with 912 bytes of encrypted content, a hash value of length 32 for the encrypted content, and padding. The process for updating a block involves reading the current contents of the block (if it exists) and combining it with the new content to be written. Padding is added as needed to ensure that the content is the correct length, and then the combined content is encrypted using AES encryption with the key derived from the user's password.
This approach ensures that even if an attacker gains access to the encrypted file and reads the contents of each individual block, they cannot decrypt the file without knowing the password used for the encryption. The key used for encryption is not stored anywhere and can only be derived from the password and salt value.
Additionally, the size of the actual content within each file is not revealed to attackers, as the maximum amount of actual content in the file is 912 bytes even though the file size is 1024 bytes. This makes it more difficult for attackers to guess the actual content size, thereby increasing the overall security of the file storage system.



## d) Length hiding

Instead of explicitly storing the file length within each block of the file, the length is calculated by reading the metadata stored in the first block of the file. The metadata contains the length of the entire file. By knowing this information, we can calculate the number of blocks by dividing the file length by the maximum content length of 912 bytes per block. Additionally, the content length in the last block can be calculated by subtracting the content length of all previous blocks.
By using this approach, the system saves storage space as it does not need to store the content length in each block, instead it is only stored once in the first block as metadata.
Each file within the system consists of 1024 bytes, with 912 bytes of encrypted content, a hash value of length 32 for the encrypted content, and padding. Even if an adversary knows the number of blocks used to store the content, they cannot determine the actual length of the content. This approach helps to minimize the number of physical files needed and makes it more difficult for an attacker to determine the actual size of the file.


## e) Message Authentication

The authenticity of a previously encrypted message is verified using HMAC (hash-based message authentication code) in a file storage system.
When a message is encrypted and stored on disk, it is divided into blocks. For each block, the system extracts the HMAC and data. The HMAC is the last HMAC_LENGTH bytes of the block, while the data is the first BLOCK_SIZE bytes of the block.
To verify the authenticity of the message, the system calculates the HMAC of the data using the hash_SHA256 function, which computes the SHA-256 hash of the data. If the calculated HMAC matches the extracted HMAC, the block is considered authentic. However, if any block fails this check, it indicates that the file is not authentic and may have been tampered with.
Overall, this process provides message authentication, as any tampering with the encrypted data will result in an incorrect HMAC, and the function will detect that the file is not authentic. This approach helps to ensure the integrity and security of the stored data.


## f) Efficiency

The design is based on using 1024-byte blocks to store data. However, only 912 bytes are used to store actual data. The remaining 32 bytes are used to compute the hash, and the remaining 80 bytes are used for ISO7816_4 padding. The use of HMAC, padding, and encryption algorithms adds some overheads to the storage, but the design choice to pad the metadata file to 1024 bytes increases storage efficiency.

The design uses a secure and robust hashing algorithm (SHA-256) and encryption algorithm (AES). The use of these algorithms helps to ensure the security of the stored data. Additionally, the design uses a salt to derive a new key for each block, which further improves security.

The use of block-based reading and writing improves the speed efficiency of the design. By reading and writing data in blocks, the design reduces the number of disk seeks required to access data, which in turn improves the speed efficiency of the design.

Overall, the design prioritizes security over storage and speed efficiency. The use of robust security features, such as HMAC, SHA-256, and AES, adds some overheads to the storage and computational efficiency. However, the use of block-based reading and writing improves the speed efficiency of the design, making it a good balance of security and performance.


# Simulation:
[![IMAGE ALT TEXT](https://i9.ytimg.com/vi_webp/jnXEi089bK4/mq1.webp?sqp=CPSau6AG-oaymwEmCMACELQB8quKqQMa8AEB-AH-CYACpgWKAgwIABABGGUgZShlMA8=&rs=AOn4CLAuwED7uXkJOu9ybv4Thplszz1P9w)]([https://youtu.be/jnXEi089bK4](https://www.youtube.com/watch?v=jnXEi089bK4) "Encrypted File System Simulation")
