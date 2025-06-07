# Encryption/Decryption and Hashing
This project tells the basic implementation of encryption/decryption and hashing using python.

Description:
    Task-1
          The encryption/decryption python script performs the encryption/decryption operation.It takes a string from the user and it encrypt it with a key.
it uses AES(Advance encryption standard) algorithm and it works in ECB mode.It generates a 256 bit key for encryption and decryption pupose.It takes input from the user and encrypt it with the key generated and verifies the decrypted string matches with the original string.

  Task-2
        The hashing python script performs the hashing operation.It securely hashes a password using bcrypt python libaray.It uses bcrypt algorithm.It takes a input from the user and it performs hashing operation with generated salt.Later it checks the re-entered input with the the same hash value whether the re-entered input is correct or not.
        
Library used:
   Task-1
        Crypto.Cipher (AES)
        Crypto.Random.get_random_bytes(to generate random key)
        Crypto.Util.Padding (pad, unpad)
    Task-2
        bcrypt (library)

Sample output:
    Task-1
    ![encryption_decryption](https://github.com/user-attachments/assets/f71ee8da-1455-4e18-8b26-c520adb410cb)

        
         ![encryption_decryption](https://github.com/user-attachments/assets/0b1671d4-f300-412f-afdb-749e525f1ce2)

