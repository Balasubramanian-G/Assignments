from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

message = input("Enter a message to send:")
print("Original Message:",message)
key = get_random_bytes(32)
encryptobject = AES.new(key,AES.MODE_ECB)
paddedmessage = pad(message.encode(),AES.block_size)
ciphertext = encryptobject.encrypt(paddedmessage)
print("encrypted Message:",ciphertext.hex())
decryptobject = AES.new(key,AES.MODE_ECB)
decryptedpadded = decryptobject.decrypt(ciphertext)
decryptedmessage = unpad(decryptedpadded,AES.block_size).decode()
print("Decrypted Message:",decryptedmessage)

if decryptedmessage==message:
    print("Decrypted message matches the original.")
else:
    print("Decrypted message not match the original.")
