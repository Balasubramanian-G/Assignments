import bcrypt

password = input("Enter the password:")
encodedpassword = password.encode()
salt = bcrypt.gensalt()
hashedpassword = bcrypt.hashpw(encodedpassword, salt)
print("Hashed password:", hashedpassword.decode())
login = input("Re-enter your password:")
encodedlogin = login.encode()
if bcrypt.checkpw(encodedlogin,hashedpassword):
    print("Password correct")
else:
    print("pasword not correct")

