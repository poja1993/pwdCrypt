from cryptography.fernet import Fernet
import json
from os.path import exists
import os

class pwdCrypt():
    key_file = os.getcwd() + "/.key.key"

    def write_key(self):
        """
        Generates a key and save it into a file
        """
        key = Fernet.generate_key()
        try:
            with open(self.key_file, "wb") as key_file:
                key_file.write(key)
        except:
            print("Cannot write .key.key")
        return key

    def load_key(self):
        """
        Loads the key from the current directory named `.key.key`
        """
        return open(self.key_file, "rb").read()

    def get_and_encrypt(self, data):
        """
        Read Json then encrypt and substitute the password present in the Json file
        """
        # Create and write key into file
        key = self.write_key()
        f = Fernet(key)
        # Get data of password from json and encrypt it
        encrypted = f.encrypt(data["password"].encode())
        # Substitute the password with the encryption
        data["password"] = encrypted.decode()
        # Update the Json file with the encrypted password
        try:
            with open("config.json", "w") as file:
                file.write(json.dumps(data, indent=4))
        except IOError:
            print("cannot open file")
        # Encode password to decrypt it
        data["password"] = f.decrypt(data["password"].encode())
        return data

    def get_and_decrypt(self, data):
        """
        Read Json and then decrypt password
        """
        # Load key from file
        key = self.load_key()
        f = Fernet(key)
        # Substitute in dictionary the unencrypted password as string
        data["password"] = f.decrypt(data["password"].encode()).decode()
        return data
        
    def get_user_info(self):
        """
        Get user info from JSon file. If .key.key file doesn't exists, encrypt the field password
        """
        try:
            with open("config.json") as f:
                data = json.load(f)
        except IOError:
                print("Cannot open config.json")
                pass

        if not exists(".key.key"):
            # If no key is present, encrypt the password present in the JSon file
            data = self.get_and_encrypt(data)
        else:
            # If the key is present, then decrypt
            data = self.get_and_decrypt(data)
        return data
