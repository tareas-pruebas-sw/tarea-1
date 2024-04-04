from cryptography.fernet import Fernet

class PasswordManager:
    def __init__(self, key, user_collection, username):
        self.key = key
        self.user_collection = user_collection
        self.username = username

    def add_password(self, keyword, password):
        try:
            # Verify if the keyword already exists
            user = self.user_collection.find_one({"username": self.username})
            if user.get("password-storage").get(keyword):
                raise Exception("The keyword already exists")  
            
            # Encrypt the password
            fernet = Fernet(self.key)
            encrypted_password = fernet.encrypt(password.encode())

            # Add the password to the user password-storage
            self.user_collection.update_one({"username": self.username}, {"$set": {f"password-storage.{keyword}": encrypted_password}})
        
        except Exception as e:
            print(e)
            
    def recover_password(self, keyword):
        try:
            # Get the user
            user = self.user_collection.find_one({"username": self.username})

            # Get the encrypted password
            encrypted_password = user.get("password-storage").get(keyword)
            # Verify if the keyword exists
            if not encrypted_password:
                raise Exception("The keyword does not exist")

            # Decrypt the password
            fernet = Fernet(self.key)
            decrypted_password = fernet.decrypt(encrypted_password).decode()

            return decrypted_password
            
        except Exception as e:
            print(e)
            return None
        
    def delete_password(self, keyword):
        try:
            # Get the user
            user = self.user_collection.find_one({"username": self.username})

            # Get the encrypted password
            encrypted_password = user.get("password-storage").get(keyword)
            # Verify if the keyword exists
            if not encrypted_password:
                raise Exception("The keyword does not exist")

            # Delete the password
            self.user_collection.update_one({"username": self.username}, {"$unset": {f"password-storage.{keyword}": ""}})
            
        except Exception as e:
            print(e)
    
    def update_password(self, keyword, new_password):
        try:
            # Get the user
            user = self.user_collection.find_one({"username": self.username})

            # Get the encrypted password
            encrypted_password = user.get("password-storage").get(keyword)
            # Verify if the keyword exists
            if not encrypted_password:
                raise Exception("The keyword does not exist")

            # Encrypt the new password
            fernet = Fernet(self.key)
            encrypted_new_password = fernet.encrypt(new_password.encode())

            # Update the password
            self.user_collection.update_one({"username": self.username}, {"$set": {f"password-storage.{keyword}": encrypted_new_password}})
        
        except Exception as e:
            print(e)