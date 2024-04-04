from cryptography.fernet import Fernet

'''
PasswordManager class
- This class is used to manage the passwords of a user
Attributes:
- key: The key to encrypt and decrypt the passwords
- user_collection: The user collection in the mongo database
- username: The username of the user
'''
class PasswordManager:
    def __init__(self, key, user_collection, username):
        self.key = key
        self.user_collection = user_collection
        self.username = username

    '''
    Add a password to the user password-storage
    Parameters:
    - keyword: The keyword to store the password
    - password: The password to store
    Raises:
    - Exception: If the keyword is invalid
    - Exception: If the keyword already exists
    '''
    def add_password(self, keyword, password):
        try:
            # Verify if the keyword is valid
            if not self.keyword_is_valid(keyword):
                raise Exception("The keyword is invalid, it must be between 4 and 25 characters and alphanumeric only")
            
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
            raise Exception(e)
    
    '''
    Get all the keywords of the user
    Returns:
    - A list of all the keywords
    Raises:
    - Exception: If an error occurs
    '''
    def get_all_keywords(self):
        try:
            # Get the user
            user = self.user_collection.find_one({"username": self.username})

            # Get the keywords
            keywords = user.get("password-storage").keys()

            return keywords

        except Exception as e:
            raise Exception(e)
    
    '''
    Recover a password using a keyword
    Parameters:
    - keyword: The keyword to recover the password
    Returns:
    - The decrypted password
    '''
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
            raise Exception(e)
    
    '''
    Delete a password using a keyword
    Parameters:
    - keyword: The keyword to delete the password
    Raises:
    - Exception: If the keyword does not exist
    '''
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
            raise Exception(e)
    
    '''
    Update a password using a keyword
    Parameters:
    - keyword: The keyword to update the password
    - new_password: The new password
    Raises:
    - Exception: If the keyword does not exist
    '''
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
            raise Exception(e)
    
    '''
    Verify if a keyword is valid
    Parameters:
    - keyword: The keyword to verify
    Returns:
    - True if the keyword is valid, False otherwise
    '''
    def keyword_is_valid(self, keyword):
        if len(keyword) < 4 or len(keyword) > 25 or keyword.isalnum() is False:
            return False
        return True
        
