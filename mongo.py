from pymongo import MongoClient

'''
Connects to the database and returns the user collection
Returns:
- The user collection
'''
def get_user_collection():
    mongo_url = "mongodb+srv://admin:admin123@cluster0.yxtnf1z.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0"
    client = MongoClient(mongo_url)

    try:
        client.admin.command('ping')
    except Exception as e:
        raise Exception("Could not connect to the database")
    
    user_collection = client["pruebas-sw"]["user"]
    
    return user_collection