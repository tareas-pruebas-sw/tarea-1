from pymongo import MongoClient

mongo_url = "mongodb+srv://admin:admin123@cluster0.yxtnf1z.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0"
client = MongoClient(mongo_url)
try:
    client.admin.command('ping')
    print("Pinged your deployment. You successfully connected to MongoDB!")
except Exception as e:
    print(e)
    
user_collection = client["pruebas-sw"]["user"]