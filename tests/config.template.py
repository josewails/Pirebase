SIMPLE_CONFIG = {
    "apiKey": "AIzaSyBfGClE3cLOfs0c0rmGnYvZerwIky9rVgg",
    "authDomain": "pirebase-test.firebaseapp.com",
    "databaseURL": "https://pirebase-test.firebaseio.com",
    "storageBucket": "pirebase-test.appspot.com",
}

SERVICE_ACCOUNT_PATH = "../secret.json"

SERVICE_CONFIG = dict(SIMPLE_CONFIG, serviceAccount=SERVICE_ACCOUNT_PATH)
