import os
import hashlib
import json
import time
import random
from flask import Flask, request, jsonify, redirect, url_for, session
from functools import wraps
from pymongo import MongoClient
import requests
from cryptography.fernet import Fernet
from threading import Thread
import logging
from werkzeug.security import generate_password_hash, check_password_hash
def load_registered_users():
    try:
        with open(REGISTERED_USERS_FILE, 'r') as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        # Initialize as empty dictionary if file is missing or corrupted
        save_registered_users({})
        return {}

def save_registered_users(users):
    with open(REGISTERED_USERS_FILE, 'w') as f:
        json.dump(users, f, indent=4)


# Flask app setup
app = Flask(__name__)
app.config['SECRET_KEY'] = "my_secret_key"
app.config['SESSION_TYPE'] = 'filesystem'

# MongoDB setup
mongo_client = MongoClient("mongodb://localhost:27017/")
mongo_db = mongo_client["productDB"]
mongo_collection = mongo_db["products"]

# IPFS setup
ipfs_api_url = "http://127.0.0.1:5002/api/v0/"
#use this for retriving from webui
#http://127.0.0.1:8080/ipfs/<CID>
# Blockchain setup
BLOCKCHAIN_FILE = 'Blockchain_data.json'
REGISTERED_USERS_FILE = 'registered_users.json'
ENCRYPTION_KEY_FILE = 'encryption_key.key'



#validation deeplearning
from tensorflow.keras.models import load_model
from tensorflow.keras.preprocessing.sequence import pad_sequences
import pickle
Tokenizer_path="C:/Users/Srijith/Desktop/miniproject/tokenizer.pkl";
with open(Tokenizer_path,'rb') as file:
    tokenizer=pickle.load(file)
# Load the model once during application startup
product_model = load_model('validation.h5')

# Validate product with the model
def validate_product_with_model(product_name):
    if not product_name:
        raise ValueError("Product name cannot be empty.")
    
    # Tokenize and preprocess the product name
    sequence = tokenizer.texts_to_sequences([product_name])
    padded_sequence = pad_sequences(sequence, maxlen=50)  # Use the same max length as training

    # Predict
    prediction = product_model.predict(padded_sequence)
    return prediction[0][0] < 0.5  # True if Real, False if Fake
# Load or generate encryption key
def load_encryption_key():
    if os.path.exists(ENCRYPTION_KEY_FILE):
        with open(ENCRYPTION_KEY_FILE, 'rb') as f:
            return f.read()
    else:
        key = Fernet.generate_key()
        with open(ENCRYPTION_KEY_FILE, 'wb') as f:
            f.write(key)
        return key

ENCRYPTION_KEY = load_encryption_key()
cipher = Fernet(ENCRYPTION_KEY)


# Logging setup
logging.basicConfig(level=logging.INFO, filename='blockchain.log', format='%(asctime)s - %(message)s')

class Blockchain:
    def __init__(self):
        self.chain = []
        self.stakeholders = {}
        self.load_chain()
        if "genesis_user" not in self.stakeholders:
            self.stakeholders["genesis_user"] = 1
            self.save_chain()

    def load_chain(self):
        blockchain_collection = mongo_db["blockchain"]
        stakeholders_collection = mongo_db["stakeholders"]

        try:
            # Load from MongoDB
            self.chain = list(blockchain_collection.find({}, {"_id": 0}).sort("index", 1))
            stakeholders = stakeholders_collection.find({}, {"_id": 0})
            self.stakeholders = {doc["user"]: doc["stake"] for doc in stakeholders}

            # Check for genesis block
            if not self.chain:
                self.create_block(proof="genesis_user", previous_hash="0")
            if "genesis_user" not in self.stakeholders:
                self.stakeholders["genesis_user"] = 1

            # Save in case of missing data
            self.save_chain()

        except Exception as e:
            print(f"Error loading from MongoDB: {e}")
            self.chain = []
            self.stakeholders = {}
            # Fallback to JSON file
            try:
                with open(BLOCKCHAIN_FILE, 'r') as f:
                    data = json.load(f)
                    self.chain = data.get('chain', [])
                    self.stakeholders = data.get('stakeholders', {})
            except (FileNotFoundError, json.JSONDecodeError):
                self.chain = []
                self.stakeholders = {}
                # Create genesis block if needed
                if not self.chain:
                    self.create_block(proof="genesis_user", previous_hash="0")
                    self.stakeholders["genesis_user"] = 1
                self.save_chain()

    def save_chain(self):
        # Save to JSON file
        with open(BLOCKCHAIN_FILE, 'w') as f:
            json.dump({"chain": self.chain, "stakeholders": self.stakeholders}, f)

        # Save to MongoDB
        self._save_to_mongo()
    
        def save_chai(self):
         with open('blockchain.json', 'w') as f:
             json.dump(self.chain, f)
        
    def _save_to_mongo(self):
        blockchain_collection = mongo_db["blockchain"]
        stakeholders_collection = mongo_db["stakeholders"]

        try:
            # Upsert blocks in the chain
            for block in self.chain:
                blockchain_collection.update_one({'index': block['index']}, {'$set': block}, upsert=True)

            # Upsert stakeholders
            for user, stake in self.stakeholders.items():
                stakeholders_collection.update_one({'user': user}, {'$set': {'user': user, 'stake': stake}}, upsert=True)

        except Exception as e:
            print(f"Error saving to MongoDB: {e}")

    def create_block(self, proof, previous_hash, metadata_hash=None, ipfs_cid=None):
        block = {
            'index': len(self.chain) + 1,
            'timestamp': time.strftime("%Y-%m-%d %H:%M:%S"),
            'proof': proof,
            'previous_hash': previous_hash,
            'ipfs_cid': ipfs_cid
        }
        self.chain.append(block)
        self.save_chain()
        return block

    def get_previous_block(self):
        return self.chain[-1] if self.chain else None

    def proof_of_stake(self, exclude_user=None):
        eligible_stakeholders = {user: stake for user, stake in self.stakeholders.items() if user != exclude_user and user != "genesis_user"}
        if eligible_stakeholders:
            total_stake = sum(eligible_stakeholders.values())
            weighted_choices = [(user, stake / total_stake) for user, stake in eligible_stakeholders.items()]
            chosen_stakeholder = random.choices([user for user, _ in weighted_choices], weights=[w for _, w in weighted_choices])[0]
            return chosen_stakeholder
        return None

    def add_stake(self, user, amount=1):
        if user in self.stakeholders:
            self.stakeholders[user] += amount
        else:
            self.stakeholders[user] = amount
        self.save_chain()

    def penalize_stakeholder(self, user):
        if user in self.stakeholders:
            self.stakeholders[user] = max(0, self.stakeholders[user] - 1)
            self.save_chain()


blockchain = Blockchain()

# IPFS utility functions
def upload_metadata_to_ipfs(metadata):
    try:
        response = requests.post(ipfs_api_url + "add", files={"file": metadata})
        response.raise_for_status()
        return response.json()["Hash"]  # Return CID
    except requests.exceptions.RequestException as e:
        logging.error(f"Failed to upload metadata to IPFS: {e}")
        raise Exception(f"Failed to upload metadata to IPFS: {e}")

def get_metadata_from_ipfs(cid):
    try:
        response = requests.post(ipfs_api_url + f"cat?arg={cid}")
        response.raise_for_status()
        return response.text
    except requests.exceptions.RequestException as e:
        logging.error(f"Failed to retrieve metadata from IPFS: {e}")
        raise Exception(f"Failed to retrieve metadata from IPFS: {e}")
# Authentication decorator
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        username = session.get('username')
        if not username or username not in load_registered_users():
            return redirect(url_for('manufacturer_login'))
        return f(username, *args, **kwargs)
    return decorated
# Load registered users
def load_registered_users():
    try:
        with open(REGISTERED_USERS_FILE, 'r') as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}

def save_registered_users(users):
    with open(REGISTERED_USERS_FILE, 'w') as f:
        json.dump(users, f)


@app.route('/')
def home():
  
    # Fetch blockchain stats
    num_blocks = len(blockchain.chain)
    num_stakeholders = len(blockchain.stakeholders)

    return f'''
   <html>
   <head>
       <style>
           body {{
               font-family: Arial, sans-serif;
               background-image:url(https://blog.williampenn.net/wp-content/uploads/2023/09/fake-sheaffer-main-banner-1-1536x864.jpeg);
               background-repeat:no-repeat;
               background-size:cover;
               background-blend-mode: overlay;
               filter: brightness(50%); 
               opacity=0.3;
               margin: 0;
               padding: 0;
               text-align: center;
           }}
           h1, h2 {{
               color: #333;
           }}
           button {{
               background: linear-gradient(90deg, #2ab2fc, #aee8f5);
           color: #fff;
               border: none;
               padding: 10px 20px;
               text-align: center;
               text-decoration: none;
               display: inline-block;
               font-size: 16px;
               margin: 10px 5px;
               cursor: pointer;
               border-radius: 5px;
               transition: background-color 0.3s ease;
           }}
           button:hover {{
               background-color: #0056b3;
           }}
           form {{
               margin: 20px auto;
               width: 300px;
               text-align: left;
           }}
           input[type="text"] {{
               width: 100%;
               padding: 8px;
               margin: 5px 0 10px;
               box-sizing: border-box;
               border: 2px solid #ccc;
               border-radius: 4px;
           }}
           input[type="submit"] {{
               background-color: #007BFF;
               color: white;
               padding: 10px 15px;
               border: none;
               border-radius: 5px;
               cursor: pointer;
               font-size: 14px;
           }}
           input[type="submit"]:hover {{
               background-color: #0056b3;
           }}
           ul {{
               list-style-type: none;
               padding: 0;
           }}
           li {{
               background: #e7f3fe;
               padding: 10px;
               margin: 5px 0;
               border-radius: 5px;
               color: #333;
           }}
           p {{
               font-size: 16px;
               color:white;
           }}
       </style>
   </head>
   <body>
       <h1> Fraud Product Detection </h1>
       <h2>Navigation</h2>
       <a href="/manufacturer_register"><button>Register Manufacturer</button></a>
       <a href="/manufacturer_login"><button>Login Manufacturer</button></a>
       <a href="/list_blocks"><button>List Blockchain</button></a>
       <a href="/verify_product"><button>Verify Product</button></a>
       <h2>Blockchain Status</h2>
       <p>Number of Blocks: <strong>{num_blocks}</strong></p>
       <p>Number of Stakeholders: <strong>{num_stakeholders}</strong></p>
       <form action="/shutdown" method="POST" style="display:inline;">
           <button type="submit">Exit</button>
       </form>
   </body>
   </html>
   '''
    

@app.route('/shutdown', methods=['POST'])
def shutdown_server():
    print("Server is shutting down...")
    os._exit(0)
logging.basicConfig(level=logging.DEBUG)    

@app.route('/manufacturer_register', methods=['GET', 'POST'])
def manufacturer_register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if not username or not password:
            return 'Missing username or password!', 400

        users = load_registered_users()
        if username in users:
            return 'Username already registered!', 400

        # Hash the password and store it
        hashed_password = generate_password_hash(password, method='sha256')
        users[username] = {'password': hashed_password, 'stake': 1}
        save_registered_users(users)
        blockchain.add_stake(username, amount=1)

        return 'Registration successful! You have been granted an initial stake.<br><a href="/">Home</a>'

    return '''
   <!DOCTYPE html>
<html>
<head>
    <style>
        body {
            font-family: Arial, sans-serif;
            background-color: #f0f8ff;
            margin: 0;
            padding: 0;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            text-align: center;
        }
        form {
            background-color: #fff;
            padding: 20px;
            border-radius: 10px;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
            width: 300px;
        }
        form input[type="text"] {
            width: 90%;
            padding: 10px;
            margin: 10px 0;
            border: 2px solid #ccc;
            border-radius: 4px;
            font-size: 14px;
        }
        form input[type="submit"] {
            background-color: #28a745;
            color: white;
            padding: 10px 15px;
            border: none;
            border-radius: 5px;
            cursor: pointer;
            font-size: 16px;
        }
        form input[type="submit"]:hover {
            background-color: #218838;
        }
        a {
            display: inline-block;
            margin-top: 20px;
            text-decoration: none;
            font-size: 16px;
            color: white;
            background-color: #007BFF;
            padding: 10px 15px;
            border-radius: 5px;
        }
        a:hover {
            background-color: #0056b3;
        }
    </style>
</head>
<body>
    <form method="POST">
        <h2>Register</h2>
        <label for="username">Username:</label><br>
        <input type="text" name="username" placeholder="Enter your username" required><br>
        <label for="password">Password:</label><br>
        <input type="password" name="password" placeholder="Enter your password" required><br>
        <input type="submit" value="Register">
    </form>
    <a href="/">Home</a>
</body>
</html>

    '''


@app.route('/manufacturer_login', methods=['GET', 'POST'])
def manufacturer_login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        users = load_registered_users()
        if username not in users:
            return 'Invalid username!', 400

        # Verify the password
        stored_password = users[username]['password']
        if not check_password_hash(stored_password, password):
            return 'Invalid password!', 400

        session['username'] = username
        return redirect(url_for('add_product'))

    return '''
    <!DOCTYPE html>
<html>
<head>
    <style>
        body {
            font-family: Arial, sans-serif;
            background-color: #f0f8ff;
            margin: 0;
            padding: 0;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            text-align: center;
        }
        form {
            background-color: #fff;
            padding: 20px;
            border-radius: 10px;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
            width: 300px;
        }
        form h1 {
            font-size: 24px;
            color: #333;
            margin-bottom: 15px;
        }
        form input[type="text"] {
            width: 90%;
            padding: 10px;
            margin: 10px 0;
            border: 2px solid #ccc;
            border-radius: 4px;
            font-size: 14px;
        }
        form input[type="submit"] {
            background-color: #28a745;
            color: white;
            padding: 10px 15px;
            border: none;
            border-radius: 5px;
            cursor: pointer;
            font-size: 16px;
        }
        form input[type="submit"]:hover {
            background-color: #218838;
        }
        a {
            display: inline-block;
            margin-top: 20px;
            text-decoration: none;
            font-size: 16px;
            color: white;
            background-color: #007BFF;
            padding: 10px 15px;
            border-radius: 5px;
        }
        a:hover {
            background-color: #0056b3;
        }
    </style>
</head>
<body>
    <form method="POST">
        <h1>Manufacturer Login</h1>
        <label for="username">Username:</label><br>
        <input type="text" name="username" placeholder="Enter your username" required><br>
        <input type="submit" value="Login">
    </form>
    <a href="/">Home</a>
</body>
</html>

    '''


@app.route('/add_product', methods=['GET', 'POST'])
@token_required
def add_product(username):
    if request.method == 'POST':
        # Get product details
        product_name = request.form.get('product_name')
        product_id = request.form.get('product_id')

        # Validate both fields
        if not product_id or not product_name:
            return 'Missing product data (both product ID and name are required)!<br><a href="/">Home</a>', 400

        try:
            # Validate product name and ID
            is_real_name = validate_product_with_model(product_name)
            is_real_id = validate_product_with_model(product_id)  # Assuming IDs can also be validated similarly

            if not is_real_name or not is_real_id:
                blockchain.penalize_stakeholder(username)
                return f"Product validation failed! The product is classified as fake.<br><a href='/'>Home</a>", 403

            # Metadata preparation and upload to IPFS
            product_metadata = json.dumps({
                "manufacturer": username,
                "product_id": product_id,
                "product_name": product_name,
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                "feedback": [],
                "reports": []
            })

            ipfs_cid = upload_metadata_to_ipfs(product_metadata)

            # Store metadata in MongoDB
            mongo_collection.insert_one({
                "manufacturer": username,
                "product_id": product_id,
                "product_name": product_name,
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                "ipfs_cid": ipfs_cid,
                "feedback":[] ,
                "report": [],
            })

            # Proof of Stake (PoS) for stakeholder selection
            chosen_stakeholder = blockchain.proof_of_stake(exclude_user=username)
            if not chosen_stakeholder:
                return 'No eligible stakeholders available for validation!<br><a href="/">Home</a>', 500

            # Add block to the blockchain
            previous_block = blockchain.get_previous_block()
            previous_hash = (
                hashlib.sha256(str(previous_block).encode()).hexdigest()
                if previous_block else "0"
            )
            blockchain.create_block(proof=chosen_stakeholder, previous_hash=previous_hash, ipfs_cid=ipfs_cid)

            # Reward the validator
            blockchain.add_stake(chosen_stakeholder, amount=1)

            return f'Product added successfully! Validated by: {chosen_stakeholder}<br>IPFS CID: {ipfs_cid}<br><a href="/">Home</a>'
        except ValueError as ve:
            return f"Validation Error: {str(ve)}<br><a href='/'>Home</a>", 400
        except Exception as e:
            return f"An unexpected error occurred: {str(e)}<br><a href='/'>Home</a>", 500

    # Render form for adding a product
    return '''
     <!DOCTYPE html>
 <html>
 <head>
     <style>
         body {
             font-family: Arial, sans-serif;
             background-color: #f0f8ff;
             margin: 0;
             padding: 0;
             display: flex;
             justify-content: center;
             align-items: center;
             height: 100vh;
             text-align: center;
         }
         form {
             background-color: #fff;
             padding: 20px;
             border-radius: 10px;
             box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
             width: 300px;
         }
         form h1 {
             font-size: 24px;
             color: #333;
             margin-bottom: 15px;
         }
         form input[type="text"] {
             width: 90%;
             padding: 10px;
             margin: 10px 0;
             border: 2px solid #ccc;
             border-radius: 4px;
             font-size: 14px;
         }
         form input[type="submit"] {
             background-color: #28a745;
             color: white;
             padding: 10px 15px;
             border: none;
             border-radius: 5px;
             cursor: pointer;
             font-size: 16px;
         }
         form input[type="submit"]:hover {
             background-color: #218838;
         }
         a {
             display: inline-block;
             margin-top: 20px;
             text-decoration: none;
             font-size: 16px;
             color: white;
             background-color: #007BFF;
             padding: 10px 15px;
             border-radius: 5px;
         }
         a:hover {
             background-color: #0056b3;
         }
     </style>
 </head>
 <body>
     <form method="POST">
         <h1>Add Product</h1>
         <form action="/add_product" method="POST">
         <label for="product_id">Product ID:</label>
         <input type="text" id="product_id" name="product_id" required><br>
         <label for="product_name">Product Name:</label>
         <input type="text" id="product_name" name="product_name" required><br>
         <button type="submit">Add Product</button>
    </form>

     <a href="/">Home</a>
 </body>
 </html>
    '''

@app.route('/verify_product', methods=['GET', 'POST'])
def verify_product():
    if request.method == 'POST':
        product_id = request.form.get('product_id')
        if not product_id:
            return 'Missing product ID!<br><a href="/">Home</a>', 400

        product = mongo_collection.find_one({"product_id": product_id})
        if not product:
            return 'Product not found<br><a href="/">Home</a>', 404

        try:
            metadata = get_metadata_from_ipfs(product["ipfs_cid"])
            metadata_dict = json.loads(metadata)
        except Exception as e:
            return f"Failed to retrieve metadata from IPFS! {str(e)}<br><a href='/'>Home</a>", 500

        # Find the block containing the product
        block_with_proof = next(
            (block for block in blockchain.chain if block.get('ipfs_cid') == product["ipfs_cid"]),
            None
        )

        if not block_with_proof:
            return 'Block containing the product was not found in the blockchain!<br><a href="/">Home</a>', 404

        # Get manufacturer and verifier details
        manufacturer = metadata_dict.get("manufacturer", "Unknown")
        verifier = block_with_proof.get('proof', 'Unknown')

        # Check if the manufacturer validated their own product
        if manufacturer == verifier:
            blockchain.penalize_stakeholder(manufacturer)
            return f"Fraud detected! Manufacturer {manufacturer} validated their own product. Their stake has been reduced.<br><a href='/'>Home</a>"

        # Fetch feedback and reports from MongoDB
        feedback_list = product.get("feedback", [])
        report_list = product.get("reports", [])

        feedback_html = "<ul>" + "".join(
            f"<li><strong>{f['user']}:</strong> {f['feedback']}</li>" for f in feedback_list
        ) + "</ul>" if feedback_list else "No feedback available."

        report_html = "<ul>" + "".join(
            f"<li><strong>{r['user']}:</strong> {r['report']}</li>" for r in report_list
        ) + "</ul>" if report_list else "No reports available."

        # Display product metadata line by line
        metadata_html = "<ul>" + "".join(
            f"<li><strong>{key}:</strong> {value}</li>" for key, value in metadata_dict.items()
        ) + "</ul>"

        # Inline CSS for styling
        style = """
        <style>
            body {
                font-family: Arial, sans-serif;
                margin: 20px;
                padding: 0;
                line-height: 1.6;
            }
            h1, h2, h3 {
                color: #333;
            }
            ul {
                list-style: none;
                padding: 0;
            }
            ul li {
                background: #f4f4f4;
                margin: 5px 0;
                padding: 10px;
                border: 1px solid #ddd;
                border-radius: 5px;
            }
            form {
                margin-top: 10px;
                margin-bottom: 20px;
            }
            form input[type="text"] {
                width: 300px;
                padding: 5px;
                margin-bottom: 10px;
                border: 1px solid #ccc;
                border-radius: 5px;
            }
            form input[type="submit"] {
                background-color: #007bff;
                color: white;
                border: none;
                padding: 8px 12px;
                cursor: pointer;
                border-radius: 5px;
            }
            form input[type="submit"]:hover {
                background-color: #0056b3;
            }
            hr {
                margin: 20px 0;
            }
            a {
                color: #007bff;
                text-decoration: none;
            }
            a:hover {
                text-decoration: underline;
            }
        </style>
        """

        return f'''
        {style}
        <h1>Product Verified!</h1><br>
        <h2>Product Data:</h2>
        {metadata_html}
        <p><strong>Verified by Stakeholder:</strong> {verifier}</p><br>
        <hr>
        <h2>Feedback</h2>
        {feedback_html}
        <hr>
        <h2>Reports</h2>
        {report_html}
        <hr>
        <h2>Leave Feedback</h2>
        <form method="POST" action="/leave_feedback">
            <input type="hidden" name="product_id" value="{product_id}">
            Feedback: <input type="text" name="feedback" required><br>
            User: <input type="text" name="user" required><br>
            <input type="submit" value="Submit Feedback">
        </form>
        <h3>Report Product</h3>
        <form method="POST" action="/report_product">
            <input type="hidden" name="product_id" value="{product_id}">
            Report: <input type="text" name="report" required><br>
            User: <input type="text" name="user" required><br>
            <input type="submit" value="Report Product">
        </form>
        <hr>
        <a href="/">Home</a>
        '''
    return '''
    <style>
        body {
            font-family: Arial, sans-serif;
            margin: 20px;
        }
        form input[type="text"], form input[type="submit"] {
            padding: 5px;
            margin: 10px 0;
        }
    </style>
    <h1>Verify Product</h1>
    <form method="POST">
      Product ID: <input type="text" name="product_id" required><br>
      <input type="submit" value="Verify Product">
    </form>
    <a href="/">Home</a>
    '''

@app.route('/list_blocks')
def list_blocks():
    return jsonify({
        "blockchain": blockchain.chain,
        "stakeholders": blockchain.stakeholders
    })
@app.route('/leave_feedback', methods=['POST'])
def leave_feedback():
    # Retrieve data from the form
    product_id = request.form.get('product_id')
    feedback = request.form.get('feedback')
    user = request.form.get('user')

    # Validate input fields
    if not product_id or not feedback or not user:
        return 'All fields (Product ID, Feedback, and User) are required!<br><a href="/">Home</a>', 400

    # Update MongoDB
    result = mongo_collection.update_one(
        {"product_id": product_id},  # Correct key for finding product by ID
        {"$push": {"feedback": {"user": user, "feedback": feedback, "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")}}}
    )

    if result.matched_count == 0:
        return 'Product not found in MongoDB!<br><a href="/">Home</a>', 404

    return 'Feedback added successfully!<br><a href="/">Home</a>'

@app.route('/report_product', methods=['POST'])
def report_product():
    # Retrieve data from the form
    product_id = request.form.get('product_id')
    report = request.form.get('report')
    user = request.form.get('user')

    # Validate input fields
    if not product_id or not report or not user:
        return 'All fields (Product ID, Report, and User) are required!<br><a href="/">Home</a>', 400

    # Update MongoDB
    result = mongo_collection.update_one(
        {"product_id": product_id},  # Correct key for finding product by ID
        {"$push": {"reports": {"user": user, "report": report, "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")}}}
    )

    if result.matched_count == 0:
        return 'Product not found in MongoDB!<br><a href="/">Home</a>', 404

    return 'Report added successfully!<br><a href="/">Home</a>'



def run_flask():
  
    app.run(host="0.0.0.0", port=1100)

flask_thread = Thread(target=run_flask)
flask_thread.start()