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

# Flask app setup
app = Flask(__name__)
app.config['SECRET_KEY'] = "my_secret_key"
app.config['SESSION_TYPE'] = 'filesystem'

# MongoDB setup
mongo_client = MongoClient("mongodb://localhost:27017/")
mongo_db = mongo_client["productDB"]
mongo_collection = mongo_db["products"]

# IPFS setup
ipfs_api_url = "http://127.0.0.1:5001/api/v0/"

# Blockchain setup
BLOCKCHAIN_FILE = 'Blockchain_data.json'
REGISTERED_USERS_FILE = 'registered_users.json'
ENCRYPTION_KEY_FILE = 'encryption_key.key'

# Peer-to-peer setup
PEERS_FILE = "peers.json"
PORT = 1111
connected_peers = set()
local_node = None


#validation deeplearning
from tensorflow.keras.models import load_model
from tensorflow.keras.preprocessing.sequence import pad_sequences
import pickle
Tokenizer_path = r"C:\Users\Srijith\Downloads\tokenizer.pkl"
with open(Tokenizer_path,'rb') as file:
    tokenizer=pickle.load(file)
# Load the model once during application startup
product_model = load_model(r"C:\Users\Srijith\Downloads\validation.h5")


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
# Peer-to-peer networking
# Helper Functions
def load_peers():
    """Load peers from a file (or database)."""
    try:
        with open('peers.json', 'r') as file:
            return set(json.load(file))
    except FileNotFoundError:
        return set()

def save_peers(peers):
    """Save the connected peers to a file (or database)."""
    with open('peers.json', 'w') as file:
        json.dump(list(peers), file)
        
def broadcast_to_peers(data):
    """Broadcast data to all connected peers."""
    for peer in connected_peers:
        addr, port = peer.split(':')
        try:
            local_node.new_client(addr, int(port))  # Establish connection if not already connected
            local_node.data_spread(json.dumps(data))
        except Exception as e:
            logging.error(f"Failed to broadcast to {peer}: {e}")

@app.route('/')
def home():
    # Fetch current peers dynamically
    peers = list(connected_peers)
    peer_list_html = ''.join([f'<li>{peer}</li>' for peer in peers])

    # Fetch blockchain stats
    num_blocks = len(blockchain.chain)
    num_stakeholders = len(blockchain.stakeholders)

    return f'''
    <h1>Welcome to the Fraud Product Detection API</h1>
    <h2>Navigation</h2>
    <a href="/manufacturer_register"><button>Register Manufacturer</button></a>
    <a href="/manufacturer_login"><button>Login Manufacturer</button></a>
    <a href="/list_blocks"><button>List Blockchain</button></a>
    <a href="/verify_product"><button>Verify Product</button></a>
    <h2>Peers</h2>
    <form method="POST" action="/peer">
        Peer Address: <input type="text" name="peer" placeholder="127.0.0.1:5000" required><br>
        <input type="submit" value="Add Peer">
    </form>
    <h3>Connected Peers</h3>
    <ul>
        {peer_list_html}
    </ul>
    <a href="/list_peers"><button>View Peers</button></a>
    <a href="/update_blockchain"><button>Update Blockchain</button></a>
    <a href="/broadcast_blockchain"><button>Broadcast Blockchain</button></a>
    <h2>Blockchain Status</h2>
    <p>Number of Blocks: <strong>{num_blocks}</strong></p>
    <p>Number of Stakeholders: <strong>{num_stakeholders}</strong></p>
    <form action="/shutdown" method="POST" style="display:inline;">
        <button type="submit">Exit</button>
    </form>
    '''

@app.route('/shutdown', methods=['POST'])
def shutdown_server():
    print("Server is shutting down...")
    os._exit(0)

@app.route('/manufacturer_register', methods=['GET', 'POST'])
def manufacturer_register():
    if request.method == 'POST':
        username = request.form['username']
        if not username:
            return 'Missing username!', 400
        users = load_registered_users()
        if username in users:
            return 'Username already registered!', 400

        # Initialize user with a starting stake
        initial_stake = 1
        users[username] = {'stake': initial_stake}
        save_registered_users(users)
        blockchain.add_stake(username, amount=initial_stake)

        return 'Registration successful! You have been granted an initial stake.<br><a href="/">Home</a>'

    return '''
    <form method="POST">
        Username: <input type="text" name="username"><br>
        <input type="submit" value="Register">
    </form>
    <a href="/">Home</a>
    '''


@app.route('/manufacturer_login', methods=['GET', 'POST'])
def manufacturer_login():
    if request.method == 'POST':
        username = request.form['username']
        if username not in load_registered_users():
            return 'Invalid username!', 400
        session['username'] = username
        return redirect(url_for('add_product'))
    return '''
    <h1>Manufacturer Login</h1>
    <form method="POST">
        Username: <input type="text" name="username"><br>
        <input type="submit" value="Login">
    </form>
    <a href="/">Home</a>
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
    <h1>Add Product</h1>
    <form method="POST">
      Product ID: <input type="text" name="product_id"><br>
      Product Name: <input type="text" name="product_name"><br>
      <input type="submit" value="Add Product">
    </form>
    <a href="/">Home</a>
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
        manufacturer = json.loads(metadata).get("manufacturer", "Unknown")
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

        return f'''
        <h1>Product Verified!</h1><br>
        <p><strong>Product Data:</strong> {metadata}</p><br>
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

@app.route('/peer', methods=['POST'])
def connect_peer():
    """Connect a new peer."""
    peer = request.form.get('peer')
    if not peer:
        return jsonify({"error": "Peer address is required!"}), 400
    
    connected_peers.add(peer)
    save_peers(connected_peers)  # Assume a function that persists peer data
    logging.info(f"Peer {peer} connected successfully.")
    
    # Connect to the new peer in the P2P network
    addr, port = peer.split(':')
    local_node.new_client(addr, int(port))

    return jsonify({"message": "Peer connected successfully!", "peers": list(connected_peers)}), 200

@app.route('/list_peers', methods=['GET'])
def list_peers():
    """List all connected peers."""
    return jsonify({"peers": list(connected_peers)})

@app.route('/update_blockchain', methods=['POST'])
def update_blockchain():
    """Update the blockchain with a longer chain."""
    incoming_chain = request.json.get('chain', [])
    if len(incoming_chain) > len(blockchain.chain):
        blockchain.chain = incoming_chain
        blockchain.save_chain()  # Assume this saves the chain persistently
        logging.info("Blockchain updated successfully.")
        return jsonify({"message": "Blockchain updated successfully!"}), 200
    logging.info("No update required.")
    return jsonify({"message": "No update required!"}), 200


@app.route('/broadcast_blockchain', methods=['GET'])
def broadcast_blockchain():
    """Broadcast the blockchain to all connected peers."""
    data = {"chain": blockchain.chain}
    thread = threading.Thread(target=broadcast_to_peers, args=(data,))
    thread.start()
    logging.info("Blockchain broadcast initiated.")
    return jsonify({"message": "Blockchain broadcast initiated!"}), 200

def run_flask():
    #MAX_INCOMING = 5
    #MAX_OUTGOING = 5
    #local_node = LocalNode(MAX_INCOMING, MAX_OUTGOING)
# Start listening for incoming data in a separate thread
    #def listen_for_data():
        #while True:
            #data = local_node.local_data_queue.get()
            #if data:
                #logging.info(f"Received data: {data}")
    #threading.Thread(target=listen_for_data, daemon=True).start()*/
    # Load previously connected peers
    connected_peers = load_peers()
    app.run(host="0.0.0.0", port=1111)

flask_thread = Thread(target=run_flask)
flask_thread.start()