from datetime import datetime
from flask import Flask, request, render_template, redirect, url_for, session, jsonify
from flask_jwt_extended import JWTManager
from pymongo import MongoClient
from bson.objectid import ObjectId
from dotenv import load_dotenv
import os, base64, hashlib
from nacl.secret import SecretBox
from nacl.utils import random as nacl_random
from nacl.exceptions import CryptoError

# Load environment variables
load_dotenv()
app = Flask(__name__)
app.secret_key = os.getenv("JWT_SECRET")

# Setup JWT and Mongo
jwt = JWTManager(app)
client = MongoClient(os.getenv("MONGO_URI"))
db = client.voting_system
users = db.users
votes = db.votes
candidates = db.candidates

# Encryption + Hashing utilities using PyNaCl
def get_encryption_key():
    key = os.getenv("ENCRYPTION_KEY")
    if not key:
        raise ValueError("ENCRYPTION_KEY is not set in .env")
    return base64.urlsafe_b64decode(key)

def encrypt_data(plaintext: str) -> dict:
    key = get_encryption_key()
    nonce = nacl_random(24)
    box = SecretBox(key)
    encrypted = box.encrypt(plaintext.encode(), nonce)
    return {
        'nonce': base64.b64encode(nonce).decode(),
        'ciphertext': base64.b64encode(encrypted.ciphertext).decode()
    }

def decrypt_data(nonce_b64: str, ciphertext_b64: str) -> str:
    key = get_encryption_key()
    nonce = base64.b64decode(nonce_b64)
    ciphertext = base64.b64decode(ciphertext_b64)
    box = SecretBox(key)
    try:
        decrypted = box.decrypt(nonce + ciphertext)
        return decrypted.decode()
    except CryptoError:
        raise ValueError("Decryption failed")

def hash_data(data: str) -> str:
    return hashlib.sha256(data.encode()).hexdigest()

@app.route('/')
def index():
    return redirect(url_for('login_page'))

@app.route('/login', methods=['GET', 'POST'])
def login_page():
    if request.method == 'POST':
        data = request.form
        user = users.find_one({"username": data['username']})
        if user:
            try:
                decrypted_password = decrypt_data(user['password_nonce'], user['password'])
                if hash_data(data['password']) == decrypted_password:
                    session['user_id'] = str(user['_id'])
                    session['role'] = user['role']
                    if user['role'] == 'admin':
                        return redirect(url_for('admin_dashboard'))
                    return redirect(url_for('user_dashboard'))
            except Exception:
                pass
        return "Invalid credentials", 401
    return render_template("login.html")

@app.route('/admin_dashboard')
def admin_dashboard():
    all_users = list(users.find())
    vote_docs = list(votes.find())

    vote_counts = {}
    for v in vote_docs:
        try:
            cid = decrypt_data(v["nonce"], v["candidate"])
            vote_counts[cid] = vote_counts.get(cid, 0) + 1
        except Exception:
            continue

    final_results = []
    for cid, count in vote_counts.items():
        candidate = candidates.find_one({"_id": ObjectId(cid)})
        final_results.append({
            "name": candidate["name"] if candidate else "Unknown",
            "count": count
        })

    sorted_results = sorted(final_results, key=lambda x: x["count"], reverse=True)
    top_candidate = sorted_results[0]["name"] if sorted_results else "N/A"

    return render_template(
        "admin_dashboard.html",
        users=all_users,
        results=final_results,
        top_candidate=top_candidate
    )

@app.route('/admin/create_user', methods=['POST'])
def create_user():
    data = request.form
    hashed_pw = hash_data(data['password'])
    encrypted = encrypt_data(hashed_pw)
    users.insert_one({
        "username": data['username'],
        "password": encrypted['ciphertext'],
        "password_nonce": encrypted['nonce'],
        "role": "user",
        "has_voted": False
    })
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/delete_user/<user_id>')
def delete_user(user_id):
    users.delete_one({"_id": ObjectId(user_id)})
    return redirect(url_for('admin_dashboard'))

@app.route('/user')
def user_dashboard():
    if session.get('role') != 'user':
        return redirect(url_for('login_page'))
    uid = ObjectId(session['user_id'])
    user = users.find_one({"_id": uid})
    if user.get('has_voted'):
        return "You have already voted."
    all_candidates = list(candidates.find())
    return render_template("user_dashboard.html", candidates=all_candidates)

@app.route('/vote/<cid>')
def vote(cid):
    uid = ObjectId(session['user_id'])
    user = users.find_one({"_id": uid})
    if user.get('has_voted'):
        return "Already voted."

    encrypted = encrypt_data(str(cid))
    votes.insert_one({
        "user_id": uid,
        "candidate": encrypted['ciphertext'],
        "nonce": encrypted['nonce']
    })
    users.update_one({"_id": uid}, {"$set": {"has_voted": True}})
    return "Vote cast successfully."

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login_page'))

@app.route('/seed_candidates')
def seed_candidates():
    candidates.insert_many([
        {"name": "TDP"},
        {"name": "YSRCP"},
        {"name": "KAPAUL"},
        {"name":"JSP"}
    ])
    return "Candidates seeded successfully"

@app.route('/admin/users')
def user_management():
    if session.get('role') != 'admin':
        return redirect(url_for('login_page'))
    all_users = list(users.find({"role": "user"}))
    return render_template("user_management.html", users=all_users)

@app.route('/api/results-data')
def api_results_data():
    results = votes.find()
    vote_counts = {}

    for vote in results:
        try:
            decrypted_cid = decrypt_data(vote['nonce'], vote['candidate'])
            vote_counts[decrypted_cid] = vote_counts.get(decrypted_cid, 0) + 1
        except Exception:
            continue

    output = []
    for cid, count in vote_counts.items():
        candidate = candidates.find_one({"_id": ObjectId(cid)})
        output.append({
            "name": candidate["name"] if candidate else "Unknown",
            "count": count
        })
    return jsonify(output)

def seed_admin():
    if not users.find_one({"username": "admin"}):
        hashed_pw = hash_data("admin123")
        encrypted = encrypt_data(hashed_pw)
        users.insert_one({
            "username": "admin",
            "password": encrypted['ciphertext'],
            "password_nonce": encrypted['nonce'],
            "role": "admin",
            "has_voted": False
        })
        print("✅ Default admin created: username = admin, password = admin123")
    else:
        print("ℹ️ Admin already exists.")

seed_admin()

if __name__ == '__main__':
    app.run(debug=True)
