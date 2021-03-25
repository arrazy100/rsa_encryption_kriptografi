from flask import Blueprint, render_template, request, jsonify
from . import db
from .rsa import get_rsa_key, encrypt_with_key, decrypt_with_key

main = Blueprint("main", __name__)

@main.route("/")
def index():
    return render_template("index.html")

@main.route("/_generate_key", methods=["POST"])
def generate_key():
    if request.method == "POST":
        key_length = int(request.form.get("key_length"))
        [public_key, private_key] = get_rsa_key(key_length)
        data = {
            "public_key": public_key,
            "private_key": private_key
        }

        return jsonify(data)

@main.route("/_encryption", methods=["POST"])
def encryption():
    if request.method == "POST":
        public_key = request.form.get("public_key")
        message = request.form.get("message")
        encrypted = encrypt_with_key(message, public_key)
        data = {
            "encrypted": encrypted
        }

        return jsonify(data)

@main.route("/_decryption", methods=["POST"])
def decryption():
    if request.method == "POST":
        private_key = request.form.get("private_key")
        message = request.form.get("message")
        decrypted = decrypt_with_key(message, private_key)

        data = {
            "decrypted": decrypted
        }

        return jsonify(data)