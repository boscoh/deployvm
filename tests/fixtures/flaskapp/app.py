from flask import Flask, jsonify

app = Flask(__name__)


@app.get("/")
def root():
    return jsonify({"status": "ok", "version": 1, "app": "flaskapp"})
