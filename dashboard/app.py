#!/usr/bin/env python3
"""
Simple dashboard for AI Honeypot AgentCore
"""

from flask import Flask, render_template, jsonify
import os

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/health')
def health():
    return jsonify({
        'status': 'healthy',
        'message': 'Dashboard is running'
    })

@app.route('/api/status')
def status():
    return jsonify({
        'agents': {
            'detection': 'running',
            'coordinator': 'running',
            'interaction': 'running',
            'intelligence': 'running'
        },
        'honeypots': {
            'ssh': 'active',
            'web_admin': 'active',
            'database': 'active'
        }
    })

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8090, debug=True)