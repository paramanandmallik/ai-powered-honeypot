#!/usr/bin/env python3
"""
Simple Mock AgentCore for Testing Validation
"""

from flask import Flask, jsonify
import threading
import time

app = Flask(__name__)

@app.route('/health')
def health():
    return jsonify({
        'status': 'healthy',
        'service': 'mock-agentcore',
        'timestamp': time.time()
    })

@app.route('/agents')
def agents():
    return jsonify({
        'agents': [
            {'id': 'detection-agent', 'status': 'running', 'port': 8001},
            {'id': 'coordinator-agent', 'status': 'running', 'port': 8002},
            {'id': 'interaction-agent', 'status': 'running', 'port': 8003},
            {'id': 'intelligence-agent', 'status': 'running', 'port': 8004}
        ],
        'count': 4
    })

@app.route('/messages/publish', methods=['POST'])
def publish_message():
    return jsonify({
        'success': True,
        'message_id': f'msg-{int(time.time())}'
    })

@app.route('/sessions/create', methods=['POST'])
def create_session():
    return jsonify({
        'success': True,
        'session_id': 'test-session'
    })

@app.route('/sessions/<session_id>')
def get_session(session_id):
    return jsonify({
        'session_id': session_id,
        'status': 'active'
    })

# Mock agent services
def create_agent_app(agent_name, port):
    agent_app = Flask(f'mock-{agent_name}')
    
    @agent_app.route('/health')
    def agent_health():
        return jsonify({
            'status': 'healthy',
            'service': agent_name,
            'port': port
        })
    
    return agent_app

def run_agent(agent_name, port):
    agent_app = create_agent_app(agent_name, port)
    agent_app.run(host='0.0.0.0', port=port, debug=False)

if __name__ == '__main__':
    # Start mock agents in separate threads
    agents = [
        ('detection-agent', 8001),
        ('coordinator-agent', 8002),
        ('interaction-agent', 8003),
        ('intelligence-agent', 8004)
    ]
    
    threads = []
    for agent_name, port in agents:
        thread = threading.Thread(target=run_agent, args=(agent_name, port))
        thread.daemon = True
        thread.start()
        threads.append(thread)
        print(f"Started {agent_name} on port {port}")
    
    print("Starting mock AgentCore on port 8000")
    app.run(host='0.0.0.0', port=8000, debug=False)