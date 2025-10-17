#!/usr/bin/env python3
"""
Complete AI-Powered Honeypot Demo
Starts the complete system and runs attack simulation
"""

import asyncio
import subprocess
import time
import signal
import sys
import os
from datetime import datetime

def log_message(message):
    """Log message with timestamp"""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{timestamp}] {message}")

class CompleteDemoRunner:
    """Runs the complete honeypot demo"""
    
    def __init__(self):
        self.system_process = None
        self.simulator_process = None
        self.running = False
    
    def start_demo(self):
        """Start the complete demo"""
        log_message("🚀 Starting Complete AI-Powered Honeypot Demo")
        log_message("=" * 60)
        
        try:
            # Start the complete system
            self.start_complete_system()
            
            # Wait for system to initialize
            log_message("⏳ Waiting for system to initialize...")
            time.sleep(15)
            
            # Start attack simulator
            self.start_attack_simulator()
            
            self.running = True
            log_message("✅ Complete demo started successfully!")
            log_message("")
            log_message("📊 Dashboard: http://localhost:8080")
            log_message("🤖 AgentCore API: http://localhost:8000")
            log_message("🎯 Attack Simulator: Running every 5 minutes")
            log_message("")
            log_message("Press Ctrl+C to stop the demo")
            
            # Keep running
            while self.running:
                time.sleep(1)
                
        except KeyboardInterrupt:
            log_message("🛑 Demo interrupted by user")
        except Exception as e:
            log_message(f"❌ Demo failed: {e}")
        finally:
            self.stop_demo()
    
    def start_complete_system(self):
        """Start the complete system"""
        log_message("🔧 Starting complete system...")
        
        try:
            self.system_process = subprocess.Popen([
                sys.executable, "start_complete_system.py"
            ], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            
            log_message("✅ Complete system started")
            
        except Exception as e:
            log_message(f"❌ Failed to start complete system: {e}")
            raise
    
    def start_attack_simulator(self):
        """Start the attack simulator"""
        log_message("🎯 Starting attack simulator...")
        
        try:
            # Run attack simulator in continuous mode
            self.simulator_process = subprocess.Popen([
                sys.executable, "cron_attack_simulator.py", "--continuous"
            ], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            
            log_message("✅ Attack simulator started")
            
        except Exception as e:
            log_message(f"❌ Failed to start attack simulator: {e}")
            raise
    
    def stop_demo(self):
        """Stop the complete demo"""
        log_message("🛑 Stopping Complete AI-Powered Honeypot Demo...")
        
        self.running = False
        
        # Stop attack simulator
        if self.simulator_process:
            try:
                self.simulator_process.terminate()
                self.simulator_process.wait(timeout=10)
                log_message("✅ Attack simulator stopped")
            except subprocess.TimeoutExpired:
                self.simulator_process.kill()
                log_message("⚠️  Attack simulator force killed")
            except Exception as e:
                log_message(f"❌ Error stopping attack simulator: {e}")
        
        # Stop complete system
        if self.system_process:
            try:
                self.system_process.terminate()
                self.system_process.wait(timeout=15)
                log_message("✅ Complete system stopped")
            except subprocess.TimeoutExpired:
                self.system_process.kill()
                log_message("⚠️  Complete system force killed")
            except Exception as e:
                log_message(f"❌ Error stopping complete system: {e}")
        
        log_message("✅ Demo stopped")

def main():
    """Main function"""
    # Setup signal handler
    demo_runner = CompleteDemoRunner()
    
    def signal_handler(signum, frame):
        log_message(f"Received signal {signum}")
        demo_runner.stop_demo()
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # Check if required files exist
    required_files = [
        "start_complete_system.py",
        "cron_attack_simulator.py"
    ]
    
    for file in required_files:
        if not os.path.exists(file):
            log_message(f"❌ Required file not found: {file}")
            sys.exit(1)
    
    # Start demo
    demo_runner.start_demo()

if __name__ == "__main__":
    main()