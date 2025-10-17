#!/usr/bin/env python3
"""
Test Agent Packages Script
Tests that the packaged agents can be loaded and initialized correctly.
"""

import os
import sys
import json
import zipfile
import tempfile
import logging
from pathlib import Path
from typing import Dict, Any

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class AgentPackageTester:
    """Tests agent packages for correctness"""
    
    def __init__(self, workspace_root: str):
        self.workspace_root = Path(workspace_root)
        self.build_dir = self.workspace_root / "build" / "agentcore"
        
        self.agents_to_test = ["detection", "coordinator", "interaction", "intelligence"]
        
        logger.info(f"Agent Package Tester initialized")
    
    def test_all_packages(self) -> Dict[str, Any]:
        """Test all agent packages"""
        try:
            logger.info("Testing all agent packages...")
            
            test_results = {
                "test_id": f"test-{int(__import__('time').time())}",
                "timestamp": __import__('datetime').datetime.utcnow().isoformat(),
                "agents": {},
                "overall_status": "in_progress"
            }
            
            successful_tests = 0
            for agent_type in self.agents_to_test:
                try:
                    logger.info(f"Testing {agent_type} agent package...")
                    result = self.test_agent_package(agent_type)
                    test_results["agents"][agent_type] = result
                    
                    if result["status"] == "success":
                        successful_tests += 1
                        logger.info(f"✅ {agent_type} agent package test passed")
                    else:
                        logger.error(f"❌ {agent_type} agent package test failed: {result.get('error', 'Unknown error')}")
                        
                except Exception as e:
                    logger.error(f"❌ {agent_type} agent package test failed with exception: {e}")
                    test_results["agents"][agent_type] = {
                        "status": "failed",
                        "error": str(e),
                        "timestamp": __import__('datetime').datetime.utcnow().isoformat()
                    }
            
            # Update overall status
            if successful_tests == len(self.agents_to_test):
                test_results["overall_status"] = "success"
                logger.info(f"🎉 All {successful_tests} agent packages tested successfully!")
            elif successful_tests > 0:
                test_results["overall_status"] = "partial_success"
                logger.warning(f"⚠️ {successful_tests}/{len(self.agents_to_test)} agent packages tested successfully")
            else:
                test_results["overall_status"] = "failed"
                logger.error("❌ No agent packages passed testing")
            
            # Save test results
            self._save_test_results(test_results)
            
            return test_results
            
        except Exception as e:
            logger.error(f"Package testing failed: {e}")
            return {
                "test_id": f"test-{int(__import__('time').time())}",
                "timestamp": __import__('datetime').datetime.utcnow().isoformat(),
                "overall_status": "failed",
                "error": str(e)
            }
    
    def test_agent_package(self, agent_type: str) -> Dict[str, Any]:
        """Test a single agent package"""
        try:
            start_time = __import__('time').time()
            
            # Find agent package
            package_path = self._find_agent_package(agent_type)
            if not package_path:
                return {
                    "status": "failed",
                    "error": f"Agent package not found for {agent_type}",
                    "timestamp": __import__('datetime').datetime.utcnow().isoformat()
                }
            
            # Test package structure
            structure_test = self._test_package_structure(package_path)
            if not structure_test["valid"]:
                return {
                    "status": "failed",
                    "error": f"Invalid package structure: {structure_test['error']}",
                    "timestamp": __import__('datetime').datetime.utcnow().isoformat()
                }
            
            # Test agent loading
            loading_test = self._test_agent_loading(package_path, agent_type)
            if not loading_test["success"]:
                return {
                    "status": "failed",
                    "error": f"Agent loading failed: {loading_test['error']}",
                    "timestamp": __import__('datetime').datetime.utcnow().isoformat()
                }
            
            # Test configuration
            config_test = self._test_agent_configuration(package_path)
            
            test_time = __import__('time').time() - start_time
            
            return {
                "status": "success",
                "test_time_seconds": test_time,
                "structure_test": structure_test,
                "loading_test": loading_test,
                "config_test": config_test,
                "timestamp": __import__('datetime').datetime.utcnow().isoformat()
            }
                
        except Exception as e:
            logger.error(f"Failed to test {agent_type} agent package: {e}")
            return {
                "status": "failed",
                "error": str(e),
                "timestamp": __import__('datetime').datetime.utcnow().isoformat()
            }
    
    def _find_agent_package(self, agent_type: str) -> Path:
        """Find agent deployment package"""
        package_name = f"ai-honeypot-{agent_type}-agent-deployment-package.zip"
        package_path = self.build_dir / package_name
        
        if package_path.exists():
            return package_path
        
        return None
    
    def _test_package_structure(self, package_path: Path) -> Dict[str, Any]:
        """Test package structure"""
        try:
            required_files = [
                "main.py",
                "agent.py", 
                "requirements.txt",
                "deployment_metadata.json"
            ]
            
            with zipfile.ZipFile(package_path, 'r') as zip_ref:
                file_list = zip_ref.namelist()
                
                missing_files = []
                for required_file in required_files:
                    if required_file not in file_list:
                        missing_files.append(required_file)
                
                if missing_files:
                    return {
                        "valid": False,
                        "error": f"Missing required files: {missing_files}",
                        "files_found": file_list
                    }
                
                return {
                    "valid": True,
                    "files_found": file_list,
                    "required_files_present": required_files
                }
                
        except Exception as e:
            return {
                "valid": False,
                "error": str(e)
            }
    
    def _test_agent_loading(self, package_path: Path, agent_type: str) -> Dict[str, Any]:
        """Test agent loading"""
        try:
            with tempfile.TemporaryDirectory() as temp_dir:
                temp_path = Path(temp_dir)
                
                # Extract package
                with zipfile.ZipFile(package_path, 'r') as zip_ref:
                    zip_ref.extractall(temp_path)
                
                # Add to Python path
                sys.path.insert(0, str(temp_path))
                
                try:
                    # Test importing main module
                    import importlib.util
                    
                    main_py = temp_path / "main.py"
                    spec = importlib.util.spec_from_file_location("main", main_py)
                    main_module = importlib.util.module_from_spec(spec)
                    
                    # Try to load the module (but don't execute)
                    spec.loader.exec_module(main_module)
                    
                    # Check if required functions/classes exist
                    if hasattr(main_module, 'create_agent_app'):
                        return {
                            "success": True,
                            "message": "Agent module loaded successfully",
                            "has_create_agent_app": True
                        }
                    else:
                        return {
                            "success": False,
                            "error": "create_agent_app function not found in main.py"
                        }
                        
                except Exception as import_error:
                    return {
                        "success": False,
                        "error": f"Failed to import agent module: {str(import_error)}"
                    }
                finally:
                    # Clean up Python path
                    if str(temp_path) in sys.path:
                        sys.path.remove(str(temp_path))
                
        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }
    
    def _test_agent_configuration(self, package_path: Path) -> Dict[str, Any]:
        """Test agent configuration"""
        try:
            with zipfile.ZipFile(package_path, 'r') as zip_ref:
                # Test deployment metadata
                try:
                    metadata_content = zip_ref.read("deployment_metadata.json")
                    metadata = json.loads(metadata_content)
                    
                    required_metadata_fields = [
                        "agent_name", "agent_type", "entrypoint", 
                        "package_version", "capabilities"
                    ]
                    
                    missing_metadata = []
                    for field in required_metadata_fields:
                        if field not in metadata:
                            missing_metadata.append(field)
                    
                    if missing_metadata:
                        return {
                            "valid": False,
                            "error": f"Missing metadata fields: {missing_metadata}",
                            "metadata": metadata
                        }
                    
                    # Test requirements.txt
                    try:
                        requirements_content = zip_ref.read("requirements.txt").decode('utf-8')
                        requirements_lines = [line.strip() for line in requirements_content.split('\n') if line.strip()]
                        
                        required_packages = ["bedrock-agentcore", "strands-agents"]
                        missing_packages = []
                        
                        for package in required_packages:
                            if not any(package in line for line in requirements_lines):
                                missing_packages.append(package)
                        
                        if missing_packages:
                            return {
                                "valid": False,
                                "error": f"Missing required packages: {missing_packages}",
                                "requirements": requirements_lines
                            }
                        
                        return {
                            "valid": True,
                            "metadata": metadata,
                            "requirements": requirements_lines
                        }
                        
                    except KeyError:
                        return {
                            "valid": False,
                            "error": "requirements.txt not found in package"
                        }
                    
                except KeyError:
                    return {
                        "valid": False,
                        "error": "deployment_metadata.json not found in package"
                    }
                except json.JSONDecodeError as e:
                    return {
                        "valid": False,
                        "error": f"Invalid JSON in deployment_metadata.json: {str(e)}"
                    }
                
        except Exception as e:
            return {
                "valid": False,
                "error": str(e)
            }
    
    def _save_test_results(self, results: Dict[str, Any]):
        """Save test results to file"""
        try:
            results_file = self.build_dir / f"package_test_results_{results['test_id']}.json"
            with open(results_file, 'w') as f:
                json.dump(results, f, indent=2)
            
            # Also save as latest
            latest_file = self.build_dir / "latest_package_test_results.json"
            with open(latest_file, 'w') as f:
                json.dump(results, f, indent=2)
            
            logger.info(f"Test results saved to: {results_file}")
            
        except Exception as e:
            logger.error(f"Failed to save test results: {e}")

def main():
    """Main test script entry point"""
    try:
        # Get workspace root
        workspace_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        
        # Create tester
        tester = AgentPackageTester(workspace_root)
        
        # Test all packages
        results = tester.test_all_packages()
        
        # Print results
        print("\n" + "="*60)
        print("Agent Package Test Results")
        print("="*60)
        print(f"Test ID: {results.get('test_id', 'Unknown')}")
        print(f"Overall Status: {results.get('overall_status', 'Unknown')}")
        print(f"Timestamp: {results.get('timestamp', 'Unknown')}")
        
        if "agents" in results:
            print("\nAgent Test Status:")
            for agent_type, agent_result in results["agents"].items():
                status = agent_result.get("status", "unknown")
                if status == "success":
                    print(f"  ✅ {agent_type.upper()}: {status}")
                    if "test_time_seconds" in agent_result:
                        print(f"     Test Time: {agent_result['test_time_seconds']:.2f}s")
                else:
                    print(f"  ❌ {agent_type.upper()}: {status}")
                    if "error" in agent_result:
                        print(f"     Error: {agent_result['error']}")
        
        print(f"\n📋 Test results: build/agentcore/latest_package_test_results.json")
        
        # Exit with appropriate code
        if results.get("overall_status") == "success":
            print("\n🎉 All agent packages passed testing!")
            sys.exit(0)
        elif results.get("overall_status") == "partial_success":
            print("\n⚠️ Some agent packages failed testing. Check individual results.")
            sys.exit(1)
        else:
            print("\n❌ Agent package testing failed. Check logs for details.")
            sys.exit(1)
            
    except Exception as e:
        logger.error(f"Test script failed: {e}")
        print(f"\n❌ Test script failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()