#!/bin/bash

# Development Tools Script for AI Honeypot AgentCore
# Provides various development and debugging utilities

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
COMPOSE_FILE="docker-compose.dev.yml"
PROJECT_NAME="honeypot-dev"

# Helper functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to check if Docker is running
check_docker() {
    if ! docker info > /dev/null 2>&1; then
        log_error "Docker is not running. Please start Docker first."
        exit 1
    fi
}

# Function to check if Docker Compose is available
check_compose() {
    if ! command -v docker-compose > /dev/null 2>&1; then
        log_error "Docker Compose is not installed. Please install Docker Compose first."
        exit 1
    fi
}

# Function to start the development environment
start_dev_env() {
    log_info "Starting development environment..."
    check_docker
    check_compose
    
    # Build and start services
    docker-compose -f $COMPOSE_FILE -p $PROJECT_NAME up -d --build
    
    log_success "Development environment started!"
    log_info "Services available at:"
    echo "  - Mock AgentCore Runtime: http://localhost:8000"
    echo "  - Detection Agent: http://localhost:8001"
    echo "  - Coordinator Agent: http://localhost:8002"
    echo "  - Interaction Agent: http://localhost:8003"
    echo "  - Intelligence Agent: http://localhost:8004"
    echo "  - Management Dashboard: http://localhost:8090"
    echo "  - Grafana: http://localhost:3000 (admin/admin)"
    echo "  - Prometheus: http://localhost:9090"
    echo "  - RabbitMQ Management: http://localhost:15672 (honeypot/honeypot_dev_password)"
    echo ""
    echo "Honeypots available at:"
    echo "  - SSH Honeypot: localhost:2222"
    echo "  - Web Admin Honeypot: http://localhost:8080"
    echo "  - Database Honeypot: localhost:3306 (MySQL), localhost:5433 (PostgreSQL)"
}

# Function to stop the development environment
stop_dev_env() {
    log_info "Stopping development environment..."
    docker-compose -f $COMPOSE_FILE -p $PROJECT_NAME down
    log_success "Development environment stopped!"
}

# Function to restart the development environment
restart_dev_env() {
    log_info "Restarting development environment..."
    stop_dev_env
    start_dev_env
}

# Function to show logs
show_logs() {
    local service=$1
    if [ -z "$service" ]; then
        log_info "Showing logs for all services..."
        docker-compose -f $COMPOSE_FILE -p $PROJECT_NAME logs -f
    else
        log_info "Showing logs for service: $service"
        docker-compose -f $COMPOSE_FILE -p $PROJECT_NAME logs -f $service
    fi
}

# Function to show service status
show_status() {
    log_info "Service status:"
    docker-compose -f $COMPOSE_FILE -p $PROJECT_NAME ps
}

# Function to execute commands in containers
exec_container() {
    local service=$1
    local command=${2:-"/bin/bash"}
    
    if [ -z "$service" ]; then
        log_error "Please specify a service name"
        echo "Available services:"
        docker-compose -f $COMPOSE_FILE -p $PROJECT_NAME ps --services
        return 1
    fi
    
    log_info "Executing command in $service container..."
    docker-compose -f $COMPOSE_FILE -p $PROJECT_NAME exec $service $command
}

# Function to run tests
run_tests() {
    local test_type=${1:-"all"}
    
    log_info "Running tests: $test_type"
    
    case $test_type in
        "unit")
            docker-compose -f $COMPOSE_FILE -p $PROJECT_NAME exec dev-tools python -m pytest tests/unit/ -v
            ;;
        "integration")
            docker-compose -f $COMPOSE_FILE -p $PROJECT_NAME exec dev-tools python -m pytest tests/integration/ -v
            ;;
        "security")
            docker-compose -f $COMPOSE_FILE -p $PROJECT_NAME exec dev-tools python -m pytest tests/security/ -v
            ;;
        "all")
            docker-compose -f $COMPOSE_FILE -p $PROJECT_NAME exec dev-tools python -m pytest tests/ -v
            ;;
        *)
            log_error "Unknown test type: $test_type"
            echo "Available test types: unit, integration, security, all"
            return 1
            ;;
    esac
}

# Function to generate synthetic threat data
generate_threats() {
    local count=${1:-10}
    log_info "Generating $count synthetic threat events..."
    
    docker-compose -f $COMPOSE_FILE -p $PROJECT_NAME exec dev-tools python -c "
import sys
sys.path.append('/app/workspace')
from tests.integration.integration_test_config import ThreatSimulator
simulator = ThreatSimulator()
simulator.generate_synthetic_threats($count)
"
    log_success "Generated $count synthetic threat events"
}

# Function to simulate attacker interactions
simulate_attack() {
    local honeypot_type=${1:-"ssh"}
    local duration=${2:-60}
    
    log_info "Simulating attack on $honeypot_type honeypot for $duration seconds..."
    
    docker-compose -f $COMPOSE_FILE -p $PROJECT_NAME exec dev-tools python -c "
import sys
sys.path.append('/app/workspace')
from tests.integration.integration_test_config import AttackerSimulator
simulator = AttackerSimulator()
simulator.simulate_attack('$honeypot_type', $duration)
"
    log_success "Attack simulation completed"
}

# Function to check system health
check_health() {
    log_info "Checking system health..."
    
    # Check AgentCore Runtime
    if curl -s http://localhost:8000/health > /dev/null; then
        log_success "Mock AgentCore Runtime: Healthy"
    else
        log_error "Mock AgentCore Runtime: Unhealthy"
    fi
    
    # Check agents
    for port in 8001 8002 8003 8004; do
        agent_name=""
        case $port in
            8001) agent_name="Detection Agent" ;;
            8002) agent_name="Coordinator Agent" ;;
            8003) agent_name="Interaction Agent" ;;
            8004) agent_name="Intelligence Agent" ;;
        esac
        
        if curl -s http://localhost:$port/health > /dev/null; then
            log_success "$agent_name: Healthy"
        else
            log_error "$agent_name: Unhealthy"
        fi
    done
    
    # Check infrastructure services
    if docker-compose -f $COMPOSE_FILE -p $PROJECT_NAME ps redis | grep -q "Up"; then
        log_success "Redis: Running"
    else
        log_error "Redis: Not running"
    fi
    
    if docker-compose -f $COMPOSE_FILE -p $PROJECT_NAME ps postgres | grep -q "Up"; then
        log_success "PostgreSQL: Running"
    else
        log_error "PostgreSQL: Not running"
    fi
    
    if docker-compose -f $COMPOSE_FILE -p $PROJECT_NAME ps rabbitmq | grep -q "Up"; then
        log_success "RabbitMQ: Running"
    else
        log_error "RabbitMQ: Not running"
    fi
}

# Function to clean up development environment
cleanup() {
    log_info "Cleaning up development environment..."
    
    # Stop and remove containers
    docker-compose -f $COMPOSE_FILE -p $PROJECT_NAME down -v --remove-orphans
    
    # Remove unused images
    docker image prune -f
    
    # Remove unused volumes
    docker volume prune -f
    
    log_success "Cleanup completed!"
}

# Function to show system metrics
show_metrics() {
    log_info "System metrics:"
    
    # Get metrics from AgentCore Runtime
    curl -s http://localhost:8000/system/metrics | jq '.' 2>/dev/null || echo "AgentCore Runtime metrics unavailable"
    
    # Show Docker stats
    echo ""
    log_info "Container resource usage:"
    docker stats --no-stream --format "table {{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.NetIO}}"
    
    # Show system resource usage
    echo ""
    log_info "Host system resources:"
    echo "CPU Usage: $(top -bn1 | grep "Cpu(s)" | awk '{print $2}' | cut -d'%' -f1)%"
    echo "Memory Usage: $(free | grep Mem | awk '{printf("%.2f%%", $3/$2 * 100.0)}')"
    echo "Disk Usage: $(df -h / | awk 'NR==2{printf "%s", $5}')"
}

# Function to run comprehensive validation
validate_system() {
    log_info "Running comprehensive system validation..."
    
    docker-compose -f $COMPOSE_FILE -p $PROJECT_NAME exec dev-tools python -c "
import sys
sys.path.append('/app/workspace')
from tests.validation.system_validator import SystemValidator
import asyncio

async def run_validation():
    validator = SystemValidator()
    await validator.initialize()
    report = await validator.validate_system()
    
    print(f'Validation Report: {report.validation_id}')
    print(f'Overall Success: {report.overall_success}')
    print(f'Tests: {report.summary[\"successful_tests\"]}/{report.summary[\"total_tests\"]} passed')
    
    for result in report.results:
        status = '✓' if result.success else '✗'
        print(f'{status} {result.test_name}: {result.message}')

asyncio.run(run_validation())
"
}

# Function to monitor message flow
monitor_messages() {
    local duration=${1:-30}
    log_info "Monitoring message flow for $duration seconds..."
    
    docker-compose -f $COMPOSE_FILE -p $PROJECT_NAME exec dev-tools python -c "
import sys
sys.path.append('/app/workspace')
import asyncio
import aiohttp
import time

async def monitor_messages():
    start_time = time.time()
    message_count = 0
    
    async with aiohttp.ClientSession() as session:
        while time.time() - start_time < $duration:
            try:
                async with session.get('http://mock-agentcore:8000/messages/history?limit=10') as response:
                    if response.status == 200:
                        data = await response.json()
                        current_count = data.get('count', 0)
                        if current_count > message_count:
                            print(f'New messages: {current_count - message_count}')
                            message_count = current_count
            except Exception as e:
                print(f'Error monitoring messages: {e}')
            
            await asyncio.sleep(2)
    
    print(f'Total messages processed: {message_count}')

asyncio.run(monitor_messages())
"
}

# Function to stress test the system
stress_test() {
    local concurrent_users=${1:-5}
    local duration=${2:-60}
    
    log_info "Running stress test with $concurrent_users concurrent users for $duration seconds..."
    
    docker-compose -f $COMPOSE_FILE -p $PROJECT_NAME exec dev-tools python -c "
import sys
sys.path.append('/app/workspace')
from tests.simulation.performance_tester import PerformanceTester
import asyncio

async def run_stress_test():
    tester = PerformanceTester()
    results = await tester.run_load_test(
        concurrent_users=$concurrent_users,
        duration_seconds=$duration,
        target_endpoint='http://mock-agentcore:8000'
    )
    
    print(f'Stress Test Results:')
    print(f'Total Requests: {results.get(\"total_requests\", 0)}')
    print(f'Successful Requests: {results.get(\"successful_requests\", 0)}')
    print(f'Failed Requests: {results.get(\"failed_requests\", 0)}')
    print(f'Average Response Time: {results.get(\"avg_response_time\", 0):.2f}ms')
    print(f'Requests per Second: {results.get(\"requests_per_second\", 0):.2f}')

asyncio.run(run_stress_test())
"
}

# Function to analyze threat intelligence
analyze_intelligence() {
    log_info "Analyzing threat intelligence data..."
    
    docker-compose -f $COMPOSE_FILE -p $PROJECT_NAME exec dev-tools python -c "
import sys
sys.path.append('/app/workspace')
from tests.simulation.intelligence_validator import IntelligenceValidator
import asyncio

async def analyze_intelligence():
    validator = IntelligenceValidator()
    
    # Get recent intelligence data
    intelligence_data = await validator.get_recent_intelligence()
    
    if intelligence_data:
        print(f'Recent Intelligence Reports: {len(intelligence_data)}')
        
        # Analyze patterns
        patterns = await validator.analyze_attack_patterns(intelligence_data)
        
        print('Attack Patterns:')
        for pattern, count in patterns.items():
            print(f'  {pattern}: {count} occurrences')
    else:
        print('No intelligence data available')

asyncio.run(analyze_intelligence())
"
}

# Function to backup development data
backup_data() {
    local backup_dir="./backups/$(date +%Y%m%d_%H%M%S)"
    mkdir -p "$backup_dir"
    
    log_info "Backing up development data to $backup_dir..."
    
    # Backup Redis data
    docker-compose -f $COMPOSE_FILE -p $PROJECT_NAME exec redis redis-cli BGSAVE
    docker cp $(docker-compose -f $COMPOSE_FILE -p $PROJECT_NAME ps -q redis):/data/dump.rdb "$backup_dir/redis_dump.rdb"
    
    # Backup PostgreSQL data
    docker-compose -f $COMPOSE_FILE -p $PROJECT_NAME exec postgres pg_dump -U honeypot honeypot_intelligence > "$backup_dir/postgres_dump.sql"
    
    # Backup logs
    mkdir -p "$backup_dir/logs"
    docker-compose -f $COMPOSE_FILE -p $PROJECT_NAME logs > "$backup_dir/logs/all_services.log"
    
    log_success "Backup completed: $backup_dir"
}

# Function to show help
show_help() {
    echo "AI Honeypot AgentCore Development Tools"
    echo ""
    echo "Usage: $0 <command> [options]"
    echo ""
    echo "Commands:"
    echo "  start                 Start the development environment"
    echo "  stop                  Stop the development environment"
    echo "  restart               Restart the development environment"
    echo "  status                Show service status"
    echo "  logs [service]        Show logs (all services or specific service)"
    echo "  exec <service> [cmd]  Execute command in container"
    echo "  test [type]           Run tests (unit|integration|security|all)"
    echo "  threats [count]       Generate synthetic threat events"
    echo "  attack [type] [dur]   Simulate attack (ssh|web|db) for duration"
    echo "  health                Check system health"
    echo "  metrics               Show system metrics"
    echo "  validate              Run comprehensive system validation"
    echo "  monitor [duration]    Monitor message flow for duration (seconds)"
    echo "  stress [users] [dur]  Run stress test with concurrent users"
    echo "  intelligence          Analyze threat intelligence data"
    echo "  backup                Backup development data"
    echo "  cleanup               Clean up environment and unused resources"
    echo "  help                  Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0 start"
    echo "  $0 logs detection-agent"
    echo "  $0 exec dev-tools python"
    echo "  $0 test integration"
    echo "  $0 threats 50"
    echo "  $0 attack ssh 120"
}

# Main script logic
case "${1:-help}" in
    "start")
        start_dev_env
        ;;
    "stop")
        stop_dev_env
        ;;
    "restart")
        restart_dev_env
        ;;
    "status")
        show_status
        ;;
    "logs")
        show_logs "$2"
        ;;
    "exec")
        exec_container "$2" "$3"
        ;;
    "test")
        run_tests "$2"
        ;;
    "threats")
        generate_threats "$2"
        ;;
    "attack")
        simulate_attack "$2" "$3"
        ;;
    "health")
        check_health
        ;;
    "metrics")
        show_metrics
        ;;
    "validate")
        validate_system
        ;;
    "monitor")
        monitor_messages "$2"
        ;;
    "stress")
        stress_test "$2" "$3"
        ;;
    "intelligence")
        analyze_intelligence
        ;;
    "backup")
        backup_data
        ;;
    "cleanup")
        cleanup
        ;;
    "help"|*)
        show_help
        ;;
esac