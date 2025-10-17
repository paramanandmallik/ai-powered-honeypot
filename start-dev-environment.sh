#!/bin/bash

# AI Honeypot AgentCore Development Environment Startup Script
# Comprehensive setup for local development and testing

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Configuration
PROJECT_NAME="honeypot-dev"
COMPOSE_FILE="docker-compose.dev.yml"
MONITORING_FILE="deployment/monitoring/local-monitoring.yml"

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

log_step() {
    echo -e "${PURPLE}[STEP]${NC} $1"
}

# Function to check prerequisites
check_prerequisites() {
    log_step "Checking prerequisites..."
    
    # Check Docker
    if ! command -v docker &> /dev/null; then
        log_error "Docker is not installed. Please install Docker first."
        exit 1
    fi
    
    if ! docker info &> /dev/null; then
        log_error "Docker daemon is not running. Please start Docker first."
        exit 1
    fi
    
    # Check Docker Compose
    if ! command -v docker-compose &> /dev/null; then
        log_error "Docker Compose is not installed. Please install Docker Compose first."
        exit 1
    fi
    
    # Check available disk space (minimum 10GB)
    available_space=$(df . | tail -1 | awk '{print $4}')
    if [ "$available_space" -lt 10485760 ]; then  # 10GB in KB
        log_warning "Low disk space detected. At least 10GB recommended for development environment."
    fi
    
    # Check available memory (minimum 8GB)
    available_memory=$(free -m | awk 'NR==2{printf "%.0f", $7}')
    if [ "$available_memory" -lt 4096 ]; then  # 4GB available
        log_warning "Low available memory detected. At least 4GB available memory recommended."
    fi
    
    log_success "Prerequisites check completed"
}

# Function to create necessary directories
create_directories() {
    log_step "Creating necessary directories..."
    
    directories=(
        "logs/agents"
        "logs/honeypots"
        "logs/security"
        "logs/monitoring"
        "data/redis"
        "data/postgres"
        "data/sessions"
        "data/intelligence"
        "reports/validation"
        "reports/performance"
        "reports/security"
        "notebooks"
        "monitoring/grafana/dashboards"
        "monitoring/prometheus/data"
        "backups"
    )
    
    for dir in "${directories[@]}"; do
        mkdir -p "$dir"
        log_info "Created directory: $dir"
    done
    
    log_success "Directory structure created"
}

# Function to set up environment files
setup_environment() {
    log_step "Setting up environment configuration..."
    
    # Create .env file if it doesn't exist
    if [ ! -f .env ]; then
        cat > .env << EOF
# AI Honeypot AgentCore Development Environment Configuration

# Environment
ENVIRONMENT=development
DEBUG=true
LOG_LEVEL=DEBUG

# Database Configuration
POSTGRES_DB=honeypot_intelligence
POSTGRES_USER=honeypot
POSTGRES_PASSWORD=honeypot_dev_password
DATABASE_URL=postgresql://honeypot:honeypot_dev_password@postgres:5432/honeypot_intelligence

# Redis Configuration
REDIS_URL=redis://redis:6379/0

# RabbitMQ Configuration
RABBITMQ_DEFAULT_USER=honeypot
RABBITMQ_DEFAULT_PASS=honeypot_dev_password
RABBITMQ_URL=amqp://honeypot:honeypot_dev_password@rabbitmq:5672/

# AgentCore Configuration
AGENTCORE_ENDPOINT=http://mock-agentcore:8000
AGENTCORE_API_KEY=dev_api_key_12345

# Security Configuration
ENCRYPTION_KEY=dev_encryption_key_for_testing_only
JWT_SECRET=dev_jwt_secret_for_testing_only

# Monitoring Configuration
PROMETHEUS_URL=http://prometheus:9090
GRAFANA_URL=http://grafana:3000
JAEGER_URL=http://jaeger:16686

# Development Tools
JUPYTER_TOKEN=
JUPYTER_PASSWORD=

# Feature Flags
ENABLE_SYNTHETIC_DATA=true
ENABLE_THREAT_SIMULATION=true
ENABLE_PERFORMANCE_MONITORING=true
ENABLE_SECURITY_TESTING=true
EOF
        log_success "Created .env file with development configuration"
    else
        log_info ".env file already exists, skipping creation"
    fi
}

# Function to build Docker images
build_images() {
    log_step "Building Docker images..."
    
    # Build all images in parallel for faster startup
    docker-compose -f $COMPOSE_FILE -p $PROJECT_NAME build --parallel
    
    log_success "Docker images built successfully"
}

# Function to start core infrastructure
start_infrastructure() {
    log_step "Starting core infrastructure services..."
    
    # Start infrastructure services first
    docker-compose -f $COMPOSE_FILE -p $PROJECT_NAME up -d redis postgres rabbitmq
    
    # Wait for services to be ready
    log_info "Waiting for infrastructure services to be ready..."
    
    # Wait for Redis
    until docker-compose -f $COMPOSE_FILE -p $PROJECT_NAME exec -T redis redis-cli ping &> /dev/null; do
        echo -n "."
        sleep 1
    done
    log_success "Redis is ready"
    
    # Wait for PostgreSQL
    until docker-compose -f $COMPOSE_FILE -p $PROJECT_NAME exec -T postgres pg_isready -U honeypot &> /dev/null; do
        echo -n "."
        sleep 1
    done
    log_success "PostgreSQL is ready"
    
    # Wait for RabbitMQ
    until docker-compose -f $COMPOSE_FILE -p $PROJECT_NAME exec -T rabbitmq rabbitmq-diagnostics ping &> /dev/null; do
        echo -n "."
        sleep 1
    done
    log_success "RabbitMQ is ready"
}

# Function to start AgentCore and agents
start_agents() {
    log_step "Starting AgentCore Runtime and AI agents..."
    
    # Start mock AgentCore first
    docker-compose -f $COMPOSE_FILE -p $PROJECT_NAME up -d mock-agentcore
    
    # Wait for AgentCore to be ready
    log_info "Waiting for AgentCore Runtime to be ready..."
    until curl -s http://localhost:8000/health &> /dev/null; do
        echo -n "."
        sleep 2
    done
    log_success "AgentCore Runtime is ready"
    
    # Start all agents
    docker-compose -f $COMPOSE_FILE -p $PROJECT_NAME up -d detection-agent coordinator-agent interaction-agent intelligence-agent
    
    # Wait for agents to register
    log_info "Waiting for agents to register..."
    sleep 10
    
    log_success "AI agents started and registered"
}

# Function to start honeypots
start_honeypots() {
    log_step "Starting honeypot services..."
    
    docker-compose -f $COMPOSE_FILE -p $PROJECT_NAME up -d ssh-honeypot web-admin-honeypot database-honeypot
    
    log_success "Honeypot services started"
}

# Function to start monitoring stack
start_monitoring() {
    log_step "Starting monitoring and observability stack..."
    
    # Start basic monitoring
    docker-compose -f $COMPOSE_FILE -p $PROJECT_NAME up -d prometheus grafana
    
    # Start enhanced monitoring if file exists
    if [ -f "$MONITORING_FILE" ]; then
        docker-compose -f $MONITORING_FILE -p "${PROJECT_NAME}-monitoring" up -d
        log_success "Enhanced monitoring stack started"
    else
        log_info "Enhanced monitoring configuration not found, using basic monitoring"
    fi
}

# Function to start management tools
start_management() {
    log_step "Starting management and development tools..."
    
    docker-compose -f $COMPOSE_FILE -p $PROJECT_NAME up -d dashboard dev-tools
    
    log_success "Management tools started"
}

# Function to run initial validation
run_initial_validation() {
    log_step "Running initial system validation..."
    
    # Wait a bit for all services to stabilize
    sleep 15
    
    # Run basic health checks
    log_info "Performing health checks..."
    
    services=(
        "http://localhost:8000/health:AgentCore Runtime"
        "http://localhost:8001/health:Detection Agent"
        "http://localhost:8002/health:Coordinator Agent"
        "http://localhost:8003/health:Interaction Agent"
        "http://localhost:8004/health:Intelligence Agent"
        "http://localhost:8090/health:Management Dashboard"
    )
    
    for service in "${services[@]}"; do
        url=$(echo $service | cut -d: -f1-2)
        name=$(echo $service | cut -d: -f3-)
        
        if curl -s "$url" &> /dev/null; then
            log_success "$name: Healthy"
        else
            log_warning "$name: Not responding (may still be starting up)"
        fi
    done
}

# Function to display access information
show_access_info() {
    log_step "Development environment is ready!"
    
    echo ""
    echo -e "${CYAN}=== AI Honeypot AgentCore Development Environment ===${NC}"
    echo ""
    echo -e "${GREEN}Core Services:${NC}"
    echo "  🤖 AgentCore Runtime:     http://localhost:8000"
    echo "  🔍 Detection Agent:       http://localhost:8001"
    echo "  🎯 Coordinator Agent:     http://localhost:8002"
    echo "  💬 Interaction Agent:     http://localhost:8003"
    echo "  🧠 Intelligence Agent:    http://localhost:8004"
    echo ""
    echo -e "${GREEN}Management & Monitoring:${NC}"
    echo "  📊 Management Dashboard:  http://localhost:8090"
    echo "  📈 Grafana:              http://localhost:3000 (admin/admin)"
    echo "  📊 Prometheus:           http://localhost:9090"
    echo "  🐰 RabbitMQ Management:  http://localhost:15672 (honeypot/honeypot_dev_password)"
    echo ""
    echo -e "${GREEN}Development Tools:${NC}"
    echo "  📓 Jupyter Lab:          http://localhost:8888"
    echo "  🔍 Jaeger Tracing:       http://localhost:16686"
    echo "  📋 Kibana:               http://localhost:5601"
    echo ""
    echo -e "${GREEN}Honeypots (for testing):${NC}"
    echo "  🔐 SSH Honeypot:         ssh://localhost:2222"
    echo "  🌐 Web Admin Honeypot:   http://localhost:8080"
    echo "  🗄️  Database Honeypot:    mysql://localhost:3306, postgres://localhost:5433"
    echo ""
    echo -e "${GREEN}Development Commands:${NC}"
    echo "  ./deployment/scripts/dev-tools.sh help    # Show all available commands"
    echo "  ./deployment/scripts/dev-tools.sh status  # Check service status"
    echo "  ./deployment/scripts/dev-tools.sh logs    # View logs"
    echo "  ./deployment/scripts/dev-tools.sh test    # Run tests"
    echo ""
    echo -e "${YELLOW}Note: All services may take a few minutes to fully initialize.${NC}"
    echo -e "${YELLOW}Use 'docker-compose -f $COMPOSE_FILE -p $PROJECT_NAME logs -f' to monitor startup.${NC}"
    echo ""
}

# Function to handle cleanup on exit
cleanup_on_exit() {
    log_info "Cleaning up on exit..."
    # Add any cleanup logic here if needed
}

# Set up trap for cleanup
trap cleanup_on_exit EXIT

# Main execution
main() {
    echo -e "${CYAN}"
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║        AI Honeypot AgentCore Development Environment         ║"
    echo "║                    Startup Script                            ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    
    check_prerequisites
    create_directories
    setup_environment
    build_images
    start_infrastructure
    start_agents
    start_honeypots
    start_monitoring
    start_management
    run_initial_validation
    show_access_info
    
    log_success "Development environment startup completed successfully!"
}

# Handle command line arguments
case "${1:-start}" in
    "start")
        main
        ;;
    "stop")
        log_info "Stopping development environment..."
        docker-compose -f $COMPOSE_FILE -p $PROJECT_NAME down
        if [ -f "$MONITORING_FILE" ]; then
            docker-compose -f $MONITORING_FILE -p "${PROJECT_NAME}-monitoring" down
        fi
        log_success "Development environment stopped"
        ;;
    "restart")
        $0 stop
        sleep 5
        $0 start
        ;;
    "help")
        echo "Usage: $0 [start|stop|restart|help]"
        echo ""
        echo "Commands:"
        echo "  start    - Start the complete development environment (default)"
        echo "  stop     - Stop all services"
        echo "  restart  - Restart the development environment"
        echo "  help     - Show this help message"
        ;;
    *)
        log_error "Unknown command: $1"
        $0 help
        exit 1
        ;;
esac