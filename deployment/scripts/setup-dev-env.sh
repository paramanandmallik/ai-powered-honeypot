#!/bin/bash

# AI Honeypot System - Development Environment Setup Script

set -e

echo "🚀 Setting up AI Honeypot Development Environment..."

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if Python 3.11+ is installed
check_python() {
    print_status "Checking Python version..."
    if command -v python3 &> /dev/null; then
        PYTHON_VERSION=$(python3 --version | cut -d' ' -f2)
        PYTHON_MAJOR=$(echo $PYTHON_VERSION | cut -d'.' -f1)
        PYTHON_MINOR=$(echo $PYTHON_VERSION | cut -d'.' -f2)
        
        if [ "$PYTHON_MAJOR" -eq 3 ] && [ "$PYTHON_MINOR" -ge 11 ]; then
            print_success "Python $PYTHON_VERSION found"
        else
            print_error "Python 3.11+ required, found $PYTHON_VERSION"
            exit 1
        fi
    else
        print_error "Python 3 not found. Please install Python 3.11+"
        exit 1
    fi
}

# Check if Docker is installed and running
check_docker() {
    print_status "Checking Docker..."
    if command -v docker &> /dev/null; then
        if docker info &> /dev/null; then
            print_success "Docker is running"
        else
            print_error "Docker is installed but not running. Please start Docker."
            exit 1
        fi
    else
        print_error "Docker not found. Please install Docker."
        exit 1
    fi
}

# Check if Docker Compose is available
check_docker_compose() {
    print_status "Checking Docker Compose..."
    if docker compose version &> /dev/null; then
        print_success "Docker Compose found"
    elif command -v docker-compose &> /dev/null; then
        print_success "Docker Compose (standalone) found"
    else
        print_error "Docker Compose not found. Please install Docker Compose."
        exit 1
    fi
}

# Create virtual environment
setup_venv() {
    print_status "Setting up Python virtual environment..."
    if [ ! -d "venv" ]; then
        python3 -m venv venv
        print_success "Virtual environment created"
    else
        print_warning "Virtual environment already exists"
    fi
    
    # Activate virtual environment
    source venv/bin/activate
    
    # Upgrade pip
    pip install --upgrade pip
    
    # Install dependencies
    print_status "Installing Python dependencies..."
    pip install -r requirements.txt
    print_success "Dependencies installed"
}

# Setup environment variables
setup_env() {
    print_status "Setting up environment variables..."
    if [ ! -f ".env" ]; then
        cp .env.example .env
        print_success "Environment file created from template"
        print_warning "Please edit .env file with your configuration"
    else
        print_warning ".env file already exists"
    fi
}

# Create necessary directories
create_directories() {
    print_status "Creating necessary directories..."
    mkdir -p logs data/intelligence data/sessions data/backups
    mkdir -p static/css static/js static/images
    mkdir -p deployment/grafana/dashboards deployment/grafana/datasources
    print_success "Directories created"
}

# Setup pre-commit hooks
setup_pre_commit() {
    print_status "Setting up pre-commit hooks..."
    if command -v pre-commit &> /dev/null; then
        pre-commit install
        print_success "Pre-commit hooks installed"
    else
        print_warning "pre-commit not found. Installing..."
        pip install pre-commit
        pre-commit install
        print_success "Pre-commit hooks installed"
    fi
}

# Start development services
start_services() {
    print_status "Starting development services..."
    
    # Pull latest images
    docker compose pull
    
    # Build custom images
    docker compose build
    
    # Start services
    docker compose up -d
    
    print_success "Development services started"
    
    # Wait for services to be ready
    print_status "Waiting for services to be ready..."
    sleep 10
    
    # Check service health
    check_services_health
}

# Check if services are healthy
check_services_health() {
    print_status "Checking service health..."
    
    services=("redis" "postgres" "prometheus" "grafana")
    
    for service in "${services[@]}"; do
        if docker compose ps $service | grep -q "healthy\|Up"; then
            print_success "$service is running"
        else
            print_warning "$service may not be ready yet"
        fi
    done
}

# Display service URLs
display_urls() {
    echo ""
    echo "🎉 Development environment is ready!"
    echo ""
    echo "📊 Service URLs:"
    echo "  • Mock AgentCore Runtime: http://localhost:8000"
    echo "  • Management Dashboard:   http://localhost:8080"
    echo "  • Prometheus:            http://localhost:9090"
    echo "  • Grafana:               http://localhost:3000 (admin/admin)"
    echo ""
    echo "🗄️  Database Connections:"
    echo "  • PostgreSQL: localhost:5432 (honeypot/honeypot_dev_password)"
    echo "  • Redis:      localhost:6379"
    echo ""
    echo "📝 Next Steps:"
    echo "  1. Edit .env file with your configuration"
    echo "  2. Run 'source venv/bin/activate' to activate virtual environment"
    echo "  3. Run 'python -m agents.detection' to start detection agent"
    echo "  4. Check logs with 'docker compose logs -f'"
    echo ""
}

# Main execution
main() {
    echo "🤖 AI-Powered Honeypot System"
    echo "Development Environment Setup"
    echo "=============================="
    echo ""
    
    check_python
    check_docker
    check_docker_compose
    setup_venv
    setup_env
    create_directories
    setup_pre_commit
    start_services
    display_urls
    
    print_success "Setup complete! 🎉"
}

# Run main function
main "$@"