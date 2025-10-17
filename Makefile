# AI Honeypot System - Development Makefile

.PHONY: help setup dev-up dev-down test lint format clean install build deploy

# Default target
help:
	@echo "AI-Powered Honeypot System - Development Commands"
	@echo "=================================================="
	@echo ""
	@echo "Setup Commands:"
	@echo "  setup          Setup development environment"
	@echo "  install        Install Python dependencies"
	@echo ""
	@echo "Development Commands:"
	@echo "  dev-up         Start development services"
	@echo "  dev-down       Stop development services"
	@echo "  dev-logs       Show development service logs"
	@echo "  dev-shell      Open shell in development container"
	@echo ""
	@echo "Code Quality Commands:"
	@echo "  test           Run all tests"
	@echo "  test-unit      Run unit tests only"
	@echo "  test-integration Run integration tests only"
	@echo "  lint           Run linting checks"
	@echo "  format         Format code with black"
	@echo "  type-check     Run type checking with mypy"
	@echo ""
	@echo "Agent Commands:"
	@echo "  run-detection  Run detection agent locally"
	@echo "  run-coordinator Run coordinator agent locally"
	@echo "  run-interaction Run interaction agent locally"
	@echo "  run-intelligence Run intelligence agent locally"
	@echo ""
	@echo "Deployment Commands:"
	@echo "  build          Build Docker images"
	@echo "  deploy-local   Deploy to local environment"
	@echo "  deploy-aws     Deploy to AWS"
	@echo "  deploy-agentcore Deploy to AgentCore Runtime"
	@echo ""
	@echo "Utility Commands:"
	@echo "  clean          Clean up temporary files"
	@echo "  reset          Reset development environment"
	@echo ""

# Setup development environment
setup:
	@echo "🚀 Setting up development environment..."
	./deployment/scripts/setup-dev-env.sh

# Install Python dependencies
install:
	@echo "📦 Installing dependencies..."
	pip install -r requirements.txt
	pip install -e .

# Start development services
dev-up:
	@echo "🐳 Starting development services..."
	docker compose up -d
	@echo "✅ Services started. Check status with 'make dev-logs'"

# Stop development services
dev-down:
	@echo "🛑 Stopping development services..."
	docker compose down

# Show development service logs
dev-logs:
	docker compose logs -f

# Open shell in development container
dev-shell:
	docker compose exec mock-agentcore /bin/bash

# Run all tests
test:
	@echo "🧪 Running all tests..."
	pytest tests/ -v --cov=agents --cov=honeypots --cov=config

# Run unit tests only
test-unit:
	@echo "🧪 Running unit tests..."
	pytest tests/unit/ -v

# Run integration tests only
test-integration:
	@echo "🧪 Running integration tests..."
	pytest tests/integration/ -v

# Run linting checks
lint:
	@echo "🔍 Running linting checks..."
	flake8 agents/ honeypots/ config/ tests/
	black --check agents/ honeypots/ config/ tests/

# Format code with black
format:
	@echo "🎨 Formatting code..."
	black agents/ honeypots/ config/ tests/
	isort agents/ honeypots/ config/ tests/

# Run type checking
type-check:
	@echo "🔍 Running type checks..."
	mypy agents/ honeypots/ config/

# Run detection agent locally
run-detection:
	@echo "🔍 Starting Detection Agent..."
	python -m agents.detection.main

# Run coordinator agent locally
run-coordinator:
	@echo "🎯 Starting Coordinator Agent..."
	python -m agents.coordinator.main

# Run interaction agent locally
run-interaction:
	@echo "💬 Starting Interaction Agent..."
	python -m agents.interaction.main

# Run intelligence agent locally
run-intelligence:
	@echo "🧠 Starting Intelligence Agent..."
	python -m agents.intelligence.main

# Build Docker images
build:
	@echo "🏗️ Building Docker images..."
	docker compose build

# Deploy to local environment
deploy-local:
	@echo "🚀 Deploying to local environment..."
	make build
	make dev-up

# Deploy to AWS
deploy-aws:
	@echo "☁️ Deploying to AWS..."
	./deployment/scripts/deploy-aws.sh

# Deploy to AgentCore Runtime
deploy-agentcore:
	@echo "🤖 Deploying to AgentCore Runtime..."
	./deployment/scripts/deploy-agentcore.sh

# Clean up temporary files
clean:
	@echo "🧹 Cleaning up..."
	find . -type f -name "*.pyc" -delete
	find . -type d -name "__pycache__" -delete
	find . -type d -name "*.egg-info" -exec rm -rf {} +
	find . -type f -name ".coverage" -delete
	find . -type d -name ".pytest_cache" -exec rm -rf {} +
	find . -type d -name ".mypy_cache" -exec rm -rf {} +

# Reset development environment
reset:
	@echo "🔄 Resetting development environment..."
	make dev-down
	docker compose down -v
	docker system prune -f
	make clean
	make setup

# Database commands
db-migrate:
	@echo "🗄️ Running database migrations..."
	alembic upgrade head

db-reset:
	@echo "🗄️ Resetting database..."
	docker compose exec postgres psql -U honeypot -d honeypot_intelligence -c "DROP SCHEMA IF EXISTS honeypot CASCADE; CREATE SCHEMA honeypot;"
	make db-migrate

# Monitoring commands
monitor:
	@echo "📊 Opening monitoring dashboards..."
	@echo "Prometheus: http://localhost:9090"
	@echo "Grafana: http://localhost:3000 (admin/admin)"
	@echo "Dashboard: http://localhost:8080"

# Security scan
security-scan:
	@echo "🔒 Running security scan..."
	safety check
	bandit -r agents/ honeypots/ config/

# Generate documentation
docs:
	@echo "📚 Generating documentation..."
	sphinx-build -b html docs/ docs/_build/html