.PHONY: build run clean status logs stop help check-perms

# Detectar arquitetura e definir variáveis
ARCH := $(shell uname -m)
ifeq ($(ARCH), x86_64)
  export MASSCAN_IMAGE := ilyaglow/masscan:latest
  export MASSCAN_PLATFORM := linux/amd64
  export NMAP_PLATFORM := linux/amd64
else ifeq ($(ARCH), aarch64)
  export MASSCAN_IMAGE := letiemble/masscan:latest
  export MASSCAN_PLATFORM := linux/arm64
  export NMAP_PLATFORM := linux/arm64
else
  $(error Arquitetura $(ARCH) não suportada)
endif

# Exportar UID/GID para uso no docker-compose
export UID := $(shell id -u)
export GID := $(shell id -g)

build:
	@echo "🔨 Building containers for $(ARCH)..."
	docker compose build

check-perms:
	@echo "🔐 Verificando permissões..."
	@./scripts/check_perms.sh

run: build check-perms
	@echo "🚀 Starting full security scan..."
	@chmod +x scripts/*.sh
	@mkdir -p outputs/masscan outputs/scan_results
	./scripts/run_full_scan.sh

status:
	@echo "📊 Container status:"
	docker compose ps

logs:
	@echo "📋 Following logs..."
	docker compose logs -f

stop:
	@echo "🛑 Stopping all containers..."
	docker compose down

clean:
	@echo "🧹 Cleaning outputs..."
	rm -rf outputs/*
	docker compose down --volumes

help:
	@echo "Available targets:"
	@echo "  build       - Build all Docker containers"
	@echo "  run         - Run full security scan pipeline"
	@echo "  status      - Show container status"
	@echo "  logs        - Follow container logs"
	@echo "  stop        - Stop all containers"
	@echo "  clean       - Clean outputs and stop containers"
	@echo "  check-perms - Check and fix permissions"
	@echo "  help        - Show this help"