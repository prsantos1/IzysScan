#!/usr/bin/env bash
set -Eeuo pipefail

log() { 
    echo "$(date '+%Y-%m-%d %H:%M:%S') [$(basename "$0")] $*" >&2
}

# Dependências necessárias
deps=(jq curl docker)

# Detectar sistema operacional e gerenciador de pacotes
detect_system() {
    if command -v apt &>/dev/null; then
        echo "apt"
    elif command -v yum &>/dev/null; then
        echo "yum"
    elif command -v dnf &>/dev/null; then
        echo "dnf"
    elif command -v pacman &>/dev/null; then
        echo "pacman"
    elif command -v brew &>/dev/null; then
        echo "brew"
    else
        return 1
    fi
}

# Instalar pacote conforme o sistema
install_package() {
    local pkg="$1"
    local pkg_mgr="$2"
    
    case "$pkg_mgr" in
        apt)
            sudo apt install -y "$pkg"
            ;;
        yum|dnf)
            sudo "$pkg_mgr" install -y "$pkg"
            ;;
        pacman)
            sudo pacman -S --noconfirm "$pkg"
            ;;
        brew)
            brew install "$pkg"
            ;;
        *)
            log "[ERROR] Gerenciador de pacotes não suportado: $pkg_mgr"
            return 1
            ;;
    esac
}

# Verificar se Docker está rodando
check_docker() {
    if ! docker info &>/dev/null; then
        log "[WARN] Docker não está rodando. Tentando iniciar..."
        
        if command -v systemctl &>/dev/null; then
            sudo systemctl start docker
            sudo systemctl enable docker
        elif command -v service &>/dev/null; then
            sudo service docker start
        else
            log "[ERROR] Não foi possível iniciar o Docker automaticamente"
            log "[INFO] Inicie manualmente: sudo systemctl start docker"
            return 1
        fi
        
        # Aguardar Docker inicializar
        for i in {1..10}; do
            if docker info &>/dev/null; then
                log "[OK] Docker iniciado com sucesso"
                break
            fi
            log "[INFO] Aguardando Docker inicializar... ($i/10)"
            sleep 2
        done
        
        if ! docker info &>/dev/null; then
            log "[ERROR] Falha ao inicializar Docker"
            return 1
        fi
    else
        log "[OK] Docker está rodando"
    fi
}

# Verificar se Docker Compose está disponível
check_docker_compose() {
    if docker compose version &>/dev/null; then
        log "[OK] docker compose (plugin) encontrado"
        return 0
    elif command -v docker-compose &>/dev/null; then
        log "[OK] docker-compose (standalone) encontrado"
        return 0
    else
        log "[ERROR] Docker Compose não encontrado"
        log "[INFO] Instale com: sudo apt install docker-compose-plugin"
        return 1
    fi
}

# Verificar permissões do Docker
check_docker_permissions() {
    if ! docker ps &>/dev/null; then
        log "[WARN] Usuário $(whoami) não tem permissões Docker"
        log "[INFO] Adicionando usuário ao grupo docker..."
        
        sudo usermod -aG docker "$USER"
        log "[INFO] Faça logout/login ou execute: newgrp docker"
        log "[INFO] Ou execute com sudo se necessário"
    else
        log "[OK] Permissões Docker OK"
    fi
}

# Script principal
log "[INFO] ===== Verificação de Dependências ====="

# Detectar sistema
pkg_mgr=$(detect_system) || {
    log "[ERROR] Sistema não suportado. Instale manualmente:"
    log "  - jq, curl, docker, docker-compose"
    exit 1
}

log "[INFO] Sistema detectado: $pkg_mgr"

# Verificar dependências básicas
log "[INFO] Verificando dependências básicas..."
missing=()

for cmd in "${deps[@]}"; do
    if command -v "$cmd" &>/dev/null; then
        version=$("$cmd" --version 2>/dev/null | head -1 || echo "versão não disponível")
        log "[OK] $cmd: $version"
    else
        missing+=("$cmd")
        log "[MISSING] $cmd"
    fi
done

# Instalar dependências ausentes
if (( ${#missing[@]} > 0 )); then
    log "[INFO] Instalando dependências ausentes: ${missing[*]}"
    
    # Atualizar cache de pacotes
    case "$pkg_mgr" in
        apt)
            log "[INFO] Atualizando cache de pacotes..."
            sudo apt update
            ;;
        yum|dnf)
            sudo "$pkg_mgr" makecache
            ;;
    esac
    
    # Instalar cada dependência
    for pkg in "${missing[@]}"; do
        log "[INFO] Instalando $pkg..."
        
        # Mapeamento de nomes de pacotes específicos do sistema
        case "$pkg" in
            docker)
                case "$pkg_mgr" in
                    apt) pkg="docker.io" ;;
                    yum|dnf) pkg="docker" ;;
                esac
                ;;
        esac
        
        if ! install_package "$pkg" "$pkg_mgr"; then
            log "[ERROR] Falha ao instalar $pkg"
            exit 1
        fi
    done
    
    log "[OK] Todas as dependências foram instaladas"
else
    log "[OK] Todas as dependências básicas estão instaladas"
fi

# Verificações específicas do Docker
log "[INFO] Verificando configuração do Docker..."

check_docker || exit 1
check_docker_compose || exit 1
check_docker_permissions

# Verificar se Docker Compose plugin está disponível
if ! (docker compose version &>/dev/null); then
    log "[WARN] Docker Compose plugin não encontrado, instalando..."
    case "$pkg_mgr" in
        apt)
            sudo apt install -y docker-compose-plugin
            ;;
        yum|dnf)
            sudo "$pkg_mgr" install -y docker-compose-plugin
            ;;
    esac
fi

# Teste final
log "[INFO] Testando configuração..."
if docker compose version &>/dev/null && jq --version &>/dev/null; then
    log "[SUCCESS] ✅ Todas as dependências estão funcionando!"
else
    log "[ERROR] ❌ Algumas dependências não estão funcionando corretamente"
    exit 1
fi

log "[INFO] Sistema pronto para executar IzysScan!"