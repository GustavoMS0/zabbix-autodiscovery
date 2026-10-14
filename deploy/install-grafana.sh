#!/usr/bin/env bash
# ==============================================================================
# zabbix-autodiscovery: Instalador Automatizado do Grafana
# Para servidores onde o Zabbix já está rodando.
#
# Uso:
#   chmod +x deploy/install-grafana.sh
#   ./deploy/install-grafana.sh [docker|native]
# ==============================================================================
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
ENV_FILE="$SCRIPT_DIR/.env"
EXAMPLE_ENV="$SCRIPT_DIR/.env.example"

echo "========================================================================"
echo "  Instalação do Grafana Integrado ao Zabbix (AutoDiscovery NOC)"
echo "========================================================================"

# 1. Carregar ou criar deploy/.env
if [ ! -f "$ENV_FILE" ]; then
    if [ -f "$EXAMPLE_ENV" ]; then
        cp "$EXAMPLE_ENV" "$ENV_FILE"
        echo "[+] Criado deploy/.env a partir do modelo de exemplo."
    else
        touch "$ENV_FILE"
    fi
fi

# Detectar IP local
LOCAL_IP=$(hostname -I 2>/dev/null | awk '{print $1}' || echo "127.0.0.1")

# Solicitar configurações básicas se ainda não definidas
echo ""
echo "--- Configuração de Conexão com o Zabbix ---"
DEFAULT_URL="http://${LOCAL_IP}:8080/api_jsonrpc.php"
if grep -q "^ZABBIX_API_URL=" "$ENV_FILE" && ! grep -q "zabbix-web:8080" "$ENV_FILE"; then
    CURRENT_URL=$(grep "^ZABBIX_API_URL=" "$ENV_FILE" | cut -d= -f2-)
    DEFAULT_URL="$CURRENT_URL"
fi

read -r -p "URL da API do Zabbix [$DEFAULT_URL]: " INPUT_URL
ZBX_URL="${INPUT_URL:-$DEFAULT_URL}"

read -r -p "Usuário do Grafana no Zabbix [grafana]: " INPUT_USER
ZBX_USER="${INPUT_USER:-grafana}"

# Senha do Zabbix Grafana User
DEFAULT_ZBX_PASS="GrafanaZabbix@$(date +%Y)"
if grep -q "^ZABBIX_GRAFANA_PASSWORD=" "$ENV_FILE" && ! grep -q "change-me" "$ENV_FILE"; then
    DEFAULT_ZBX_PASS=$(grep "^ZABBIX_GRAFANA_PASSWORD=" "$ENV_FILE" | cut -d= -f2-)
fi
read -r -p "Senha do usuário $ZBX_USER no Zabbix [$DEFAULT_ZBX_PASS]: " INPUT_ZBX_PASS
ZBX_PASS="${INPUT_ZBX_PASS:-$DEFAULT_ZBX_PASS}"

# Senha do Admin do Grafana
DEFAULT_ADMIN_PASS="admin@123"
if grep -q "^GRAFANA_ADMIN_PASSWORD=" "$ENV_FILE" && ! grep -q "change-me" "$ENV_FILE"; then
    DEFAULT_ADMIN_PASS=$(grep "^GRAFANA_ADMIN_PASSWORD=" "$ENV_FILE" | cut -d= -f2-)
fi
read -r -p "Senha do usuário 'admin' do Grafana [$DEFAULT_ADMIN_PASS]: " INPUT_ADMIN_PASS
ADMIN_PASS="${INPUT_ADMIN_PASS:-$DEFAULT_ADMIN_PASS}"

# Atualizar deploy/.env
sed -i '/^ZABBIX_API_URL=/d' "$ENV_FILE" 2>/dev/null || true
sed -i '/^ZABBIX_GRAFANA_USER=/d' "$ENV_FILE" 2>/dev/null || true
sed -i '/^ZABBIX_GRAFANA_PASSWORD=/d' "$ENV_FILE" 2>/dev/null || true
sed -i '/^GRAFANA_ADMIN_PASSWORD=/d' "$ENV_FILE" 2>/dev/null || true

cat <<EOF >> "$ENV_FILE"
ZABBIX_API_URL=${ZBX_URL}
ZABBIX_GRAFANA_USER=${ZBX_USER}
ZABBIX_GRAFANA_PASSWORD=${ZBX_PASS}
GRAFANA_ADMIN_PASSWORD=${ADMIN_PASS}
EOF

echo "[+] Configurações salvas em deploy/.env."

# Escolher método de instalação (Docker vs Nativo)
MODE="$1"
if [ -z "$MODE" ]; then
    echo ""
    echo "Como deseja instalar o Grafana?"
    echo "  1) Docker Compose (Recomendado - isolado, já inclui plugins e dashboards)"
    echo "  2) Pacote Nativo Linux (apt/systemd - sem Docker)"
    read -r -p "Escolha [1]: " CHOICE
    if [ "$CHOICE" = "2" ]; then
        MODE="native"
    else
        MODE="docker"
    fi
fi

if [ "$MODE" = "docker" ]; then
    echo ""
    echo "--- Instalando via Docker Compose ---"
    if ! command -v docker &>/dev/null; then
        echo "[!] Docker não encontrado. Instalando Docker oficial..."
        curl -fsSL https://get.docker.com | sh
        sudo systemctl enable --now docker
        if [ -n "$USER" ]; then
            sudo usermod -aG docker "$USER" 2>/dev/null || true
        fi
    fi

    COMPOSE_CMD="docker compose"
    if ! docker compose version &>/dev/null; then
        if command -v docker-compose &>/dev/null; then
            COMPOSE_CMD="docker-compose"
        else
            echo "[!] docker compose plugin não encontrado. Instalando docker-compose-plugin..."
            sudo apt-get update && sudo apt-get install -y docker-compose-plugin || true
        fi
    fi

    cd "$SCRIPT_DIR"
    echo "[+] Subindo container do Grafana (porta 3000)..."
    $COMPOSE_CMD --profile grafana up -d

    echo ""
    echo "========================================================================"
    echo "  Grafana instalado e rodando com sucesso via Docker!"
    echo "  URL     : http://${LOCAL_IP}:3000"
    echo "  Usuário : admin"
    echo "  Senha   : ${ADMIN_PASS}"
    echo "  Plugin  : Alexanderzobnin Zabbix App pré-instalado"
    echo "  Pastas  : Dashboards pré-carregados na pasta 'Zabbix AutoDiscovery'"
    echo "========================================================================"

elif [ "$MODE" = "native" ]; then
    echo ""
    echo "--- Instalando Pacote Nativo Grafana no Linux ---"
    sudo apt-get update
    sudo apt-get install -y apt-transport-https software-properties-common wget curl

    # Adicionar repositório oficial da Grafana Labs
    sudo mkdir -p /etc/apt/keyrings/
    wget -q -O - https://apt.grafana.com/gpg.key | gpg --dearmor | sudo tee /etc/apt/keyrings/grafana.gpg > /dev/null
    echo "deb [signed-by=/etc/apt/keyrings/grafana.gpg] https://apt.grafana.com stable main" | sudo tee /etc/apt/sources.list.d/grafana.list

    sudo apt-get update
    sudo apt-get install -y grafana

    echo "[+] Instalando plugin Zabbix no Grafana..."
    sudo grafana-cli plugins install alexanderzobnin-zabbix-app || true

    # Provisionamento do Datasource Zabbix
    sudo mkdir -p /etc/grafana/provisioning/datasources /etc/grafana/provisioning/dashboards /var/lib/grafana/dashboards
    cat <<EOF | sudo tee /etc/grafana/provisioning/datasources/zabbix.yaml > /dev/null
apiVersion: 1
datasources:
  - name: Zabbix
    uid: zabbix
    type: alexanderzobnin-zabbix-datasource
    access: proxy
    url: "${ZBX_URL}"
    isDefault: true
    editable: true
    jsonData:
      username: "${ZBX_USER}"
      trends: true
      trendsFrom: "7d"
      trendsRange: "4d"
      cacheTTL: "1h"
    secureJsonData:
      password: "${ZBX_PASS}"
EOF

    cat <<EOF | sudo tee /etc/grafana/provisioning/dashboards/autodiscovery.yaml > /dev/null
apiVersion: 1
providers:
  - name: autodiscovery
    folder: Zabbix AutoDiscovery
    type: file
    allowUiUpdates: true
    options:
      path: /var/lib/grafana/dashboards
EOF

    # Copiar dashboards pré-construídos
    if [ -d "$SCRIPT_DIR/grafana/dashboards" ]; then
        sudo cp -r "$SCRIPT_DIR/grafana/dashboards/"*.json /var/lib/grafana/dashboards/ 2>/dev/null || true
        sudo chown -R grafana:grafana /var/lib/grafana/dashboards /etc/grafana/provisioning
    fi

    # Definir senha do admin do Grafana via CLI
    sudo systemctl daemon-reload
    sudo systemctl enable --now grafana-server
    sleep 3
    sudo grafana-cli admin reset-admin-password "$ADMIN_PASS" || true

    echo ""
    echo "========================================================================"
    echo "  Grafana nativo instalado e rodando com sucesso no Linux!"
    echo "  URL     : http://${LOCAL_IP}:3000"
    echo "  Usuário : admin"
    echo "  Senha   : ${ADMIN_PASS}"
    echo "  Serviço : systemctl status grafana-server"
    echo "========================================================================"
fi
