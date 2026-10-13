# Módulo Zabbix: Controle Interativo e Zoom nos Mapas Nativos

Este módulo adiciona **controle fluido de zoom com o scroll do mouse**, **pan (arrastar)** e **botão de foco automático em alertas** diretamente nas telas de mapa nativas do Zabbix (`Monitoring -> Maps` e widgets de mapa no Dashboard).

---

## Como Instalar no Servidor Zabbix

No servidor onde o Zabbix Web UI está instalado:

### 1. Copiar a pasta do módulo para o diretório de módulos do Zabbix:
```bash
# Se estiver no servidor local:
sudo cp -r deploy/zabbix-modules/interactive_map_zoom /usr/share/zabbix/ui/modules/

# Ou se for transferir do Windows via SCP:
scp -r deploy/zabbix-modules/interactive_map_zoom usuario@192.168.0.15:/tmp/
ssh usuario@192.168.0.15 "sudo mv /tmp/interactive_map_zoom /usr/share/zabbix/ui/modules/ && sudo chown -R www-data:www-data /usr/share/zabbix/ui/modules/interactive_map_zoom"
```

### 2. Ativar no Zabbix Web:
1. Acesse o Zabbix: `http://192.168.0.15:8080`
2. Vá em **Administration** (Administração) -> **General** (Geral) -> **Modules** (Módulos).
3. Clique no botão **Scan directory** (Escanear diretório) no canto superior direito.
4. O módulo **NOC Interactive Map Controls** aparecerá listado como *Disabled*.
5. Clique em **Enable** (Ativar).

Pronto! Ao abrir qualquer mapa (`Monitoring -> Maps`), os controles interativos (zoom com scroll, arrastar e focar alarme) estarão ativos instantaneamente sobre o mapa nativo.

