# Módulo Zabbix: Controle Interativo e Zoom nos Mapas Nativos

Este módulo adiciona **controle fluido de zoom com o scroll do mouse**, **pan (arrastar)** e **botão de foco automático em alertas** diretamente nas telas de mapa nativas do Zabbix (`Monitoring -> Maps` e widgets de mapa no Dashboard). É a forma oficial do projeto de ter um mapa interativo: tudo fica dentro do Zabbix, sobre os mapas criados por `zabbix-autodiscovery maps`.

Requer Zabbix 6.4 ou mais novo (manifest v2).

---

## Como Instalar

### Docker (`deploy/docker-compose.yml`)
Nada a copiar: o container `zabbix-web` monta esta pasta, somente leitura, em `/usr/share/zabbix/modules/interactive_map_zoom` (diretório de módulos das imagens oficiais `zabbix/zabbix-web-*`).

### Zabbix instalado por pacotes
```bash
# Zabbix 7.0+ (frontend em /usr/share/zabbix/ui):
sudo cp -r deploy/zabbix-modules/interactive_map_zoom /usr/share/zabbix/ui/modules/
# Zabbix 6.4 (frontend em /usr/share/zabbix):
sudo cp -r deploy/zabbix-modules/interactive_map_zoom /usr/share/zabbix/modules/
```

## Como Ativar

* **Automático (Zabbix 7.0+):** `zabbix-autodiscovery maps` ativa o módulo pela API (token de Super admin). Se o módulo não estiver no frontend ou faltar permissão, o comando apenas avisa. Para não ativar, use `maps.enable_module: false` no `config.yaml`.
* **Manual:**
  1. Vá em **Administration** (Administração) -> **General** (Geral) -> **Modules** (Módulos).
  2. Clique em **Scan directory** (Escanear diretório).
  3. O módulo **NOC Interactive Map Controls** aparecerá como *Disabled*; clique em **Enable** (Ativar).

Ao abrir qualquer mapa (`Monitoring -> Maps`), os controles (zoom com scroll, arrastar, ajustar e focar alarme) aparecem sobre o mapa nativo.
