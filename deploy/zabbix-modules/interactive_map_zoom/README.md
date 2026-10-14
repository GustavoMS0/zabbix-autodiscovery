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

Ao abrir qualquer mapa (`Monitoring -> Maps`) ou um dashboard com widget de mapa, os controles aparecem no canto superior direito do mapa.

## Como Usar

| Ação | Como |
|---|---|
| Zoom | Roda do mouse (o ponto sob o cursor fica fixo) ou os botões `−` / `+` |
| Mover | Arrastar com o botão esquerdo (arrastar a partir de um host não abre o menu dele) |
| Ajustar | Botão **Ajustar** ou duplo clique: mostra o mapa inteiro, centralizado |
| Próximo alerta | Centraliza o próximo elemento com problema, do mais grave para o menos grave, e destaca-o com um anel |

O módulo só atua nos mapas nativos (SVG com `g.map-container`); gráficos, honeycomb e outros widgets não são alterados. O zoom escolhido é mantido quando o Zabbix atualiza o mapa. Na tela `Monitoring -> Maps`, a área do mapa fica limitada à janela e o arrastar substitui as barras de rolagem.

## Atualizar

Depois de atualizar os arquivos do módulo no servidor (Docker: `git pull` na pasta do projeto, o volume já aponta para ela), recarregue a página com **Ctrl+F5**. Se o Zabbix ainda servir a versão antiga, desative e ative o módulo em **Administration -> General -> Modules**.
