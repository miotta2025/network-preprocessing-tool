
# Análisis de Tráfico de Red a partir de PCAPs por Ventanas y Flujos

## Descripción

Este script permite analizar archivos `.pcap` (capturas de tráfico de red) utilizando `tshark`, `pandas` y `scipy`. Realiza el análisis dividiendo el tráfico en **ventanas de tamaño configurable (por paquetes)**, y también **por flujos TCP/UDP**, extrayendo métricas estadísticas detalladas en ambos niveles.

Se generan CSVs con estadísticas por:

- **Paquetes individuales**
- **Ventanas de tráfico** (con métricas agregadas)
- **Flujos de red** (agrupados por IPs y puertos en cada ventana)
- **Estadísticas combinadas** (flujos agregados por ventana + estadísticas generales)

---

## Requisitos

- Python 3.7 o superior
- Dependencias de Python:
  ```bash
  pip3 install pandas numpy scipy dpkt
  ```
- `tshark` instalado (Wireshark CLI)

---

## Uso

```bash
python preprocessing_tool.py archivo.pcap [--size_of_window N] [--modo MODO]
```

### Argumentos

- `archivo.pcap`: Ruta del archivo `.pcap` a analizar.
- `--size_of_window`: Número de paquetes por ventana (por defecto: `10`).
- `--modo`: Tipo de análisis que se desea ejecutar. Valores disponibles:
  - `paquetes`: Genera solo el CSV con todos los paquetes extraídos.
  - `ventana`: Estadísticas por ventana.
  - `flujos`: Estadísticas por flujo.
  - `combinada`: Estadísticas combinadas por ventana y flujo.
  - `all` (por defecto): Ejecuta todos los modos anteriores.

---

## Salidas

Según el modo seleccionado, se generarán los siguientes archivos:

- `paquetes_nombreArchivo.csv`: Todos los paquetes extraídos usando `tshark`.
- `estadisticas_ventanas_nombreArchivo.csv`: Estadísticas por ventanas.
- `estadisticas_flujo_nombreArchivo.csv`: Estadísticas por flujo.
- `estadisticas_combinadas_nombreArchivo.csv`: Estadísticas por ventana + flujos agregados.

Si no se selecciona ningún modo ni se especifica size_of_window, por defecto se generarán los cuatro archivos .csv y el número de paquetes por ventana será de 10.

---

## Métricas

###  Métricas por Paquete

| Atributo                    | Descripción                                                |
|-----------------------------|------------------------------------------------------------|
| ip.src                      | Dirección IP de origen                                     |
| ip.dst                      | Dirección IP de destino                                    |
| ip.proto                    | Protocolo IP (ej. TCP=6, UDP=17, ICMP=1)                   |
| frame.len                   | Longitud total del paquete (en bytes)                     |
| tcp.flags                   | Valor de flags TCP en hexadecimal                         |
| tcp.srcport                 | Puerto TCP de origen                                      |
| tcp.dstport                 | Puerto TCP de destino                                     |
| tcp.len                     | Longitud de los datos TCP                                 |
| udp.length                  | Longitud total del paquete UDP                            |
| tcp.hdr_len                 | Longitud de la cabecera TCP                               |
| udp.srcport                 | Puerto UDP de origen                                      |
| udp.dstport                 | Puerto UDP de destino                                     |
| eth.type                    | Tipo de protocolo Ethernet                                |
| llc.control                 | Campo de control LLC                                      |
| frame.time                  | Timestamp del paquete                                     |
| ip.ttl                      | Tiempo de vida (TTL) del paquete IP                       |
| ip.hdr_len                  | Longitud de la cabecera IP                                |
| tcp.analysis.initial_rtt    | RTT inicial estimada por TCP                              |
| tcp.connection.fin          | Indicador de finalización de conexión TCP                 |
| tcp.connection.syn          | Indicador de inicio de conexión TCP                       |
| tcp.flags.cwr               | Flag CWR (Congestion Window Reduced)                      |
| tcp.flags.ecn               | Flag ECN (Explicit Congestion Notification)               |
| tcp.urgent_pointer          | Puntero urgente de TCP                                    |
| ip.frag_offset              | Offset de fragmentación IP                                |
| eth.src_not_group           | Si la MAC de origen no pertenece a un grupo (booleano)    |



### Métricas por Ventana

| Atributo                   | Descripción                                       |
|----------------------------|---------------------------------------------------|
| Window                     | Número de la ventana                              |
| Header_Length              | Longitud media de la cabecera                     |
| Protocol_Type              | Tipo de protocolo IP (valor medio)                |
| TTL                        | Tiempo de vida promedio                           |
| fin_flag_number            | Promedio del flag TCP FIN                         |
| syn_flag_number            | Promedio del flag TCP SYN                         |
| rst_flag_number            | Promedio del flag TCP RST                         |
| psh_flag_number            | Promedio del flag TCP PSH                         |
| ack_flag_number            | Promedio del flag TCP ACK                         |
| ece_flag_number            | Promedio del flag TCP ECE                         |
| cwr_flag_number            | Promedio del flag TCP CWR                         |
| HTTP                       | Presencia del protocolo HTTP (puerto 80)          |
| HTTPS                      | Presencia del protocolo HTTPS (puerto 443)        |
| DNS                        | Presencia del protocolo DNS (puerto 53)           |
| Telnet                     | Presencia del protocolo Telnet (puerto 23)        |
| SMTP                       | Presencia del protocolo SMTP (puerto 25)          |
| SSH                        | Presencia del protocolo SSH (puerto 22)           |
| IRC                        | Presencia del protocolo IRC (puerto 6667)         |
| TCP                        | Tráfico TCP identificado                          |
| UDP                        | Tráfico UDP identificado                          |
| DHCP                       | Tráfico DHCP (identificado como ARP en el script) |
| ARP                        | Tráfico ARP identificado                          |
| ICMP                       | Tráfico ICMP identificado                         |
| IGMP                       | Tráfico IGMP identificado                         |
| IPV4                       | Tráfico IPv4 identificado                         |
| LLC                        | Tráfico con control LLC                           |
| IAT                        | Tiempo medio entre paquetes                       |
| Tot_size                   | Tamaño medio de los paquetes                      |
| tcp_analysis_initial_rtt   | RTT inicial TCP promedio                          |
| tcp_connection_fin         | Fin de conexión detectado                         |
| tcp_connection_syn         | Inicio de conexión detectado                      |
| tcp_flags_cwr              | Flag CWR medio                                    |
| tcp_flags_ecn              | Flag ECN medio                                    |
| tcp_urgent_pointer         | Puntero urgente promedio                          |
| ip_frag_offset             | Offset de fragmentación IP                        |
| eth_src_not_group          | Dirección MAC no perteneciente a grupo            |



### Métricas por Flujo

| Atributo                 | Descripción                                       |
|--------------------------|---------------------------------------------------|
| Window                   | Ventana a la que pertenece el flujo               |
| flow                     | Identificador del flujo (IPs y puertos)           |
| Rate                     | Tasa total de paquetes por segundo                |
| Srate                    | Tasa de paquetes forward                          |
| Drate                    | Tasa de paquetes backward                         |
| ack_count                | Número de paquetes con flag ACK                   |
| syn_count                | Número de paquetes con flag SYN                   |
| fin_count                | Número de paquetes con flag FIN                   |
| rst_count                | Número de paquetes con flag RST                   |
| Bytes                    | Total de bytes en el flujo                        |
| Min_Length               | Longitud mínima de los paquetes                   |
| Max_Length               | Longitud máxima de los paquetes                   |
| Avg_Length               | Longitud media de los paquetes                    |
| Std_Length               | Desviación estándar de la longitud de paquetes    |
| Number                   | Número de paquetes en el flujo                    |
| Magnite                  | Magnitud dinámica de los flujos                   |
| Radius                   | Radio dinámico de los flujos                      |
| Covariance               | Covarianza entre tráfico entrante y saliente      |
| Var_Ratio                | Ratio de varianza entre flujos                    |
| Weight                   | Peso dinámico (volumen del flujo)                 |
| Orig_Bytes               | Bytes enviados por el originador                  |
| Resp_Bytes               | Bytes enviados por el respondedor                 |
| Orig_Pkts                | Paquetes enviados por el originador               |
| Resp_Pkts                | Paquetes enviados por el respondedor              |
| flow_timestamps          | Tiempos del flujo completo                        |
| fwd_timestamps           | Tiempos de los paquetes forward                   |
| bwd_timestamps           | Tiempos de los paquetes backward                  |
| Fwd_Pkts_Tot             | Total de paquetes forward                         |
| Bwd_Pkts_Tot             | Total de paquetes backward                        |
| Fwd_Data_Pkts_Tot        | Paquetes de datos forward                         |
| Bwd_Data_Pkts_Tot        | Paquetes de datos backward                        |
| Fwd_Pkts_Per_Sec         | Tasa de paquetes forward por segundo              |
| Bwd_Pkts_Per_Sec         | Tasa de paquetes backward por segundo             |
| Flow_Pkts_Per_Sec        | Tasa total de paquetes por segundo en el flujo    |
| Fwd_Header_Size          | Tamaño de headers forward                         |
| Bwd_Header_Size          | Tamaño de headers backward                        |
| Fwd_Pkts_Payload         | Payload total forward                             |
| Bwd_Pkts_Payload         | Payload total backward                            |
| Flow_Pkts_Payload        | Payload total en el flujo                         |
| Fwd_IAT                  | Tiempo entre paquetes forward                     |
| Bwd_IAT                  | Tiempo entre paquetes backward                    |
| Flow_IAT                 | Tiempo entre cualquier paquete del flujo          |

---

## Ejemplo

```bash
python Example_Chunks.py TCP_IP.pcap --size_of_window 20 --modo all
```

Esto generará los cuatro CSVs con análisis completos sobre `TCP_IP.pcap`, agrupando cada 20 paquetes.

---

## Notas adicionales

- El script maneja archivos grandes usando `chunks` de 200,000 líneas para no agotar la memoria.
- Si `tshark` falla, revisad que esté correctamente instalado y que los campos usados estén disponibles en vuestro `.pcap`.
