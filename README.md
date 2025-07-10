# MIOTTA-NPT: Network Traffic Analysis Tool for IoMT and IoT Research

## 🔍 Descripción general

**MIOTTA-NPT** es una herramienta de preprocesamiento de tráfico de red diseñada para facilitar el análisis de archivos `.pcap`. Permite extraer estadísticas en formato `.csv` a partir de:
- Métricas por paquetes individuales
- Agrupación por **ventanas** de tamaño configurable
- Agrupación por **flujos** (TCP/UDP)
- Representaciones en **crudo de paquetes** usando el estándar [nPrint](https://github.com/nprint/nprint)

Este repositorio está pensado para investigadores que trabajan en la detección de intrusiones (IDS), aprendizaje automático en redes, y análisis de tráfico en entornos **IoT/IoMT**.

---

## ⚙️ Instalación

### Requisitos generales

- Python 3.8+
- `tshark` (CLI de Wireshark)
- Compilación de `nPrint` (modificado para soporte ARP)

### Instalación de dependencias

```bash
pip install -r requirements.txt

```

### Compilar nPrint (una vez)

```bash
cd nprint
make
```

## 🚀 Ejecución rápida

```bash
python3 miotta_npt.py archivo.pcap --config config/example_config.yaml
```

## 🛠️ Archivo de configuración YAML

Ejemplo básico (`config/example_config.yaml`):

```yaml
mode: "nprint"              # o "classic"
output_dir: "./output"

classic:
  mode: all                 # Tipo de análisis (paquetes, ventanas, flujos, combinada, all)
  size_of_window: 10        # Número de paquetes por ventana

nprint:
  headers: [ethernet, ipv4, ipv6, absolute_time, icmp, tcp, udp, relative_time, arp]    # Headers de los protocolos incluidos en el output
  masks: [ethernet, arp, ipv4, ipv6, tcp, udp, ip, icmp]                                # Headers de los cuales eliminar información de localización
```

## 📂 Salidas generadas

Según el método, se generan CSVs en la carpeta `output/`.

### Estadístico (`preprocessing_tool.py`)
- `paquetes_*.csv`: tráfico completo
- `estadisticas_ventanas_*.csv`: agrupación por ventanas
- `estadisticas_flujo_*.csv`: agrupación por flujo
- `estadisticas_combinadas_*.csv`: combinación de ambos

### nPrint (`preprocessing_tool_nprint.py`)
- `nprint_output.csv`: representación cruda de cabeceras binarias

## 📁 Estructura del repositorio

```bash
miotta-npt/
├── miotta_npt.py                 # Script principal
├── preprocessing_tool.py         # Procesamiento estadístico
├── preprocessing_tool_nprint.py  # Procesamiento con nPrint
├── config/
│   └── example_config.yaml
├── output/
├── nprint/
│   └── (fuentes + Makefile)
├── requirements.txt
└── README.md
```

## 📜 Licencia

Este proyecto puede utilizarse bajo la licencia MIT.


