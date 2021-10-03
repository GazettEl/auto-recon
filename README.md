# auto-recon

## Uso 

### La herramienta tiene dos modos de operación.

Escanear un host
```bash
sudo bash scan.sh hosts_alive 10.10.10.10
```
Descubir y escanear una subred
```bash
sudo bash scan.sh scan_host 10.10.10.0/24
```

Al finalizar, obtendremos algunos archivos .nmap con los resultados.

## Usage

### This tool has two modes of operation

Scan a single host
```bash
sudo bash scan.sh hosts_alive 10.10.10.10
```
Discover and scan a subnet
```bash
sudo bash scan.sh scan_host 10.10.10.0/24
```

At the end, we will have some .nmap files with the results.
