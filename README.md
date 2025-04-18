# PCAPHeatmap

**PCAPHeatmap** is a Go-based tool that analyzes **PCAP** files and generates detailed heatmaps for various packet-level metrics, such as IPs, ports, packet sizes, TTL values, protocols, and TCP flags. It helps users visually explore network traffic by extracting key information and providing insightful summaries.

With **PCAPHeatmap**, users can examine the contents of **network traffic**, filtered by **destination IP** and optionally export the results in **JSON** format for further analysis.

---

## Features

- Parses **IPv4** packets from **PCAP** files  
- Filters traffic based on **destination IP**  
- Generates **heatmaps** for:
  - Source IPs and Ports  
  - Destination IPs and Ports  
  - Packet Sizes  
  - Time-to-Live (TTL) values  
  - Protocol Types (TCP, UDP, ICMPv4, ICMPv6)  
  - TCP Flags (SYN, ACK, FIN, etc.)  
  - Application Payloads (truncated and displayed in hex format)  
- **Export results** as a **JSON** file for further analysis  
- **Color-coded output** for visual heatmaps in the terminal

---

### Dependencies

To install the necessary dependencies, run:

```sh
go get github.com/google/gopacket
```

---

## Installation

Ensure you have **Go 1.18+** installed.

```sh
git clone https://github.com/lilsheepyy/pcap-heatmap
cd pcap-heatmap
go run main.go -pcap=/path/to/your/file.pcap
```

## Options

- `-pcap` → Path to the **PCAP** file (required)
- `-destip` → **Destination IP** filter (optional)
- `-export` → Path to export results as a **JSON** file (optional)

---

## Example

```sh
go run heatmap.go -pcap=traffic.pcap -destip=192.168.1.1 -export=output.json
```
---

This command will:

- Analyze the `traffic.pcap` file
- Filter traffic to only include packets with destination IP `192.168.1.1`
- Export the results as a **JSON** file `output.json`

---

## Output

The program will print heatmaps of the top results for the following:

- **Source IPs**
- **Source Ports**
- **Packet Sizes**
- **TTL (Time-to-Live) values**
- **Destination IPs**
- **Destination Ports**
- **Top Payloads (hex, truncated)**
- **Top TCP Flags**
- **Top Protocols**

