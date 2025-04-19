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
go run main.go -pcap=Example.pcap
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

---

## Images

![Preview](https://cdn.discordapp.com/attachments/1351649169051488279/1362930133492830249/image.png?ex=68058099&is=68042f19&hm=3f71ef62b3852b1aa4097f713b1999d2e79749404e2106b66d5cff34eb2745ff)


## Contact

- Telegram: [t.me/sheepthesillycat](https://t.me/sheepthesillycat)
- Telegram Channel: [t.me/sheepsbio](https://t.me/sheepsbio)
- Website: [sheepyy.love](https://sheepyy.love)
