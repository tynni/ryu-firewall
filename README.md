# SDN Firewall with Ryu

An adaptive Software-Defined Networking (SDN) firewall built using the **Ryu controller** and tested in **Mininet**.  
This project demonstrates how SDN programmability can detect abnormal traffic and dynamically install blocking rules in real time.

## 🧠 Project Purpose

Traditional firewalls rely on static rules and are hard to update during attacks.  
Our goal is to build a **dynamic SDN firewall** that:

- Monitors network traffic using OpenFlow statistics  
- Detects abnormal or excessive flows  
- Automatically installs DROP rules to block suspicious sources  
- Compares **Static Firewall** vs **Dynamic Firewall** performance  
- Shows why SDN is powerful for network security and control  

Everything stays **within SDN** (Ryu ↔ OpenFlow ↔ OVS ↔ Mininet).

## Project Structure

```
ryu-firewall/
├── controller/
│   ├── dynamic_firewall.py    # Ryu controller app: dynamic detection + blocking
│   └── static_firewall.py     # Ryu controller app: static ACLs for comparison
├── topology/
│   └── simple_topo.py         # Mininet topology(s) used for experiments
├── tests/
│   ├── normal_traffic.sh      # Script to generate benign/normal traffic
│   ├── attack_traffic.sh      # Script to generate attack traffic (e.g., flood)
│   └── benchmarks.py          # Benchmarks and measurement harness
├── README.md                  # Project overview and run instructions
```

- **`controller/`**: Contains Ryu controller applications. Use `dynamic_firewall.py` to run the adaptive firewall that monitors flows and installs blocking rules; use `static_firewall.py` to run a baseline firewall with static rules for comparison.
- **`topology/`**: Mininet topology definitions and helper scripts. `simple_topo.py` defines a small topology used in experiments and tests.
- **`tests/`**: Traffic generation and benchmark utilities. `normal_traffic.sh` and `attack_traffic.sh` create traffic patterns; `benchmarks.py` runs experiments and saves metrics for later analysis.
- **`README.md`**: This file — contains purpose, structure, and quick run instructions.

## How to Run this Project

### **1. Clone inside your Mininet VM**
```bash
git clone https://github.com/<yourteam>/sdn-firewall.git
cd sdn-firewall
```
### **2. Run a Ryu controller**
```bash
ryu-manager controller/dynamic_firewall.py
or 
ryu-manager controller/static_firewall.py
```
### **3. Start Mininet**
```bash
sudo mn --topo single,3 --controller=remote,ip=127.0.0.1
```
### **4. Start Tests**
```bash
sudo ./tests/normal_traffic.sh
sudo ./tests/attack_traffic.sh
sudo python3 tests/benchmarks.py
```