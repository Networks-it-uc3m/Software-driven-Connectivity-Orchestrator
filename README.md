# Software-driven Connectivity Orchestrator
Repository including the source code developed to support the flexible, cost-efficient and reliable data-layer link communications among heterogeneous NFV Infrastructures. In particular, the repository contains implementation of an Software Defined Networking (SDN) framework, based on Ryu [1].  


## Quickstart

This section lists next the commands to install all the dependencies, and thus enable the execution of the implemented Ryu SDN framework:

1. Create the Python virtual environment (venv) to install the dependencies included in this repository:
```
# apt-get install python3-venv
# python3 -m venv ./venv
```

2. Activate the venv:
```
# cd venv
# source bin/activate
```

3. Install the dependencies (included in this repository with the requirements.txt file):
```
# pip install -r requirements.txt
```
 
4. Run the SDN framework based on Ryu, and the developed application:
````
# ryu-manager --observe-links l2s-sdn-framework-app.py
````

> **Note**:
> this development has been validated using **Linux Ubuntu 18.04.6 LTS** as Operating System, and **Python v3.6.9**. 

## References
[1] Ryu, component-based software defined networking framework [Online]. Available: https://ryu-sdn.org
