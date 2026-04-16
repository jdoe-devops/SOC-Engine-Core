# Infrastructure Testing Environment

> **Maintainer:** Jamal Doe ([@jdoe-devops](https://github.com/jdoe-devops))  
> **Last Updated:** 2026-03-15

## Overview

This directory contains the infrastructure configuration files for the SOC Engine Core testing environment, hosted at the CyberAlam Solutions Shah Alam lab.

## Network Architecture

```
                    ┌──────────────┐
                    │   pfSense    │
                    │  (Gateway)   │
                    └──────┬───────┘
                           │
            ┌──────────────┼──────────────┐
            │              │              │
     ┌──────┴──────┐ ┌────┴────┐ ┌───────┴──────┐
     │  LAN VLAN   │ │SOC VLAN │ │FORENSICS VLAN│
     │ 10.200.0/24 │ │10.200.1 │ │ 10.200.2/24  │
     │  (Office)   │ │  /24    │ │  (Isolated)  │
     └─────────────┘ └─────────┘ └──────────────┘
                       DevStack      IRENE
                       Cluster       Sandbox
```

## Components

### DevStack (OpenStack) — `devstack/local.conf`

Local OpenStack deployment used to spin up testing VMs for the SOC Engine. The DevStack instance creates:
- **Floating IP pool** for external access to test VMs
- **Internal network** for inter-service communication
- **Neutron networking** with OVS bridge

### pfSense Firewall — `pfsense/config.xml`

pfSense firewall backup configuration controlling traffic between the three VLANs:

| VLAN | Subnet | Purpose |
|------|--------|---------|
| LAN | `10.200.0.0/24` | Office network |
| SOC_ENGINE_VLAN | `10.200.1.0/24` | SOC Engine testing cluster |
| FORENSICS_VLAN | `10.200.2.0/24` | IRENE isolated analysis sandbox |

Key rules:
- SOC Engine can receive syslog from LAN
- SOC Engine can submit samples to IRENE sandbox
- IRENE sandbox is **blocked from internet access** (isolation requirement)
- IRENE can write results back to SOC Engine database only

## Deployment Steps

1. Import `pfsense/config.xml` into a clean pfSense installation
2. Configure DevStack using `devstack/local.conf`
3. Run `stack.sh` to deploy OpenStack
4. Provision test VMs and install the SOC Engine
5. Deploy IRENE modules to the sandbox nodes

## ⚠️ Security Notes

- Change all default passwords in `local.conf` before deploying
- The pfSense config uses lab-only credentials — **do not use in production**
- IRENE sandbox must remain air-gapped from the internet at all times
