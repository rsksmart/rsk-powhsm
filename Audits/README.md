# PowHSM – Security Audits

## Overview

This directory contains public security audits performed on the PowHSM project.

PowHSM is a critical component of the Rootstock PowPeg infrastructure. It protects private keys held by the pegnatories, used to authorize Bitcoin peg-out transactions and enforces authorization rules based on accumulated proof-of-work.

Given its security-critical role, PowHSM has undergone independent third-party security assessments.

## Audit History

### 1. NCC Group – Security Assessment (2022)

Auditor: NCC Group

Date: October 2022

Scope: Security assessment of IOV Labs PowHSM

Report:
https://research.nccgroup.com/2022/10/05/public-report-iov-labs-powhsm-security-assessment/

This audit reviewed the PowHSM design and implementation and provided recommendations to improve security posture and robustness.

### 2. Quarkslab – PowHSM SGX Security Audit (2025)

Auditor: Quarkslab SAS

Initial Audit Period: June 10 – July 15, 2025

Control Audit Period: December 15 – December 19, 2025

Scope: Security review of the Intel SGX implementation of PowHSM (introduced in v5.4.0)

Report: [25-07-2216-REP-v1.1.pdf](./25-07-2216-REP-v1.1.pdf)
