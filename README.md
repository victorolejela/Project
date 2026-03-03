# Secure Hospital Result Delivery System

##  Project Overview
This is a Python-based web application built using Flask to **securely deliver medical test results to patients**.  
It is designed to **prevent data breaches and ensure that only the correct patient can access their results**.

---

## Purpose of the Project
The goal of this project is to:
- Prevent unauthorized access to sensitive medical records
- Ensure patients receive only their own results
- Track all result deliveries and access for auditing purposes
- Encrypt stored results for maximum security

This project was created to enhance patient privacy and improve trust in hospital result delivery systems.

---

##  Technologies Used
- Python  
- Flask  
- HTML / CSS  
- Nix (`shell.nix` for environment management)  
- Email and OTP verification for secure access  
- Encryption for storing sensitive results  

---

## How It Works
1. **Result Delivery**: The hospital uploads patient results into the system.
2. **Patient Notification**: Patients receive an email when their result is ready.
3. **Secure Access**:  
   - The patient requests a **one-time OTP** (One-Time Password).  
   - Only with the OTP can the patient decrypt and view their result.
4. **Audit Trail**:  
   - The system logs who sent the result, to whom, and at what time.  
   - If a breach occurs, the responsible party can be traced immediately.
5. **Encryption**: All results stored in the system are encrypted until the patient accesses them with their OTP.

---

## How to Run Locally

1. Clone the repository:

```bash
git clone <your-repo-url>
cd <your-repo-folder>
