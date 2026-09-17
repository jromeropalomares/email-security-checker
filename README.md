# Email Security Checker

A Python-based command-line tool that performs basic DNS-based email security checks for a given domain.

The project was created to strengthen my understanding of email authentication, DNS, and security automation while practicing Python, object-oriented programming, and error handling.

## Features

The current version checks for:

* MX records
* SPF records
* DMARC records
* Optional DKIM records using a provided selector
* Common DNS lookup errors such as nonexistent domains, missing records, and timeouts

## Technologies Used

* Python
* dnspython
* DNS
* SPF
* DKIM
* DMARC
* Object-Oriented Programming
* Git and GitHub

## How It Works

The program creates an `EmailSecurityChecker` object for a supplied domain.

Each method performs a separate DNS lookup:

* `check_mx()` checks where the domain receives email.
* `check_spf()` searches TXT records for an SPF policy.
* `check_dmarc()` checks the domain's DMARC record.
* `check_dkim()` checks for a DKIM record when a selector is provided.
* `generate_report()` runs the checks and displays the results.

## Installation

Clone the repository:

```bash
git clone https://github.com/jromeropalomares/email-security-checker
```

Move into the project directory:

```bash
cd email-security-checker
```

Install the required dependency:

```bash
pip install -r requirements.txt
```

## Usage

Run the program:

```bash
python email_security_checker.py
```

Enter a domain when prompted:

```text
Enter domain: example.com
```

Example output:

```text
Email Security Check
--------------------
Domain: example.com
MX found: [...]
SPF found: "v=spf1 ..."
DMARC found: "v=DMARC1; p=..."
```

## DKIM

DKIM records require a selector.

Unlike SPF and DMARC, a DKIM selector cannot always be discovered through a standard DNS lookup. Because of this, DKIM checking is optional in the current version and requires a known selector.

## What I Learned

This project helped me better understand:

* How email security depends on DNS
* How MX records identify mail infrastructure
* How SPF identifies authorized email senders
* How DMARC uses SPF and DKIM authentication results to apply email policies
* How DKIM public keys are published through DNS
* How Python can automate repetitive security checks
* How object-oriented programming can organize related data and functionality
* How to handle common DNS lookup failures
* How Git can be used to track and document project development

## Current Limitations

This is an early version of the project.

Currently:

* SPF and DMARC records are detected but not fully analyzed.
* DKIM requires the user to provide a selector.
* The program currently displays raw DNS record information.
* The tool does not yet provide security scoring or configuration recommendations.

## Planned Improvements

Future versions may include:

* DMARC policy parsing
* SPF policy analysis
* Identification of common email providers such as Microsoft 365 or Google Workspace
* Improved DKIM support
* Security recommendations based on discovered records
* Markdown or JSON report generation
* Command-line arguments
* Microsoft 365 and email security integrations

## Purpose

This project is intended for educational purposes and to build practical experience with email security, DNS, Python automation, and security engineering concepts.
