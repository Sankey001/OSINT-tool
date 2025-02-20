# OSINT Tool

A Python-based OSINT (Open Source Intelligence) tool built with Tkinter. This project demonstrates how to integrate various OSINT functionalities into a user-friendly graphical interface.

## Overview

This tool assists in gathering publicly available information on a given target. It offers multiple features such as:
- **Domain-specific search:** Quickly search a target across multiple websites.
- **Google Dork File Search:** Leverage advanced Google search operators to find specific file types.
- **WHOIS Lookup:** Retrieve domain registration details using the `python-whois` module.
- **Map Lookup:** Open Google Maps for geographical searches.
- **Random Cybersecurity Tip:** Get useful cybersecurity tips with a link to Have I Been Pwned.

## Features

- **Domain Search:**  
  Generate Google search queries restricted to specific domains (e.g., Twitter, Facebook, GitHub, etc.) with a simple click.

- **Google Dork Search:**  
  Use advanced search queries to locate documents and file types related to the target.

- **WHOIS Lookup:**  
  Perform domain WHOIS lookups (ensure the `python-whois` module is installed: `pip install python-whois`).

- **Map Lookup:**  
  Open Google Maps with the entered location for a quick geographical search.

- **Random Cybersecurity Tip:**  
  Get a random cybersecurity tip and check if your information has been compromised using Have I Been Pwned.

## Installation

1. **Clone the Repository:**
   ```bash
   git clone https://github.com/yourusername/osint-tool.git
   cd osint-tool
