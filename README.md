# OSINT Tool

This Python-based OSINT (Open Source Intelligence) tool provides a graphical user interface (GUI) for conducting various intelligence-gathering activities. Built with Tkinter, it enables users to perform domain-specific searches, execute Google dork queries, perform WHOIS lookups, conduct map searches, and receive cybersecurity tips. The application utilizes threading (not working though) to ensure smooth performance and integrates popular web services to efficiently gather public information.

## Features

- **Domain Search:**  
  Perform targeted searches across popular domains such as Twitter, Facebook, LinkedIn, GitHub, and more. The tool constructs Google search queries restricted to the selected domain, facilitating focused information retrieval.

- **Google Dork Search:**  
  Leverage advanced Google search operators to find specific file types (e.g., PDF, DOCX, XLSX) related to the target. This feature helps in uncovering publicly available documents pertinent to the subject of interest.

- **WHOIS Lookup:**  
  Retrieve domain registration details using the `python-whois` module. This function provides insights into domain ownership, registration dates, and other relevant information. *Note: The `python-whois` module must be installed separately.*

- **Map Lookup:**  
  Conduct geographical searches by opening Google Maps with the specified location query. This feature is useful for visualizing addresses, coordinates, or place names associated with the target.

- **Cybersecurity Tips:**  
  Access random cybersecurity tips to enhance awareness and best practices. Additionally, the tool provides a direct link to the "Have I Been Pwned" website, allowing users to check if their credentials have been compromised.

## Installation

1. **Clone the Repository:**
   ```bash
   git clone https://github.com/yourusername/osint-tool.git
   cd osint-tool
   ```

2. **Install Dependencies:**
   Ensure you have Python 3 installed. Install the required libraries:
   ```bash
   pip install python-whois
   ```
   *Note:* Tkinter is typically included with Python installations. If it's not available, refer to your operating system's package manager or Python distribution for installation instructions.

## Usage

1. **Run the Application:**
   ```bash
   python osint_tool.py
   ```

2. **Enter Target Information:**
   Input the target name, domain, or location into the designated field.

3. **Select Desired Action:**
   Choose from the available options:
   - **Run OSINT:** Initiates domain-specific searches.
   - **Google Dork Search:** Opens a window for advanced file type searches.
   - **Whois Lookup:** Retrieves WHOIS information for the specified domain.
   - **Map Lookup:** Opens Google Maps for the entered location.
   - **Random Cyber Tip (HIBP):** Displays a cybersecurity tip and redirects to "Have I Been Pwned."

4. **Clear Input:**
   Use the **Clear** button to reset the input field as needed.

## License

This project is licensed under the MIT License. For more details, refer to the `LICENSE` file in the repository.

## Contributing

Contributions are welcome! To contribute:

1. Fork the repository.
2. Create a new branch (`git checkout -b feature/YourFeature`).
3. Commit your changes (`git commit -m 'Add YourFeature'`).
4. Push to the branch (`git push origin feature/YourFeature`).
5. Open a pull request detailing your changes.

## Credits

Developed by Sanket Subhralok Mohapatra for educational purposes.

## Disclaimer

This tool is intended for educational use only. Users are responsible for ensuring compliance with all applicable laws and regulations when using this tool.
