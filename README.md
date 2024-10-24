# GoKnocker

GoKnocker is a network port scanner written in Go. It allows users to scan a range of ports on a specified host to determine which ports are open and gather information about the services running on those ports.

## Features

- Scan a range of ports on a specified host.
- Determine the state of each port (open, closed, filtered).
- Identify services running on common ports (e.g., HTTP, SSH).
- Gather HTTP information such as status code, server, and TLS details.
- Display scan progress and results in a user-friendly format.

## Installation

1. **Clone the Repository:**

   ```bash
   git clone https://github.com/YOUR_USERNAME/GoKnocker.git
   cd GoKnocker
   ```

2. **Build the Project:**

   Ensure you have Go installed on your system. Then, run:

   ```bash
   go build -o GoKnocker main.go
   ```

## Usage

Run the `GoKnocker` executable and follow the prompts to enter the target host, port range, and scan rate.