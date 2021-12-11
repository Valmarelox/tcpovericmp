# tcpovericmp
Final project for the networking workshop in the Open university 

## Installation
Make sure you have python3.9 installed
then
```bash
pip install -r requirements.txt
sudo ./src/setup.sh
sudo ./src/execute.sh
```
## Usage
Shell in the client's namespace
```bash
sudo ip netns exec client bash
```
Shell in the server's namespace
```bash
sudo ip netns exec server bash
```
