ESP32 GPIO WebServer from anywhere - ESP-IDF

This is an ESP32 project to run: HTTPS/HTTP server + WS/WSS + Wireguard + WIFI provisioning

Prerequisites, ESP-IDF framework (here to download: https://github.com/espressif/esp-idf/releases)


Steps to deploy:
- Download this repo.
- Inside the root folder, run : 
  . <esp-idf instalation path>/export.sh 
  idf.py menuconfig 
- Select the option "Example configuration", here can edit the wireguard client data.
- After setup, you can edit some other parameters in main.c, like ssl option enabled for server, and the Web username and password (optional)
  If you changue ssl to 0, need to change the wss connection to ws on the index.html
- Then run:
  idf.py build
  idf.py flash
- Then you can run 'idf.py monitor' to check the logs.
- In the first boot, you will need to setup wifi credentials by the 'ESP BLE prov' app on smartphone. The monitor output will by like this:

                        I (704) WebSocket Server: Starting provisioning
                        I (704) WebSocket Server: Development mode: using hard coded salt
                        I (714) WebSocket Server: Development mode: using hard coded verifier
                        I (724) phy_init: phy_version 4830,54550f7,Jun 20 2024,14:22:08
                        W (804) phy_init: saving new calibration data because of checksum failure, mode(0)
                        I (834) wifi:mode : sta (e0:5a:1b:d2:46:94)
                        I (834) wifi:enable tsf
                        I (844) BTDM_INIT: BT controller compile version [f021fb7]
                        I (844) BTDM_INIT: Bluetooth MAC: e0:5a:1b:d2:46:96
                        I (1174) wifi_prov_mgr: Provisioning started with service name : PROV_D24694 
                        I (1184) WebSocket Server: Provisioning started
                        I (1454) WebSocket Server: BLE transport: Connected!
                        W (2224) BT_HCI: hcif disc complete: hdl 0x0, rsn 0x5
                        I (2234) WebSocket Server: BLE transport: Disconnected!
                        I (3324) WebSocket Server: BLE transport: Connected!
                        W (4104) BT_HCI: hcif disc complete: hdl 0x0, rsn 0x5
                        I (4104) WebSocket Server: BLE transport: Disconnected!
                        I (4374) WebSocket Server: BLE transport: Connected!
                        W (5154) BT_HCI: hcif disc complete: hdl 0x0, rsn 0x5
                        I (5154) WebSocket Server: BLE transport: Disconnected!
                        I (5574) WebSocket Server: BLE transport: Connected!

- If you see something like that, means you can connect the ESP via the wifi provisioning mobile APP. After that, if everything is okey and the VPN server running (and the client exist), you will see something like this:

                        I (427) cpu_start: Multicore app
                        I (436) cpu_start: Pro cpu start user code

...

                        I (9184) WebSocket Server: Connected with IP Address:192.168.1.20
                        I (9184) esp_https_server: Starting server
                        I (9184) esp_https_server: Server listening on port 443
                        I (9184) esp_netif_handlers: sta ip: 192.168.1.20, mask: 255.255.255.0, gw: 192.168.1.0
                        I (9194) sync_time: Initializing SNTP
                        I (9204) sync_time: Waiting for system time to be set... (1/20)
                        I (10304) sync_time: Time synced
                        I (11204) WebSocket Server: The current date/time in New York is: Thu Feb  6 17:32:39 2025
                        I (11204) WebSocket Server: Initializing WireGuard.
                        I (11204) WebSocket Server: Connecting to the peer.
                        I (11214) esp_wireguard: allowed_ip: 10.8.0.2
                        I (11254) esp_wireguard: using preshared_key
                        I (11254) esp_wireguard: X25519: default
                        I (11274) esp_wireguard: Peer: test.com (12.123.123.123:3333)
                        I (11314) esp_wireguard: Connecting to xxxx.com:1234
                        I (12314) WebSocket Server: Peer is up
                        I (12314) WebSocket Server: Initializing ping...
                        I (12314) WebSocket Server: ICMP echo target: 10.8.0.1
                        I (12324) WebSocket Server: ESP32 ESP-IDF WebSocket Web Server is running ... ...
                        
                        I (12394) WebSocket Server: Pin 22 state: ON
                        I (12394) main_task: Returned from app_main()
                        I (12524) WebSocket Server: 64 bytes from 10.8.0.1 icmp_seq=1 ttl=64 time=201 ms
  
- So in this example with can access with the 192.168.1.20 local IP (or forward it), or access by the VPN ip 10.8.0.2 from anywhere with another VPN client, or deploy a proxy to internet there is connected to the VPN  (Here is an example of wireguard easy deploy: https://github.com/AndyPecotche/IoTServer).
  If you dont want to use a VPN you still can access directly to the local IP.
  The ping is for test the status of the VPN server, because if the public IP of the VPN changes, the ESP needs to be restarted, so after some failiure pings the board will be restart, in this state the local server is still working. If no PING ip is configured, the ping is not checked.

- For reset Wifi, press 3 seconds the BOOT button in devkit (or gpio0 by default), and then reset the board.

- This particular example sets GPIO 22 as "reset" and "status" PIN, and 23 to PWR pin. When the PWR or RST button is pressed on the Web server, a websocket message is send to the board, so the corresponding GPIO is set to LOW, so the GND and GPIO are shorted (and acts like if the ATX button is pressed on the PC), during the backend action, more websocket messages are sent, so the web client has some feedback of what is happening behind (like change the button color when GPIO its actually set to LOW and revert when is back to HIGH). The RST GPIO, also works as Status of power check, by changing as INPUT and OUTPUT GPIO dynamically, but it can be other GPIO, this just simplify the ATX connection.
- 
- The connection for this example, is just:
  - GPIO 22 to Reset+ on motherboard.
  - GPIO 23 to Power+ on motherboard.
  - VCC of ESP32 to 5v USB output of motherboard.
  - GND of ESP32 to GND of USB output of motherboard.
  This connection was tested on a msi b560m pro motherboard, and the current flow when the GPIO is set to GND is minimal as the same current when the ATX button is pressed on the mobo.
