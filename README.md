How to install and run:

1. copy ECOverloaded.wl, FiatShamir.wl, SchnorrPrimes.wl, SigmaTools.wl from folder "Mathematica Library Files" to ...
- WINDOWS: ... ~\AppData\Roaming\Mathematica\Applications\
- MAC OS: ... ~/Library/Mathematica/Applications/

2. open MultiKeyShuffle-Prover.nb and MultiKeyShuffle-Verifier.nb with Mathematica and follow the instructions inside
- you may have to change the room name in the configuration if it already exists

3. to launch a local room server, run RoomServer.py from folder "Room Server" with python 3 and the dependencies in requirements.txt installed

4. to monitor the communication between prover and verifier, open http://localhost:11080/

5. if you would like to run RoomServer.py on your own public server
- consider the example nginx serverblock configuration that is built to be used with letsencrypt SSL certificates and expose RoomServer.py on your domain on a configurable path - adjust to your needs and install to the serverblock directory which usually is /etc/nginx/sites-available/
- consider running it through the wrapper script RoomServer-Monitor-Default.sh which restarts RoomServer.py every day at 3:30 am - just fill in your domain name and the path
