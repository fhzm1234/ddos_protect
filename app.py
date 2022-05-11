from scapy.all import *
from flask import *
from time import *
import os, threading, datetime


attack = False
lim = 2600
i = 0
ip = 0
port = 0
risk = 0

def packet_print(packet):
    global i, ip, port

    i += 2

    try:
        IP = packet['IP']
        TCP = packet['TCP']
    except:
        return


    ip = IP.src
    port = IP.sport

def start():
    while 1:
        global i, ip, port
        i = 0
        ip = 0
        port = 0

        def ddos_find():
            global attack, risk
            if i>lim:
                if attack:
                    risk = 2
                else:
                    risk = 1
                    attack = True
            else:
                risk = 0
                attack = False
        
        sniff(prn=packet_print, timeout=1, count=30000)
        ddos_find()

t = threading.Thread(target=start)
t.start()

def ddos_log():
    while True:
        if risk == 0:
            ddos_log = datetime.datetime.now().strftime('%H:%M:%S')+" "+"Not Found Attack" + "\n"
        elif risk == 1:
            ddos_log = datetime.datetime.now().strftime('%H:%M:%S')+" "+"Detect Attack!"+" Attacker IP: "+ str(ip) +"  Attacker Port: " + str(port) + "\n"
        elif risk == 2:
            ddos_log = datetime.datetime.now().strftime('%H:%M:%S')+" "+"Detect a series of Attacks!!"+" Attacker IP: "+ str(ip) + "  Attacker Port: " + str(port) + "\n"

        yield ddos_log.encode()
        sleep(1)

app = Flask(__name__)
@app.route('/', methods=['GET'])
def root():
    return render_template("index.html")

@app.route('/log', methods=["GET"])
def stream():
    return Response(ddos_log(), mimetype="text/plain", content_type="text/event_stream")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5030, threaded=True, debug=True)
