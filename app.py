from scapy.all import *
from flask import *
from time import *
import os, threading, datetime


attack = False
lim = 2000
i = 0
ip = 0
port = 0
risk = 0
i_syn = 0
i_ack = 0
i_result = 0
"""
scpay로 초당 트래픽당 syn, ack확인을 통한 DDOS탐지 방법
"""
def packet_print(packet):
    global i, ip, port, i_syn, i_ack
    SYN = 0x02
    ACK = 0x10


    i += 2

    try:
        IP = packet['IP']
        TCP = packet['TCP']
    except:
        return
        #트래픽 하나에 대한 SYN, ACK 계산
    if TCP.flags & SYN:
        i_syn += 2
    elif TCP.flags & ACK:
        i_ack += 2

    ip = IP.src
    port = IP.sport

def start():
    while 1:
        global i, ip, port, i_syn, i_ack, i_result
        i = 0
        ip = 0
        port = 0
        i_syn = 0
        i_ack = 0
        i_result = 0

        def ddos_find():
            global attack, risk, i_syn, i_ack, i_result
            #전체 패킷에 대한 syn의 비율
            try:
                i_result = i_syn / i
            except:
                risk = 3

            #테스트해보면 DDOS의 경우 result값이 매우 높은 수치를 가짐
            
            if i>lim:
                if attack:
                    if i_result > 0.9 and i_syn > 400:
                        risk = 0
                else:
                    if i_result > 0.9 and i_syn > 400:
                        risk = 1
                        attack = True
            else:
                if attack:
                    if i_result > 0.9:
                        risk = 2
                risk = 3
                attack = False
        
        sniff(prn=packet_print, timeout=0.9, count=30000)
        ddos_find()

t = threading.Thread(target=start)
t.start()

def ddos_log():
    while True:
        if risk == 0:
            ddos_log = datetime.datetime.now().strftime('%H:%M:%S')+" "+"More than once Detect DDOS Attack!"+" Attacker IP: "+ str(ip) + "  Attacker Port: " + str(port) + " Traffic : " + str(i)+" " +str(i_syn)+" "+str(i_ack)+" "+str(i_result) + "\n"
        elif risk == 1:
            ddos_log = datetime.datetime.now().strftime('%H:%M:%S')+" "+"First Detect DDOS Attack!"+" Attacker IP: "+ str(ip) + "  Attacker Port: " + str(port) + " Traffic : " + str(i)+" " +str(i_syn)+" "+str(i_ack)+" "+str(i_result) + "\n"
        elif risk == 2:
            ddos_log = datetime.datetime.now().strftime('%H:%M:%S')+" "+"Detect DDOS Attack!"+" Attacker IP: "+ str(ip) + "  Attacker Port: " + str(port) + " Traffic : " + str(i)+" " +str(i_syn)+" "+str(i_ack)+" "+str(i_result) + "\n"
        else:
            ddos_log = datetime.datetime.now().strftime('%H:%M:%S')+" "+"Not Found DDOS Attack" +" Traffic : " + str(i)+" " +str(i_syn)+" "+str(i_ack)+" "+str(i_result)+ "\n"

        yield ddos_log.encode()
        sleep(1)

app = Flask(__name__)
@app.route('/', methods=['GET', 'POST'])
def root():
    return render_template("index.html")

@app.route('/param', methods=['GET', 'POST'])
def param():
    ip = request.args.get('ip')
    print (ip)
    return f'ip : {ip}'

@app.route('/log', methods=["GET", "POST"])
def stream():
    return Response(ddos_log(), mimetype="text/plain", content_type="text/event_stream")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, threaded=True, debug=True)
