from scapy.all import *
from flask import *
from time import *
import os, threading, datetime, re, socket

attack = False
lim = 2000
i = 0
ip_s = 0
ip_d = 0
port_s = 0
port_d = 0
risk = 0
i_syn = 0
i_ack = 0
i_syn_dos = 0
ip_list=list()
app = Flask(__name__)
"""
scpay로 초당 트래픽당 syn, ack확인을 통한 DDOS탐지 방법
"""

def myip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    return (s.getsockname()[0])

def ipread():
    with open('logip', 'r') as ips:
        for line in ips:
            line = line[9: ]
            line = line.rstrip('\n')
            ip_list.append(line)


def packet_print(packet):
    global i, i_syn, i_ack, ip_s, ip_d, port_s, port_d
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

    ip_s = IP.src
    port_s = IP.sport

    ip_d = IP.dst
    port_d = IP.dport


def start():
    while 1:
        global i, i_syn, i_ack, ip_s, ip_d, port_s, port_d, i_syn_dos
        i = 0
        ip_s = 0
        port_s = 0
        ip_d = 0
        port_d = 0
        i_syn = 0
        i_ack = 0
        i_syn_dos = 0

        def ddos_find():
            global attack, risk, i_syn, i_ack, i_syn_dos
            #전체 패킷에 대한 syn의 비율

            try:
                i_syn_dos = i_syn / i
            except:
                risk = 3

            if i>lim or (i_syn_dos > 0.9 and i_syn > 400) or (i_ack > 400):
                if attack:
                    Myip = myip()
                    if ip_s != Myip:
                        risk = 0
                        ip_list.append(ip_s)
                        data_print = datetime.datetime.now().strftime('%H:%M:%S') + " " +str(ip_s) +"\n"
                        add1 = "iptables -A INPUT -s " + str(ip_s) + " -j DROP"
                        os.system(add1)
                        logi = open('logip', 'a')
                        logi.write(data_print)
                else:
                    risk = 1
                    attack = True
            else:
                if attack:
                    risk = 2
                risk = 3
                attack = False
        
        sniff(prn=packet_print, timeout=0.9, count=30000)
        ddos_find()


def ip_list_made(ip1):
    logi = open('logip', 'a')
    if re.match("[A]+", ip1):
        ip2 = ip1[1:]
        ip_list.append(ip2)
        add = "iptables -A INPUT -s " + str(ip2) + " -j DROP"
        os.system(add)
        data_print = datetime.datetime.now().strftime('%H:%M:%S') + " " +str(ip2) +"\n"
        logi.write(data_print)
    if re.match("[D]+", ip1):
        ip2 = ip1[1:]
        ip_list.remove(ip2)
        delete = "iptables -D INPUT -s " + str(ip2) + " -j DROP"
        os.system(delete)

        with open('logip', 'r+') as ips:
            lines = ips.readlines()
            ips.seek(0)
            for line in lines:
                if ip2 not in line:
                    ips.write(line)
            ips.truncate()


def ddos_log():
    while True:
        if risk == 0:
            ddos_log = datetime.datetime.now().strftime('%H:%M:%S')+" "+"DDOS Detect!" + " Src IP : "+ str(ip_s) +" ==> "+ "Dst IP : "+str(ip_d) +"   Traffic : " +str(i)+"\n"
        elif risk == 1:
            ddos_log = datetime.datetime.now().strftime('%H:%M:%S')+" "+"First DDOS Attack!"+" Src IP : "+ str(ip_s) +" ==> "+ "Dst IP : "+str(ip_d) +"   Traffic : " +str(i)+"\n"
        elif risk == 2:
            ddos_log = datetime.datetime.now().strftime('%H:%M:%S')+" "+"Suspect DDOS" +" Src IP : "+ str(ip_s) +" ==> "+ "Dst IP : "+str(ip_d) +"   Traffic : " +str(i)+"\n"
        else:
            ddos_log = datetime.datetime.now().strftime('%H:%M:%S')+" "+"Not Found DDOS Attack" +" Src IP : "+ str(ip_s) +" ==> "+ "Dst IP : "+str(ip_d) +"   Traffic : " +str(i)+"\n"

        yield ddos_log.encode()
        sleep(1)

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == "POST":
        ip_black = request.form["ip_black"]
        ip_list_made(ip_black)
        a = '<br>'.join(ip_list)
        return a
    return render_template("index.html")


@app.route('/log', methods=["GET", "POST"])
def stream():
    return Response(ddos_log(), mimetype="text/plain", content_type="text/event_stream")

ipread()
t = threading.Thread(target=start)
t.start()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
