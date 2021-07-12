import argparse
import socket
import select
import queue
import sys
import LNP
import crypt
from crypt import *

def get_args():
    '''
    Gets command line argumnets.
    '''

    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--port",
        metavar='p',
        dest='port',
        help="port number",
        type=int,
        default=42069
    )

    parser.add_argument(
        "--ip",
        metavar='i',
        dest='ip',
        help="IP address for client",
        default='127.0.0.1'
    )

    return parser.parse_args()

#Main method
def main():
    '''
    uses a select loop to process user and server messages. Forwards user input to the server.
    '''

    args = get_args()
    server_addr = args.ip
    port = args.port

    server = socket.socket()
    server.connect((server_addr, port))

    msg_buffer = {}
    recv_len = {}
    msg_len = {}
    msg_ids = {}
    symmetric_keys = {}
    personal_sym_keys = {}
    established_DH = False
    DH_init_msg = None

    inputs = [server, sys.stdin]
    outputs = [server]
    message_queue = queue.Queue()

    waiting_accept = True
    username = ''
    username_next = False
    certString = None

    while server in inputs:

        readable, writable, exceptional = select.select(inputs, outputs, inputs)

        for s in readable:
            omit_user_tag = 0
            ###
            ### Process server messages
            ###
            if s == server:

                # This point may iterate multiple times until the message is completely read since LNP.recv, receives a few bytes at a time.
                code = LNP.recv(s, msg_buffer, recv_len, msg_len, msg_ids)

                # This will not happen until the message is switched to MSG_COMPLETE when then it is read from the buffer.
                if code != "LOADING_MSG":
                    code_id, msg = LNP.get_msg_from_queue(s, msg_buffer, recv_len, msg_len, msg_ids, symmetric_keys)

                    if code_id is not None:
                        code = code_id

                #receive public key and encrypt/send symmetric key
                if code == "ENCRYPT":
                    public_key = RSA.importKey(base64.b64decode(msg))
                    symmetric_key = crypt.generate_sym_key()
                    symmetric_keys[s] = symmetric_key
                    encrypted_sym = crypt.encrypt_sym_key(public_key, symmetric_key)
                    LNP.send(s, encrypted_sym, "SENDING_SYM")

                # Check certificate to send
                elif code == "CERTIFICATE-EXCHANGE":
                    # get username certificate and send
                    certString = read_certificates(username)
                    if certString != ' ':
                        LNP.send(s, certString, "CERTIFICATE-EXCHANGE", symmetric_keys[s])
                    # disconnect if not found
                    else:
                        print("Cert not found")
                        exit()

                #DH key exchange initiated
                elif code == "DH-HELLO":
                    sender = msg.split("|")[1]
                    hex_key = msg.split("|")[2]
                    shared_key = bytearray.fromhex(hex_key)
                    personal_sym_keys[s] = get_DH_key(shared_key)
                    LNP.send(s, "@" + sender + "|" + username + "|", "DH-KEY-EXCHANGE", symmetric_keys[s])

                #Acknowledge DH key exchange by recipient
                elif code == "DH-KEY-EXCHANGE":
                    sender = msg.split("|")[1]
                    DH_init_cipher = crypt.sym_encrypt(personal_sym_keys[s], DH_init_msg)
                    DH_init_cipher_bytes = bytearray(DH_init_cipher).hex()
                    payload = "@" + sender + "|" + username + "|" + DH_init_cipher_bytes
                    LNP.send(s, payload, "DH-REPLY", symmetric_keys[s])
                    omit_user_tag = 1

                #Send original private message
                elif code == "DH-REPLY":
                    sender = msg.split("|")[1]
                    DH_init_cipher = msg.split("|")[2]
                    DH_bytes = bytes(bytearray.fromhex(DH_init_cipher))
                    DH_TEXT = crypt.sym_decrypt(personal_sym_keys[s], DH_bytes)
                    if established_DH == False:
                        established_DH = True

                    sys.stdout.write('\r' + "SECRET>" + sender + ": " + DH_TEXT.decode("utf-8") + '\n')
                    sys.stdout.write("> " + username + ": ")
                    sys.stdout.flush()

                elif code == "MSG_CMPLT":
                    if username_next:
                        print("complete")
                        username_msg = msg
                        username = username_msg.split(' ')[1]
                        sys.stdout.write(username_msg + '\n')
                        sys.stdout.write("> " + username + ": ")
                        sys.stdout.flush()
                        username_next = False

                    elif msg:
		        #If username exists, add message prompt to end of message
                        if username != '':
                            sys.stdout.write('\r' + msg + '\n')
                            sys.stdout.write("> " + username + ": ")

                        #If username doesnt exist, just write message
                        else:
                            sys.stdout.write(msg)

                        sys.stdout.flush()

                # This and any other codes can be edited in protocol.py, this way you can add new codes for new states, e.g., is this a public key, CODE is PUBKEY and msg contains the key.
                elif code == "ACCEPT":
                    waiting_accept = False
                    sys.stdout.write(msg)
                    sys.stdout.flush()

                elif code == "USERNAME-INVALID" or code == "USERNAME-TAKEN":
                    msg = exit()

                elif code == "USERNAME-ACCEPT":
                    username_next = True

                elif code == "NO_MSG" or code == "EXIT":
                    sys.stdout.write(msg + '\n')
                    sys.stdout.flush()
                    inputs.remove(s)
                    if s in writable:
                        writable.remove(s)

            ###
            ### Process user input
            ###
            else:
                if not waiting_accept:
                    msg = sys.stdin.readline()
                    msg = msg.rstrip()

                    if msg:
                        message_queue.put(msg)
                    if not ((username == '') or (msg == "exit()")):
                        sys.stdout.write("> " + username + ": ")
                        sys.stdout.flush()
                    if username == '':
                        username = msg
                        if (len(msg) < 1) or (len(msg) > 10) or (' ' in msg):
                            msg = "exit()"


        ###
        ### Send messages to server
        ###
        for s in writable:

            try:
                msg = message_queue.get_nowait()
            except queue.Empty:
                msg = None

	 #if there is a message to send
            if msg:

	     #if exit message, send the exit code
                if msg == "exit()":
                    outputs.remove(s)
                    LNP.send(s, '', "EXIT")
                    exit()

	     #otherwise just send the messsage
                else:
                    #if private message
                    if msg[0] == '@':
                        msgPeer = msg.split(' ')[0]
                        msgText = ''
                        for t in msg.split(' ')[1:]:
                            msgText = msgText + t + " "
                        #new DH exchange
                        if established_DH == False:
                            #save message
                            DH_init_msg = msgText
                            #initiate DH key sharing
                            shared_key = generate_DH_sharedKey()
                            personal_sym_keys[s] = get_DH_key(shared_key)
                            key_string = shared_key.hex()

                            LNP.send(s, msgPeer  + "|" + username + "|" + key_string, "DH-HELLO", symmetric_keys[s])
                        #if DH already set up
                        else:
                            payload = ''
                            for t in msg.split(' ')[1:]:
                                payload = payload + t + " "
                            cipher_text = sym_encrypt(personal_sym_keys[s], payload)
                            cipher_msg = msgPeer + "|" + username + "|" + cipher_text.hex()
                            LNP.send(s, cipher_msg, "DH-REPLY", symmetric_keys[s])

                    else:
                        LNP.send(s, msg, None, symmetric_keys[s])

        for s in exceptional:
            print("Disconnected: Server exception")
            inputs.remove(s)

    server.close()

if __name__ == '__main__':
    main()
