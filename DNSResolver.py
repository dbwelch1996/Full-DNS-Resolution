import struct
import socket
import time 

#b.root-servers.net 199.9.14.201, 2001:500:200::b 	University of Southern California, Information Sciences Institute
# DNS Header Format (12 bytes, 96 bits)
# Transaction ID (2), Flags (2), QDCOUNT (2), ANCOUNT (2), NSCOUNT (2), ARCOUNT (2)
#DNS Question Format ()
#Good, working

def create_dns_request(name):
    dns_header = struct.pack('!HHHHHH', #! (big endian order, standard for dns requests), H(Unsigned short 16 bits)
                         0x6969,   # Transaction ID
                         0x0000, # Flags (0000000000000000: 0 (request), 0000 (standard request), 0 (not authoritive server), 0 (trunication), 0 (do not want recursion), 0 (recursion avaiable), 0 (reserve for future use), 0 (DNSSEC validation), 0 (Disable DNSSEC validation))
                         0x0001,      # QDCOUNT (Number of questions, only got 1)
                         0x0000,      # ANCOUNT (No answers follow)
                         0x0000,      # NSCOUNT (no records follow)
                         0x0000)      # ARCOUNT (no additional records follow)
    
    domain_name = encode_dns_name(name)

    dns_question = struct.pack('!HH', #big endin order, H(Unsigned short 16 bits)
                           0x0001,  # QTYPE (A record)
                           0x0001)  # QCLASS (IN class)
    
    dns_query = dns_header + domain_name + dns_question
    #print(dns_query)
    return dns_query

#Good working
def encode_dns_name(domain_name):
    encoded = b""
    for part in domain_name.encode("ascii").split(b"."):
        encoded += bytes([len(part)]) + part
    return encoded + b"\x00"

#Good working
def request_Resolver(dns_query):
    timeout = 10
    resolver_ips = [
    "198.41.0.4", "199.9.14.201", "192.33.4.12", "199.7.91.13", 
    "192.203.230.10", "192.5.5.241", "192.112.36.4", "198.97.190.53", 
    "192.36.148.17", "192.58.128.30", "193.0.14.129", "199.7.83.42", 
    "202.12.27.33"
    ]
    response = None
    RTT_Start = time.time()
    for resolver_ip in resolver_ips:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client_socket:
            try:
                client_socket.settimeout(timeout) 
                client_socket.sendto(dns_query, (resolver_ip, 53)) #send to resolvers dns port
                response, address = client_socket.recvfrom(512) #recieve the response
                break 
            except socket.timeout:
                continue 
    RTT_End = time.time()
    return response, RTT_End - RTT_Start


def parse_header(header):
    # Unpacks the header so i can use the counts for parsing the response
    (
        transaction_id,
        flags,
        question_count,
        answer_count,
        authority_count,
        additional_count
    ) = struct.unpack('>HHHHHH', header)

    return {
        'transaction_id': transaction_id,
        'flags': flags,
        'question_count': question_count,
        'answer_count': answer_count,
        'authority_count': authority_count,
        'additional_count': additional_count
    }


def parse_response(response):
    header = response[:12] 
    header_info = parse_header(header)
    answers = response[12:]
    
    position = 0
    
    #For the Question Section
    for _ in range(header_info['question_count']):
        # Skip the domain name
        while answers[position] != 0:
            # Move past the label length byte and the label itself
            position += 1 + answers[position]
        # Skip the null byte (end of domain)
        position += 1
        # Skip type, class fields
        position += 4 
     
    #For the Answer Section
    for _ in range(header_info['answer_count']):
        # Check for a pointer (the name is compressed)
        if (answers[position] & 0xC0) == 0xC0:
            # Skip the pointer
            position += 2
        else:
            # If it's not a pointer, skip the normal sequence of labels
            while answers[position] != 0:
                position += 1 + answers[position]
            # Skip the null byte at the end of the name
            position += 1
        # Skip the type, class, and ttl fields
        position += 8
        # Read the data length
        rdlength = int.from_bytes(answers[position:position+2], byteorder='big')
        # Skip the data length and the data
        position += 2 + rdlength
        
    #SO FAR AT THE START OF THE AUTHORITIVE NAME SERVER SECTION
    #print(answers[position:])
    #For Authoritive Section
    for _ in range(header_info['authority_count']):
        if (answers[position] & 0xC0) == 0xC0: #For pointers
            position += 2 #Move past the pointer bits 
        else: #For domain
            # It's a series of labels
            while answers[position] != 0:
                # Skip each label
                position += 1 + answers[position]
            position += 1  # Skip the null byte at the end of the name

        # Skip the type, class, TTL, and data length fields
        position += 8
        data_length = int.from_bytes(answers[position:position + 2], byteorder='big')
        position += 2
        position += data_length
             

    ip_addresses = []

    for _ in range(header_info['additional_count']):
        # Check for a pointer and skip past it
        if (answers[position] & 0xC0) == 0xC0:
            position += 2
        else:
            # Skip over the domain name
            while answers[position] != 0:
                position += 1 + answers[position]
            position += 1  # Skip the null byte at the end of the name
        # Read the record type
        record_type = int.from_bytes(answers[position:position+2], byteorder='big')
        position += 4  # Move past the type and class
        position += 4 #TTL Field
        data_length = int.from_bytes(answers[position:position+2], byteorder='big') #Read Data Length
        position += 2
        if record_type == 1 and data_length == 4:
            ip_address_bytes = answers[position:position+data_length]
            ip_parts = [str(b) for b in ip_address_bytes] #Byte -> Decimal -> string
            ip_address = '.'.join(ip_parts) #Adds the .
            ip_addresses.append(ip_address)
        position += data_length #Next record
    return ip_addresses

#Basically the parse response but instead extracting it from the Answer section
def extract_answer(response):
    header = response[:12] 
    header_info = parse_header(header)
    answers = response[12:]   
    position = 0  
    for _ in range(header_info['question_count']):
        while answers[position] != 0:
            position += 1 + answers[position]
        position += 1
        position += 4
    tmz_addresses = []  
    for _ in range(header_info['answer_count']):
        if answers[position] == 0xc0: 
            position += 2
        else:
            while answers[position] != 0:
                position += 1 + answers[position]
            position += 1
        kind, part, ttl, data_length = struct.unpack('>HHIH', answers[position:position + 10])
        position += 10
        if kind == 1 and data_length == 4:
            ip_address_bytes = struct.unpack('>BBBB', answers[position:position + data_length])
            ip_address = '.'.join(map(str, ip_address_bytes))
            tmz_addresses.append(ip_address)
        position += data_length
    return tmz_addresses
            
#Good working
def send_dns_query(query, server):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(query, (server, 53))
    data, _ = sock.recvfrom(512)
    sock.close()
    return data 
        

#Good working            
def make_http_request(ip_address):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    port = 80
    try:
        RTT_Start = time.time()
        sock.connect((ip_address, port))
        http_get_request = (
            "GET / HTTP/1.1\r\n"
            "Host: tmz.com\r\n"
            "User-Agent:Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/119.0\r\n"
            "Connection: close\r\n\r\n"
        )
        sock.sendall(http_get_request.encode()) 
        response = b""
        while True:
            data = sock.recv(4096)
            if not data:
                break
            response += data
        RTT_Stop = time.time()
    except socket.error as e:
        print(f"Error: {e}")
        response = b""
    finally:
        sock.close()
    return response.decode(errors='ignore'), RTT_Stop - RTT_Start  

    



def main():
    dns_query = create_dns_request('tmz.com')

    try:
        #Get the IP Address for the Root Server
        dns_response, RTT_Resolver = request_Resolver(dns_query)
        print('RTT from Client to the Resolver: ', RTT_Resolver)
        
        #Get the IP address for the TLD server
        root_list = parse_response(dns_response)
        TLD_list = send_dns_query(dns_query, root_list[0])
        
        #Get the final ip address from the Authoritative server
        auth = parse_response(TLD_list)
        final = send_dns_query(dns_query,auth[0])
        
        #Finally, we make the HTTP request to the TMZ website
        tmz_address = extract_answer(final)
        HTTP_Response, RTT_for_HTTP = (make_http_request(tmz_address[0]))
        #print(tmz_address[0])
        print(HTTP_Response)    
        print("RTT from HTTP request", RTT_for_HTTP)
        
        
        
    except Exception as e:
        print(":(", e)

if __name__ == "__main__":
    main()