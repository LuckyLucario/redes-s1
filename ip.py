from iputils import *
from tcputils import fix_checksum
from trie import *
import struct

# Lindas classes de endereços IPv4 sem verificação alguma :)
class IPv4Net:
    def __init__(self, ip: str):
        # Dividindo o ip da sua máscara
        self.ip_string = ip
        ips = ip.split('/')
        self.mask = 32 - int(ips[1])

        # Transformando o ip em bibibibits
        self.ip, = struct.unpack('!I', str2addr(ips[0]))

        # print(f"{self.ip:032b}") # Imprime IP em binário

class IPv4Addr:
    def __init__(self, ip: int):
        self.ip = ip

    def __init__(self, ip: str):
        # Transformando o ip em bibibibits
        self.ip, = struct.unpack('!I', str2addr(ip))

    def inside(self, ip_net: IPv4Net):
        m = ip_net.mask
        ip = self.ip >> m << m

        if ip_net.ip == self.ip >> m << m:
            return True
        return False

class IP:
    def __init__(self, enlace):
        """
        Inicia a camada de rede. Recebe como argumento uma implementação
        de camada de enlace capaz de localizar os next_hop (por exemplo,
        Ethernet com ARP).
        """
        self.callback = None
        self.enlace = enlace
        self.enlace.registrar_recebedor(self.__raw_recv)
        self.ignore_checksum = self.enlace.ignore_checksum
        self.meu_endereco = None
        self.id = 0 # Usado para criação do header

    def create_icmp_packet(self, datagrama):
        tipo = 11
        code = 0
        checksum = 0
        payload = datagrama[:28]
        packet = bytearray(struct.pack('!BBHI',tipo,code,checksum,0))
        packet.extend(payload)
        checksum = calc_checksum(bytes(packet))
        packet = bytearray(struct.pack('!BBHI',tipo,code,checksum,0))
        packet.extend(payload)
        return bytes(packet)

    def __raw_recv(self, datagrama):
        dscp, ecn, identification, flags, frag_offset, ttl, proto, \
           src_addr, dst_addr, payload = read_ipv4_header(datagrama)
        source_address, = struct.unpack('!I', str2addr(src_addr))
        destination_address, = struct.unpack('!I', str2addr(dst_addr))
        if dst_addr == self.meu_endereco:
            # atua como host
            if proto == IPPROTO_TCP and self.callback:
                self.callback(src_addr, dst_addr, payload)
        else:
            # atua como roteador
            ttl = ttl - 1
            if ttl > 0:
                next_hop = self._next_hop(dst_addr)
                datagram = self.create_ipv4_datagram(payload, identification, source_address, destination_address, ttl)
            else:
                next_hop = self._next_hop(src_addr)
                destination_address = source_address
                source_address, = struct.unpack('!I', str2addr(self.meu_endereco))
                payload = self.create_icmp_packet(datagrama)
                datagram = self.create_ipv4_datagram(payload, identification, source_address, destination_address, protocol = IPPROTO_ICMP)
            self.enlace.enviar(datagram, next_hop)

    def _next_hop(self, dest_addr):
        # Usa a tabela de encaminhamento para determinar o próximo salto
        # (next_hop) a partir do endereço de destino do datagrama (dest_addr).
        # Retorna o next_hop para o dest_addr fornecido.
        dest_addr = str2addr(dest_addr)
        dest = int.from_bytes(dest_addr, byteorder='big')
        dest = "{0:b}".format(dest)
        while len(dest) < 32:
            dest = '0' + dest
        next_hop = self.tabela.query(dest)
        return next_hop

    def definir_endereco_host(self, meu_endereco):
        """
        Define qual o endereço IPv4 (string no formato x.y.z.w) deste host.
        Se recebermos datagramas destinados a outros endereços em vez desse,
        atuaremos como roteador em vez de atuar como host.
        """
        self.meu_endereco = meu_endereco

    def definir_tabela_encaminhamento(self, tabela):
        """
        Define a tabela de encaminhamento no formato
        [(cidr0, next_hop0), (cidr1, next_hop1), ...]
        Onde os CIDR são fornecidos no formato 'x.y.z.w/n', e os
        next_hop são fornecidos no formato 'x.y.z.w'.
        """
        # TODO: Guarde a tabela de encaminhamento. Se julgar conveniente,
        # converta-a em uma estrutura de dados mais eficiente.
        self.tabela = Trie()
        for cidr, next_hop in tabela:
            ip_addr, n = cidr.split("/", 1)
            ip_addr = str2addr(ip_addr)
            n = int(n)
            ip_addr = int.from_bytes(ip_addr, byteorder='big')
            ip_addr = "{0:b}".format(ip_addr)
            while len(ip_addr) < 32:
                ip_addr = '0' + ip_addr
            chave = ip_addr[:n]
            if chave:
                self.tabela.insert(chave,next_hop)
            else:
                self.tabela.insert("",next_hop)
        pass

    def registrar_recebedor(self, callback):
        """
        Registra uma função para ser chamada quando dados vierem da camada de rede
        """
        self.callback = callback

    def create_ipv4_datagram(self, segmento, identification, source_address, destination_address, ttl = 64, protocol = IPPROTO_TCP):
        """
        Cria Header IPv4
        (https://www.wikiwand.com/en/IPv4#/Header)
        """
        # Usando valores padrões
        version = 4 # Para IPv4, = 4
        IHL = 5 # Implementação simplificada, será sempre 5 (Nro de bytes do header / 4)
        DSCP = 0 # Padrão
        ECN = 0
        total_len = 20 + len(segmento) # Tamanho do cabeçalho + Payload do protocolo IP (Segmento)
        self.id += 1
        flags = 0
        frag_offset = 0
        checksum = 0 # Inicialmente 0 para o cálculo posterior do checksum

        vihl = version << 4 | IHL
        dscpecn = DSCP << 6 | ECN
        flagsfrag = flags << 3 | frag_offset

        datagram = struct.pack('!BBHHHBBHII', 
                                vihl, dscpecn, total_len,
                                identification, flagsfrag,
                                ttl, protocol, checksum,
                                source_address, destination_address)

        checksum = calc_checksum(datagram)

        datagram = bytearray(struct.pack('!BBHHHBBHII', 
                                vihl, dscpecn, total_len,
                                identification, flagsfrag,
                                ttl, protocol, checksum,
                                source_address, destination_address
                                ))
        datagram.extend(segmento)

        return bytes(datagram)

    # Esse método só é chamado pela camada de transporte/superior/TCP
    def enviar(self, segmento, dest_addr):
        """
        Envia segmento para dest_addr, onde dest_addr é um endereço IPv4
        (string no formato x.y.z.w).
        """
        next_hop = self._next_hop(dest_addr)

        s = IPv4Addr(self.meu_endereco)
        source_address = s.ip
        d = IPv4Addr(dest_addr)
        destination_address = d.ip

        datagrama = self.create_ipv4_datagram(segmento, self.id, source_address, destination_address)

        self.enlace.enviar(datagrama, next_hop)
