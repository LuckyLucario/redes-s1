import asyncio
import random
import time
from tcputils import *

DEBUG = True

ALFA = 0.125
BETA = 0.25
class Servidor:
    def __init__(self, rede, porta):
        self.rede = rede
        self.porta = porta
        self.conexoes = {}
        self.callback = None
        self.rede.registrar_recebedor(self._rdt_rcv)

    def registrar_monitor_de_conexoes_aceitas(self, callback):
        """
        Usado pela camada de aplicação para registrar uma função para ser chamada
        sempre que uma nova conexão for aceita
        """
        self.callback = callback

    def _rdt_rcv(self, src_addr, dst_addr, segment):
        src_port, dst_port, seq_no, ack_no, \
            flags, window_size, checksum, urg_ptr = read_header(segment)
        if dst_port != self.porta:
            # Ignora segmentos que não são destinados à porta do nosso servidor
            return
        if not self.rede.ignore_checksum and calc_checksum(segment, src_addr, dst_addr) != 0:
            print('descartando segmento com checksum incorreto')
            return

        payload = segment[4*(flags>>12):]
        id_conexao = (src_addr, src_port, dst_addr, dst_port)

        if (flags & FLAGS_SYN) == FLAGS_SYN:
            # A flag SYN estar setada significa que é um cliente tentando estabelecer uma conexão nova
            # TODO: talvez você precise passar mais coisas para o construtor de conexão
            c_seq_no = random.SystemRandom().randint(0, 0xffff)
            c_ack_no = seq_no + 1
            conexao = self.conexoes[id_conexao] = Conexao(self, id_conexao, c_seq_no, c_ack_no)
            # TODO: você precisa fazer o handshake aceitando a conexão. Escolha se você acha melhor
            # fazer aqui mesmo ou dentro da classe Conexao.
            header = fix_checksum(make_header(dst_port, src_port, c_seq_no, c_ack_no, FLAGS_SYN | FLAGS_ACK), src_addr, dst_addr)
            self.rede.enviar(header, src_addr)
            seq_no+=1
            if self.callback:
                self.callback(conexao)
        elif id_conexao in self.conexoes:
            self.conexoes[id_conexao]._rdt_rcv(seq_no, ack_no, flags, payload)
            if (flags & FLAGS_FIN) == FLAGS_FIN:
                del self.conexoes[id_conexao]
        else:
            print('%s:%d -> %s:%d (pacote associado a conexão desconhecida)' %
                  (src_addr, src_port, dst_addr, dst_port))


class Conexao:
    def __init__(self, servidor, id_conexao, seq_no, ack_no):
        self.servidor = servidor
        self.id_conexao = id_conexao
        self.seq_no = seq_no + 1
        self.ack_no = ack_no
        self.callback = None
        
        self.sendBase = self.seq_no
        self.nya_segments = []
        self.timer = None
        
        self.EstimatedRTT = 0
        self.DevRTT = 0
        self.SampleRTT = 0
        self.dtInicial = {}
        self.timeoutInterval = 1
        
        self.CWND = MSS
        self.nys_data = []
        self.ackedBytes = 0
    
    def _stop_timer(self):
        if self.timer is not None:
            self.timer.cancel()
        self.timer = None
            
    def start_timer(self):
        self._stop_timer()
        self.timer = asyncio.get_event_loop().call_later(self.timeoutInterval, self._timer)
        #self.timer = asyncio.get_event_loop().call_later(1, self._timer)

    def _timer(self):
        if self.nya_segments:
            self.CWND = int((self.CWND / MSS) // 2) * MSS
            self.servidor.rede.enviar(self.nya_segments[0][0],self.nya_segments[0][1])
            key = self.seq_no - self.nya_segments[0][2]
            if key in self.dtInicial:
                del self.dtInicial[key]
            #self.timer.cancel()
            self.start_timer()
            

    def funcaoMagica(self, payload):
        self.callback(self,payload)
        self.ack_no = self.ack_no + len(payload)
        src_addr, src_port, dst_addr, dst_port = self.id_conexao
        self.servidor.rede.enviar(fix_checksum(make_header(dst_port, src_port, self.seq_no, self.ack_no, FLAGS_ACK), dst_addr, src_addr), src_addr)

    def _rdt_rcv(self, seq_no, ack_no, flags, payload):
        # TODO: trate aqui o recebimento de segmentos provenientes da camada de rede.
        # Chame self.callback(self, dados) para passar dados para a camada de aplicação após
        # garantir que eles não sejam duplicados e que tenham sido recebidos em ordem.
        if seq_no != self.ack_no:
            return

        if (flags & FLAGS_ACK) == FLAGS_ACK and ack_no > self.sendBase:
            
            dtFinal = time.time()
            
            self.ackedBytes += ack_no - self.sendBase
            ackedBytes = self.ackedBytes
            if self.ackedBytes >= self.CWND:
                self.CWND += MSS
                self.ackedBytes = 0        
                
            if(self.sendBase in self.dtInicial):
                self.SampleRTT = dtFinal - self.dtInicial[self.sendBase]
                del self.dtInicial[self.sendBase]
                if(self.EstimatedRTT == 0):
                    self.EstimatedRTT = self.SampleRTT
                    self.DevRTT = self.SampleRTT/2
                else:
                    self.EstimatedRTT = (1-ALFA) * self.EstimatedRTT + ALFA * self.SampleRTT
                    self.DevRTT = (1-BETA) * self.DevRTT + BETA * abs((self.SampleRTT - self.EstimatedRTT))
                    
                self.timeoutInterval = self.EstimatedRTT + 4 * self.DevRTT
            if DEBUG:
                print("tempo ate timeout: ", self.timeoutInterval)
            self.sendBase = ack_no
            
            if self.nya_segments:
                while(ackedBytes >= self.nya_segments[0][2]):
                    ackedBytes -= self.nya_segments[0][2]
                    del self.nya_segments[0]
                    if not (self.nya_segments):
                        break
                    
                if self.nya_segments:
                    self.start_timer()
                else:
                    self.timer.cancel()   
            if self.nys_data:
                self.enviar(self.nys_data.pop(0))
                
        if (flags & FLAGS_FIN) == FLAGS_FIN:
            payload = b''
            self.ack_no = self.ack_no + 1
        elif payload == b'':
            return
        self.funcaoMagica(payload)
        if DEBUG:
            print('recebido payload: %r' % payload)

    # Os métodos abaixo fazem parte da API

    def registrar_recebedor(self, callback):
        """
        Usado pela camada de aplicação para registrar uma função para ser chamada
        sempre que dados forem corretamente recebidos
        """
        self.callback = callback

    def enviar(self, dados):
        """
        Usado pela camada de aplicação para enviar dados
        """
        src_addr, src_port, dst_addr, dst_port = self.id_conexao
        payload_size = len(dados)
        used_space = 0
        
        if self.nya_segments:
            for nya_segment in self.nya_segments:
                used_space += nya_segment[2]
        
        header = fix_checksum(make_header(dst_port, src_port, self.seq_no, self.ack_no, FLAGS_ACK), src_addr, dst_addr)
        if payload_size <= MSS:
            segmento = header + dados
            
            segmento = fix_checksum(segmento, src_addr, dst_addr)
            if (used_space + payload_size) <= self.CWND:
                self.servidor.rede.enviar(segmento, dst_addr)
                self.dtInicial[self.seq_no] = time.time()
                self.start_timer()
                self.nya_segments.append([segmento,src_addr, payload_size])
                self.seq_no += payload_size
            else:
                self.nys_data.append(dados)
        else:
            segmento = header + dados[:MSS]
            
            segmento = fix_checksum(segmento, src_addr, dst_addr)
            if (used_space + MSS) <= self.CWND:
                self.servidor.rede.enviar(segmento, dst_addr)
                self.dtInicial[self.seq_no] = time.time()
                self.start_timer()
                self.nya_segments.append([segmento,src_addr, MSS])
                self.seq_no += MSS 
                self.enviar(dados[MSS:])
            else:
                self.nys_data.append(dados)
        
        # Chame self.servidor.rede.enviar(segmento, dest_addr) para enviar o segmento
        # que você construir para a camada de rede.

    def fechar(self):
        """
        Usado pela camada de aplicação para fechar a conexão
        """
        # TODO: implemente aqui o fechamento de conexão
        src_addr, src_port, dst_addr, dst_port = self.id_conexao
        self.servidor.rede.enviar(fix_checksum(make_header(dst_port, src_port, self.seq_no, self.ack_no, FLAGS_FIN), dst_addr, src_addr), src_addr)
