import flow as tcp
import logging as log

class FlowBuilder:
    '''
    Builds and stores tcp.Flow's from packets.

    Takes a series of tcp.Packet's and sorts them into the correct tcp.Flow's
    based on their socket. Exposes them in a dictionary keyed by socket. Each
    socket maps to a list of flows.  Call
    .add(pkt) for each packet. This will find the right tcp.Flow in the dict and
    call .add() on it. This class should be renamed.

    Members:
    flowdict = {socket: tcp.Flow}
    '''
    def __init__(self):
        self.flowdict = {}
    def add(self, pkt):
        '''
        filters out unhandled packets, and sorts the remainder into the correct
        flow
        '''
        #shortcut vars
        src, dst = pkt.socket
        srcip, srcport = src
        dstip, dstport = dst
        # filter out weird packets, LSONG
        if(srcport == 5223 or dstport == 5223):
            log.warning('hpvirgtrp packets are ignored')
            return
        if(srcport == 5228 or dstport == 5228):
            log.warning('hpvroom packets are ignored')
            return
        if(srcport == 443 or dstport == 443):
            log.warning('https packets are ignored')
            return
        # sort it into a tcp.Flow in flowdict
        if (src, dst) in self.flowdict:
          try:
            self.flowdict[(src, dst)][-1].add(pkt)
          except direction.SequenceError as err:
            self.flowdict[(src, dst)].append(tcp.Flow())
            for err_pkt in err.packets:
              self.add(err_pkt)
        elif (dst, src) in self.flowdict:
          try:
            self.flowdict[(dst, src)][-1].add(pkt)
          except direction.SequenceError as err:
            self.flowdict[(dst, src)].append(tcp.Flow())
            for err_pkt in err.packets:
              self.add(err_pkt)
        else:
            newflow = tcp.Flow()
            newflow.add(pkt)
            self.flowdict[(src, dst)] = [newflow]
    def finish(self):
        map(lambda x: map(tcp.Flow.finish, x), self.flowdict.itervalues())
