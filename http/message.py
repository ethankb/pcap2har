import logging as log


class Message:
    '''
    Contains a dpkt.http.Request/Response, as well as other data required to
    build a HAR, including (mostly) start and end time.

    * msg: underlying dpkt class
    * data_consumed: how many bytes of input were consumed
    * raw_msg: raw message, including http header, as a string
    * seq_start: first sequence number of the Message's data in the tcpdir
    * seq_end: first sequence number past Message's data (slice-style indices)
    * ts_start: when Message started arriving (dpkt timestamp)
    * ts_end: when Message had fully arrived (dpkt timestamp)
    * body_raw: body before compression is taken into account
    * tcpdir: The tcp.Direction corresponding to the HTTP message
    '''
    def __init__(self, tcpdir, pointer, msgclass):
        '''
        Args:
        tcpdir = tcp.Direction
        pointer = position within tcpdir.data to start parsing from. byte index
        msgclass = dpkt.http.Request/Response
        '''
        self.tcpdir = tcpdir
        # attempt to parse as http. let exception fall out to caller
        self.msg = msgclass(tcpdir.data[pointer:])
        self.data = self.msg.data
        self.data_consumed = (len(tcpdir.data) - pointer) - len(self.data)
        # calculate sequence numbers of data
        self.seq_start = tcpdir.byte_to_seq(pointer)
        self.seq_end = tcpdir.byte_to_seq(pointer + self.data_consumed) # past-the-end
        # calculate arrival_times
        self.ts_start = tcpdir.seq_final_arrival(self.seq_start)
        self.ts_end = tcpdir.seq_final_arrival(self.seq_end - 1)
        if self.ts_start is None:
          if self.ts_end is None:
            self.ts_end = 0
          self.ts_start = self.ts_end
        if self.ts_end is None:
          self.ts_end = self.ts_start
        # get raw body
        self.raw_body = self.msg.body
        self.raw_msg = self.tcpdir.data[pointer:(pointer+self.data_consumed)]
        log.info("%s-%s [%s] (%s) for %s", self.ts_start, self.ts_end,
                 self.seq_start, pointer, msgclass)
        log.info(self.raw_msg)
