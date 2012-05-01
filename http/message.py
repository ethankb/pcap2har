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
    * padding_intervals: [(seq start byte, length)]
    '''
    def __init__(self, tcpdir, pointer, msgclass):
        '''
        Args:
        tcpdir = tcp.Direction
        pointer = position within tcpdir.data to start parsing from. byte index
        msgclass = dpkt.http.Request/Response
        '''
        self.bytes_of_padding = 0
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
          log.warn('Missing ts_start for msg %s tcpdir [%s]',
                   self, self.tcpdir)
          if self.ts_end is None:
            log.warn('Missing ts_end for msg %s tcpdir [%s]',
                     self, self.tcpdir)
            self.ts_end = 0
          self.ts_start = self.ts_end
        if self.ts_end is None:
          log.warn('Missing ts_end for msg %s tcpdir [%s]',
                   self, self.tcpdir)
          self.ts_end = self.ts_start
        # get raw body
        self.raw_body = self.msg.body
        self.raw_msg = self.tcpdir.data[pointer:(pointer+self.data_consumed)]
        log.info("%s-%s [%s] (%s) for %s", self.ts_start, self.ts_end,
                 self.seq_start, pointer, msgclass)
        self.padding_intervals=[]
        last_padding = None
        # iterate in ascending time order, break ties with descending length to
        # handle overlapping ones gracefully
        for start_byte, length in sorted(tcpdir.padding_intervals, lambda x,y:
                                         cmp((x[0],-1*x[1]), (y[0],-1*y[1]))):
          if start_byte >= self.seq_start and start_byte <= self.seq_end:
            if start_byte + length <= self.seq_end:
              if (last_padding and
                  start_byte <= last_padding[0] + last_padding[1]):
                log.info("Padding %s redundant with padding %s",
                         (start_byte, length), last_padding)
                if start_byte + length > last_padding[0] + last_padding[1]:
                  log.fatal("Padding %s overhangs padding %s",
                            (start_byte, length), last_padding)
                next
              else:
                self.bytes_of_padding += length
                self.padding_intervals.append((start_byte, length))
                last_padding = (start_byte, length)
            else:
              log.warn("Padding mismatch: %d plus %d does not fit in %d to %d",
                       start_byte, length, self.seq_start, self.seq_end)

    def raw_message(self, omit_padding=False):
      '''
      Returns the message as a byte string.
      Args:
        omit_padding: whether or not to remove all padding bytes.
      '''
      if omit_padding:
        msg = ""
        current_byte = 0
        for start_byte, length in self.padding_intervals:
          msg += self.raw_msg[current_byte:(start_byte-self.seq_start)]
          current_byte = start_byte - self.seq_start + length
        msg += self.raw_msg[current_byte:]
        return msg
      else:
        return self.raw_msg
