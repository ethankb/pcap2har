#!/usr/bin/python

import dpkt
import optparse
import logging
import sys

import pcaputil
from pcap2har import http
from pcap2har import pcap
from pcap2har import settings
from pcap2har.http import flow as httpflow
from pcap2har.packetdispatcher import PacketDispatcher

# get cmdline args/options
parser = optparse.OptionParser(
    usage='usage: %prog inputfile outputfile'
)
parser.add_option('--allow_trailing_semicolon', action="store_true",
                  dest="allow_trailing_semicolon", default=False)
parser.add_option('--allow_empty_mediatype', action="store_true",
                  dest="allow_empty_mediatype", default=False)
parser.add_option('--strict_mediatype_parsing', action="store_true",
                  dest="strict_mediatype_parsing", default=False)
parser.add_option('--no-pages', action="store_false", dest="pages", default=True)
parser.add_option('--no-padding-in-output', action="store_false",
                  dest="padding_in_output", default=True)
parser.add_option('--no-strict_http_parse_body', action="store_false",
                  dest="strict_http_parse_body", default=True)
parser.add_option('--pad_missing_tcp_data', action="store_true",
                  dest="pad_missing_tcp_data", default=False)
# Whether to write HTTP responses, one per file.
options, args = parser.parse_args()

# copy options to settings module
settings.process_pages = options.pages
settings.pad_missing_tcp_data = options.pad_missing_tcp_data
settings.allow_trailing_semicolon = options.allow_trailing_semicolon
settings.allow_empty_mediatype = options.allow_empty_mediatype
settings.strict_mediatype_parsing = options.strict_mediatype_parsing
settings.strict_http_parse_body = options.strict_http_parse_body

# setup logs
logging.basicConfig(filename='reconstitute_tcp.log', level=logging.INFO)

# get filenames, or bail out with usage error
if len(args) == 2:
    inputfile, outputfile = args[0:2]
elif len(args) == 1:
    inputfile = args[0]
    outputfile = inputfile
else:
    parser.print_help()
    sys.exit()

logging.info("Processing %s", inputfile)

# parse pcap file
dispatcher = PacketDispatcher()
pcap.ParsePcap(dispatcher, filename=inputfile)
dispatcher.finish()

fnum = 0
for flowlist in dispatcher.tcp.flowdict.itervalues():
  for flow in flowlist:
    fwd = flow.fwd.data
    rev = flow.rev.data
    socket = pcaputil.friendly_socket(flow.socket)

    fn = '%s-%s-%d' % (outputfile, socket, fnum)
    fnum += 1
    with open(fn + '.fwd', 'w') as f:
      f.write(flow.fwd.data)
    with open(fn + '.rev', 'w') as f:
      f.write(flow.rev.data)
#     for r in requests + responses:
#       fn = '%s-%s-%d.%s' % (outputfile, str(r.ts_end).replace('.', '_'), fnum,
#                             r.__class__.__name__.lower())
#       fnum += 1
#       with open(fn, 'w') as f:
#         f.write(r.raw_message(not options.padding_in_output))
#       if r.bytes_of_padding > 0:
#         logging.info("%s has %d bytes of padding out of %d", fn, r.bytes_of_padding,
#                      r.data_consumed)
