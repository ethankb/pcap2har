#!/usr/bin/python

import dpkt
import optparse
import logging
import sys

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

# setup logs
logging.basicConfig(filename='reconstitute_http.log', level=logging.INFO)

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
for tcpflow in dispatcher.tcp.flowdict.itervalues():
  # try parsing it with forward as request dir
  # TODO(ethankb): Should the try be around the whole block? Not sure if it can
  # parse in one direction but not the other.  Probably not, but doing this for
  # now to be safe.
  success = False
  try:
    success, requests, responses = httpflow.parse_streams(
        tcpflow.fwd, tcpflow.rev)
  except (http.Error,):
    error = sys.exc_info()[1]
    logging.warning(error)
  except (dpkt.dpkt.Error,):
    error = sys.exc_info()[1]
    logging.warning(error)
  # if not, try parsing it the other way
  if not success:
    try:
      success, requests, responses = httpflow.parse_streams(
          tcpflow.rev, tcpflow.fwd)
    except (http.Error,):
      error = sys.exc_info()[1]
      logging.warning(error)
    except (dpkt.dpkt.Error,):
      error = sys.exc_info()[1]
      logging.warning(error)
  if success:
    for r in requests + responses:
      fn = '%s-%s-%d.%s' % (outputfile, str(r.ts_end).replace('.', '_'), fnum,
                            r.__class__.__name__.lower())
      fnum += 1
      with open(fn, 'w') as f:
        f.write(r.raw_message(not options.padding_in_output))
      if r.bytes_of_padding > 0:
        logging.info("%s has %d bytes of padding out of %d", fn, r.bytes_of_padding,
                     r.data_consumed)
  else:
    # flow is not HTTP
    logging.warn('TCP Flow does not contain HTTP')
